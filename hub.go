// Package gossiper is a Mercure-compatible publish/subscribe hub: publishers POST updates, subscribers receive
// them over Server-Sent Events, and a cluster of hubs shares them through a Transport. It speaks both revisions of
// the protocol: draft-07 and Mercure 1.0 (draft-08).
package gossiper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/gossiper/topic"
	"github.com/paularlott/gossiper/urlpattern"
	"github.com/paularlott/logger"
)

// ErrClosed is returned by Publish once the hub is closing.
var ErrClosed = errors.New("gossiper: hub closed")

// ErrUpdateTooLarge is returned (wrapped) by a transport that cannot carry an update of its size; the hub answers
// 413.
var ErrUpdateTooLarge = errors.New("gossiper: update too large")

// maxWitnessAhead bounds how far ahead of this node's clock a peer's stamp may move it.
const maxWitnessAhead = 5 * time.Second

// Hub is a Mercure hub. It is an http.Handler serving the hub's URL (/.well-known/mercure), the subscriptions API
// under it, and the hub's OAuth protected resource metadata.
type Hub struct {
	cfg        Config
	log        logger.Logger
	pub, sub   *auth.Verifier       // draft-07 tokens; nil: no key configured
	apub, asub *auth.AccessVerifier // Mercure 1.0 tokens; nil: no trusted issuer
	matcher    *topic.Matcher
	urls       *urlpattern.Matcher
	base       *url.URL // the hub URL relative topics and patterns resolve against
	clock      *hlc.Clock
	hist       *history
	tokens     tokenCache
	idem       idempotency // the IDs of the idempotent updates applied lately
	// fanned counts the events queued for subscribers; loaded says that the last loadInterval queued more than
	// loadEvents: streams whose writes carry few events then wait loadedLinger before each write (see linger).
	fanned    atomic.Uint64
	loaded    atomic.Bool
	store     HistoryStore // or nil
	loading   bool         // the history is being loaded from the store: what is restored is not saved again
	transport Transport
	nodeID    string
	tenant    string // the tenant this hub serves when Tenants run it (see Update.Tenant); "" otherwise

	mu        sync.RWMutex
	subs      map[*subscriber]struct{}
	exact     map[string]map[*subscriber]struct{} // topic -> subscribers with an exact matcher for it
	patterned map[*subscriber]struct{}            // subscribers with a matcher that is not exact

	closing    chan struct{}
	closingCtx context.Context // done when closing is closed
	endCtx     context.CancelFunc
	closeOnce  sync.Once
	streams    sync.WaitGroup
	pubMu      sync.Mutex // guards pubClosed, and publishers.Add against Close
	pubClosed  bool
	publishers sync.WaitGroup // publishes in progress: Close waits for them before it stops the transport

	applyMu     sync.RWMutex // guards applyClosed, and applying.Add against Close
	applyClosed bool
	applying    sync.WaitGroup // updates being applied: Close waits for them, so none is stored after it returns

	since uint64        // updates stamped before it were a former tenant's of this name (Config.since)
	stop  chan struct{} // ends the housekeeping loop
	done  chan struct{}

	stats Stats

	refusedLogged atomic.Int64 // when an update refused for its clock was last logged, in Unix nanoseconds
}

// Stats are the hub's counters. Read them with Hub.Stats.
type Stats struct {
	Subscribers     atomic.Int64  // open streams on this node
	Published       atomic.Uint64 // updates published through this node
	Applied         atomic.Uint64 // updates applied on this node (published here or replicated)
	Delivered       atomic.Uint64 // events written to subscribers
	Dropped         atomic.Uint64 // subscribers disconnected for falling behind
	Replayed        atomic.Uint64 // events sent from the history
	ReplayMisses    atomic.Uint64 // reconnections whose last event ID was not in the history
	Duplicates      atomic.Uint64 // updates applied twice, ignored
	Refused         atomic.Uint64 // updates from other nodes refused, stamped too far ahead of this node's clock
	PublishRejected atomic.Uint64 // publish requests refused (auth or validation)
	KeySetsFailing  atomic.Int64  // remote key sets (JWK Sets, discovery) whose last fetch failed
}

// StatsSnapshot is a copy of the hub's counters.
type StatsSnapshot struct {
	Subscribers, Published, Applied, Delivered, Dropped, Replayed, ReplayMisses, Duplicates, PublishRejected, Refused uint64
	KeySetsFailing                                                                                                    uint64
	HistoryLen                                                                                                        int
	HistoryBytes                                                                                                      int64
}

// New returns a hub. Call Close to stop it.
func New(c Config) (*Hub, error) {
	cfg, err := c.withDefaults()
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse(cfg.HubURL)
	if !base.IsAbs() {
		base, _ = url.Parse("https://localhost" + hubPath)
	}
	h := &Hub{
		cfg:       cfg,
		log:       cfg.Logger,
		matcher:   topic.NewMatcher(cfg.MatchCacheSize),
		urls:      urlpattern.NewMatcher(base.String(), cfg.MatchCacheSize),
		base:      base,
		clock:     hlc.NewClock(),
		since:     cfg.since,
		hist:      newHistory(cfg.HistorySize, cfg.HistoryBytes, cfg.HistoryAge, cfg.ReplayWindow),
		subs:      map[*subscriber]struct{}{},
		exact:     map[string]map[*subscriber]struct{}{},
		patterned: map[*subscriber]struct{}{},
		closing:   make(chan struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	h.closingCtx, h.endCtx = context.WithCancel(context.Background())
	// What it publishes orders after its tenant's creation, whichever node created it (within the bound on skew).
	h.clock.WitnessBounded(hlc.Timestamp(h.since), maxWitnessAhead)
	if err := h.newVerifiers(); err != nil {
		h.closeVerifiers()
		return nil, err
	}
	if u, _ := url.Parse(cfg.HubURL); (h.apub != nil || h.asub != nil) && cfg.ResourceIdentifier == "" && (u == nil || !u.IsAbs()) {
		h.log.Warn("no resource identifier configured: Mercure 1.0 tokens are checked against the hub URL each " +
			"client contacted (its Host header); set ResourceIdentifier or an absolute HubURL to bind tokens to this hub")
	}
	h.transport = cfg.Transport
	if h.transport == nil {
		h.transport = &local{}
	}
	if tt, ok := h.transport.(*tenantTransport); ok {
		h.tenant = tt.tenant
	}
	// The node id is settled before the transport starts: a peer's update can reach Apply from then on.
	h.nodeID = cfg.NodeID
	if h.nodeID == "" {
		h.nodeID = h.transport.NodeID()
	}
	if h.nodeID == "" {
		h.nodeID = newSubscriberID()[9:]
	}
	h.store = cfg.HistoryStore
	if err := h.loadHistory(); err != nil {
		h.closeVerifiers()
		return nil, fmt.Errorf("loading the history: %w", err)
	}
	if err := h.transport.Start(h); err != nil {
		h.closeVerifiers()
		return nil, err
	}
	go h.housekeeping()
	return h, nil
}

// newVerifiers builds the token verifiers the configured protocols need.
func (h *Hub) newVerifiers() error {
	cfg := &h.cfg
	pubKey, subKey := cfg.PublisherKey, cfg.SubscriberKey
	if !hasKey(subKey) {
		subKey = pubKey
	}
	pubKey.AllowInsecureHTTP, subKey.AllowInsecureHTTP = cfg.AllowInsecureKeyURLs, cfg.AllowInsecureKeyURLs
	if cfg.KeyURLsCAs != nil { // key sets and discovery fetched trusting those authorities too
		c := auth.KeyURLClient(cfg.KeyURLsCAs, cfg.AllowInsecureKeyURLs)
		if pubKey.HTTPClient == nil {
			pubKey.HTTPClient = c
		}
		if subKey.HTTPClient == nil {
			subKey.HTTPClient = c
		}
	}
	var err error
	if cfg.Protocol.legacy() {
		if hasKey(pubKey) {
			if h.pub, err = auth.NewVerifier(pubKey); err != nil {
				return err
			}
		}
		if hasKey(subKey) {
			if h.sub, err = auth.NewVerifier(subKey); err != nil {
				return err
			}
		}
	}
	// The keys are checked whatever the protocol: a Mercure 1.0 only hub with no trusted issuer to bind them to
	// verifies nothing with them, but a bad key is still refused, and a weak one still warned about.
	for _, k := range []struct {
		key  auth.KeyConfig
		role string
		warn bool
	}{{pubKey, "publisher", true}, {subKey, "subscriber", hasKey(cfg.SubscriberKey)}} {
		if !hasKey(k.key) {
			continue
		}
		weak, err := auth.CheckKey(k.key)
		if err != nil {
			return err
		}
		if weak && k.warn {
			h.log.Warn("the " + k.role + " key is shorter than its algorithm needs; use a longer secret")
		}
	}
	if cfg.Protocol.modern() {
		if h.apub, err = h.accessVerifier(pubKey); err != nil {
			return err
		}
		if h.asub, err = h.accessVerifier(subKey); err != nil {
			return err
		}
	}
	return nil
}

// accessVerifier returns the Mercure 1.0 verifier of one role: each trusted issuer bound to the role's key, and
// the issuers with keys of their own. Nil when there are none.
func (h *Hub) accessVerifier(key auth.KeyConfig) (*auth.AccessVerifier, error) {
	cfg := &h.cfg
	var issuers []auth.Issuer
	if hasKey(key) {
		for _, iss := range cfg.TrustedIssuers {
			is := auth.Issuer{Issuer: iss, Key: key.Key, JWKSURL: key.JWKSURL, PreviousKey: key.PreviousKey, PreviousUntil: key.PreviousUntil}
			if key.Algorithm != "" {
				is.Algorithms = []string{key.Algorithm}
			}
			issuers = append(issuers, is)
		}
	}
	issuers = append(issuers, cfg.Issuers...)
	if len(issuers) == 0 {
		return nil, nil
	}
	return auth.NewAccessVerifier(auth.AccessConfig{
		Issuers:           issuers,
		Audience:          cfg.ResourceIdentifier,
		JWKSRefresh:       key.JWKSRefresh,
		HTTPClient:        key.HTTPClient,
		Leeway:            key.Leeway,
		AllowInsecureHTTP: cfg.AllowInsecureKeyURLs,
		ValidateMatcher: func(matchType, pattern string) error {
			if matchType == "urlpattern" {
				return h.urls.Valid(pattern)
			}
			return nil
		},
	})
}

func (h *Hub) closeVerifiers() {
	for _, v := range []*auth.Verifier{h.pub, h.sub} {
		if v != nil {
			v.Close()
		}
	}
	for _, v := range []*auth.AccessVerifier{h.apub, h.asub} {
		if v != nil {
			v.Close()
		}
	}
}

// A hub is loaded while it queues more than loadEvents events for its subscribers in loadInterval (50k a second).
const (
	loadInterval = 50 * time.Millisecond
	loadEvents   = 2500
)

// housekeeping expires old history while the hub is quiet, and measures its load.
func (h *Hub) housekeeping() {
	defer close(h.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	load := time.NewTicker(loadInterval)
	defer load.Stop()
	var last uint64
	var keyErr string
	trimmed := time.Now()
	for {
		select {
		case <-h.stop:
			return
		case <-load.C:
			n := h.fanned.Load()
			h.loaded.Store(n-last > loadEvents)
			last = n
		case now := <-t.C:
			h.hist.expire()
			if now.Sub(trimmed) >= storeTrimEvery {
				trimmed = now
				h.trimStore()
			}
			keyErr = h.checkKeySets(keyErr)
		}
	}
}

// checkKeySets logs a remote key set (JWK Set or discovery) that fails to load, and when it loads again: a hub
// that cannot fetch its keys refuses every token, so the failure must be seen. last is the failure logged last.
func (h *Hub) checkKeySets(last string) string {
	var errs []string
	add := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, v := range []*auth.Verifier{h.pub, h.sub} {
		if v != nil {
			add(v.JWKSError())
		}
	}
	for _, v := range []*auth.AccessVerifier{h.apub, h.asub} {
		if v != nil {
			add(v.JWKSError())
		}
	}
	h.stats.KeySetsFailing.Store(int64(len(errs)))
	now := strings.Join(errs, "; ")
	switch {
	case now == last:
	case now == "":
		h.log.Info("key sets loading again")
	default:
		h.log.Warn("key set fetch failing: tokens are refused until it loads", "error", now)
	}
	return now
}

// NodeID returns the id this node stamps on the updates it publishes.
func (h *Hub) NodeID() string { return h.nodeID }

// Publish publishes a copy of u through the hub and returns its event ID: u's ID, or one the hub makes when it
// has none. Publishers' authorization is not checked: the caller is trusted.
func (h *Hub) Publish(ctx context.Context, u *Update) (string, error) {
	if !h.enterPublish() {
		return "", ErrClosed
	}
	defer h.publishers.Done()
	c := &Update{ID: u.ID, Topics: slices.Clone(u.Topics), Data: u.Data, Private: u.Private, Type: u.Type,
		Retry: u.Retry, HasRetry: u.HasRetry, Replicas: u.Replicas}
	if err := h.validate(c); err != nil {
		return "", err
	}
	id, err := h.publish(ctx, c)
	if err == nil {
		err = h.replicated(ctx, c)
	}
	return id, err
}

// enterPublish registers a publish in progress (call publishers.Done when it is over); false once the hub closes.
func (h *Hub) enterPublish() bool {
	h.pubMu.Lock()
	defer h.pubMu.Unlock()
	if h.pubClosed {
		return false
	}
	h.publishers.Add(1)
	return true
}

// publish stamps a validated update and hands it to the transport.
func (h *Hub) publish(ctx context.Context, u *Update) (string, error) {
	ts := h.clock.Now()
	u.Stamp = uint64(ts)
	u.Origin = h.nodeID
	u.Idempotent = u.Replicas > 0 && u.ID != ""
	if u.ID == "" {
		u.ID = newEventID(ts)
	}
	u.encoded = nil
	var err error
	if u.Replicas > 0 {
		err = h.publishCopies(ctx, u)
	} else {
		err = h.transport.Publish(ctx, u)
	}
	if err != nil {
		return "", err
	}
	h.stats.Published.Add(1)
	return u.ID, nil
}

// Apply applies an update on this node: it records it in the history and sends it to the matching subscribers.
// Transports call it for every update, published on this node or another; an update applied before is ignored.
// The hub keeps u: the caller must not change it afterwards.
func (h *Hub) Apply(u *Update) { h.apply(u, false) }

// Restore records an update the node held before it restarted, or a peer held (its history, copied), as Apply
// does, but as received when it was published: a subscriber resuming after it is not sent again the updates that
// were already before it, as the late-arrival rule would send updates that only just arrived.
func (h *Hub) Restore(u *Update) { h.apply(u, true) }

func (h *Hub) apply(u *Update, restored bool) {
	if u == nil || len(u.Topics) == 0 || u.ID == "" {
		return
	}
	if u.Tenant != h.tenant { // another tenant's update, reaching a node that does not run that tenant as a hub
		return
	}
	if u.Stamp < h.since { // a former tenant's of this name, deleted since: from a peer that missed it, or the store
		return
	}
	h.applyMu.RLock()
	if h.applyClosed { // the hub is closing: nothing more goes into its history or its store
		h.applyMu.RUnlock()
		return
	}
	h.applying.Add(1)
	h.applyMu.RUnlock()
	defer h.applying.Done()
	if u.Origin != h.nodeID && !h.clock.WitnessBounded(hlc.Timestamp(u.Stamp), maxWitnessAhead) {
		// Kept, it would sort after everything published here for as long as the skew lasts, and a cursor at it would
		// skip those updates on reconnection.
		h.stats.Refused.Add(1)
		if now := time.Now().UnixNano(); now-h.refusedLogged.Load() > int64(time.Minute) { // once a minute, not per update
			h.refusedLogged.Store(now)
			h.log.Warn("update refused: stamped too far ahead of this node's clock (check the nodes' clocks)", "origin", u.Origin,
				"refused_total", h.stats.Refused.Load())
		}
		return
	}
	if u.encoded == nil {
		u.encoded = u.encode()
	}
	// Before it reaches any subscriber, who share it. (Apply is handed each update once: one from another node is
	// decoded for this node, one published here is the publisher's own copy, so none is written here while
	// subscribers read it.)
	recv, at := h.clock.Now(), time.Time{}
	if restored { // as when it was published, for the replay window and the age bound
		recv = hlc.Timestamp(u.Stamp)
		at = recv.Time()
	}
	if u.Idempotent && !h.idem.first(u.ID, time.Now()) && !restored { // published again: the first was applied
		h.stats.Duplicates.Add(1)
		return
	}
	if !h.hist.addAt(u, recv, at) {
		h.stats.Duplicates.Add(1)
		return
	}
	h.save(u)
	h.stats.Applied.Add(1)
	// An update waits for the subscribers behind, published here or on another node (the cluster transport applies
	// each peer's on a goroutine of its own, so a slow reader here paces that peer's replication, and nothing else).
	if behind := h.fanout(u); len(behind) > 0 && !restored {
		h.wait(behind)
	}
}

// Back-pressure: an update waits for subscribers whose queue is more than half full, as long as they are still
// writing, for at most stallMax; one that has written nothing for stallAlive is not waited for, and is dropped when
// its queue fills.
const (
	stallMax   = 20 * time.Millisecond
	stallAlive = 250 * time.Millisecond
)

// wait holds the publisher while the subscribers in behind work their queues down below half, for at most stallMax:
// a burst then slows the publishers down instead of disconnecting subscribers that read a little slower.
func (h *Hub) wait(behind []*subscriber) {
	t := time.NewTimer(stallMax)
	defer t.Stop()
	for _, s := range behind {
		ch := s.drainWaiter()
		if ch == nil {
			continue
		}
		select {
		case <-ch:
		case <-s.kicked:
		case <-h.closing:
			return
		case <-t.C:
			return
		}
	}
}

// fanout queues u for every subscriber that may receive it. It never blocks: a subscriber whose queue is full is
// disconnected (after the lock: that writes to its connection), and catches up from the history when it reconnects.
// It returns the subscribers whose queue is over half full but who are still writing, for the publisher to wait for.
func (h *Hub) fanout(u *Update) (behind []*subscriber) {
	var full []*subscriber
	queued := 0
	h.mu.RLock()
	for s := range h.patterned {
		if h.canReceive(s, u) {
			behind, full, queued = h.send(s, u, behind, full, queued)
		}
	}
	var seen map[*subscriber]struct{}
	if len(u.Topics) > 1 {
		seen = map[*subscriber]struct{}{}
	}
	for _, t := range u.Topics {
		for s := range h.exact[t] {
			if seen != nil {
				if _, ok := seen[s]; ok {
					continue
				}
				seen[s] = struct{}{}
			}
			if !u.Private || h.authorized(s, u) {
				behind, full, queued = h.send(s, u, behind, full, queued)
			}
		}
	}
	h.mu.RUnlock()
	h.fanned.Add(uint64(queued))
	for _, s := range full {
		if s.kick() {
			h.stats.Dropped.Add(1)
			h.log.Debug("subscriber fell behind, disconnecting", "subscriber", s.id)
		}
	}
	return behind
}

// send queues u for s: added to behind when its queue is over half full while it still writes, to full when its
// queue is full (to be disconnected); queued counts the updates queued.
func (h *Hub) send(s *subscriber, u *Update, behind, full []*subscriber, queued int) ([]*subscriber, []*subscriber, int) {
	select {
	case s.ch <- u:
		if len(s.ch) > cap(s.ch)/2 && time.Since(time.Unix(0, s.progress.Load())) < stallAlive {
			behind = append(behind, s)
		}
		return behind, full, queued + 1
	default:
		return behind, append(full, s), queued
	}
}

// canReceive reports whether s subscribed to one of u's topics and, for a private update, may see it.
func (h *Hub) canReceive(s *subscriber, u *Update) bool {
	return h.matchAny(s.matchers, u.Topics) && (!u.Private || h.authorized(s, u))
}

// authorized reports whether s's token lets it receive the private update u: it grants subscribe on one of u's
// topics, canonical or alternate.
func (h *Hub) authorized(s *subscriber, u *Update) bool {
	return s.grants != nil && h.matchAny(s.grants.subscribe, u.Topics)
}

// add registers s; false when the node is at its limit or closing.
func (h *Hub) add(s *subscriber) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.closing:
		return false
	default:
	}
	if h.cfg.MaxSubscribers > 0 && len(h.subs) >= h.cfg.MaxSubscribers {
		return false
	}
	h.subs[s] = struct{}{}
	for _, m := range s.matchers {
		if m.isPatterned() {
			s.patterned = true
		}
	}
	if s.patterned {
		h.patterned[s] = struct{}{}
	} else {
		for _, m := range s.matchers {
			set := h.exact[m.pattern]
			if set == nil {
				set = map[*subscriber]struct{}{}
				h.exact[m.pattern] = set
			}
			set[s] = struct{}{}
		}
	}
	h.stats.Subscribers.Add(1)
	h.streams.Add(1) // under mu: Close cannot start waiting between the closing check and this
	return true
}

func (h *Hub) remove(s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[s]; !ok {
		return
	}
	delete(h.subs, s)
	if s.patterned {
		delete(h.patterned, s)
	} else {
		for _, m := range s.matchers {
			if set := h.exact[m.pattern]; set != nil {
				delete(set, s)
				if len(set) == 0 {
					delete(h.exact, m.pattern)
				}
			}
		}
	}
	h.stats.Subscribers.Add(-1)
	h.streams.Done()
}

// History implements Host.
func (h *Hub) History(stamp uint64, origin string, maxBytes int) ([]*Update, bool) {
	return h.hist.page(stamp, origin, maxBytes)
}

// LocalSubscriptions returns the active subscriptions of this node's subscribers.
func (h *Hub) LocalSubscriptions() []Subscription {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Subscription, 0, len(h.subs))
	for s := range h.subs {
		for _, m := range s.matchers {
			out = append(out, h.subscription(s, m, true))
		}
	}
	return out
}

// Stats returns a copy of the hub's counters.
func (h *Hub) Stats() StatsSnapshot {
	s := &h.stats
	return StatsSnapshot{
		Subscribers: uint64(max(s.Subscribers.Load(), 0)), Published: s.Published.Load(), Applied: s.Applied.Load(),
		Delivered: s.Delivered.Load(), Dropped: s.Dropped.Load(), Replayed: s.Replayed.Load(),
		ReplayMisses: s.ReplayMisses.Load(), Duplicates: s.Duplicates.Load(), PublishRejected: s.PublishRejected.Load(),
		Refused:        s.Refused.Load(),
		KeySetsFailing: uint64(max(s.KeySetsFailing.Load(), 0)),
		HistoryLen:     h.hist.len(),
		HistoryBytes:   h.hist.size(),
	}
}

// Close stops the hub: new requests are refused, open streams end (clients reconnect, to another node when there
// is one), and the transport stops. It waits for the streams to end, or for ctx.
func (h *Hub) Close(ctx context.Context) error {
	var err error
	h.closeOnce.Do(func() {
		h.mu.Lock()
		close(h.closing)
		h.endCtx()
		h.pubMu.Lock()
		h.pubClosed = true
		h.pubMu.Unlock()
		h.applyMu.Lock()
		h.applyClosed = true
		h.applyMu.Unlock()
		for s := range h.subs {
			if s.closed != nil {
				close(s.closed)
			}
			s.abortWrite() // a stream blocked writing to a stalled client ends now, not at its write timeout
		}
		h.mu.Unlock()
		waited := make(chan struct{})
		go func() { h.streams.Wait(); h.publishers.Wait(); h.applying.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-ctx.Done():
			err = ctx.Err()
		}
		close(h.stop)
		<-h.done
		if terr := h.transport.Close(); terr != nil && err == nil {
			err = terr
		}
		h.closeVerifiers()
		h.hist.share(nil) // what it holds no longer counts against a budget it shares
	})
	return err
}

// ServeHTTP serves the hub: publishing and subscribing at /.well-known/mercure, the subscriptions API under
// /.well-known/mercure/subscriptions, and the protected resource metadata at
// /.well-known/oauth-protected-resource/.well-known/mercure. Mount it at the root of a mux, or route those paths
// to it.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	h.cors(w, r)
	path := r.URL.Path
	switch {
	case path == hubPath:
		switch r.Method {
		case http.MethodGet, http.MethodHead, methodQuery:
			h.serveSubscribe(w, r)
		case http.MethodPost:
			h.servePublish(w, r)
		case http.MethodOptions:
			h.preflight(w, r)
		default:
			w.Header().Set("Allow", "GET, HEAD, QUERY, POST, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case path == subscriptionsPath || len(path) > len(subscriptionsPath) && path[:len(subscriptionsPath)+1] == subscriptionsPath+"/":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			h.serveSubscriptions(w, r)
		case http.MethodOptions:
			h.preflight(w, r)
		default:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case path == metadataPath && h.cfg.Protocol.modern():
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			h.serveMetadata(w, r)
		case http.MethodOptions:
			h.preflight(w, r)
		default:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

const (
	hubPath           = "/.well-known/mercure"
	subscriptionsPath = "/.well-known/mercure/subscriptions"
	metadataPath      = "/.well-known/oauth-protected-resource/.well-known/mercure"
	methodQuery       = "QUERY"
)

// jsonMarshal is json.Marshal without HTML escaping (topics and IDs keep their & < >).
func jsonMarshal(v any) []byte {
	var b jsonBuffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return b.bytes()
}

type jsonBuffer struct{ b []byte }

func (j *jsonBuffer) Write(p []byte) (int, error) { j.b = append(j.b, p...); return len(p), nil }
func (j *jsonBuffer) bytes() []byte {
	if n := len(j.b); n > 0 && j.b[n-1] == '\n' {
		return j.b[:n-1]
	}
	return j.b
}
