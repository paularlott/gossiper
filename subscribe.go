package gossiper

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// subscriber is one open stream.
type subscriber struct {
	id       string
	matchers []matcher
	grants   *grants // nil: anonymous
	ch       chan *Update
	kicked   chan struct{} // closed when the hub drops the subscriber (it fell behind)
	kickOnce sync.Once
	// closed is closed when the hub closes. Each subscriber has its own: a channel every stream waited on would make
	// each of them lock it whenever it waits or wakes, and thousands of streams would queue for that one lock.
	closed    chan struct{}
	patterned bool // has a matcher that is not exact (set by Hub.add)

	progress atomic.Int64 // when the stream last wrote and flushed, in Unix nanoseconds

	drainMu sync.Mutex
	drained chan struct{} // closed when the queue is back below half full; nil when no publisher waits

	abortMu sync.Mutex
	abort   func() // makes a blocked write fail now; nil until the stream starts
}

// drainWaiter returns a channel closed once the queue is back below half full, or nil when it already is.
func (s *subscriber) drainWaiter() chan struct{} {
	s.drainMu.Lock()
	defer s.drainMu.Unlock()
	if len(s.ch) <= cap(s.ch)/2 {
		return nil
	}
	if s.drained == nil {
		s.drained = make(chan struct{})
	}
	return s.drained
}

// took tells the publishers waiting for s that its queue is back below half full, if it is.
func (s *subscriber) took() {
	if len(s.ch) > cap(s.ch)/2 {
		return
	}
	s.drainMu.Lock()
	if s.drained != nil {
		close(s.drained)
		s.drained = nil
	}
	s.drainMu.Unlock()
}

// kick disconnects the subscriber; true the first time.
func (s *subscriber) kick() bool {
	did := false
	s.kickOnce.Do(func() { close(s.kicked); did = true })
	if did {
		s.abortWrite()
	}
	return did
}

// abortWrite makes the stream's current or next write fail at once, so a stream blocked on a stalled client
// ends when the hub drops it or closes.
func (s *subscriber) abortWrite() {
	s.abortMu.Lock()
	defer s.abortMu.Unlock()
	if s.abort != nil {
		s.abort()
	}
}

// subscription describes s's subscription with matcher m.
func (h *Hub) subscription(s *subscriber, m matcher, active bool) Subscription {
	sub := Subscription{Subscriber: s.id, Active: active, Payload: h.payloadFor(s.grants, m)}
	if m.kind == kindSelector {
		sub.ID = subscriptionsPath + "/" + escapeSegment(m.pattern) + "/" + escapeSegment(s.id)
		sub.Topic = m.pattern
	} else {
		sub.ID = subscriptionsPath + "/" + m.kind.String() + "/" + escapeSegment(m.pattern) + "/" + escapeSegment(s.id)
		sub.MatchType, sub.Match = m.kind.String(), m.pattern
	}
	return sub
}

// escapeSegment percent-encodes everything but the unreserved characters, as an RFC 6570 simple expansion does.
func escapeSegment(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 3 / 2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// replayDedupe is how long after a replay the stream skips live updates it already sent from the history.
const replayDedupe = 5 * time.Second

// batchMax is how many queued updates one write sends before it flushes.
const batchMax = 64

// A stream waits a moment before a write, for the events arriving meanwhile to share it (a write is a system call),
// in one of two cases; otherwise it writes each event at once, so a quiet stream's latency does not change.
const (
	// writeLinger: the stream's own events come fast (its last write carried at least sseLingerMin), and too few are
	// queued to fill a write.
	writeLinger  = 200 * time.Microsecond
	sseLingerMin = 2
	// loadedLinger: the hub as a whole is loaded (Hub.loaded) and the stream's writes carry few events (fewer than
	// loadedFull): thousands of streams each writing every event on its own would spend the machine on system calls.
	// It waits until a write's worth (batchMax) is queued, for loadedLinger at most, so a stream that speeds up does
	// not fill its queue meanwhile; a stream whose writes are already well filled does not wait.
	loadedLinger = 2 * time.Millisecond
	loadedFull   = batchMax / 4
)

// linger waits before s's next write, if it should; last is how many events its previous write carried.
func (s *subscriber) linger(loaded bool, last int) {
	switch {
	case loaded && last < loadedFull:
		for deadline := time.Now().Add(loadedLinger); len(s.ch) < batchMax && time.Now().Before(deadline); {
			time.Sleep(loadedLinger / 4)
		}
	case !loaded && last >= sseLingerMin && len(s.ch) < sseLingerMin:
		time.Sleep(writeLinger)
	}
}

// maxQueryBody bounds the form body of a QUERY subscription request.
const maxQueryBody = 1 << 20

// formMediaType is the media type a QUERY subscription's body is read in.
const formMediaType = "application/x-www-form-urlencoded"

// acceptsEventStream reports whether the Accept header values allow text/event-stream: no header at all states no
// preference; otherwise the most specific range matching text/event-stream (the type itself, text/*, */*) decides,
// and a q of 0 refuses it (so "text/event-stream;q=0, */*" does).
func acceptsEventStream(values []string) bool {
	if len(values) == 0 {
		return true
	}
	best, q := -1, 0.0 // specificity of the best range found: 2 exact, 1 text/*, 0 */*
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			spec := -1
			switch mt {
			case "text/event-stream":
				spec = 2
			case "text/*":
				spec = 1
			case "*/*":
				spec = 0
			}
			if spec <= best {
				continue
			}
			best, q = spec, 1
			if qs, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(qs, 64); err == nil {
					q = f
				}
			}
		}
	}
	return best >= 0 && q > 0
}

// serveSubscribe handles GET (and QUERY) /.well-known/mercure: a Server-Sent Events stream of the updates
// matching the subscription's matchers, after the ones missed since its last event ID.
func (h *Hub) serveSubscribe(w http.ResponseWriter, r *http.Request) {
	// Authentication first: nothing the request asks for is read, parsed or compiled for a client the hub refuses.
	g, src, ok := h.authenticate(w, r, roleSubscriber)
	if !ok {
		return
	}
	if src == noToken && !h.cfg.Anonymous {
		h.writeAuthError(w, r, http.StatusUnauthorized, "")
		return
	}
	if !acceptsEventStream(r.Header.Values("Accept")) {
		writeError(w, http.StatusNotAcceptable, http.StatusText(http.StatusNotAcceptable))
		return
	}
	var body url.Values
	if r.Method == methodQuery {
		w.Header().Set("Accept-Query", formMediaType) // on an error too, so the client learns what to send
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			writeError(w, http.StatusBadRequest, "Missing Content-Type")
			return
		}
		if mt, _, _ := mime.ParseMediaType(ct); mt != formMediaType {
			writeError(w, http.StatusUnsupportedMediaType, http.StatusText(http.StatusUnsupportedMediaType))
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxQueryBody))
		if err != nil {
			if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
				writeError(w, http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge))
			} else {
				writeError(w, http.StatusBadRequest, "Invalid request body")
			}
			return
		}
		if body, err = url.ParseQuery(string(b)); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}
	ms, cursor, err := h.subscriptionParams(r.URL.Query(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, upperFirst(err.Error()))
		return
	}
	if len(ms) == 0 {
		writeError(w, http.StatusBadRequest, h.missingMatcher())
		return
	}
	ms = dedupeMatchers(ms)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		cursor = v
	}
	if r.Method == http.MethodHead { // the headers only: nothing to register, nor to replay
		_, at := h.replayFor(&subscriber{matchers: ms, grants: g}, cursor)
		h.streamHeaders(w, r, cursor, at)
		return
	}
	s := &subscriber{
		id:       newSubscriberID(),
		matchers: ms,
		grants:   g,
		ch:       make(chan *Update, h.cfg.DispatchBuffer),
		kicked:   make(chan struct{}),
		closed:   make(chan struct{}),
	}
	rc := http.NewResponseController(w)
	s.abort = func() { _ = rc.SetWriteDeadline(time.Now()) }
	if !h.add(s) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	defer h.remove(s)
	defer func() { // the response writer is gone once the handler returns
		s.abortMu.Lock()
		s.abort = nil
		s.abortMu.Unlock()
	}()

	// Registered before the history is read: an update applied meanwhile is in the queue, the history, or both
	// (the duplicates are skipped below), never in neither.
	replay, at := h.replayFor(s, cursor)
	h.streamHeaders(w, r, cursor, at)

	// arm readies the stream for a batch of writes: false when it has ended. The write deadline is moved forward at
	// most every quarter of the write timeout, not at every batch (each move is a change to a runtime timer, which
	// thousands of streams writing at once contend for); it is set a quarter beyond, so a batch always has the whole
	// timeout.
	var deadline time.Time
	arm := func(now time.Time) bool {
		if now.After(deadline.Add(-h.cfg.WriteTimeout)) {
			deadline = now.Add(h.cfg.WriteTimeout + h.cfg.WriteTimeout/4)
			_ = rc.SetWriteDeadline(deadline)
		}
		select { // set after an abort, the deadline above would undo it
		case <-s.closed:
			return false
		case <-s.kicked:
			return false
		default:
			return true
		}
	}
	write := func(b []byte, flush bool) bool {
		if _, err := w.Write(b); err != nil {
			return false
		}
		return !flush || rc.Flush() == nil
	}
	if !arm(time.Now()) || !write([]byte(":\n"), true) {
		return
	}
	s.progress.Store(time.Now().UnixNano())
	if h.cfg.Subscriptions { // once the client has its response: announcing waits for the transport
		h.announce(s, true)
		defer h.announce(s, false)
	}

	var sent map[key]struct{}
	dedupeUntil := time.Time{}
	if len(replay) > 0 {
		sent = make(map[key]struct{}, len(replay))
		for i, u := range replay {
			sent[key{u.Origin, u.Stamp}] = struct{}{}
			flush := i == len(replay)-1 || (i+1)%batchMax == 0
			if !write(u.encoded, flush) {
				return
			}
			if flush { // still writing: publishers wait for its queue rather than see it stalled and drop it
				s.progress.Store(time.Now().UnixNano())
			}
		}
		h.stats.Replayed.Add(uint64(len(replay)))
		h.stats.Delivered.Add(uint64(len(replay)))
		dedupeUntil = time.Now().Add(replayDedupe)
	}

	var heartbeat <-chan time.Time
	if h.cfg.Heartbeat > 0 {
		t := time.NewTicker(h.cfg.Heartbeat)
		defer t.Stop()
		heartbeat = t.C
	}
	// A Mercure 1.0 token ends its stream when it expires; a draft-07 one when configured to.
	var end time.Time
	if g != nil && !g.expiry.IsZero() && (g.modern || h.cfg.CloseOnTokenExpiry) {
		end = g.expiry
	}
	if l := h.cfg.MaxConnectionLifetime; l > 0 && (end.IsZero() || time.Now().Add(l).Before(end)) {
		end = time.Now().Add(l)
	}
	var expired <-chan time.Time
	if !end.IsZero() {
		t := time.NewTimer(time.Until(end))
		defer t.Stop()
		expired = t.C
	}
	ctx := r.Context()
	// writeBatch writes u and what else is queued (up to batchMax), and flushes.
	writeBatch := func(u *Update) (int, bool) {
		now := time.Now()
		if !arm(now) {
			return 0, false
		}
		if sent != nil && now.After(dedupeUntil) {
			sent = nil
		}
		n := 0
		for i := 0; ; i++ {
			dup := false
			if sent != nil {
				_, dup = sent[key{u.Origin, u.Stamp}]
			}
			if !dup {
				if !write(u.encoded, false) {
					return n, false
				}
				n++
			}
			if i+1 >= batchMax {
				break
			}
			var more bool
			select {
			case u = <-s.ch:
				more = true
			default:
			}
			if !more {
				break
			}
		}
		if n > 0 {
			if !write(nil, true) {
				return n, false
			}
			s.progress.Store(now.UnixNano())
			s.took()
			h.stats.Delivered.Add(uint64(n))
		}
		return n, true
	}
	last := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-s.kicked:
			return
		case <-expired:
			return
		case <-heartbeat:
			if !arm(time.Now()) || !write([]byte(":\n"), true) {
				return
			}
		case u := <-s.ch:
			s.linger(h.loaded.Load(), last)
			n, ok := writeBatch(u)
			if !ok {
				return
			}
			last = n
		}
	}
}

// streamHeaders writes the status and headers of a subscription stream; at is the cursor its replay follows.
func (h *Hub) streamHeaders(w http.ResponseWriter, r *http.Request, cursor, at string) {
	hd := w.Header()
	if cursor != "" {
		hd.Set("Mercure-Last-Event-ID", at)
		if h.cfg.Protocol.legacy() {
			hd.Set("Last-Event-ID", at)
		}
	}
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "private, no-cache, no-store, must-revalidate, max-age=0")
	hd.Set("Pragma", "no-cache")
	hd.Set("Expires", "0")
	hd.Set("X-Accel-Buffering", "no")
	hd.Set("Accept-Query", formMediaType)
	if r.ProtoMajor == 1 {
		hd.Set("Connection", "keep-alive")
	}
	w.WriteHeader(http.StatusOK)
}

// missingMatcher is the error of a subscription without a matcher, in the parameter of the accepted revision.
func (h *Hub) missingMatcher() string {
	if h.cfg.Protocol.legacy() {
		return `Missing "topic" parameter`
	}
	return `Missing "match" parameter`
}

// replayFor returns the updates of the history after cursor that s may receive, and the cursor they follow: cursor
// itself, earliest when the history does not have it, or the event before a late arrival sent ahead of the cursor's
// successors. Call it once s is registered: an update applied meanwhile is in the queue, the history, or both, never
// in neither. No cursor, no replay.
func (h *Hub) replayFor(s *subscriber, cursor string) (replay []*Update, at string) {
	if cursor == "" {
		return nil, ""
	}
	replay, at, found := h.hist.replay(cursor, func(u *Update) bool { return h.canReceive(s, u) })
	if !found {
		h.stats.ReplayMisses.Add(1)
	}
	return replay, at
}

// announce publishes the subscription events of s: one per matcher, active when it connects, inactive when it
// goes. A Mercure 1.0 subscription's events (and, with ModernSubscriptionFormat, a draft-07 one's) are of type
// "mercure" with a plain JSON document; a draft-07 one's otherwise use the JSON-LD document of draft-07.
func (h *Hub) announce(s *subscriber, active bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, m := range s.matchers {
		sub := h.subscription(s, m, active)
		u := &Update{Topics: []string{sub.ID}, Private: true}
		if sub.modern() || h.cfg.ModernSubscriptionFormat {
			sub.Type = "subscription"
			u.Type = "mercure"
		} else {
			sub.Type = "Subscription"
			sub.Context = "https://mercure.rocks/"
		}
		u.Data = string(jsonMarshal(sub))
		if _, err := h.publish(ctx, u); err != nil && !errors.Is(err, ErrClosed) {
			h.log.Debug("subscription event not published", "subscriber", s.id, "error", err.Error())
		}
	}
}
