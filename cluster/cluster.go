// Package cluster is a gossiper.Transport over a gossip cluster: every hub in the cluster sends the updates
// published through it straight to every other hub, in order, many to a message when it is busy, so a subscriber
// connected to any node receives every update.
//
// Each peer has a sender of its own that keeps one batch in flight and sends the next once the peer has acknowledged
// it, so a peer receives a node's updates in the order they were published there, and a slow peer gets larger batches
// rather than a backlog of messages. A batch that is not acknowledged is sent again while the peer is a member of the
// group, so a peer may receive an update more than once; its hub applies it once (by origin and stamp). What is
// queued for a peer that leaves, or more than MaxQueueBytes for one that cannot keep up, is dropped and counted
// (Dropped), as are updates a peer cannot decode (a node of another version). A node that starts copies the history of
// a peer (Options.Backfill), so its subscribers can resume with Last-Event-ID from there, and two nodes that lost each
// other (a partition, a node declared dead) exchange what they published meanwhile when they meet again, as far as
// their histories still hold it. A publish may ask for copies
// (PublishCopies): it is answered once that many nodes hold the update.
package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper"
	"github.com/shamaton/msgpack/v3"
)

// ErrUpdateTooLarge is returned by Publish for an update too large to send to the other nodes in one gossip packet.
var ErrUpdateTooLarge = fmt.Errorf("%w: too large to replicate in one gossip packet", gossiper.ErrUpdateTooLarge)

// defaultMaxUpdate is gossip's default packet limit (Config.TCPMaxPacketSize, 4 MiB), less 16 KiB for the packet's
// header, the encoding of the update's fields and the encryption.
const defaultMaxUpdate = 4<<20 - 16<<10

const (
	batchBytes       = 1 << 20          // a batch holds up to this much (a larger update goes alone)
	defaultMaxQueue  = 64 << 20         // bytes queued for one peer before updates for it are dropped
	sendTimeout      = 10 * time.Second // for a peer to acknowledge a batch
	retryMin         = 50 * time.Millisecond
	retryMax         = 2 * time.Second
	closeTimeout     = 3 * time.Second        // Close sends what is queued for this long
	historyPageBytes = 1 << 20                // the backfill copies a peer's history in requests of about this much
	readyPoll        = 100 * time.Millisecond // the backfill asks again this often for a peer that is ready
	coldStart        = 2 * time.Second        // every peer not ready this long: the cluster is starting together
	resyncMargin     = 5 * time.Second        // a resync starts this long before a peer left: late arrivals, skew
	gapMaxAge        = 24 * time.Hour         // a peer away longer is not resynced (bounds the gaps kept)
)

// metaKey is the gossip metadata key a node publishes, set to "on", while its hub is running: the hubs replicate to
// each other, and not to a node that is starting or closing.
const metaKey = "gossiper.hub"

// Options configure a Transport.
type Options struct {
	// MsgBase is the first of the three gossip message types the transport uses (MsgBase to MsgBase+2). Default
	// gossip.UserMsg+64.
	MsgBase gossip.MessageType
	// MaxUpdateBytes is the largest update, in bytes of its data, ID, type, topics and origin, that Publish accepts.
	// An update travels in one gossip packet, which the receiving node refuses over its Config.TCPMaxPacketSize
	// (4 MiB by default): an update over that would be applied here and lost everywhere else, so Publish fails with
	// ErrUpdateTooLarge instead. Raise it together with TCPMaxPacketSize on every node. Default: 4 MiB less 16 KiB.
	MaxUpdateBytes int
	// MaxQueueBytes bounds what is queued for one peer that does not keep up (or cannot be reached while it is still a
	// member); updates for it over that are dropped and counted. Default 64 MiB.
	MaxQueueBytes int
	// Backfill is how long a starting node waits for a peer to copy the history of; 0: it does not copy one (a node
	// that has no peers to join). It copies from a peer that is ready itself (one still copying has a partial
	// history); when none is in time, from any that answers, and it logs a warning. Ready reports false until the copy
	// is done or the wait is over.
	Backfill time.Duration
}

// Transport is a gossiper.Transport over a gossip cluster. The caller creates, starts, joins and stops the
// gossip cluster; the transport only uses it.
type Transport struct {
	c       *gossip.Cluster
	opts    Options
	group   *gossip.NodeGroup
	hub     gossiper.Host
	msgPub  gossip.MessageType
	msgSubs gossip.MessageType
	msgHist gossip.MessageType

	mu     sync.RWMutex // held by Publish, so Close waits for the publishes under way
	closed atomic.Bool

	lmu     sync.Mutex
	links   map[gossip.NodeID]*link // a sender per peer, made when there is something to send it
	gaps    map[gossip.NodeID]*gap  // peers that left the group, for when they come back
	resyncs sync.WaitGroup
	// amu guards appliers: a goroutine per peer applying its batches.
	amu      sync.Mutex
	appliers map[gossip.NodeID]chan applyJob
	applying sync.WaitGroup
	dropped  atomic.Uint64
	ready    atomic.Bool
	stop     chan struct{} // closed by Close
	// done ends every exchange with the peers: cancelled closeTimeout after Close starts.
	done         context.Context
	cancel       context.CancelFunc
	backfillDone chan struct{} // closed when the backfill is over
}

// batch is updates sent together, in the order they were published, each encoded (msgpack) once for every peer. S
// asks the peer to acknowledge it once stored: it holds an update that asked for copies.
type batch struct {
	U [][]byte `msgpack:"u"`
	S bool     `msgpack:"s,omitempty"`
}

// ack acknowledges a batch: the peer has applied it, but for Bad updates it could not decode (-1: the batch), which
// the sender drops rather than send again. Unstored says that a batch asked to be stored was not.
type ack struct {
	Bad      int  `msgpack:"b,omitempty"`
	Unstored bool `msgpack:"n,omitempty"`
}

// historyReq asks a peer for the updates of its history after the one stamped S by O, none if R and the peer is not
// ready; historyResp answers, and says whether the peer is ready (its history complete).
type historyReq struct {
	S uint64 `msgpack:"s"`
	O string `msgpack:"o"`
	R bool   `msgpack:"r,omitempty"`
}

type historyResp struct {
	U     []*gossiper.Update `msgpack:"u"`
	More  bool               `msgpack:"m"`
	Ready bool               `msgpack:"r"`
}

// applyJob is a peer's batch, decoded, waiting to be applied and acknowledged (once stored, with store).
type applyJob struct {
	us    []*gossiper.Update
	store bool
	a     ack
	r     gossip.Replier
}

// applyQueue bounds the batches of one peer waiting to be applied: it sends one at a time, so more are batches sent
// again after a timeout.
const applyQueue = 8

// errBusy answers a batch that finds its peer's queue full: the peer sends it again.
var errBusy = errors.New("cluster: too many batches waiting to be applied")

// item is an update queued for a peer, encoded; c counts the peers that acknowledged it, when it asked for copies.
type item struct {
	raw   []byte
	stamp uint64
	c     *copies
}

// copies counts the peers that acknowledged an update that asked for copies: done is closed once need have.
type copies struct {
	need int32
	got  atomic.Int32
	done chan struct{}
}

func (c *copies) ack() {
	if c.got.Add(1) == c.need {
		close(c.done)
	}
}

// wait returns once the copies are made, or ErrNotReplicated when ctx ends first.
func (c *copies) wait(ctx context.Context) error {
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %d of %d nodes", gossiper.ErrNotReplicated, c.got.Load()+1, c.need+1)
	}
}

// gap is what a peer that left the group missed of this node's updates, and this node of its: those stamped after
// from.
type gap struct{ from uint64 }

var _ gossiper.Transport = (*Transport)(nil)

// New returns a transport over the gossip cluster c.
func New(c *gossip.Cluster, opts Options) *Transport {
	if opts.MsgBase == 0 {
		opts.MsgBase = gossip.UserMsg + 64
	}
	if opts.MaxUpdateBytes <= 0 {
		opts.MaxUpdateBytes = defaultMaxUpdate
	}
	if opts.MaxQueueBytes <= 0 {
		opts.MaxQueueBytes = defaultMaxQueue
	}
	done, cancel := context.WithCancel(context.Background())
	return &Transport{c: c, opts: opts, msgPub: opts.MsgBase, msgSubs: opts.MsgBase + 1, msgHist: opts.MsgBase + 2,
		links: map[gossip.NodeID]*link{}, gaps: map[gossip.NodeID]*gap{}, appliers: map[gossip.NodeID]chan applyJob{}, stop: make(chan struct{}), done: done, cancel: cancel, backfillDone: make(chan struct{})}
}

// subscriptionsReq asks a node for its active subscriptions.
type subscriptionsReq struct{}

type subscriptionsResp struct {
	Subs []gossiper.Subscription `msgpack:"s"`
}

// Start registers the transport's handlers and announces this node as a hub of the group.
func (t *Transport) Start(h gossiper.Host) error {
	t.hub = h
	handlers := []struct {
		typ gossip.MessageType
		fn  gossip.ReplyHandler
	}{{t.msgSubs, t.handleSubscriptions}, {t.msgHist, t.handleHistory}}
	// A batch is applied on its peer's goroutine and acknowledged then: applying waits for this node's slow
	// subscribers, which must hold neither gossip's incoming workers (pings, membership) nor other peers' updates.
	if err := t.c.HandleFuncWithDeferredReply(t.msgPub, t.handlePublish); err != nil {
		return err
	}
	for i, hd := range handlers {
		if err := t.c.HandleFuncWithReply(hd.typ, hd.fn); err != nil {
			for _, prev := range handlers[:i] {
				t.c.UnregisterMessageType(prev.typ)
			}
			t.c.UnregisterMessageType(t.msgPub)
			return err
		}
	}
	t.group = gossip.NewNodeGroup(t.c, map[string]string{metaKey: "on"}, &gossip.NodeGroupOptions{
		OnNodeAdded:   t.rejoined,
		OnNodeRemoved: func(n *gossip.Node) { t.forget(n.ID) },
	})
	t.c.LocalMetadata().SetString(metaKey, "on")
	if t.opts.Backfill > 0 {
		go t.backfill()
	} else {
		t.ready.Store(true)
		close(t.backfillDone)
	}
	return nil
}

// Ready reports whether the node has copied a peer's history, or need not (see Options.Backfill).
func (t *Transport) Ready() bool { return t.ready.Load() }

// Dropped returns how many updates this node has dropped instead of sending them to a peer: queued for a peer that
// left the group, over MaxQueueBytes for one that did not keep up, or that the peer could not decode. Each peer that
// missed an update counts it.
func (t *Transport) Dropped() uint64 { return t.dropped.Load() }

// NodeID returns the gossip node id.
func (t *Transport) NodeID() string { return t.c.LocalNode().ID.String() }

// peers returns the other hubs of the group that are alive.
func (t *Transport) peers() []*gossip.Node {
	return t.group.GetNodes([]gossip.NodeID{t.c.LocalNode().ID})
}

// Publish applies u on this node and queues it for every other hub of the group.
func (t *Transport) Publish(_ context.Context, u *gossiper.Update) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.publish(u, t.peers(), nil)
}

// PublishCopies implements gossiper.Replicator: it publishes u as Publish does, and its wait returns once n-1 peers
// have acknowledged u, having stored it when they keep a history store.
func (t *Transport) PublishCopies(_ context.Context, u *gossiper.Update, n int) (func(context.Context) error, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	peers := t.peers()
	if len(peers)+1 < n {
		return nil, fmt.Errorf("%w: %d of %d", gossiper.ErrTooFewNodes, len(peers)+1, n)
	}
	c := &copies{need: int32(n - 1), done: make(chan struct{})}
	if err := t.publish(u, peers, c); err != nil {
		return nil, err
	}
	return c.wait, nil
}

// publish applies u on this node and queues it for peers. Called with mu held for reading.
func (t *Transport) publish(u *gossiper.Update, peers []*gossip.Node, c *copies) error {
	if t.closed.Load() {
		return gossiper.ErrClosed
	}
	if updateSize(u) > t.opts.MaxUpdateBytes {
		return ErrUpdateTooLarge
	}
	raw, err := msgpack.Marshal(u) // once for every peer, before the hub hands u to its subscribers
	if err != nil {
		return err
	}
	t.hub.Apply(u)
	for _, n := range peers {
		if l := t.linkTo(n); l != nil {
			l.enqueue(item{raw: raw, stamp: u.Stamp, c: c})
		} else {
			t.dropped.Add(1)
		}
	}
	return nil
}

// linkTo returns the sender to n, starting one if there is none, or nil if n has left the group meanwhile (its link
// would never be stopped: forget has run) or the transport is closing (Close would not wait for it).
func (t *Transport) linkTo(n *gossip.Node) *link {
	t.lmu.Lock()
	defer t.lmu.Unlock()
	l := t.links[n.ID]
	if l == nil {
		if t.closed.Load() || !t.group.Contains(n.ID) {
			return nil
		}
		l = &link{t: t, node: n, wake: make(chan struct{}, 1), gone: make(chan struct{}), done: make(chan struct{})}
		t.links[n.ID] = l
		go l.run()
	}
	return l
}

// forget stops the sender to a node that left the group; what was queued for it is dropped. It records the gap from
// the oldest update the node has not acknowledged (or now), for a resync if it comes back.
func (t *Transport) forget(id gossip.NodeID) {
	now := time.Now()
	from := uint64(hlc.FromTime(now))
	t.lmu.Lock()
	l := t.links[id]
	delete(t.links, id)
	if l != nil {
		from = min(from, l.oldest())
	}
	if m := uint64(resyncMargin.Microseconds()) << hlc.CounterBits; from > m {
		from -= m
	} else {
		from = 0
	}
	if g := t.gaps[id]; g != nil { // back and gone again before the resync was done
		from = min(from, g.from)
	}
	cutoff := uint64(hlc.FromTime(now.Add(-gapMaxAge)))
	for other, g := range t.gaps {
		if g.from < cutoff {
			delete(t.gaps, other)
		}
	}
	t.gaps[id] = &gap{from}
	t.lmu.Unlock()
	if l != nil {
		close(l.gone)
	}
	t.stopApplier(id)
}

// rejoined starts a resync with a node that joins the group, if it left it before.
func (t *Transport) rejoined(n *gossip.Node) {
	t.lmu.Lock()
	defer t.lmu.Unlock()
	g := t.gaps[n.ID]
	if g == nil || t.closed.Load() {
		return
	}
	t.resyncs.Add(1)
	go t.resync(n, g)
}

// resync makes up for a gap with a peer that is back: it copies the peer's updates stamped after the gap's start into
// this node's history, then queues its own for the peer. The peer may do the same; the hubs apply an update once. The
// gap is kept, for the next return, if the peer leaves again first.
func (t *Transport) resync(n *gossip.Node, g *gap) {
	defer t.resyncs.Done()
	for wait := retryMin; ; wait = min(2*wait, retryMax) {
		if _, err := t.copyHistory(n, g.from, t.hub.Apply, false); err == nil {
			break
		}
		if !t.group.Contains(n.ID) {
			return
		}
		select {
		case <-t.stop:
			return
		case <-time.After(wait):
		}
	}
	if !t.push(n, g.from) {
		return
	}
	t.lmu.Lock()
	if t.gaps[n.ID] == g {
		delete(t.gaps, n.ID)
	}
	t.lmu.Unlock()
}

// push queues for n the updates of this node's history stamped after from, a page at a time as its link makes room
// (so MaxQueueBytes drops none), and reports whether it queued them all: false if n left or the transport closes.
func (t *Transport) push(n *gossip.Node, from uint64) bool {
	stamp, origin := from, ""
	for {
		l := t.linkTo(n)
		if l == nil {
			return false
		}
		for l.queued() > t.opts.MaxQueueBytes/2 {
			select {
			case <-l.gone:
				return false
			case <-t.stop:
				return false
			case <-time.After(10 * time.Millisecond):
			}
		}
		ups, more := t.hub.History(stamp, origin, historyPageBytes)
		for _, u := range ups {
			if raw, err := msgpack.Marshal(u); err == nil {
				l.enqueue(item{raw: raw, stamp: u.Stamp})
			}
		}
		if !more || len(ups) == 0 {
			return true
		}
		last := ups[len(ups)-1]
		stamp, origin = last.Stamp, last.Origin
	}
}

// link sends the updates published here to one peer, in order, a batch at a time.
type link struct {
	t        *Transport
	node     *gossip.Node
	mu       sync.Mutex
	queue    []item
	inflight []item // the batch being sent
	bytes    int
	dead     bool // stopped: updates for it are dropped
	warned   bool // has logged updates the peer could not decode (the sender's own)
	wake     chan struct{}
	gone     chan struct{} // the peer left the group
	done     chan struct{}
}

func (l *link) enqueue(it item) {
	l.mu.Lock()
	if l.dead || l.bytes+len(it.raw) > l.t.opts.MaxQueueBytes {
		l.mu.Unlock()
		l.t.dropped.Add(1)
		return
	}
	l.queue = append(l.queue, it)
	l.bytes += len(it.raw)
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// next takes the next batch off the queue: up to batchBytes, at least one update. It returns nil when the queue is
// empty. The batch it took before has been acknowledged.
func (l *link) next() []item {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, size := 0, 0
	for n < len(l.queue) && (n == 0 || size+len(l.queue[n].raw) <= batchBytes) {
		size += len(l.queue[n].raw)
		n++
	}
	if n == 0 {
		l.inflight = nil
		return nil
	}
	b := l.queue[:n:n]
	l.queue, l.bytes, l.inflight = l.queue[n:], l.bytes-size, b
	if len(l.queue) == 0 {
		l.queue = nil // let the backing array go
	}
	return b
}

// run sends batches until the peer leaves (what is queued is dropped) or the transport closes (what is queued is
// sent, for at most closeTimeout).
func (l *link) run() {
	defer close(l.done)
	for {
		select {
		case <-l.wake:
		case <-l.gone:
			l.drop(nil)
			return
		case <-l.t.stop:
			l.flush()
			return
		}
		for b := l.next(); b != nil; b = l.next() {
			if !l.send(b) {
				l.drop(b)
				return
			}
		}
	}
}

// queued returns the bytes queued.
func (l *link) queued() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes
}

// oldest returns the earliest stamp of the updates queued or in flight, ^0 if there are none.
func (l *link) oldest() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := ^uint64(0)
	for _, it := range l.inflight {
		s = min(s, it.stamp)
	}
	for _, it := range l.queue {
		s = min(s, it.stamp)
	}
	return s
}

// send sends b until the peer acknowledges it, and reports whether it did: false once the peer has left the group or
// the transport is closing. Only a failure to reach the peer is retried: an update the peer cannot decode never will
// be, and is dropped.
func (l *link) send(b []item) bool {
	msg := batchOf(b)
	wait := retryMin
	for {
		var a ack
		ctx, cancel := context.WithTimeout(l.t.done, sendTimeout)
		err := l.t.c.SendToWithResponseContext(ctx, l.node, l.t.msgPub, msg, &a)
		cancel()
		if err == nil {
			l.acked(b, a)
			return true
		}
		select {
		case <-l.gone:
			return false
		case <-l.t.stop: // Close sends what is queued once, not again and again
			return false
		case <-time.After(wait):
		}
		wait = min(2*wait, retryMax)
	}
}

// flush sends what is queued, each batch once, until closeTimeout; the rest is dropped.
func (l *link) flush() {
	ctx := l.t.done
	for b := l.next(); b != nil; b = l.next() {
		var a ack
		if ctx.Err() != nil || l.t.c.SendToWithResponseContext(ctx, l.node, l.t.msgPub, batchOf(b), &a) != nil {
			l.drop(b)
			return
		}
		l.acked(b, a)
	}
}

// drop counts b and whatever is still queued as dropped; the link takes no more.
func (l *link) drop(b []item) {
	l.mu.Lock()
	n := len(b) + len(l.queue)
	l.queue, l.inflight, l.bytes, l.dead = nil, nil, 0, true
	l.mu.Unlock()
	l.t.dropped.Add(uint64(n))
}

// acked takes the peer's acknowledgement of b: it counts a copy of each update in it that asked for copies (unless
// the peer could not store what it was asked to), and the updates it could not decode.
func (l *link) acked(b []item, a ack) {
	if a.Bad >= 0 && !a.Unstored {
		for _, it := range b {
			if it.c != nil {
				it.c.ack()
			}
		}
	}
	l.rejected(len(b), a.Bad)
}

// rejected counts as dropped the bad updates of a batch of n that the peer could not decode (-1: all), and logs the
// first time.
func (l *link) rejected(n, bad int) {
	if bad == 0 {
		return
	}
	if bad < 0 || bad > n {
		bad = n
	}
	l.t.dropped.Add(uint64(bad))
	if !l.warned {
		l.warned = true
		l.t.c.Logger().Warn("cluster: a peer could not decode updates sent to it (a node of another version?); dropped",
			"peer", l.node.ID.String(), "updates", bad)
	}
}

func batchOf(b []item) *batch {
	msg := &batch{U: make([][]byte, len(b))}
	for i, it := range b {
		msg.U[i] = it.raw
		msg.S = msg.S || it.c != nil
	}
	return msg
}

// updateSize is the size of u's variable-length fields.
func updateSize(u *gossiper.Update) int {
	n := len(u.ID) + len(u.Data) + len(u.Type) + len(u.Origin)
	for _, topic := range u.Topics {
		n += len(topic)
	}
	return n
}

// handlePublish applies a batch and acknowledges it, with the count of updates it could not decode: those, or a batch
// that does not decode, would not decode the next time either, so the sender drops them instead.
func (t *Transport) handlePublish(n *gossip.Node, p *gossip.Packet, r gossip.Replier) {
	var b batch
	if err := p.Unmarshal(&b); err != nil {
		r.Reply(&ack{Bad: -1}, nil)
		return
	}
	if t.closed.Load() || n == nil {
		r.Reply(&ack{}, nil)
		return
	}
	j := applyJob{r: r, store: b.S}
	for _, raw := range b.U {
		u := new(gossiper.Update) // a copy of its own, for the hub to keep
		if msgpack.Unmarshal(raw, u) != nil {
			j.a.Bad++
			continue
		}
		j.us = append(j.us, u)
	}
	t.amu.Lock()
	defer t.amu.Unlock()
	if t.closed.Load() {
		r.Reply(&ack{}, nil)
		return
	}
	jobs := t.appliers[n.ID]
	if jobs == nil {
		jobs = make(chan applyJob, applyQueue)
		t.appliers[n.ID] = jobs
		t.applying.Go(func() { t.apply(jobs) })
	}
	select {
	case jobs <- j:
	default:
		r.Reply(nil, errBusy)
	}
}

// apply applies a peer's batches in order and acknowledges each, until jobs is closed.
func (t *Transport) apply(jobs <-chan applyJob) {
	for j := range jobs {
		if !t.closed.Load() {
			for _, u := range j.us {
				t.hub.Apply(u)
			}
			if j.store && t.hub.Stored(t.done) != nil {
				j.a.Unstored = true
			}
		}
		j.r.Reply(&j.a, nil)
	}
}

// stopApplier ends the goroutine applying id's batches, once it has applied those queued.
func (t *Transport) stopApplier(id gossip.NodeID) {
	t.amu.Lock()
	defer t.amu.Unlock()
	if jobs := t.appliers[id]; jobs != nil {
		close(jobs)
		delete(t.appliers, id)
	}
}

func (t *Transport) handleHistory(_ *gossip.Node, p *gossip.Packet) (any, error) {
	var req historyReq
	if err := p.Unmarshal(&req); err != nil {
		return nil, err
	}
	ready := t.ready.Load()
	if req.R && !ready {
		return &historyResp{}, nil
	}
	ups, more := t.hub.History(req.S, req.O, historyPageBytes)
	return &historyResp{U: ups, More: more, Ready: ready}, nil
}

// backfill copies the history of a peer into this node's, from a peer that is ready itself, trying them all until one
// is or Options.Backfill is over; then from any that answers, with a warning. Then the node is ready.
func (t *Transport) backfill() {
	defer close(t.backfillDone)
	defer t.ready.Store(true)
	deadline := time.Now().Add(t.opts.Backfill)
	var starting time.Time // since when every peer has answered that it is not ready either
	for {
		now := time.Now()
		// Every peer starting too (a whole cluster starting) for coldStart: none has more to give than the others.
		cold := !starting.IsZero() && now.Sub(starting) >= coldStart
		last := cold || now.After(deadline)
		peers, notReady := t.peers(), 0
		for _, n := range peers {
			ready, err := t.copyHistory(n, 0, t.hub.Restore, !last)
			if err == nil {
				if !ready && !cold {
					t.warnIncomplete()
				}
				return
			}
			if errors.Is(err, errNotReady) {
				notReady++
			}
		}
		switch {
		case last:
			t.warnIncomplete()
			return
		case len(peers) > 0 && notReady == len(peers):
			if starting.IsZero() {
				starting = now
			}
		default:
			starting = time.Time{}
		}
		select {
		case <-t.stop:
			return
		case <-time.After(readyPoll):
		}
	}
}

func (t *Transport) warnIncomplete() {
	select {
	case <-t.stop:
	default:
		t.c.Logger().Warn("cluster: no ready peer to copy the history of in time; ready with a possibly incomplete history",
			"backfill", t.opts.Backfill.String())
	}
}

var (
	errNotReady = errors.New("peer not ready")
	errClosed   = errors.New("closed")
)

// copyHistory copies n's updates stamped after from into this node's with apply, a page at a time, and reports
// whether n is ready. With ready set, it copies nothing from a peer that is not (errNotReady).
func (t *Transport) copyHistory(n *gossip.Node, from uint64, apply func(*gossiper.Update), ready bool) (bool, error) {
	req := historyReq{S: from, R: ready}
	for {
		var resp historyResp
		ctx, cancel := context.WithTimeout(t.done, sendTimeout)
		err := t.c.SendToWithResponseContext(ctx, n, t.msgHist, &req, &resp)
		cancel()
		if err != nil {
			return false, err
		}
		if ready && !resp.Ready {
			return false, errNotReady
		}
		select {
		case <-t.stop: // not into a hub that is closing
			return false, errClosed
		default:
		}
		for _, u := range resp.U {
			apply(u)
		}
		if !resp.More || len(resp.U) == 0 {
			return resp.Ready, nil
		}
		last := resp.U[len(resp.U)-1]
		req.S, req.O = last.Stamp, last.Origin
	}
}

func (t *Transport) handleSubscriptions(_ *gossip.Node, p *gossip.Packet) (any, error) {
	var req subscriptionsReq
	if err := p.Unmarshal(&req); err != nil {
		return nil, err
	}
	return &subscriptionsResp{Subs: t.hub.LocalSubscriptions()}, nil
}

// RemoteSubscriptions asks every other hub of the group for its active subscriptions, in parallel.
func (t *Transport) RemoteSubscriptions(ctx context.Context) ([]gossiper.Subscription, bool, error) {
	peers := t.peers()
	if len(peers) == 0 {
		return nil, true, nil
	}
	type result struct {
		subs []gossiper.Subscription
		err  error
	}
	results := make(chan result, len(peers))
	for _, n := range peers {
		go func() {
			var resp subscriptionsResp
			err := t.c.SendToWithResponseContext(ctx, n, t.msgSubs, &subscriptionsReq{}, &resp)
			results <- result{resp.Subs, err}
		}()
	}
	var out []gossiper.Subscription
	var errs []error
	for range peers {
		r := <-results
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		out = append(out, r.subs...)
	}
	return out, len(errs) == 0, errors.Join(errs...)
}

// Close stops the transport: what is queued for the peers is sent (for a few seconds at most), this node stops
// announcing itself as a hub and ignores updates from now on.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed.Swap(true) {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()
	close(t.stop)
	if t.group == nil { // never started
		t.cancel()
		return nil
	}
	timer := time.AfterFunc(closeTimeout, t.cancel) // bounds every exchange still under way
	defer timer.Stop()
	defer t.cancel()
	t.lmu.Lock()
	links := t.links
	t.links = map[gossip.NodeID]*link{}
	t.lmu.Unlock()
	for _, l := range links {
		<-l.done
	}
	t.amu.Lock()
	for id, jobs := range t.appliers {
		close(jobs)
		delete(t.appliers, id)
	}
	t.amu.Unlock()
	t.applying.Wait()
	<-t.backfillDone
	t.resyncs.Wait()
	t.c.LocalMetadata().SetString(metaKey, "")
	t.c.UnregisterMessageType(t.msgPub)
	t.c.UnregisterMessageType(t.msgSubs)
	t.c.UnregisterMessageType(t.msgHist)
	t.group.Close()
	return nil
}
