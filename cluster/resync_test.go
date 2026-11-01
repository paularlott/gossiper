package cluster_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/cluster"
	"github.com/shamaton/msgpack/v3"
)

// encode is an update as the transport sends it.
func encode(t testing.TB, u *gossiper.Update) []byte {
	t.Helper()
	b, err := msgpack.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// historyIDs returns the IDs of the updates n's history holds.
func historyIDs(n *testNode) []string {
	ups, _ := n.hub.History(0, "", 1<<30)
	var ids []string
	for _, u := range ups {
		ids = append(ids, u.ID)
	}
	return ids
}

// partition is a gossip transport that cuts its node off from the nodes set: what it sends them fails. Set on both
// sides, neither reaches the other.
type partition struct {
	gossip.Transport
	mu  sync.Mutex
	cut map[gossip.NodeID]bool
}

var errCut = errors.New("partitioned")

func (p *partition) set(id gossip.NodeID, cut bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cut == nil {
		p.cut = map[gossip.NodeID]bool{}
	}
	p.cut[id] = cut
}

func (p *partition) blocked(n *gossip.Node) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cut[n.ID]
}

func (p *partition) Send(tt gossip.TransportType, n *gossip.Node, pk *gossip.Packet) error {
	if p.blocked(n) {
		return errCut
	}
	return p.Transport.Send(tt, n, pk)
}

func (p *partition) SendWithReply(n *gossip.Node, pk *gossip.Packet) (*gossip.Packet, error) {
	if p.blocked(n) {
		return nil, errCut
	}
	return p.Transport.SendWithReply(n, pk)
}

func (p *partition) SendWithReplyContext(ctx context.Context, n *gossip.Node, pk *gossip.Packet) (*gossip.Packet, error) {
	if p.blocked(n) {
		return nil, errCut
	}
	return p.Transport.(gossip.ContextTransport).SendWithReplyContext(ctx, n, pk)
}

// TestRejoinResync: two nodes that lose each other (each declares the other dead) and meet again exchange what was
// published on either side meanwhile, the updates queued when they lost each other included; their subscribers
// receive them.
func TestRejoinResync(t *testing.T) {
	var parts [2]*partition
	nodes := newCluster(t, clusterOpts{n: 2, node: func(i int, o *nodeOpts) {
		o.gossip = func(c *gossip.Config) {
			parts[i] = &partition{Transport: c.Transport}
			c.Transport = parts[i]
			c.DeadNodeTimeout = 500 * time.Millisecond // suspect to dead
		}
	}})
	a, b := nodes[0], nodes[1]
	hc := newClient(t)
	sa := a.subscribe(t, subOpts{topics: []string{topicA}})
	sb := b.subscribe(t, subOpts{topics: []string{topicA}})
	pub := func(n *testNode, data string) string {
		return n.publish(t, hc, url.Values{"topic": {topicA}, "data": {data}})
	}
	all := []string{pub(a, "before 1"), pub(b, "before 2")}
	waitApplied(t, nodes, 2)

	cut := func(on bool) {
		parts[0].set(b.gc.LocalNode().ID, on)
		parts[1].set(a.gc.LocalNode().ID, on)
	}
	cut(true)
	queued := []string{pub(a, "queued a"), pub(b, "queued b")} // queued, then dropped when the peer is declared dead
	waitPeers(t, a, 0)
	waitPeers(t, b, 0)
	var away []string
	for i := range 3 {
		away = append(away, pub(a, fmt.Sprint("away a ", i)), pub(b, fmt.Sprint("away b ", i)))
	}
	time.Sleep(settle)
	if got := int(a.hub.Stats().Applied + b.hub.Stats().Applied); got != 2*2+len(queued)+len(away) {
		t.Fatalf("the partition let updates through: %d applied in all", got)
	}

	cut(false)
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
	all = append(append(all, queued...), away...)
	for _, n := range nodes {
		waitFor(t, waitMax, "the histories resynced", func() bool { return sameSet(historyIDs(n), all) })
	}
	for i, evs := range expectAll(t, len(all), sa, sb) {
		if !sameSet(idsOf(evs), all) {
			t.Errorf("subscriber %d received %v, want %v", i, idsOf(evs), all)
		}
	}

	// And replication goes on as before.
	all = append(all, pub(b, "after"))
	expectAll(t, len(all), sa, sb)
}

// TestBackfillPrefersReadyPeer: a starting node copies the history of a peer that is ready, not of one still copying
// its own; when no peer is ready in time it copies what one has, becomes ready all the same, and warns.
func TestBackfillPrefersReadyPeer(t *testing.T) {
	hc := newClient(t)
	nodes := make([]*testNode, 3)
	own := make([]string, 3) // an update of each node's own: the nodes join after
	for i := range nodes {
		nodes[i] = newNode(t, nodeOpts{})
		own[i] = nodes[i].publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}})
	}
	for _, n := range nodes[1:] {
		if err := n.gc.Join([]string{nodes[0].addr}); err != nil {
			t.Fatal(err)
		}
	}
	waitConverged(t, nodes)
	nodes[1].tr.SetReady(false)
	nodes[2].tr.SetReady(false)

	backfill := func(d time.Duration) *testNode {
		n := newNode(t, nodeOpts{tr: func(o *cluster.Options) { o.Backfill = d }})
		if err := n.gc.Join([]string{nodes[0].addr}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, waitMax, "the new node ready", n.tr.Ready)
		return n
	}
	incomplete := func(n *testNode) bool {
		return slices.ContainsFunc(n.gossipLog.logged(), func(l string) bool { return strings.Contains(l, "incomplete") })
	}
	n := backfill(10 * time.Second)
	if got := historyIDs(n); !slices.Equal(got, own[:1]) {
		t.Errorf("copied %v, want the ready peer's %v", got, own[:1])
	}
	if incomplete(n) {
		t.Errorf("warned of an incomplete history: %v", n.gossipLog.logged())
	}

	nodes[0].tr.SetReady(false)
	n.tr.SetReady(false)
	start := time.Now()
	m := backfill(time.Second)
	if d := time.Since(start); d < time.Second {
		t.Errorf("ready after %v, before the backfill wait was over with no peer ready", d)
	}
	if got := historyIDs(m); len(got) != 1 || !slices.Contains(own, got[0]) {
		t.Errorf("copied %v, want one peer's update", got)
	}
	if !incomplete(m) {
		t.Errorf("no warning of an incomplete history: %v", m.gossipLog.logged())
	}
}

// TestUndecodableUpdatesDropped: an update the peer cannot decode (a node of another version) is dropped and counted
// once, with one warning, instead of being sent again and again and holding up the updates behind it.
func TestUndecodableUpdatesDropped(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	a, b := nodes[0], nodes[1]
	sb := b.subscribe(t, subOpts{topics: []string{topicA}})
	peer := a.gc.GetNode(b.gc.LocalNode().ID)
	hc := newClient(t)
	var want []string
	for i := range 4 {
		if i%2 == 0 {
			a.tr.EnqueueRaw(peer, []byte{0xc1}) // never valid msgpack
		}
		want = append(want, a.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}}))
	}
	if got := expectAll(t, len(want), sb)[0]; !slices.Equal(idsOf(got), want) {
		t.Errorf("received %v, want %v", idsOf(got), want)
	}
	waitFor(t, waitMax, "the bad updates counted", func() bool { return a.tr.Dropped() == 2 })
	warned := 0
	for _, l := range a.gossipLog.logged() {
		if strings.Contains(l, "could not decode") {
			warned++
		}
	}
	if warned != 1 {
		t.Errorf("warned %d times, want once: %v", warned, a.gossipLog.logged())
	}

	// A batch that does not decode at all is answered at once, rejected, not left to time out and be sent again.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var resp struct {
		Bad int `msgpack:"b"`
	}
	if err := a.gc.SendToWithResponseContext(ctx, peer, gossip.UserMsg+64, "not a batch", &resp); err != nil || resp.Bad != -1 {
		t.Errorf("a batch that does not decode: %v, bad %d, want rejected (-1)", err, resp.Bad)
	}
}
