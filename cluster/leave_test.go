package cluster_test

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossiper"
)

// waitPeers waits until n's transport has want peers.
func waitPeers(t testing.TB, n *testNode, want int) {
	t.Helper()
	waitFor(t, waitMax, fmt.Sprintf("%d peers at %s", want, n.addr), func() bool { return len(n.tr.Peers()) == want })
}

// TestClosedHubStopsReceiving: a hub that is closed leaves its group; the others stop sending to it and keep
// working.
func TestClosedHubStopsReceiving(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 4})
	a, b, c, d := nodes[0], nodes[1], nodes[2], nodes[3]
	hc := newClient(t)
	var subs []*sseClient
	for _, n := range nodes {
		subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
	}
	var want []string
	for i := range 5 {
		want = append(want, a.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}}))
	}
	expectAll(t, 5, subs...)
	waitApplied(t, nodes, 5)

	d.hubClose(t)
	for _, n := range []*testNode{a, b, c} {
		waitPeers(t, n, 2)
		if slices.Contains(n.peerIDs(), d.gc.LocalNode().ID.String()) {
			t.Errorf("node %s still lists the closed hub as a peer", n.addr)
		}
	}
	// The closed hub's gossip node is still a member of the cluster: leaving the group is the transport's doing.
	if got := d.gc.NumAliveNodes(); got != 4 {
		t.Errorf("gossip of the closed hub sees %d alive nodes, want 4", got)
	}
	if got := len(d.tr.Peers()); got != 0 {
		t.Errorf("a closed hub has %d peers, want 0", got)
	}

	for i := 5; i < 25; i++ {
		want = append(want, b.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}}))
	}
	live := subs[:3]
	for i, evs := range expectAll(t, 25, live...) {
		if !sameSet(idsOf(evs), want) {
			t.Errorf("subscriber %d received %d events, want the %d published", i, len(evs), len(want))
		}
	}
	if st := d.hub.Stats(); st.Applied != 5 {
		t.Errorf("the closed hub applied %d updates, want 5 (nothing after it closed)", st.Applied)
	}
	for _, n := range []*testNode{a, b, c} {
		if st := n.hub.Stats(); st.Applied != 25 || st.Duplicates != 0 {
			t.Errorf("node %s applied %d updates with %d duplicates, want 25 and 0", n.addr, st.Applied, st.Duplicates)
		}
		if logged := n.hubLog.logged(); len(logged) > 0 {
			t.Errorf("node %s logged %v", n.addr, logged)
		}
	}
}

// hubClose closes the hub (so the transport) and leaves the gossip node running.
func (n *testNode) hubClose(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.hub.Close(ctx); err != nil {
		t.Fatalf("hub close: %v", err)
	}
}

// TestGossipLeaveStopsReceiving: a node that leaves the gossip cluster, without closing its transport first, is no
// longer sent updates either.
func TestGossipLeaveStopsReceiving(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	a, b, c := nodes[0], nodes[1], nodes[2]
	hc := newClient(t)
	sa := a.subscribe(t, subOpts{topics: []string{topicA}})
	sb := b.subscribe(t, subOpts{topics: []string{topicA}})
	sc := c.subscribe(t, subOpts{topics: []string{topicA}})
	var want []string
	for i := range 3 {
		want = append(want, a.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}}))
	}
	expectAll(t, 3, sa, sb, sc)

	c.gc.Leave()
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
	for i := 3; i < 13; i++ {
		want = append(want, a.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}}))
	}
	for i, evs := range expectAll(t, 13, sa, sb) {
		if !sameSet(idsOf(evs), want) {
			t.Errorf("subscriber %d received %v, want %v", i, idsOf(evs), want)
		}
	}
	time.Sleep(settle)
	if got := sc.count(); got != 3 {
		t.Errorf("the node that left received %d events, want 3", got)
	}
	if got := c.hub.Stats().Applied; got != 3 {
		t.Errorf("the node that left applied %d updates, want 3", got)
	}
	for _, n := range []*testNode{a, b} {
		if logged := n.hubLog.logged(); len(logged) > 0 {
			t.Errorf("node %s logged %v", n.addr, logged)
		}
	}
}

// TestPublishesContinueWhileNodeLeaves: publishing goes on, without error, while a node shuts down in the middle
// of it; the nodes that stay receive everything exactly once.
func TestPublishesContinueWhileNodeLeaves(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 4})
	a, b, c, d := nodes[0], nodes[1], nodes[2], nodes[3]
	hc := newClient(t)
	var subs []*sseClient
	for _, n := range []*testNode{a, b, c, d} {
		subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
	}

	const total = 300
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ids   []string
		errs  []string
		third = make(chan struct{})
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range total {
			if i == total/3 {
				close(third)
			}
			start := time.Now()
			id, status, err := a.tryPublish(hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}})
			mu.Lock()
			if err != nil || status != 200 {
				errs = append(errs, fmt.Sprintf("publish %d: status %d, %v, %s", i, status, err, id))
			} else if d := time.Since(start); d > 3*time.Second {
				errs = append(errs, fmt.Sprintf("publish %d took %v", i, d))
			}
			ids = append(ids, id)
			mu.Unlock()
		}
	}()
	<-third
	d.close() // the hub, its HTTP server, then the gossip node (which announces that it leaves)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d publishes failed, first: %s", len(errs), errs[0])
	}
	for i, evs := range expectAll(t, total, subs[:3]...) {
		if !sameSet(idsOf(evs), ids) {
			t.Errorf("subscriber %d received %d distinct events, want %d", i, len(slices.Compact(sorted(idsOf(evs)))), total)
		}
	}
	for _, n := range []*testNode{a, b, c} {
		if st := n.hub.Stats(); st.Applied != total || st.Duplicates != 0 {
			t.Errorf("node %s applied %d, duplicates %d, want %d and 0", n.addr, st.Applied, st.Duplicates, total)
		}
		waitPeers(t, n, 2)
		for _, l := range n.hubLog.logged() {
			t.Errorf("node %s logged %s", n.addr, l)
		}
		for _, l := range n.gossipLog.logged() {
			if strings.Contains(l, "queue is full") {
				t.Errorf("node %s: %s", n.addr, l)
			}
		}
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// TestPublishAfterClose: a closed transport refuses to publish, closing twice is harmless, and a hub refuses too.
func TestPublishAfterClose(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	a, b := nodes[0], nodes[1]
	a.hubClose(t)

	u := &gossiper.Update{ID: "x", Topics: []string{topicA}, Stamp: 1, Origin: "o"}
	if err := a.tr.Publish(t.Context(), u); err != gossiper.ErrClosed {
		t.Errorf("transport.Publish after Close: %v, want ErrClosed", err)
	}
	if err := a.tr.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := a.hub.Publish(t.Context(), &gossiper.Update{Topics: []string{topicA}}); err != gossiper.ErrClosed {
		t.Errorf("hub.Publish after Close: %v, want ErrClosed", err)
	}
	// The closed hub's HTTP side is gone too, and the live one is unaffected.
	waitPeers(t, b, 0)
	// Alone in its group, a hub has nobody to ask and the answer is complete.
	if subs, complete, err := b.tr.RemoteSubscriptions(t.Context()); len(subs) != 0 || !complete || err != nil {
		t.Errorf("RemoteSubscriptions of a lone hub: %v %v %v", subs, complete, err)
	}
	hc := newClient(t)
	sb := b.subscribe(t, subOpts{topics: []string{topicA}})
	b.publish(t, hc, url.Values{"topic": {topicA}, "data": {"alone"}})
	expectAll(t, 1, sb)
}

// TestUpdatesToClosedTransportAreIgnored: an update that reaches a transport after Close is not applied.
func TestUpdatesToClosedTransportAreIgnored(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	a, b := nodes[0], nodes[1]
	if err := b.tr.Close(); err != nil {
		t.Fatal(err)
	}
	hc := newClient(t)
	// Node a may still list b for a moment, and sends to it.
	for i := range 5 {
		a.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}})
	}
	time.Sleep(settle)
	if got := b.hub.Stats().Applied; got != 0 {
		t.Errorf("a hub with a closed transport applied %d updates", got)
	}
}
