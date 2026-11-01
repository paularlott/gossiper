package cluster_test

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossiper/cluster"
)

// TestPeerReceivesInPublishOrder: a peer applies a node's updates in the order they were published there, however
// many batches they took.
func TestPeerReceivesInPublishOrder(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	a, b := nodes[0], nodes[1]
	hc := newClient(t)
	sub := b.subscribe(t, subOpts{topics: []string{topicA}})
	var want []string
	for i := range 200 {
		want = append(want, a.publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint("update ", i)}}))
	}
	sub.wait(t, len(want))
	if got := sub.ids(); !slices.Equal(got, want) {
		t.Fatalf("the peer's subscriber received the updates out of order:\n got %v\nwant %v", got, want)
	}
	if d := a.tr.Dropped(); d != 0 {
		t.Errorf("%d updates dropped", d)
	}
}

// TestDroppedCounted: updates a peer's queue has no room for are dropped and counted, once per peer.
func TestDroppedCounted(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3, node: func(i int, o *nodeOpts) {
		if i == 0 {
			o.tr = func(o *cluster.Options) { o.MaxQueueBytes = 1 } // no room for any update
		}
	}})
	hc := newClient(t)
	for i := range 5 {
		nodes[0].publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}})
	}
	if got := nodes[0].tr.Dropped(); got != 10 {
		t.Errorf("dropped %d, want 10 (5 updates for each of 2 peers)", got)
	}
	time.Sleep(settle)
	for _, n := range nodes[1:] {
		if got := n.hub.Stats().Applied; got != 0 {
			t.Errorf("node %s applied %d updates that were dropped", n.addr, got)
		}
	}
}

// TestBackfill: a node that starts copies the history of a peer, in pages, so a subscriber can resume on it from an
// update published before it started; it is ready once it has.
func TestBackfill(t *testing.T) {
	a := newNode(t, nodeOpts{})
	hc := newClient(t)
	data := strings.Repeat("x", 50<<10) // 40 of them take more than one page
	var want []string
	for range 40 {
		want = append(want, a.publish(t, hc, url.Values{"topic": {topicA}, "data": {data}}))
	}
	if !a.tr.Ready() {
		t.Error("a node that copies no history is not ready")
	}

	b := newNode(t, nodeOpts{tr: func(o *cluster.Options) { o.Backfill = 10 * time.Second }})
	if b.tr.Ready() {
		t.Fatal("ready before it copied a peer's history")
	}
	if err := b.gc.Join([]string{a.addr}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the new node ready", b.tr.Ready)
	if got := b.hub.Stats().HistoryLen; got != len(want) {
		t.Fatalf("the new node's history holds %d updates, want %d", got, len(want))
	}
	r := b.subscribe(t, subOpts{topics: []string{topicA}, lastEventID: want[9]})
	r.wait(t, len(want)-10)
	if got := r.ids(); !slices.Equal(got, want[10:]) {
		t.Errorf("resumed on the new node with %v, want %v", got, want[10:])
	}

	// A node that finds no peer in time is ready anyway, with what it has.
	c := newNode(t, nodeOpts{tr: func(o *cluster.Options) { o.Backfill = 200 * time.Millisecond }})
	waitFor(t, 5*time.Second, "a lone node ready", c.tr.Ready)
}
