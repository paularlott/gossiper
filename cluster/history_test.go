package cluster_test

import (
	"fmt"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper"
)

const topicB = "https://example.com/other"

// TestReplayOnAnotherNode: a subscriber that received events on one node reconnects to another with its last event
// ID and receives the ones after it. Every node applied every update, so every node's history can serve it.
func TestReplayOnAnotherNode(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	a, b, c := nodes[0], nodes[1], nodes[2]
	hc := newClient(t)

	published := 0
	// publish sends one update through node n and waits until every node has applied it, so the history of every
	// node holds the updates in the order they were published.
	publish := func(n *testNode, topic string) string {
		published++
		id := n.publish(t, hc, url.Values{"topic": {topic}, "data": {fmt.Sprintf("update %d", published)}})
		waitApplied(t, nodes, uint64(published))
		return id
	}

	sub := a.subscribe(t, subOpts{topics: []string{topicA}})
	var xs []string // the updates on topicA, in order
	var noiseAfterX3 string
	for i := range 5 {
		n := nodes[i%3]
		xs = append(xs, publish(n, topicA))
		if i == 2 {
			noiseAfterX3 = publish(n, topicB)
		}
	}
	sub.wait(t, 5)
	if got := sub.ids(); !slices.Equal(got, xs) {
		t.Fatalf("the first subscriber received %v, want %v", got, xs)
	}
	sub.close() // it dropped after x3 reached it (it also saw x4 and x5, but is told to resume from x3)

	// While it is away: more updates, from yet another node.
	for range 3 {
		xs = append(xs, publish(c, topicA))
		publish(c, topicB)
	}

	// Resume on B and on C, after x3.
	for _, n := range []*testNode{b, c} {
		before := n.hub.Stats().Replayed
		r := n.subscribe(t, subOpts{topics: []string{topicA}, lastEventID: xs[2]})
		if got := r.header.Get("Last-Event-ID"); got != xs[2] {
			t.Errorf("node %s: Last-Event-ID header %q, want %q", n.addr, got, xs[2])
		}
		want := xs[3:]
		expectAll(t, len(want), r)
		if got := r.ids(); !slices.Equal(got, want) {
			t.Errorf("node %s replayed %v, want %v", n.addr, got, want)
		}
		if got := n.hub.Stats().Replayed - before; got != uint64(len(want)) {
			t.Errorf("node %s counted %d replayed events, want %d", n.addr, got, len(want))
		}
		// And the stream carries on live, without repeating what was replayed.
		live := publish(a, topicA)
		xs = append(xs, live)
		r.wait(t, len(want)+1)
		time.Sleep(settle)
		if got := r.ids(); !slices.Equal(got, append(slices.Clone(want), live)) {
			t.Errorf("node %s received %v after the live update, want the replay then %s", n.addr, got, live)
		}
	}

	// A cursor that is an update the subscriber is not interested in resumes just the same.
	r := b.subscribe(t, subOpts{topics: []string{topicA}, lastEventID: noiseAfterX3})
	want := xs[3:]
	expectAll(t, len(want), r)
	if got := r.ids(); !slices.Equal(got, want) {
		t.Errorf("resume from an unrelated update: %v, want %v", got, want)
	}
}

// TestReplayUnknownCursor: a cursor the node does not know replays nothing and is answered with "earliest" in the header.
func TestReplayUnknownCursor(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	hc := newClient(t)
	nodes[0].publish(t, hc, url.Values{"topic": {topicA}})
	waitApplied(t, nodes, 1)
	r := nodes[1].subscribe(t, subOpts{topics: []string{topicA}, lastEventID: "urn:uuid:does-not-exist"})
	if got := r.header.Get("Last-Event-ID"); got != "earliest" {
		t.Errorf("Last-Event-ID header %q, want earliest", got)
	}
	// Nothing is replayed: the hub cannot tell which updates the subscriber missed.
	expectAll(t, 0, r)
	if got := nodes[1].hub.Stats().ReplayMisses; got != 1 {
		t.Errorf("ReplayMisses %d, want 1", got)
	}
}

// TestLateJoinerHasNoHistory: a node that joins later has only the updates published after it joined (a hub gets
// an update once, when it is published); a cursor from before is not in its history.
func TestLateJoinerHasNoHistory(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	hc := newClient(t)
	var old []string
	for i := range 3 {
		old = append(old, nodes[0].publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}}))
	}
	waitApplied(t, nodes, 3)

	e := newNode(t, nodeOpts{})
	if err := e.gc.Join([]string{nodes[0].addr}); err != nil {
		t.Fatal(err)
	}
	all := append(slices.Clone(nodes), e)
	waitConverged(t, all)

	se := e.subscribe(t, subOpts{topics: []string{topicA}})
	fresh := nodes[1].publish(t, hc, url.Values{"topic": {topicA}, "data": {"fresh"}})
	if evs := expectAll(t, 1, se)[0]; evs[0].ID != fresh {
		t.Errorf("the late joiner received %v, want only %s", idsOf(evs), fresh)
	}
	waitApplied(t, all, 1)
	if st := e.hub.Stats(); st.Applied != 1 || st.HistoryLen != 1 {
		t.Errorf("the late joiner applied %d updates, history %d, want 1 and 1", st.Applied, st.HistoryLen)
	}

	// Its history cannot resume a cursor older than itself; an older node's can.
	r := e.subscribe(t, subOpts{topics: []string{topicA}, lastEventID: old[0]})
	if got := r.header.Get("Last-Event-ID"); got != "earliest" {
		t.Errorf("late joiner: Last-Event-ID header %q, want earliest", got)
	}
	expectAll(t, 0, r)
	if got := e.hub.Stats().ReplayMisses; got != 1 {
		t.Errorf("late joiner: ReplayMisses %d, want 1", got)
	}
	r2 := nodes[2].subscribe(t, subOpts{topics: []string{topicA}, lastEventID: old[0]})
	want := append(slices.Clone(old[1:]), fresh)
	expectAll(t, len(want), r2)
	if got := r2.ids(); !slices.Equal(got, want) {
		t.Errorf("older node replayed %v, want %v", got, want)
	}
}

// TestLateArrivalIsReplayed: an update that reaches a node after later ones (delivered late, as a replicated update
// can be) is still replayed to a subscriber whose cursor is one of those later updates, within the replay window.
func TestLateArrivalIsReplayed(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	a, b, c := nodes[0], nodes[1], nodes[2]
	hc := newClient(t)

	// u1 < late < u2 by stamp.
	u1 := a.publish(t, hc, url.Values{"topic": {topicA}, "data": {"u1"}})
	waitApplied(t, nodes, 1)
	time.Sleep(5 * time.Millisecond)
	between := time.Now() // the late update was published here, on some other node
	time.Sleep(5 * time.Millisecond)
	u2 := a.publish(t, hc, url.Values{"topic": {topicA}, "data": {"u2"}})
	waitApplied(t, nodes, 2)

	live := b.subscribe(t, subOpts{topics: []string{topicA}})
	live.wait(t, 0)

	late := &gossiper.Update{
		ID: "urn:test:late", Topics: []string{topicA}, Data: "late",
		Stamp: uint64(hlc.FromTime(between)), Origin: "some-other-node",
	}
	b.hub.Apply(late)
	live.wait(t, 1) // delivered live to the connected subscriber, once
	if got := live.ids(); !slices.Equal(got, []string{late.ID}) {
		t.Fatalf("live subscriber received %v, want just the late update", got)
	}

	replayed := func(n *testNode, cursor string, want ...string) {
		t.Helper()
		r := n.subscribe(t, subOpts{topics: []string{topicA}, lastEventID: cursor})
		if len(want) > 0 {
			r.wait(t, len(want))
		}
		time.Sleep(settle)
		if got := r.ids(); !slices.Equal(got, want) {
			t.Errorf("node %s, cursor %s: replayed %v, want %v", n.addr, cursor, got, want)
		}
	}
	// Ordered by stamp, the history on b is u1, late, u2.
	replayed(b, u2, late.ID)     // the late update is ordered before u2 but arrived after it
	replayed(b, u1, late.ID, u2) // both are after u1
	replayed(b, late.ID, u2)     // u2 is after it
	replayed(b, "earliest", u1, late.ID, u2)
	// Nodes that never got it do not replay it.
	replayed(c, u2)
	replayed(c, u1, u2)

	// An update older than the replay window (5s by default) is not replayed to a cursor that is later than that,
	// even though it arrived after the cursor's update.
	stale := &gossiper.Update{
		ID: "urn:test:stale", Topics: []string{topicA}, Data: "stale",
		Stamp: uint64(hlc.FromTime(between.Add(-10 * time.Second))), Origin: "some-other-node",
	}
	b.hub.Apply(stale)
	replayed(b, u2, late.ID)
	replayed(b, u1, late.ID, u2)
	replayed(b, "earliest", stale.ID, u1, late.ID, u2)

	// The same publication delivered twice is applied once.
	dups := b.hub.Stats().Duplicates
	b.hub.Apply(&gossiper.Update{ID: late.ID, Topics: late.Topics, Data: late.Data, Stamp: late.Stamp, Origin: late.Origin})
	if got := b.hub.Stats().Duplicates - dups; got != 1 {
		t.Errorf("a repeated update counted %d duplicates, want 1", got)
	}
	replayed(b, u2, late.ID)
	time.Sleep(settle)
	if got := live.count(); got != 2 { // late, stale: the stale one is live news to a connected subscriber
		t.Errorf("the live subscriber received %d events %v, want 2", got, live.ids())
	}
}
