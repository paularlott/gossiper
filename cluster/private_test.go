package cluster_test

import (
	"net/url"
	"testing"
	"time"
)

// TestPrivateUpdatesAuthorizeOnEveryNode: a private update is delivered on each node only to the subscribers whose
// token covers one of its topics, live and from the history.
func TestPrivateUpdatesAuthorizeOnEveryNode(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	hc := newClient(t)

	const (
		inbox = "https://example.com/users/1/inbox"
		feed  = "https://example.com/feed"
	)
	type who struct {
		name    string
		token   string
		allowed bool
	}
	people := []who{
		{"anonymous", "", false},
		{"exact selector", subscriberToken(t, inbox), true},
		{"template selector", subscriberToken(t, "https://example.com/users/{id}/inbox"), true},
		{"any selector", subscriberToken(t, "*"), true},
		{"other user", subscriberToken(t, "https://example.com/users/2/inbox"), false},
		{"empty selectors", subscriberToken(t), false},
		{"no subscribe claim", mintToken(t, map[string]any{"publish": []string{"*"}}), false},
	}
	subscribe := func(n *testNode, topic string) []*sseClient {
		var out []*sseClient
		for _, p := range people {
			out = append(out, n.subscribe(t, subOpts{topics: []string{topic}, token: p.token}))
		}
		return out
	}
	onInbox := map[*testNode][]*sseClient{}
	onFeed := map[*testNode][]*sseClient{}
	for _, n := range nodes {
		onInbox[n] = subscribe(n, inbox)
		onFeed[n] = subscribe(n, feed)
	}

	// Phase 1: a private update, published on node 0, for the inbox.
	private1 := nodes[0].publish(t, hc, url.Values{"topic": {inbox}, "private": {"on"}, "data": {"secret 1"}})
	for _, n := range nodes {
		for i, p := range people {
			if p.allowed {
				onInbox[n][i].wait(t, 1)
			}
		}
	}
	expectCounts := func(phase string, want func(p who) int) {
		t.Helper()
		time.Sleep(settle) // let a duplicate or an unexpected event show up
		for _, n := range nodes {
			for i, p := range people {
				if got, w := onInbox[n][i].count(), want(p); got != w {
					t.Errorf("%s: %s on node %s received %d events %v, want %d", phase, p.name, n.addr, got, onInbox[n][i].ids(), w)
				}
			}
		}
	}
	expectCounts("private", func(p who) int { return b2i(p.allowed) })
	for _, n := range nodes {
		for i, p := range people {
			if p.allowed {
				if evs := onInbox[n][i].all(); evs[0].ID != private1 || evs[0].Data != "secret 1" {
					t.Errorf("%s on node %s received %+v, want id %s", p.name, n.addr, evs[0], private1)
				}
			}
		}
	}

	// Phase 2: a public update on the same topic reaches everyone, through another node.
	public := nodes[2].publish(t, hc, url.Values{"topic": {inbox}, "data": {"hello all"}})
	for _, n := range nodes {
		for i, p := range people {
			onInbox[n][i].wait(t, 1+b2i(p.allowed)) // the unauthorized have this as their first
		}
	}
	expectCounts("public", func(p who) int { return 1 + b2i(p.allowed) })

	// Phase 3: a private update with an alternate topic: one topic the token covers is enough, and a subscriber of
	// the feed (the canonical topic) needs that token even though the token does not mention the feed.
	private2 := nodes[1].publish(t, hc, url.Values{"topic": {feed, inbox}, "private": {"1"}, "data": {"secret 2"}})
	for _, n := range nodes {
		for i, p := range people {
			if p.allowed {
				onFeed[n][i].wait(t, 1)
			}
		}
	}
	time.Sleep(settle)
	for _, n := range nodes {
		for i, p := range people {
			if got, w := onFeed[n][i].count(), b2i(p.allowed); got != w {
				t.Errorf("feed: %s on node %s received %d events, want %d", p.name, n.addr, got, w)
			}
		}
	}

	// Phase 4: replay on a node that applied the updates over the network applies the same rules.
	last := nodes[2]
	for _, p := range people {
		c := last.subscribe(t, subOpts{topics: []string{inbox}, token: p.token, lastEventID: "earliest"})
		want := []string{public}
		if p.allowed {
			want = []string{private1, public, private2}
		}
		expectAll(t, len(want), c)
		if got := c.ids(); !equalStrings(got, want) {
			t.Errorf("replay for %s: %v, want %v", p.name, got, want)
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
