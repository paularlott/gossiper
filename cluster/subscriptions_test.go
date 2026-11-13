package cluster_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossiper"
)

type subscriptionDoc struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Topic      string          `json:"topic"`
	Subscriber string          `json:"subscriber"`
	Active     bool            `json:"active"`
	Payload    json.RawMessage `json:"payload"`
}

type subscriptionsResponse struct {
	Type          string            `json:"type"`
	Subscriptions []subscriptionDoc `json:"subscriptions"`
}

// getSubscriptions calls the subscriptions API of n and returns the status, headers and body.
func getSubscriptions(t testing.TB, n *testNode, path string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, n.srv.URL+subsPath+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+subscriberToken(t, "*"))
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, body
}

func listSubscriptions(t testing.TB, n *testNode, path string) (subscriptionsResponse, http.Header) {
	t.Helper()
	status, hd, body := getSubscriptions(t, n, path)
	if status != http.StatusOK {
		t.Fatalf("subscriptions API on %s: status %d: %s", n.addr, status, body)
	}
	var doc subscriptionsResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("subscriptions API on %s: %v: %s", n.addr, err, body)
	}
	return doc, hd
}

func subscriptionIDs(doc subscriptionsResponse) []string {
	var ids []string
	for _, s := range doc.Subscriptions {
		ids = append(ids, s.ID)
	}
	slices.Sort(ids)
	return ids
}

func withSubscriptions(_ int, o *nodeOpts) {
	o.hub = func(c *gossiper.Config) { c.Subscriptions = true }
}

// TestSubscriptionsAPIListsEveryNodesSubscribers: the subscriptions API of one node lists the subscribers connected
// to the others, and the subscription events of a subscriber on one node reach a listener on another.
func TestSubscriptionsAPIListsEveryNodesSubscribers(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3, node: withSubscriptions})
	a, b, c := nodes[0], nodes[1], nodes[2]

	const (
		topicX = "https://example.com/x"
		topicY = "https://example.com/y?a=b&c=d"
	)
	payloadToken := func(user string) string {
		return mintToken(t, map[string]any{"subscribe": []string{"*"}, "payload": map[string]string{"user": user}})
	}

	// A listener on node A for every subscription event (they are private: its token is allowed all topics).
	listener := a.subscribe(t, subOpts{
		topics: []string{subsPath + "/{topic}/{subscriber}"},
		token:  subscriberToken(t, "*"),
	})
	// Its own subscription is announced to itself.
	listener.wait(t, 1)

	b.subscribe(t, subOpts{topics: []string{topicX, topicY}, token: payloadToken("b1")})
	b2 := b.subscribe(t, subOpts{topics: []string{topicX}})
	c.subscribe(t, subOpts{topics: []string{topicX}, token: payloadToken("c1")})
	const wantActive = 1 /* the listener */ + 2 + 1 + 1
	listener.wait(t, wantActive)

	events := func() []subscriptionDoc {
		var out []subscriptionDoc
		for _, e := range listener.all() {
			var d subscriptionDoc
			if err := json.Unmarshal([]byte(e.Data), &d); err != nil {
				t.Fatalf("subscription event %q: %v", e.Data, err)
			}
			out = append(out, d)
		}
		return out
	}
	for _, d := range events() {
		if !d.Active || d.Type != "Subscription" {
			t.Errorf("unexpected subscription event %+v", d)
		}
	}

	// Every node lists all of the subscriptions, the same ones.
	var want []string
	for _, n := range nodes {
		doc, hd := listSubscriptions(t, n, "")
		if len(doc.Subscriptions) != wantActive {
			t.Fatalf("node %s lists %d subscriptions, want %d: %+v", n.addr, len(doc.Subscriptions), wantActive, doc.Subscriptions)
		}
		if hd.Get("Warning") != "" {
			t.Errorf("node %s: complete answer has Warning %q", n.addr, hd.Get("Warning"))
		}
		ids := subscriptionIDs(doc)
		if want == nil {
			want = ids
		} else if !slices.Equal(ids, want) {
			t.Errorf("node %s lists %v, want %v", n.addr, ids, want)
		}
	}
	// The events and the API name the same subscriptions.
	var eventIDs []string
	for _, d := range events() {
		eventIDs = append(eventIDs, d.ID)
	}
	slices.Sort(eventIDs)
	if !slices.Equal(eventIDs, want) {
		t.Errorf("subscription events %v, API %v", eventIDs, want)
	}

	// Topic and payload of what the other nodes hold.
	doc, _ := listSubscriptions(t, a, "")
	byTopic := map[string]int{}
	payloads := map[string]int{}
	for _, s := range doc.Subscriptions {
		byTopic[s.Topic]++
		if len(s.Payload) > 0 {
			payloads[string(s.Payload)]++
		}
		if !s.Active || s.Type != "Subscription" || s.Subscriber == "" {
			t.Errorf("subscription %+v", s)
		}
	}
	if byTopic[topicX] != 3 || byTopic[topicY] != 1 || byTopic[subsPath+"/{topic}/{subscriber}"] != 1 {
		t.Errorf("subscriptions by topic: %v", byTopic)
	}
	if payloads[`{"user":"b1"}`] != 2 || payloads[`{"user":"c1"}`] != 1 || len(payloads) != 2 {
		t.Errorf("payloads: %v", payloads)
	}

	// The per-topic and per-subscriber endpoints cover remote nodes too.
	doc, _ = listSubscriptions(t, a, "/"+url.PathEscape(topicX))
	if len(doc.Subscriptions) != 3 {
		t.Errorf("subscriptions of %s: %d, want 3: %+v", topicX, len(doc.Subscriptions), doc.Subscriptions)
	}
	doc, _ = listSubscriptions(t, a, "/"+url.PathEscape(topicY))
	if len(doc.Subscriptions) != 1 {
		t.Fatalf("subscriptions of %s: %d, want 1", topicY, len(doc.Subscriptions))
	}
	b1ID := doc.Subscriptions[0].Subscriber
	status, _, body := getSubscriptions(t, c, "/"+url.PathEscape(topicY)+"/"+url.PathEscape(b1ID))
	if status != http.StatusOK {
		t.Fatalf("one subscription: status %d: %s", status, body)
	}
	var one subscriptionDoc
	if err := json.Unmarshal(body, &one); err != nil || one.Subscriber != b1ID || one.Topic != topicY || !one.Active {
		t.Errorf("one subscription: %+v (%v): %s", one, err, body)
	}

	// A subscriber that goes is announced inactive and leaves the list, on every node.
	b2.close()
	waitFor(t, waitMax, "the inactive event of the subscriber that left", func() bool {
		for _, d := range events() {
			if !d.Active {
				return true
			}
		}
		return false
	})
	for _, n := range nodes {
		waitFor(t, waitMax, "the subscriber that left to leave the list of "+n.addr, func() bool {
			status, _, body := getSubscriptions(t, n, "")
			if status != http.StatusOK {
				return false
			}
			var d subscriptionsResponse
			return json.Unmarshal(body, &d) == nil && len(d.Subscriptions) == wantActive-1
		})
	}
}

// bareNode is a gossip node that announces a hub but runs none: it answers nothing.
func bareNode(t testing.TB) (*gossip.Cluster, string) {
	t.Helper()
	var gc *gossip.Cluster
	var addr string
	for attempt := 0; ; attempt++ {
		port, err := freePort()
		if err != nil {
			t.Fatal(err)
		}
		addr = fmt.Sprintf("127.0.0.1:%d", port)
		cfg := gossipConfig(addr)
		cfg.Transport = gossip.NewSocketTransport(cfg)
		if gc, err = gossip.NewCluster(cfg); err != nil {
			t.Fatal(err)
		}
		if startCluster(gc) == nil {
			break
		}
		if attempt == 5 {
			t.Fatal("could not bind a gossip port")
		}
	}
	var once sync.Once
	t.Cleanup(func() { once.Do(gc.Stop) })
	gc.LocalMetadata().SetString("gossiper.hub", "on")
	return gc, addr
}

// TestSubscriptionsWithUnresponsiveNode: a node of the group that never answers makes the subscriptions API answer
// 503 (try again) within its timeout rather than serve a partial list as the answer. Publishing is not held up by it.
func TestSubscriptionsWithUnresponsiveNode(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3, node: withSubscriptions})
	a, b, c := nodes[0], nodes[1], nodes[2]
	hc := newClient(t)

	hole, _ := bareNode(t)
	if err := hole.Join([]string{a.addr}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, waitMax, "every hub to see the unresponsive node", func() bool {
		for _, n := range nodes {
			if len(n.tr.Peers()) != 3 {
				return false
			}
		}
		return true
	})

	b.subscribe(t, subOpts{topics: []string{"https://example.com/x"}})
	c.subscribe(t, subOpts{topics: []string{"https://example.com/y"}})
	sa := a.subscribe(t, subOpts{topics: []string{"https://example.com/x"}})
	sb := b.subscribe(t, subOpts{topics: []string{"https://example.com/x"}})
	sc := c.subscribe(t, subOpts{topics: []string{"https://example.com/x"}})
	const wantRemote = 4 // what nodes B and C hold

	// At the transport: the answer lists the others and says it is incomplete, at the context's deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	start := time.Now()
	subs, complete, err := a.tr.RemoteSubscriptions(ctx)
	cancel()
	if complete || err == nil {
		t.Errorf("RemoteSubscriptions: complete=%v err=%v, want incomplete with an error", complete, err)
	}
	if len(subs) != wantRemote {
		t.Errorf("RemoteSubscriptions returned %d subscriptions, want %d", len(subs), wantRemote)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("RemoteSubscriptions took %v with a 500ms deadline", d)
	}

	// Over HTTP: the hub waits at most its own timeout (5s), then answers 503 with Retry-After, not a partial list.
	start = time.Now()
	status, hd, body := getSubscriptions(t, a, "")
	took := time.Since(start)
	if took > 8*time.Second {
		t.Errorf("the subscriptions API took %v to answer; its timeout is 5s", took)
	}
	if status != http.StatusServiceUnavailable || hd.Get("Retry-After") == "" || strings.Contains(string(body), "example.com") {
		t.Errorf("incomplete answer: status %d, Retry-After %q, body %s; want 503, a Retry-After and no list", status,
			hd.Get("Retry-After"), body)
	}

	// Publishing does not wait for the node that does not answer.
	var want []string
	for i := range 20 {
		start := time.Now()
		want = append(want, a.publish(t, hc, url.Values{"topic": {"https://example.com/x"}, "data": {fmt.Sprint(i)}}))
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("publish %d took %v", i, d)
		}
	}
	for i, evs := range expectAll(t, len(want), sa, sb, sc) {
		if !sameSet(idsOf(evs), want) {
			t.Errorf("subscriber %d received %v, want %v", i, idsOf(evs), want)
		}
	}

	// The node leaves: the group shrinks and the answer is complete again.
	hole.Stop()
	waitFor(t, waitMax, "the unresponsive node to leave the group", func() bool {
		for _, n := range nodes {
			if len(n.tr.Peers()) != 2 {
				return false
			}
		}
		return true
	})
	start = time.Now()
	doc, _ := listSubscriptions(t, a, "") // 200 again: listSubscriptions fails the test otherwise
	if len(doc.Subscriptions) != wantRemote+1 || time.Since(start) > 3*time.Second {
		t.Errorf("after the node left: %d subscriptions, took %v", len(doc.Subscriptions), time.Since(start))
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
