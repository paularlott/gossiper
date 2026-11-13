package gossiper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const subsBase = "/.well-known/mercure/subscriptions"

// subEvent is a subscription event as a subscriber of the subscriptions topics sees it.
type subEvent struct {
	Context    string          `json:"@context"`
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Topic      string          `json:"topic"`
	Subscriber string          `json:"subscriber"`
	Active     bool            `json:"active"`
	Payload    json.RawMessage `json:"payload"`
}

// nextSub reads events until one about the given topic selector and returns it with its frame.
func nextSub(t *testing.T, c *sseClient, topic string) (subEvent, sseEvent) {
	t.Helper()
	for {
		ev := c.mustNext()
		var se subEvent
		if err := json.Unmarshal([]byte(ev.Data), &se); err != nil {
			t.Fatalf("event data %q: %v", ev.Data, err)
		}
		if se.Topic == topic {
			return se, ev
		}
	}
}

func subsTemplate() string { return subsBase + "/{topic}/{subscriber}" }

func TestSubscriptionEventsDraftFormat(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true})
	monitor := e.subscribe(t, tokenFor(t, nil, all), subsTemplate())
	// The monitor's own subscription is announced to it.
	if own, _ := nextSub(t, monitor, subsTemplate()); !own.Active {
		t.Fatal("own subscription not active")
	}

	claims := mercureClaims(nil, []string{"https://example.com/a"})
	claims["mercure"].(map[string]any)["payload"] = map[string]any{"user": "paul", "n": 3}
	c := e.subscribe(t, signJWT(t, testSecret, claims), "https://example.com/a", "https://example.com/b")

	got := map[string]subEvent{}
	var frames []sseEvent
	for len(got) < 2 {
		ev := monitor.mustNext()
		var se subEvent
		if err := json.Unmarshal([]byte(ev.Data), &se); err != nil {
			t.Fatal(err)
		}
		got[se.Topic] = se
		frames = append(frames, ev)
	}
	subscriber := got["https://example.com/a"].Subscriber
	if !uuidV4.MatchString(subscriber) {
		t.Fatalf("subscriber id %q", subscriber)
	}
	for _, sel := range []string{"https://example.com/a", "https://example.com/b"} {
		se, ok := got[sel]
		if !ok {
			t.Fatalf("no event for %s", sel)
		}
		wantID := subsBase + "/" + escapeSegment(sel) + "/" + escapeSegment(subscriber)
		if se.ID != wantID || se.Type != "Subscription" || !se.Active || se.Subscriber != subscriber || se.Context != "https://mercure.rocks/" {
			t.Fatalf("event %+v, want id %s", se, wantID)
		}
		if string(se.Payload) != `{"n":3,"user":"paul"}` && string(se.Payload) != `{"user":"paul","n":3}` {
			t.Fatalf("payload %s", se.Payload)
		}
	}
	for _, f := range frames {
		if f.Type != "" {
			t.Fatalf("draft format sends an event type: %q", f.Type)
		}
	}
	// The update is published on the subscription's own topic, privately: an anonymous-style token without
	// matching subscribe selectors would not see it (checked in TestSubscriptionEventsArePrivate).
	c.close()
	for i := 0; i < 2; i++ {
		ev := monitor.mustNext()
		var se subEvent
		_ = json.Unmarshal([]byte(ev.Data), &se)
		if se.Active || se.Subscriber != subscriber {
			t.Fatalf("disconnect event %+v", se)
		}
	}
}

func TestSubscriptionEventsModernFormat(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true, ModernSubscriptionFormat: true})
	monitor := e.subscribe(t, tokenFor(t, nil, all), subsTemplate())
	nextSub(t, monitor, subsTemplate())
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	se, frame := nextSub(t, monitor, "t")
	if frame.Type != "mercure" {
		t.Fatalf("event type %q, want mercure", frame.Type)
	}
	if se.Type != "subscription" || se.Context != "" || !se.Active {
		t.Fatalf("event %+v", se)
	}
	if strings.Contains(frame.Data, "@context") {
		t.Fatalf("modern event holds a context: %s", frame.Data)
	}
	c.close()
	se, _ = nextSub(t, monitor, "t")
	if se.Active {
		t.Fatal("disconnect event is active")
	}
}

func TestSubscriptionEventsArePrivate(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true, Anonymous: true})
	anon := e.subscribe(t, "", subsTemplate(), "end")
	narrow := e.subscribe(t, tokenFor(t, nil, []string{subsBase + "/something-else/{x}"}), subsTemplate(), "end")
	wide := e.subscribe(t, tokenFor(t, nil, all), subsTemplate(), "end")
	e.subscribe(t, "", "t")
	e.publish(t, "end", "end")
	// Public updates reach everyone; subscription events only the stream allowed to see them.
	for name, c := range map[string]*sseClient{"anonymous": anon, "narrow": narrow} {
		if got := c.drain("end"); len(got) != 0 {
			t.Fatalf("%s stream was sent subscription events: %v", name, got)
		}
	}
	if got := wide.drain("end"); len(got) == 0 {
		t.Fatal("the authorized stream saw no subscription events")
	}
}

func TestSubscriptionEventsNeedFeature(t *testing.T) {
	e := newEnv(t, Config{})
	monitor := e.subscribe(t, tokenFor(t, nil, all), "*")
	e.subscribe(t, tokenFor(t, nil, all), "t")
	e.publish(t, "end", "x")
	if got := monitor.drain("end"); len(got) != 0 {
		t.Fatalf("subscription events published with the feature off: %v", got)
	}
}

func TestSubscriptionsAPIAuth(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true})
	narrow := tokenFor(t, nil, []string{subsBase + "/a/{s}"})
	tests := []struct {
		name  string
		tok   string
		path  string
		want  int
		wantA string
	}{
		{"no token", "", subsBase, 401, "Bearer"},
		{"malformed", "x", subsBase, 401, `Bearer error="invalid_token"`},
		{"no subscribe claim", tokenFor(t, all, nil), subsBase, 403, `Bearer error="insufficient_scope"`},
		{"empty subscribe", tokenFor(t, nil, []string{}), subsBase, 403, `Bearer error="insufficient_scope"`},
		{"star", tokenFor(t, nil, all), subsBase, 200, ""},
		{"exact path", tokenFor(t, nil, []string{subsBase}), subsBase, 200, ""},
		{"selector for another path", narrow, subsBase, 403, `Bearer error="insufficient_scope"`},
		{"template covers path (the subscription is unknown)", narrow, subsBase + "/a/x", 404, ""},
		{"template misses other topic", narrow, subsBase + "/b/x", 403, `Bearer error="insufficient_scope"`},
		{"template with topic only", tokenFor(t, nil, []string{subsBase + "/{topic}"}), subsBase + "/a", 200, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do(t, "GET", e.srv.URL+tc.path, bearer(tc.tok), "")
			if r.code != tc.want {
				t.Fatalf("status %d (%s), want %d", r.code, strings.TrimSpace(r.body), tc.want)
			}
			if got := challenge(r.header.Get("WWW-Authenticate")); got != tc.wantA {
				t.Fatalf("WWW-Authenticate %q, want %q", got, tc.wantA)
			}
			if r.code == 200 || r.code == 404 { // what a token sees: kept by no shared cache, nor given to another token
				if cc := r.header.Get("Cache-Control"); cc != "private, must-revalidate" {
					t.Errorf("Cache-Control %q", cc)
				}
				if v := strings.Join(r.header.Values("Vary"), ", "); !strings.Contains(v, "Authorization") || !strings.Contains(v, "Cookie") {
					t.Errorf("Vary %q, want Authorization and Cookie", v)
				}
			}
		})
	}
	t.Run("query token", func(t *testing.T) {
		r := e.do(t, "GET", e.srv.URL+subsBase+"?authorization="+tokenFor(t, nil, all), nil, "")
		if r.code != 200 {
			t.Fatalf("status %d", r.code)
		}
	})
}

func TestSubscriptionsAPIDisabled(t *testing.T) {
	e := newEnv(t, Config{})
	if r := e.do(t, "GET", e.srv.URL+subsBase, bearer(tokenFor(t, nil, all)), ""); r.code != 404 {
		t.Fatalf("status %d", r.code)
	}
}

func TestSubscriptionsAPIRouting(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true})
	h := bearer(tokenFor(t, nil, all))
	for _, tc := range []struct {
		path string
		want int
	}{
		{subsBase, 200},
		{subsBase + "/", 404},
		{subsBase + "/a", 200},
		{subsBase + "/a/", 404},
		{subsBase + "//b", 404},
		{subsBase + "/a/b/c", 404},
		{subsBase + "/a/b", 404}, // unknown subscription
		{subsBase + "x", 404},
	} {
		if r := e.do(t, "GET", e.srv.URL+tc.path, h, ""); r.code != tc.want {
			t.Errorf("%s: %d, want %d", tc.path, r.code, tc.want)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		r := e.do(t, m, e.srv.URL+subsBase, h, "")
		if r.code != 405 || r.header.Get("Allow") != "GET, HEAD, OPTIONS" {
			t.Errorf("%s: %d allow %q", m, r.code, r.header.Get("Allow"))
		}
	}
}

// listing is the body of a subscriptions collection.
type listing struct {
	Context       string         `json:"@context"`
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	LastEventID   string         `json:"lastEventID"`
	Subscriptions []Subscription `json:"subscriptions"`
}

func getListing(t *testing.T, e *env, path string) (listing, result) {
	t.Helper()
	r := e.do(t, "GET", e.srv.URL+path, bearer(tokenFor(t, nil, all)), "")
	if r.code != 200 {
		t.Fatalf("GET %s: %d %s", path, r.code, r.body)
	}
	var l listing
	if err := json.Unmarshal([]byte(r.body), &l); err != nil {
		t.Fatalf("%v in %s", err, r.body)
	}
	return l, r
}

func TestSubscriptionsAPICollection(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true})
	l, r := getListing(t, e, subsBase)
	if l.Subscriptions == nil || len(l.Subscriptions) != 0 || strings.Contains(r.body, "null") {
		t.Fatalf("empty collection: %s", r.body)
	}
	if l.LastEventID != "earliest" || r.header.Get("ETag") != `"earliest"` {
		t.Fatalf("empty hub: last event %q etag %q", l.LastEventID, r.header.Get("ETag"))
	}

	claims := mercureClaims(nil, all)
	claims["mercure"].(map[string]any)["payload"] = map[string]string{"k": "v"}
	c1 := e.subscribe(t, signJWT(t, testSecret, claims), "https://example.com/a", "https://example.com/b")
	c2 := e.subscribe(t, tokenFor(t, nil, all), "https://example.com/a")
	_ = c1
	_ = c2
	l, r = getListing(t, e, subsBase)
	if l.Context != "https://mercure.rocks/" || l.Type != "Subscriptions" || l.ID != subsBase {
		t.Fatalf("draft envelope %+v", l)
	}
	if ct := r.header.Get("Content-Type"); ct != "application/ld+json" {
		t.Fatalf("content type %q", ct)
	}
	if link := r.header.Get("Link"); link != `</.well-known/mercure>; rel="mercure"` {
		t.Fatalf("link %q", link)
	}
	if r.header.Get("Cache-Control") != "private, must-revalidate" || r.header.Get("Warning") != "" {
		t.Fatalf("headers %v", r.header)
	}
	if len(l.Subscriptions) != 3 {
		t.Fatalf("%d subscriptions: %s", len(l.Subscriptions), r.body)
	}
	for i, s := range l.Subscriptions {
		if s.Type != "Subscription" || !s.Active || s.Context != "" || !uuidV4.MatchString(s.Subscriber) {
			t.Fatalf("subscription %+v", s)
		}
		if want := subsBase + "/" + escapeSegment(s.Topic) + "/" + escapeSegment(s.Subscriber); s.ID != want {
			t.Fatalf("id %q, want %q", s.ID, want)
		}
		if i > 0 && l.Subscriptions[i-1].ID >= s.ID {
			t.Fatal("subscriptions not sorted by id")
		}
	}
	if l.LastEventID == "earliest" || r.header.Get("ETag") != `"`+l.LastEventID+`"` {
		t.Fatalf("last event id %q etag %q", l.LastEventID, r.header.Get("ETag"))
	}
	// Topic filter, with the topic percent-encoded in the path.
	byTopic, _ := getListing(t, e, subsBase+"/"+escapeSegment("https://example.com/a"))
	if len(byTopic.Subscriptions) != 2 {
		t.Fatalf("by topic: %+v", byTopic.Subscriptions)
	}
	if byTopic.ID != subsBase+"/"+escapeSegment("https://example.com/a") {
		t.Fatalf("collection id %q", byTopic.ID)
	}
	if none, _ := getListing(t, e, subsBase+"/nothing"); len(none.Subscriptions) != 0 {
		t.Fatalf("unknown topic: %+v", none.Subscriptions)
	}
	var withPayload int
	for _, s := range l.Subscriptions {
		if string(s.Payload) == `{"k":"v"}` {
			withPayload++
		}
	}
	if withPayload != 2 {
		t.Fatalf("%d subscriptions carry the payload, want 2", withPayload)
	}

	// Single subscription.
	first := byTopic.Subscriptions[0]
	one := e.do(t, "GET", e.srv.URL+first.ID, bearer(tokenFor(t, nil, all)), "")
	if one.code != 200 {
		t.Fatalf("single: %d %s", one.code, one.body)
	}
	var doc struct {
		Subscription
		Context     string `json:"@context"`
		LastEventID string `json:"lastEventID"`
	}
	if err := json.Unmarshal([]byte(one.body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != first.ID || doc.Context != "https://mercure.rocks/" || doc.Type != "Subscription" || doc.LastEventID == "" || doc.Subscriber != first.Subscriber {
		t.Fatalf("single doc %+v", doc)
	}
	if r := e.do(t, "HEAD", e.srv.URL+first.ID, bearer(tokenFor(t, nil, all)), ""); r.code != 200 || r.body != "" {
		t.Fatalf("HEAD: %d %q", r.code, r.body)
	}
	missing := subsBase + "/" + escapeSegment("https://example.com/a") + "/" + escapeSegment("urn:uuid:none")
	if r := e.do(t, "GET", e.srv.URL+missing, bearer(tokenFor(t, nil, all)), ""); r.code != 404 {
		t.Fatalf("unknown subscription: %d", r.code)
	} else if strings.Contains(r.header.Get("Content-Type"), "json") {
		t.Fatalf("404 content type %q", r.header.Get("Content-Type"))
	}

	// A disconnected subscriber leaves the list.
	c1.close()
	waitSubscribers(t, e.hub, 1)
	if l, _ := getListing(t, e, subsBase); len(l.Subscriptions) != 1 {
		t.Fatalf("after disconnect: %+v", l.Subscriptions)
	}
	if r := e.do(t, "GET", e.srv.URL+first.ID, bearer(tokenFor(t, nil, all)), ""); r.code != 404 && first.Subscriber != c2Subscriber(t, e) {
		t.Fatalf("disconnected subscription still served: %d", r.code)
	}
	r = e.do(t, "HEAD", e.srv.URL+subsBase, bearer(tokenFor(t, nil, all)), "")
	if r.code != 200 || r.body != "" {
		t.Fatalf("HEAD collection: %d %q", r.code, r.body)
	}
}

// c2Subscriber returns the subscriber id of the only open stream.
func c2Subscriber(t *testing.T, e *env) string {
	t.Helper()
	subs := e.hub.LocalSubscriptions()
	if len(subs) == 0 {
		t.Fatal("no subscriptions")
	}
	return subs[0].Subscriber
}

func TestSubscriptionsAPIModernFormat(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true, ModernSubscriptionFormat: true, HubURL: "https://hub.example/.well-known/mercure"})
	e.subscribe(t, tokenFor(t, nil, all), "t")
	l, r := getListing(t, e, subsBase)
	if l.Context != "" || l.Type != "subscriptions" || l.LastEventID != "" {
		t.Fatalf("modern envelope %+v (%s)", l, r.body)
	}
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	last := e.hub.hist.last()
	wantLink := `<https://hub.example/.well-known/mercure>; rel="mercure"; last-event-id="` + last + `"; type="mercure"; content-type="application/json"`
	if r.header.Get("Link") != wantLink {
		t.Fatalf("link %q, want %q", r.header.Get("Link"), wantLink)
	}
	if len(l.Subscriptions) != 1 || l.Subscriptions[0].Type != "subscription" {
		t.Fatalf("subscriptions %+v", l.Subscriptions)
	}
	one := e.do(t, "GET", e.srv.URL+l.Subscriptions[0].ID, bearer(tokenFor(t, nil, all)), "")
	if one.code != 200 || strings.Contains(one.body, "@context") || strings.Contains(one.body, "lastEventID") {
		t.Fatalf("single: %d %s", one.code, one.body)
	}
}

func TestSubscriptionsAPIRemoteMerging(t *testing.T) {
	ft := newFakeTransport("node-a")
	e := newEnv(t, Config{Subscriptions: true, Transport: ft})
	local := e.subscribe(t, tokenFor(t, nil, all), "t")
	_ = local
	localSub := e.hub.LocalSubscriptions()[0]
	remote := func(topic, subscriber string) Subscription {
		return Subscription{
			ID: subsBase + "/" + escapeSegment(topic) + "/" + escapeSegment(subscriber), Topic: topic,
			Subscriber: subscriber, Active: true, Type: "ignored",
		}
	}
	ft.remote = []Subscription{remote("t", "urn:uuid:remote-1"), remote("other", "urn:uuid:remote-2"), localSub}

	l, r := getListing(t, e, subsBase)
	if len(l.Subscriptions) != 3 { // local, remote-1, remote-2; the repeated local one is merged
		t.Fatalf("merged %d: %s", len(l.Subscriptions), r.body)
	}
	if r.header.Get("Warning") != "" {
		t.Fatalf("complete answer carries a warning: %q", r.header.Get("Warning"))
	}
	for _, s := range l.Subscriptions {
		if s.Type != "Subscription" {
			t.Fatalf("remote subscription not reformatted: %+v", s)
		}
	}
	// Filters apply to remote subscriptions too.
	if l, _ := getListing(t, e, subsBase+"/t"); len(l.Subscriptions) != 2 {
		t.Fatalf("by topic: %+v", l.Subscriptions)
	}
	one := e.do(t, "GET", e.srv.URL+remote("other", "urn:uuid:remote-2").ID, bearer(tokenFor(t, nil, all)), "")
	if one.code != 200 || !strings.Contains(one.body, "urn:uuid:remote-2") {
		t.Fatalf("remote single: %d %s", one.code, one.body)
	}

	// Partial: some nodes did not answer. What did answer is served, with a warning.
	ft.complete = false
	l, r = getListing(t, e, subsBase)
	if len(l.Subscriptions) != 3 || !strings.Contains(r.header.Get("Warning"), "incomplete") {
		t.Fatalf("partial: %d subscriptions, warning %q", len(l.Subscriptions), r.header.Get("Warning"))
	}
	// Failed: only the local subscriptions, with a warning.
	ft.complete, ft.remote, ft.remoteErr = true, nil, errors.New("gossip down")
	l, r = getListing(t, e, subsBase)
	if len(l.Subscriptions) != 1 || !strings.Contains(r.header.Get("Warning"), "incomplete") {
		t.Fatalf("failed: %d subscriptions, warning %q", len(l.Subscriptions), r.header.Get("Warning"))
	}
	// A missing single subscription on a partial answer is still a 404.
	ft.remoteErr, ft.complete = nil, false
	if r := e.do(t, "GET", e.srv.URL+remote("t", "urn:uuid:gone").ID, bearer(tokenFor(t, nil, all)), ""); r.code != 404 {
		t.Fatalf("unknown: %d", r.code)
	}
}

func TestSubscriptionEventTopicNeedsToken(t *testing.T) {
	// The subscription events of every selector of a subscriber are published, each on its own topic.
	e := newEnv(t, Config{Subscriptions: true})
	monitor := e.subscribe(t, tokenFor(t, nil, all), subsTemplate())
	nextSub(t, monitor, subsTemplate())
	sels := []string{"a", "https://example.com/{id}", "*", "x y"}
	e.subscribe(t, tokenFor(t, nil, all), sels...)
	seen := map[string]bool{}
	for len(seen) < len(sels) {
		se, _ := nextSubAny(t, monitor)
		seen[se.Topic] = true
		if !strings.HasPrefix(se.ID, subsBase+"/"+escapeSegment(se.Topic)+"/") {
			t.Fatalf("id %q for topic %q", se.ID, se.Topic)
		}
	}
	for _, s := range sels {
		if !seen[s] {
			t.Errorf("no event for selector %q (saw %v)", s, fmt.Sprint(seen))
		}
	}
}

func nextSubAny(t *testing.T, c *sseClient) (subEvent, sseEvent) {
	t.Helper()
	ev := c.mustNext()
	var se subEvent
	if err := json.Unmarshal([]byte(ev.Data), &se); err != nil {
		t.Fatalf("event data %q: %v", ev.Data, err)
	}
	return se, ev
}

// TestSubscriptionEventsAfterFirstFlush: the stream's response reaches the client before the hub announces the
// subscription (which waits for the transport).
func TestSubscriptionEventsAfterFirstFlush(t *testing.T) {
	block := make(chan struct{})
	e := newEnv(t, Config{Anonymous: true, Subscriptions: true, Transport: &blockingTransport{block: block}})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, code, msg := e.tryOpenStream(t, http.MethodGet, url.Values{"match": {"t"}}, nil, "")
		if c == nil {
			t.Errorf("stream: %d %q", code, msg)
			return
		}
		c.close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the stream's response waited for the subscription event")
	}
	close(block)
}

// blockingTransport is a single node's transport whose publishes wait until block is closed.
type blockingTransport struct {
	local
	block chan struct{}
}

func (b *blockingTransport) Publish(ctx context.Context, u *Update) error {
	select {
	case <-b.block:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.local.Publish(ctx, u)
}
