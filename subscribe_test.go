package gossiper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
)

func TestSubscribeResponse(t *testing.T) {
	e := newEnv(t, Config{})
	resp, cancel, err := e.tryDial(url.Values{"topic": {"t"}}, bearer(tokenFor(t, nil, all)))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	want := map[string]string{
		"Content-Type":           "text/event-stream",
		"Cache-Control":          "private, no-cache, no-store, must-revalidate, max-age=0",
		"X-Accel-Buffering":      "no",
		"Incremental":            "?1",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s: %q, want %q", k, got, v)
		}
	}
	buf := make([]byte, 2)
	if _, err := resp.Body.Read(buf); err != nil || string(buf) != ":\n" {
		t.Fatalf("stream starts with %q, %v", buf, err)
	}
	if resp.Header.Get("Last-Event-ID") != "" {
		t.Fatal("Last-Event-ID set without a request for one")
	}
}

func TestSubscribeBadRequests(t *testing.T) {
	e := newEnv(t, Config{MaxTopicSelectors: 3, Anonymous: true})
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"no topic", "", 400},
		{"unrelated parameter", "x=y", 400},
		{"empty topic", "topic=", 400},
		{"one empty among others", "topic=a&topic=", 400},
		{"invalid utf8", "topic=%ff", 400},
		{"too long", "topic=" + strings.Repeat("a", MaxTopicLength+1), 400},
		{"max length", "topic=" + strings.Repeat("a", MaxTopicLength), 200},
		{"at the selector limit", "topic=a&topic=b&topic=c", 200},
		{"over the selector limit", "topic=a&topic=b&topic=c&topic=d", 400},
		{"duplicates still count", "topic=a&topic=a&topic=a&topic=a", 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, cancel, err := e.tryDial(mustQuery(tc.query), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestSubscribeAuth(t *testing.T) {
	expired := mercureClaims(nil, all)
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	tests := []struct {
		name      string
		anonymous bool
		hdr       http.Header
		query     string
		want      int
		wantAuth  string
	}{
		{"no token, not anonymous", false, nil, "", 401, "Bearer"},
		{"no token, anonymous", true, nil, "", 200, ""},
		{"good header", false, bearer(tokenFor(t, nil, all)), "", 200, ""},
		{"good query", false, nil, "&authorization=" + tokenFor(t, nil, all), 200, ""},
		{"good cookie", false, http.Header{"Cookie": {"mercureAuthorization=" + tokenFor(t, nil, all)}}, "", 200, ""},
		{"publisher-only token may subscribe to public updates", false, bearer(tokenFor(t, all, nil)), "", 200, ""},
		{"malformed", false, bearer("junk"), "", 400, `Bearer error="invalid_request"`},
		{"malformed, anonymous", true, bearer("junk"), "", 400, `Bearer error="invalid_request"`},
		{"bad signature", false, bearer(signJWT(t, "other-secret-other-secret-other-s", mercureClaims(nil, all))), "", 401, `Bearer error="invalid_token"`},
		{"bad signature, anonymous", true, bearer(signJWT(t, "other-secret-other-secret-other-s", mercureClaims(nil, all))), "", 401, `Bearer error="invalid_token"`},
		{"expired", false, bearer(signJWT(t, testSecret, expired)), "", 401, `Bearer error="invalid_token"`},
		{"no mercure claim", true, bearer(signJWT(t, testSecret, map[string]any{"sub": "x"})), "", 401, `Bearer error="invalid_token"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{Anonymous: tc.anonymous})
			resp, cancel, err := e.tryDial(mustQuery("topic=t"+tc.query), tc.hdr)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
			if got := challenge(resp.Header.Get("WWW-Authenticate")); got != tc.wantAuth {
				t.Fatalf("WWW-Authenticate %q, want %q", got, tc.wantAuth)
			}
		})
	}
	t.Run("query authorization disabled", func(t *testing.T) {
		e := newEnv(t, Config{DisableQueryAuthorization: true})
		resp, cancel, err := e.tryDial(url.Values{"topic": {"t"}, "authorization": {tokenFor(t, nil, all)}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

func mustQuery(q string) url.Values {
	v, err := url.ParseQuery(q)
	if err != nil {
		panic(err)
	}
	return v
}

func TestSubscribeAnonymousSeesPublicOnly(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	c := e.subscribe(t, "", "t")
	pub := tokenFor(t, all, nil)
	e.post(t, pub, form("topic", "t", "data", "secret", "private", "on"))
	e.post(t, pub, form("topic", "t", "data", "open"))
	e.post(t, pub, form("topic", "t", "data", "end"))
	if got := c.drain("end"); fmt.Sprint(got) != "[open]" {
		t.Fatalf("anonymous subscriber received %v", got)
	}
}

func TestSubscribeMatching(t *testing.T) {
	const a, b = "https://example.com/books/1", "https://example.com/authors/9"
	tests := []struct {
		name      string
		selectors []string
		topics    []string
		want      int // times the update is delivered
	}{
		{"exact", []string{a}, []string{a}, 1},
		{"exact miss", []string{a}, []string{b}, 0},
		{"star", []string{"*"}, []string{a}, 1},
		{"star with others", []string{"nope", "*"}, []string{a}, 1},
		{"template", []string{"https://example.com/books/{id}"}, []string{a}, 1},
		{"template miss", []string{"https://example.com/books/{id}"}, []string{b}, 0},
		{"template does not cross slash", []string{"https://example.com/{id}"}, []string{a}, 0},
		{"template with reserved expansion", []string{"https://example.com/{+path}"}, []string{a}, 1},
		{"alternate matches exact", []string{b}, []string{a, b}, 1},
		{"alternate matches template", []string{"https://example.com/authors/{id}"}, []string{a, b}, 1},
		{"canonical matches", []string{a}, []string{a, b}, 1},
		{"none of several", []string{"x", "y"}, []string{a, b}, 0},
		{"second selector matches", []string{"x", a}, []string{a}, 1},
		{"selector is not a prefix", []string{"https://example.com/books"}, []string{a}, 0},
		{"topic is not a pattern", []string{a}, []string{"https://example.com/books/{id}"}, 0},
		{"duplicate selectors", []string{a, a}, []string{a}, 1},
		{"every selector and topic matches", []string{a, b, "*", "https://example.com/{+p}"}, []string{a, b}, 1},
		{"exact subscriber, several alternates match", []string{a, b}, []string{a, b}, 1},
		{"template subscriber, several alternates match", []string{"https://example.com/{k}/{id}"}, []string{a, b}, 1},
	}
	e := newEnv(t, Config{})
	pub, sub := tokenFor(t, all, nil), tokenFor(t, nil, all)
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Every subscriber also follows a sentinel topic: a stream delivers in order, so what precedes the
			// sentinel is all it was sent.
			sentinelTopic := fmt.Sprintf("sentinel-%d", i)
			c := e.subscribe(t, sub, append(append([]string(nil), tc.selectors...), sentinelTopic)...)
			if r := e.post(t, pub, url.Values{"topic": tc.topics, "data": {"payload"}}); r.code != 200 {
				t.Fatalf("publish: %d", r.code)
			}
			e.post(t, pub, url.Values{"topic": {sentinelTopic}, "data": {"end"}})
			got := c.drain("end")
			if len(got) != tc.want {
				t.Fatalf("received %d updates (%v), want %d", len(got), got, tc.want)
			}
		})
	}
}

func TestSubscribePrivate(t *testing.T) {
	const a, b = "https://example.com/a", "https://example.com/b"
	pub := tokenFor(t, all, nil)
	tests := []struct {
		name      string
		selectors []string // the topic selectors of the subscription
		token     []string // the token's subscribe selectors; nil: no subscribe claim
		topics    []string
		want      int
	}{
		{"token matches exact", []string{a}, []string{a}, []string{a}, 1},
		{"token matches star", []string{a}, all, []string{a}, 1},
		{"token matches template", []string{a}, []string{"https://example.com/{x}"}, []string{a}, 1},
		{"token misses", []string{a}, []string{b}, []string{a}, 0},
		{"token empty", []string{a}, []string{}, []string{a}, 0},
		{"token without subscribe claim", []string{a}, nil, []string{a}, 0},
		{"token matches an alternate", []string{a}, []string{b}, []string{a, b}, 1},
		{"selector misses though the token matches", []string{b}, []string{a}, []string{a}, 0},
		{"template subscription, token matches", []string{"https://example.com/{x}"}, []string{a}, []string{a}, 1},
		{"template subscription, token misses", []string{"https://example.com/{x}"}, []string{b}, []string{a}, 0},
		{"star subscription, token misses", []string{"*"}, []string{b}, []string{a}, 0},
		{"star subscription, token star", []string{"*"}, all, []string{a}, 1},
		{"several selectors, token matches", []string{a, b, "x"}, []string{b}, []string{a, b}, 1},
		{"exact subscription, token via alternate only", []string{a, b}, []string{b}, []string{a, b}, 1},
	}
	e := newEnv(t, Config{})
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var tok string
			if tc.token == nil {
				tok = signJWT(t, testSecret, mercureClaims(all, nil)) // publish claim only
			} else {
				tok = tokenFor(t, nil, tc.token)
			}
			sentinel := fmt.Sprintf("sentinel-%d", i)
			c := e.subscribe(t, tok, append(append([]string(nil), tc.selectors...), sentinel)...)
			e.post(t, pub, url.Values{"topic": tc.topics, "data": {"secret"}, "private": {"on"}})
			e.post(t, pub, url.Values{"topic": {sentinel}, "data": {"end"}})
			if got := c.drain("end"); len(got) != tc.want {
				t.Fatalf("received %v, want %d updates", got, tc.want)
			}
		})
	}
}

func TestSubscribeFrames(t *testing.T) {
	e := newEnv(t, Config{})
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	for i, tc := range []struct {
		u    *Update
		want string
	}{
		{&Update{ID: "1", Topics: []string{"t"}, Data: "x"}, "id: 1\ndata: x\n\n"},
		{&Update{ID: "2", Topics: []string{"t"}, Type: "T", Data: "x"}, "event: T\nid: 2\ndata: x\n\n"},
		{&Update{ID: "3", Topics: []string{"t"}, HasRetry: true, Retry: 10}, "retry: 10\nid: 3\ndata: \n\n"},
		{&Update{ID: "4", Topics: []string{"t"}, Data: "a\r\nb\rc\nd"}, "id: 4\ndata: a\ndata: b\ndata: c\ndata: d\n\n"},
		{&Update{ID: "5", Topics: []string{"t"}, Data: "é日\U0001F600"}, "id: 5\ndata: é日\U0001F600\n\n"},
	} {
		if _, err := e.hub.Publish(t.Context(), tc.u); err != nil {
			t.Fatal(err)
		}
		if got := c.mustNext().Raw; got != tc.want {
			t.Fatalf("frame %d = %q, want %q", i, got, tc.want)
		}
	}
}

// publishIDs publishes n updates to topic t through the Go API and returns their ids.
func publishN(t *testing.T, h *Hub, n int, topic string) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		id, err := h.Publish(t.Context(), &Update{Topics: []string{topic}, Data: fmt.Sprintf("d%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	return ids
}

func replayHeaders(t *testing.T, e *env, query url.Values, hdr http.Header) (http.Header, *sseClient) {
	t.Helper()
	c := e.dial(t, query, hdr)
	return c.resp.Header, c
}

func TestReplay(t *testing.T) {
	e := newEnv(t, Config{})
	ids := publishN(t, e.hub, 5, "t") // d0..d4
	sub := tokenFor(t, nil, all)
	q := url.Values{"topic": {"t"}}
	with := func(k, v string) http.Header {
		h := bearer(sub)
		h.Set(k, v)
		return h
	}
	qWith := func(k, v string) url.Values {
		n := url.Values{"topic": {"t"}, "authorization": {sub}}
		n.Set(k, v)
		return n
	}
	tests := []struct {
		name    string
		query   url.Values
		hdr     http.Header
		want    []string
		wantHdr string
	}{
		{"header", q, with("Last-Event-ID", ids[1]), []string{"d2", "d3", "d4"}, ids[1]},
		{"header of the last", q, with("Last-Event-ID", ids[4]), nil, ids[4]},
		{"header of the first", q, with("Last-Event-ID", ids[0]), []string{"d1", "d2", "d3", "d4"}, ids[0]},
		{"query lastEventID", qWith("lastEventID", ids[2]), nil, []string{"d3", "d4"}, ids[2]},
		{"query Last-Event-ID", qWith("Last-Event-ID", ids[2]), nil, []string{"d3", "d4"}, ids[2]},
		{"earliest replays everything", q, with("Last-Event-ID", "earliest"), []string{"d0", "d1", "d2", "d3", "d4"}, "earliest"},
		{"earliest in the query", qWith("lastEventID", "earliest"), nil, []string{"d0", "d1", "d2", "d3", "d4"}, "earliest"},
		{"unknown id replays nothing", q, with("Last-Event-ID", "urn:uuid:unknown"), nil, "earliest"},
		{"no replay without the header", q, bearer(sub), nil, ""},
		{"header beats query", func() url.Values {
			n := qWith("lastEventID", ids[0])
			return n
		}(), http.Header{"Last-Event-ID": {ids[3]}}, []string{"d4"}, ids[3]},
		{"lastEventID beats Last-Event-ID in the query", func() url.Values {
			n := qWith("lastEventID", ids[3])
			n.Set("Last-Event-ID", ids[0])
			return n
		}(), nil, []string{"d4"}, ids[3]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hdr, c := replayHeaders(t, e, tc.query, tc.hdr)
			for _, name := range []string{"Last-Event-ID", "Mercure-Last-Event-ID"} {
				if got := hdr.Get(name); got != tc.wantHdr {
					t.Fatalf("%s: %q, want %q", name, got, tc.wantHdr)
				}
			}
			e.publish(t, "end", "t")
			got := c.drain("end")
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("replayed %v, want %v", got, tc.want)
			}
		})
	}
	s := e.hub.Stats()
	if s.ReplayMisses != 1 {
		t.Fatalf("ReplayMisses %d, want 1", s.ReplayMisses)
	}
	if s.Replayed == 0 || s.Delivered < s.Replayed {
		t.Fatalf("stats %+v", s)
	}
}

func TestReplayFiltersByTopicAndPrivacy(t *testing.T) {
	e := newEnv(t, Config{})
	pub := tokenFor(t, all, nil)
	first := e.publish(t, "start", "a")
	e.post(t, pub, form("topic", "a", "data", "public-a"))
	e.post(t, pub, form("topic", "b", "data", "public-b"))
	e.post(t, pub, form("topic", "a", "data", "private-a", "private", "1"))
	e.post(t, pub, form("topic", "x", "topic", "a", "data", "alt-a"))

	t.Run("public subscriber", func(t *testing.T) {
		c := e.dial(t, url.Values{"topic": {"a"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, nil)}, "Last-Event-ID": {first}})
		e.publish(t, "end", "a")
		if got := c.drain("end"); fmt.Sprint(got) != "[public-a alt-a]" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("authorized subscriber", func(t *testing.T) {
		c := e.dial(t, url.Values{"topic": {"a"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, []string{"a"})}, "Last-Event-ID": {first}})
		e.publish(t, "end", "a")
		if got := c.drain("end"); fmt.Sprint(got) != "[public-a private-a alt-a]" {
			t.Fatalf("got %v", got)
		}
	})
}

func TestReplayHistoryBounds(t *testing.T) {
	e := newEnv(t, Config{HistorySize: 3})
	ids := publishN(t, e.hub, 6, "t")
	sub := tokenFor(t, nil, all)
	// The 3 newest are kept: d3 d4 d5. ids[2] was trimmed, so it is unknown.
	h, c := replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + sub}, "Last-Event-ID": {ids[2]}})
	if h.Get("Last-Event-ID") != "earliest" {
		t.Fatalf("a trimmed id was found: %q", h.Get("Last-Event-ID"))
	}
	_ = c
	h, c = replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + sub}, "Last-Event-ID": {ids[3]}})
	if h.Get("Last-Event-ID") != ids[3] {
		t.Fatalf("a kept id was not found: %q", h.Get("Last-Event-ID"))
	}
	c.expect("d4", "d5")
	_, c = replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + sub}, "Last-Event-ID": {"earliest"}})
	c.expect("d3", "d4", "d5")
}

func TestReplayWithHistoryDisabled(t *testing.T) {
	e := newEnv(t, Config{HistorySize: -1})
	ids := publishN(t, e.hub, 3, "t")
	h, c := replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, all)}, "Last-Event-ID": {ids[0]}})
	if h.Get("Last-Event-ID") != "earliest" {
		t.Fatalf("Last-Event-ID %q", h.Get("Last-Event-ID"))
	}
	e.publish(t, "live", "t")
	c.expect("live")
}

func TestReplayHistoryAge(t *testing.T) {
	e := newEnv(t, Config{HistoryAge: time.Hour})
	clock := base
	e.hub.hist.now = func() time.Time { return clock }
	ids := publishN(t, e.hub, 2, "t")
	clock = clock.Add(2 * time.Hour)
	e.hub.hist.expire()
	h, _ := replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, all)}, "Last-Event-ID": {ids[0]}})
	if h.Get("Last-Event-ID") != "earliest" {
		t.Fatalf("an aged-out id was found: %q", h.Get("Last-Event-ID"))
	}
}

// TestReplayLateArrival: an update that reaches the node after the cursor was published, though stamped just before
// it, is replayed to a subscriber resuming from the cursor; one stamped long before is not.
func TestReplayLateArrival(t *testing.T) {
	e := newEnv(t, Config{ReplayWindow: 2 * time.Second})
	cursor := e.publish(t, "cursor", "t")
	ups, _ := e.hub.hist.since(earliest)
	stamp := hlc.Timestamp(ups[0].Stamp)
	remote := func(id string, before time.Duration) {
		e.hub.Apply(&Update{ID: id, Topics: []string{"t"}, Data: id, Origin: "remote", Stamp: uint64(stamp - hlc.Timestamp(before.Microseconds()<<hlc.CounterBits))})
	}
	remote("late-in-window", time.Second)
	remote("late-out-of-window", 3*time.Second)
	e.publish(t, "after", "t")
	_, c := replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, all)}, "Last-Event-ID": {cursor}})
	c.expect("late-in-window", "after")
	e.publish(t, "end", "t")
	if got := c.drain("end"); len(got) != 0 {
		t.Fatalf("unexpected replay %v", got)
	}
}

// TestReplayWhilePublishing: a subscriber that resumes while updates are being published gets every update after its
// cursor exactly once, in order, whichever of the replay and the live queue an update arrives by.
func TestReplayWhilePublishing(t *testing.T) {
	e := newEnv(t, Config{DispatchBuffer: 10000})
	const total = 600
	first, err := e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: "0"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= total; i++ {
			if _, err := e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: fmt.Sprint(i)}); err != nil {
				t.Error(err)
				return
			}
			if i%50 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	_, c := replayHeaders(t, e, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, all)}, "Last-Event-ID": {first}})
	<-done
	for i := 1; i <= total; i++ {
		if got := c.mustNext().Data; got != fmt.Sprint(i) {
			t.Fatalf("event %d: got %q", i, got)
		}
	}
	e.publish(t, "end", "t")
	c.expect("end")
}

func TestSubscribeHead(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true})
	req, _ := http.NewRequest("HEAD", e.hubURL()+"?topic=t", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, nil, all))
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	waitSubscribers(t, e.hub, 0)
	if n := len(e.hub.hist.entries); n != 0 {
		t.Fatalf("HEAD announced a subscription: %d updates", n)
	}
	// With a replay request the headers still report the cursor.
	id := e.publish(t, "x", "t")
	req, _ = http.NewRequest("HEAD", e.hubURL()+"?topic=t&lastEventID="+id, nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, nil, all))
	resp2, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.Header.Get("Last-Event-ID") != id {
		t.Fatalf("Last-Event-ID %q", resp2.Header.Get("Last-Event-ID"))
	}
	// HEAD without auth is still refused.
	req, _ = http.NewRequest("HEAD", e.hubURL()+"?topic=t", nil)
	resp3, _ := e.client.Do(req)
	resp3.Body.Close()
	if resp3.StatusCode != 401 {
		t.Fatalf("HEAD without a token: %d", resp3.StatusCode)
	}
}

func TestSubscribeMaxSubscribers(t *testing.T) {
	e := newEnv(t, Config{MaxSubscribers: 2})
	sub := tokenFor(t, nil, all)
	c1 := e.subscribe(t, sub, "t")
	e.subscribe(t, sub, "t")
	resp, cancel, err := e.tryDial(url.Values{"topic": {"t"}}, bearer(sub))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("status %d retry-after %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	c1.close()
	waitSubscribers(t, e.hub, 1)
	e.subscribe(t, sub, "t") // room again
}

func TestSubscribeHeartbeat(t *testing.T) {
	e := newEnv(t, Config{Heartbeat: 10 * time.Millisecond})
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	eventually(t, "heartbeats", func() bool { return c.comments.Load() >= 4 })
	// Heartbeats are comments, not events.
	if _, ok := c.next(0); ok {
		t.Fatal("heartbeat delivered as an event")
	}
	e.publish(t, "x", "t")
	c.expect("x")
}

func TestSubscribeNoHeartbeat(t *testing.T) {
	e := newEnv(t, Config{Heartbeat: -1})
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	e.publish(t, "x", "t")
	c.expect("x")
	if n := c.comments.Load(); n != 1 {
		t.Fatalf("%d comments with heartbeat disabled", n)
	}
}

func TestSubscribeCloseOnTokenExpiry(t *testing.T) {
	e := newEnv(t, Config{CloseOnTokenExpiry: true})
	claims := mercureClaims(nil, all)
	claims["exp"] = time.Now().Add(2 * time.Second).Unix()
	c := e.subscribe(t, signJWT(t, testSecret, claims), "t")
	e.publish(t, "before", "t")
	c.expect("before")
	if !c.waitClosed(10 * time.Second) {
		t.Fatal("stream outlived its token")
	}
	waitSubscribers(t, e.hub, 0)
	// A token without an expiry never ends the stream.
	forever := signJWT(t, testSecret, jwtNoExp())
	c2 := e.subscribe(t, forever, "t")
	e.publish(t, "x", "t")
	c2.expect("x")
	// Neither does an anonymous one.
	e2 := newEnv(t, Config{CloseOnTokenExpiry: true, Anonymous: true})
	c3 := e2.subscribe(t, "", "t")
	e2.publish(t, "y", "t")
	c3.expect("y")
}

func TestSubscribeExpiryIgnoredWithoutOption(t *testing.T) {
	e := newEnv(t, Config{})
	claims := mercureClaims(nil, all)
	claims["exp"] = time.Now().Add(1500 * time.Millisecond).Unix()
	c := e.subscribe(t, signJWT(t, testSecret, claims), "t")
	time.Sleep(2500 * time.Millisecond)
	e.publish(t, "still here", "t")
	c.expect("still here")
}

func TestSubscribeClientDisconnect(t *testing.T) {
	e := newEnv(t, Config{})
	c := e.subscribe(t, tokenFor(t, nil, all), "t", "u{x}", "*")
	waitSubscribers(t, e.hub, 1)
	c.close()
	waitSubscribers(t, e.hub, 0)
	e.hub.mu.RLock()
	defer e.hub.mu.RUnlock()
	if len(e.hub.subs)+len(e.hub.exact)+len(e.hub.patterned) != 0 {
		t.Fatalf("the hub still tracks the subscriber: %d %d %d", len(e.hub.subs), len(e.hub.exact), len(e.hub.patterned))
	}
}

func TestEscapeSegment(t *testing.T) {
	for in, want := range map[string]string{
		"":                          "",
		"abcXYZ019-._~":             "abcXYZ019-._~",
		"https://example.com/a?b=c": "https%3A%2F%2Fexample.com%2Fa%3Fb%3Dc",
		"urn:uuid:1234":             "urn%3Auuid%3A1234",
		"*":                         "%2A",
		"a b":                       "a%20b",
		"{id}":                      "%7Bid%7D",
		"é":                         "%C3%A9",
		"%":                         "%25",
		"/.well-known/mercure/x":    "%2F.well-known%2Fmercure%2Fx",
		"a+b&c=d":                   "a%2Bb%26c%3Dd",
		"\x00\xff":                  "%00%FF",
	} {
		if got := escapeSegment(in); got != want {
			t.Errorf("escapeSegment(%q) = %q, want %q", in, got, want)
		}
		if got, err := url.PathUnescape(escapeSegment(in)); err != nil || got != in {
			t.Errorf("escapeSegment(%q) does not round trip: %q %v", in, got, err)
		}
	}
}

// TestPatternSelectorLimit: matchers that match by pattern are bounded separately, and counted before any is
// compiled.
func TestPatternSelectorLimit(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true, MaxPatternSelectors: 2})
	q := url.Values{"match_urlpattern": {"https://e.example/:a", "https://e.example/:b", "https://e.example/:c"}}
	if r := e.do(t, http.MethodGet, e.hubURL()+"?"+q.Encode(), nil, ""); r.code != 400 {
		t.Fatalf("three patterns: %d", r.code)
	}
	q = url.Values{"topic": {"a{x}", "b{x}", "c{x}"}}
	if r := e.do(t, http.MethodGet, e.hubURL()+"?"+q.Encode(), nil, ""); r.code != 400 {
		t.Fatalf("three templates: %d", r.code)
	}
	// Exact matchers and "*" are not patterns.
	q = url.Values{"match": {"a", "b", "c", "d"}, "match_urlpattern": {"*", "https://e.example/:a"}, "topic": {"*", "x{y}"}}
	c, code, msg := e.tryOpenStream(t, http.MethodGet, q, nil, "")
	if c == nil {
		t.Fatalf("within the limit: %d %q", code, msg)
	}
	c.close()
}

// TestCursorHeaderMovesBackForLateArrivals: Mercure-Last-Event-ID names the event before the first one sent, so a
// late arrival sent ahead of the cursor's successors moves it back; otherwise it is the cursor itself.
func TestCursorHeaderMovesBackForLateArrivals(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true, ReplayWindow: time.Hour, NodeID: "n", HistoryAge: -1}) // stamps of a fixed past day
	base := at(0)
	stamp := func(d time.Duration) uint64 { return uint64(at(d)) }
	// Restored, so they count as received when published: none of them is a late arrival.
	e.hub.Restore(&Update{ID: "first", Topics: []string{"t"}, Stamp: uint64(base), Origin: "o"})
	e.hub.Restore(&Update{ID: "cursor", Topics: []string{"t"}, Stamp: stamp(2 * time.Second), Origin: "o"})
	e.hub.Restore(&Update{ID: "other", Topics: []string{"elsewhere"}, Stamp: stamp(3 * time.Second), Origin: "o"})
	e.hub.Restore(&Update{ID: "next", Topics: []string{"t"}, Stamp: stamp(4 * time.Second), Origin: "o"})
	open := func() string {
		r := e.do(t, http.MethodHead, e.hubURL()+"?match=t&last_event_id=cursor", nil, "")
		return r.header.Get("Mercure-Last-Event-ID")
	}
	if got := open(); got != "cursor" {
		t.Fatalf("no late arrival: %q, want the cursor (not the unrelated update before the first sent)", got)
	}
	e.hub.Apply(&Update{ID: "late", Topics: []string{"t"}, Stamp: stamp(time.Second), Origin: "o"})
	if got := open(); got != "first" {
		t.Fatalf("late arrival: %q, want the update before it", got)
	}
}

// The most specific Accept range matching text/event-stream decides; no Accept header at all states no preference.
func TestAcceptsEventStream(t *testing.T) {
	for _, tc := range []struct {
		accept []string
		want   bool
	}{
		{nil, true},
		{[]string{"text/event-stream"}, true},
		{[]string{"*/*"}, true},
		{[]string{"text/*"}, true},
		{[]string{"application/json, text/event-stream;q=0.5"}, true},
		{[]string{"application/json"}, false},
		{[]string{"text/event-stream;q=0"}, false},
		{[]string{"text/event-stream;q=0, */*"}, false}, // the exact range refuses it, whatever */* says
		{[]string{"*/*;q=0"}, false},
		{[]string{"text/html", "text/event-stream"}, true}, // several header lines
	} {
		if got := acceptsEventStream(tc.accept); got != tc.want {
			t.Errorf("Accept %q: %v, want %v", tc.accept, got, tc.want)
		}
	}
}

// A subscription that excludes text/event-stream is refused with 406; a QUERY without a Content-Type with 400, one of
// another media type with 415, both saying what to send (Accept-Query).
func TestSubscribeNegotiation(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	q := url.Values{"topic": {"https://n.test/a"}}.Encode()
	for _, accept := range []string{"application/json", "text/event-stream;q=0"} {
		if r := e.do(t, http.MethodGet, e.hubURL()+"?"+q, http.Header{"Accept": {accept}}, ""); r.code != http.StatusNotAcceptable {
			t.Errorf("Accept %q: %d, want 406", accept, r.code)
		}
	}
	for _, tc := range []struct {
		ct   string
		want int
	}{{"", http.StatusBadRequest}, {"text/plain", http.StatusUnsupportedMediaType}} {
		hdr := http.Header{}
		if tc.ct != "" {
			hdr.Set("Content-Type", tc.ct)
		}
		r := e.do(t, methodQuery, e.hubURL(), hdr, q)
		if r.code != tc.want || r.header.Get("Accept-Query") != formMediaType {
			t.Errorf("QUERY with Content-Type %q: %d, Accept-Query %q; want %d", tc.ct, r.code, r.header.Get("Accept-Query"), tc.want)
		}
	}
}

// slowWriter is a response writer whose first write blocks until after a time, and that records when each write
// happened.
type slowWriter struct {
	hdr   http.Header
	until time.Time
	mu    sync.Mutex
	first bool
	at    []time.Time
	data  []string
}

func (w *slowWriter) Header() http.Header { return w.hdr }
func (w *slowWriter) WriteHeader(int)     {}
func (w *slowWriter) Flush()              {}
func (w *slowWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	first := !w.first
	w.first = true
	w.mu.Unlock()
	if first {
		time.Sleep(time.Until(w.until))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.at, w.data = append(w.at, time.Now()), append(w.data, string(b))
	return len(b), nil
}

// A stream ends when its token expires, the replay included: a client slow to take the first bytes is not sent the
// private history afterwards.
func TestReplayStopsAtTokenExpiry(t *testing.T) {
	h := newHub(t, Config{CloseOnTokenExpiry: true})
	for i := range 5 {
		if _, err := h.Publish(context.Background(), &Update{Topics: []string{"https://x.test/p"}, Data: fmt.Sprint("secret ", i), Private: true}); err != nil {
			t.Fatal(err)
		}
	}
	exp := time.Unix(time.Now().Unix()+2, 0) // JWT expiry has whole seconds
	claims := mercureClaims(nil, []string{"https://x.test/p"})
	claims["exp"] = exp.Unix()
	tok := signJWT(t, testSecret, claims)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, hubPath+"?topic="+url.QueryEscape("https://x.test/p"), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Last-Event-ID", earliest)
	w := &slowWriter{hdr: http.Header{}, until: exp.Add(300 * time.Millisecond)}
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("the stream did not end at the token's expiry")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, d := range w.data {
		if strings.Contains(d, "secret") && w.at[i].After(exp) {
			t.Errorf("a private update was written %v after the token expired: %q", w.at[i].Sub(exp), d)
		}
	}
}
