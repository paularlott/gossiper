package gossiper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper/auth"
)

func TestHubPublishFillsUpdate(t *testing.T) {
	h := newHub(t, Config{NodeID: "n1"})
	u := &Update{Topics: []string{"t"}, Data: "x", Private: true, Type: "ty", Retry: 5, HasRetry: true}
	id, err := h.Publish(t.Context(), u)
	if err != nil {
		t.Fatal(err)
	}
	if !uuidV7.MatchString(id) {
		t.Fatalf("id %q", id)
	}
	if u.ID != "" || u.Stamp != 0 || u.Origin != "" || u.encoded != nil {
		t.Fatalf("the caller's update was changed: %+v", u)
	}
	got, _ := h.hist.since(earliest)
	if len(got) != 1 || got[0] == u {
		t.Fatal("the history must hold a copy of the update")
	}
	c := got[0]
	if c.ID != id || c.Origin != "n1" || c.Stamp == 0 || c.Data != "x" || !c.Private {
		t.Fatalf("published copy %+v", c)
	}
	if !strings.Contains(string(c.encoded), "event: ty\nretry: 5\nid: "+id+"\n") {
		t.Fatalf("frame %q", c.encoded)
	}
	u.Topics[0] = "changed" // the caller may reuse its update: the hub's copy does not move
	if got, _ := h.hist.since(earliest); got[0].Topics[0] != "t" {
		t.Fatal("the hub's copy shares the caller's topics")
	}
	s := h.Stats()
	if s.Published != 1 || s.Applied != 1 || s.HistoryLen != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestHubPublishKeepsPublisherID(t *testing.T) {
	h := newHub(t, Config{})
	for i := 0; i < 2; i++ { // the same id twice is two publications
		id, err := h.Publish(t.Context(), &Update{Topics: []string{"t"}, ID: "mine"})
		if err != nil || id != "mine" {
			t.Fatalf("%q %v", id, err)
		}
	}
	if s := h.Stats(); s.Applied != 2 || s.Duplicates != 0 || s.HistoryLen != 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestHubPublishValidates(t *testing.T) {
	h := newHub(t, Config{})
	for _, tc := range []struct {
		name string
		u    *Update
		want error
	}{
		{"no topic", &Update{}, ErrNoTopic},
		{"bad topic", &Update{Topics: []string{"*"}}, ErrInvalidTopic},
		{"reserved topic", &Update{Topics: []string{"/.well-known/mercure/x"}}, ErrReservedTopic},
		{"bad id", &Update{Topics: []string{"t"}, ID: "#x"}, ErrInvalidID},
		{"bad type", &Update{Topics: []string{"t"}, Type: "a\nb"}, ErrInvalidType},
	} {
		if _, err := h.Publish(t.Context(), tc.u); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if h.Stats().Published != 0 {
		t.Fatal("a refused update was counted")
	}
}

func TestHubPublishDeliversWithoutAuthorization(t *testing.T) {
	e := newEnv(t, Config{})
	c := e.subscribe(t, tokenFor(t, nil, []string{"t"}), "t")
	if _, err := e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: "private", Private: true}); err != nil {
		t.Fatal(err)
	}
	c.expect("private")
}

func TestHubPublishTransportError(t *testing.T) {
	ft := newFakeTransport("a")
	ft.publishErr = errors.New("transport down")
	e := newEnv(t, Config{Transport: ft})
	if _, err := e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}}); err == nil || err.Error() != "transport down" {
		t.Fatalf("err %v", err)
	}
	if r := e.post(t, tokenFor(t, all, nil), form("topic", "t")); r.code != 503 {
		t.Fatalf("HTTP publish: %d", r.code)
	}
	if e.hub.Stats().Published != 0 {
		t.Fatal("a failed publish was counted")
	}
}

func TestHubTransportContract(t *testing.T) {
	ft := newFakeTransport("node-a")
	ft.deliverLocal = false
	h := newHub(t, Config{Transport: ft})
	id, _ := h.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: "x"})
	if len(ft.published) != 1 {
		t.Fatalf("transport saw %d updates", len(ft.published))
	}
	u := ft.published[0]
	if u.ID != id || u.Origin != "node-a" || u.Stamp == 0 {
		t.Fatalf("transport got an unfinished update: %+v", u)
	}
	// The transport delivers it: only then is it applied.
	if h.Stats().Applied != 0 {
		t.Fatal("applied without the transport")
	}
	h.Apply(u)
	if h.Stats().Applied != 1 {
		t.Fatal("not applied")
	}
	if ft.isClosed() {
		t.Fatal("transport closed early")
	}
	h.Close(t.Context())
	if !ft.isClosed() {
		t.Fatal("transport not closed with the hub")
	}
}

func TestHubCloseReportsTransportError(t *testing.T) {
	ft := newFakeTransport("a")
	ft.closeErr = errors.New("close failed")
	h, err := New(Config{Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(t.Context()); err == nil || err.Error() != "close failed" {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(t.Context()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestApplyRemote(t *testing.T) {
	ft := newFakeTransport("local")
	ft.deliverLocal = false
	e := newEnv(t, Config{Transport: ft})
	c := e.subscribe(t, tokenFor(t, nil, []string{"t"}), "t")
	clock := hlc.NewClock()
	remote := func(id, origin string, mod func(*Update)) *Update {
		u := &Update{ID: id, Origin: origin, Stamp: uint64(clock.Now()), Topics: []string{"t"}, Data: id}
		if mod != nil {
			mod(u)
		}
		return u
	}
	a := remote("a", "node-b", nil)
	e.hub.Apply(a)
	c.expect("a")
	if string(a.encoded) != "id: a\ndata: a\n\n" {
		t.Fatalf("encoded %q", a.encoded)
	}
	// Delivered again (at-least-once transport): ignored.
	e.hub.Apply(remote("a", "node-b", func(u *Update) { u.Stamp = a.Stamp }))
	if s := e.hub.Stats(); s.Applied != 1 || s.Duplicates != 1 {
		t.Fatalf("stats %+v", s)
	}
	// Same stamp, other origin: a different publication.
	e.hub.Apply(remote("b", "node-c", func(u *Update) { u.Stamp = a.Stamp }))
	c.expect("b")
	// A private remote update reaches only authorized subscribers.
	e.hub.Apply(remote("p", "node-b", func(u *Update) { u.Private = true; u.Data = "priv" }))
	c.expect("priv")
	unauth := e.subscribe(t, tokenFor(t, nil, nil), "t")
	e.hub.Apply(remote("q", "node-b", func(u *Update) { u.Private = true; u.Data = "priv2" }))
	e.hub.Apply(remote("end", "node-b", nil))
	if got := unauth.drain("end"); len(got) != 0 {
		t.Fatalf("unauthorized stream got %v", got)
	}
	// Not published through this node: the Published counter stays.
	if e.hub.Stats().Published != 0 {
		t.Fatal("a remote update counted as published here")
	}
	// Garbage is ignored.
	before := e.hub.Stats()
	e.hub.Apply(nil)
	e.hub.Apply(&Update{ID: "x", Origin: "o", Stamp: 1})
	e.hub.Apply(&Update{Topics: []string{"t"}, Origin: "o", Stamp: 1})
	if e.hub.Stats() != before {
		t.Fatalf("invalid updates changed the stats: %+v", e.hub.Stats())
	}
}

func TestApplyOutOfOrder(t *testing.T) {
	ft := newFakeTransport("local")
	ft.deliverLocal = false
	e := newEnv(t, Config{Transport: ft})
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	base := hlc.FromTime(time.Now())
	mk := func(id string, off int) *Update {
		return &Update{ID: id, Origin: "r", Stamp: uint64(base) + uint64(off)<<hlc.CounterBits, Topics: []string{"t"}, Data: id}
	}
	// Arrival order is delivery order; the history keeps stamp order.
	e.hub.Apply(mk("c", 3))
	e.hub.Apply(mk("a", 1))
	e.hub.Apply(mk("b", 2))
	c.expect("c", "a", "b")
	got, _ := e.hub.hist.since(earliest)
	sameIDs(t, got, "a", "b", "c")
}

func TestApplyFarFutureStampRefused(t *testing.T) {
	log := &recLogger{}
	ft := newFakeTransport("local")
	ft.deliverLocal = false
	h := newHub(t, Config{Transport: ft, Logger: log})
	far := hlc.FromTime(time.Now().Add(24 * time.Hour))
	h.Apply(&Update{ID: "x", Origin: "r", Stamp: uint64(far), Topics: []string{"t"}})
	if !log.has("far ahead") {
		t.Fatalf("no clock warning: %v", log)
	}
	if s := h.Stats(); s.Applied != 0 || s.Refused != 1 || s.HistoryLen != 0 {
		t.Fatalf("a far-future update was kept: %+v", s)
	}
	// The clock was not dragged a day ahead.
	if ts := h.clock.Now(); ts >= far {
		t.Fatal("a far-future stamp moved the clock")
	}
	// Our own origin is never checked.
	log2 := &recLogger{}
	h2 := newHub(t, Config{Transport: newFakeTransport("local"), Logger: log2})
	h2.Apply(&Update{ID: "y", Origin: h2.NodeID(), Stamp: uint64(far), Topics: []string{"t"}})
	if log2.has("far ahead") {
		t.Fatal("warned for the node's own update")
	}
}

func TestApplyDoesNotReencode(t *testing.T) {
	h := newHub(t, Config{})
	u := &Update{ID: "x", Origin: "r", Stamp: 7, Topics: []string{"t"}, Data: "d", encoded: []byte("id: x\ndata: pre\n\n")}
	h.Apply(u)
	if string(u.encoded) != "id: x\ndata: pre\n\n" {
		t.Fatalf("encoded changed: %q", u.encoded)
	}
}

func TestAnnounceFailureIsLogged(t *testing.T) {
	log := &recLogger{}
	ft := newFakeTransport("a")
	e := newEnv(t, Config{Subscriptions: true, Transport: ft, Logger: log})
	ft.publishErr = errors.New("nope")
	e.subscribe(t, tokenFor(t, nil, all), "t")
	// The subscription is announced once the stream's response has gone out: after subscribe returns, maybe.
	eventually(t, "the failed announcement logged", func() bool { return log.has("subscription event not published") })
}

func TestStatsCounters(t *testing.T) {
	e := newEnv(t, Config{})
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	e.publish(t, "1", "t")
	e.publish(t, "2", "other")
	c.expect("1")
	first, _ := e.hub.hist.since(earliest)
	c2 := e.dial(t, url.Values{"topic": {"t"}}, http.Header{"Authorization": {"Bearer " + tokenFor(t, nil, all)}, "Last-Event-ID": {first[0].ID}})
	e.publish(t, "end", "t")
	c2.expect("end")
	s := e.hub.Stats()
	if s.Subscribers != 2 || s.Published != 3 || s.Applied != 3 || s.HistoryLen != 3 {
		t.Fatalf("stats %+v", s)
	}
	// c: "1", "end"; c2: "end" (the replay after the first update holds only the other topic's update: none match).
	eventually(t, "deliveries", func() bool { return e.hub.Stats().Delivered == 3 })
	if s.Dropped != 0 || s.Duplicates != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestLocalSubscriptions(t *testing.T) {
	e := newEnv(t, Config{})
	if n := len(e.hub.LocalSubscriptions()); n != 0 {
		t.Fatalf("%d subscriptions on an idle hub", n)
	}
	e.subscribe(t, tokenFor(t, nil, all), "a", "b", "a")
	subs := e.hub.LocalSubscriptions()
	if len(subs) != 2 {
		t.Fatalf("%d subscriptions: %+v", len(subs), subs)
	}
	topics := []string{subs[0].Topic, subs[1].Topic}
	slices.Sort(topics)
	if fmt.Sprint(topics) != "[a b]" || subs[0].Subscriber != subs[1].Subscriber || !subs[0].Active {
		t.Fatalf("subscriptions %+v", subs)
	}
}

// TestSlowSubscriberDropped: a subscriber whose queue is full is disconnected once, and the publisher is never
// blocked.
func TestSlowSubscriberDropped(t *testing.T) {
	h := newHub(t, Config{})
	slow := &subscriber{id: "slow", matchers: []matcher{{kindSelector, "t"}}, ch: make(chan *Update, 2), kicked: make(chan struct{})}
	fast := &subscriber{id: "fast", matchers: []matcher{{kindSelector, "t"}}, ch: make(chan *Update, 100), kicked: make(chan struct{})}
	tmpl := &subscriber{id: "tmpl", matchers: []matcher{{kindSelector, "t{x}"}}, ch: make(chan *Update, 1), kicked: make(chan struct{})}
	for _, s := range []*subscriber{slow, fast, tmpl} {
		if !h.add(s) {
			t.Fatal("add refused")
		}
		defer h.remove(s)
	}
	for i := 0; i < 5; i++ {
		if _, err := h.Publish(t.Context(), &Update{Topics: []string{"t", "tx"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*subscriber{slow, tmpl} {
		select {
		case <-s.kicked:
		default:
			t.Fatalf("%s not kicked", s.id)
		}
	}
	select {
	case <-fast.kicked:
		t.Fatal("fast subscriber kicked")
	default:
	}
	if d := h.Stats().Dropped; d != 2 { // each kicked once, however many updates it missed
		t.Fatalf("Dropped %d, want 2", d)
	}
	if len(fast.ch) != 5 {
		t.Fatalf("fast queue %d", len(fast.ch))
	}
}

func TestSubscriberKickOnce(t *testing.T) {
	s := &subscriber{kicked: make(chan struct{})}
	if !s.kick() || s.kick() {
		t.Fatal("kick must report true only the first time")
	}
}

// TestHubAddRefusedWhenFull and the removal of unknown subscribers.
func TestHubAddRemove(t *testing.T) {
	h := newHub(t, Config{MaxSubscribers: 1})
	a := &subscriber{matchers: []matcher{{kindSelector, "x"}}, ch: make(chan *Update, 1), kicked: make(chan struct{})}
	b := &subscriber{matchers: []matcher{{kindSelector, "x"}}, ch: make(chan *Update, 1), kicked: make(chan struct{})}
	if !h.add(a) || h.add(b) {
		t.Fatal("limit not enforced")
	}
	h.remove(b) // never added: harmless
	h.remove(a)
	h.remove(a) // twice: harmless
	if !h.add(b) {
		t.Fatal("no room after removal")
	}
	h.remove(b)
	if h.Stats().Subscribers != 0 {
		t.Fatalf("Subscribers %d", h.Stats().Subscribers)
	}
}

func TestHubCloseEndsStreams(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true})
	const n = 40
	clients := make([]*sseClient, n)
	for i := range clients {
		clients[i] = e.subscribe(t, tokenFor(t, nil, all), "t", fmt.Sprintf("u%d", i))
	}
	waitSubscribers(t, e.hub, n)
	start := time.Now()
	if err := e.hub.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close took %v with %d open streams", d, n)
	}
	for i, c := range clients {
		if !c.waitClosed(5 * time.Second) {
			t.Fatalf("stream %d still open", i)
		}
	}
	if e.hub.Stats().Subscribers != 0 {
		t.Fatalf("Subscribers %d after Close", e.hub.Stats().Subscribers)
	}
	if _, err := e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Publish after Close: %v", err)
	}
	// New streams are refused.
	resp, cancel, err := e.tryDial(url.Values{"topic": {"t"}}, bearer(tokenFor(t, nil, all)))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("subscribe after Close: %d", resp.StatusCode)
	}
	// And so are publishes over HTTP.
	if r := e.post(t, tokenFor(t, all, nil), form("topic", "t")); r.code != 503 {
		t.Fatalf("HTTP publish after Close: %d (%s)", r.code, r.body)
	}
	// Closing twice is harmless.
	if err := e.hub.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestHubCloseWithNoStreamsIsImmediate(t *testing.T) {
	h, _ := New(Config{})
	start := time.Now()
	if err := h.Close(t.Context()); err != nil || time.Since(start) > time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

// stalledClient opens a stream that never reads: once the kernel's buffers fill, the hub's writes to it block.
func stalledClient(t *testing.T, e *env, tok string, topics ...string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", e.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(2048)
	}
	q := url.Values{"topic": topics}.Encode()
	fmt.Fprintf(conn, "GET %s?%s HTTP/1.1\r\nHost: hub\r\nAuthorization: Bearer %s\r\n\r\n", hubPath, q, tok)
	return conn
}

// maxQueue is the length of the longest dispatch queue of the hub's subscribers.
func maxQueue(h *Hub) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for s := range h.subs {
		n = max(n, len(s.ch))
	}
	return n
}

// blockWrites publishes large updates until a stalled stream's writes block: its queue then holds updates the
// stream did not take, and does not shrink while we watch.
func blockWrites(t *testing.T, h *Hub) {
	t.Helper()
	data := strings.Repeat("x", 256<<10)
	deadline := time.Now().Add(wait)
	for {
		if _, err := h.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: data}); err != nil {
			t.Fatal(err)
		}
		if h.Stats().Dropped > 0 {
			return
		}
		if q := maxQueue(h); q >= 3 {
			time.Sleep(50 * time.Millisecond) // a stream that is only slow to be scheduled drains meanwhile
			if maxQueue(h) >= q {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the stalled stream never blocked")
		}
	}
}

func TestStalledClientIsDisconnected(t *testing.T) {
	e := newEnv(t, Config{WriteTimeout: 200 * time.Millisecond, DispatchBuffer: 4, HistorySize: -1})
	stalledClient(t, e, tokenFor(t, nil, all), "t")
	waitSubscribers(t, e.hub, 1)
	start := time.Now()
	blockWrites(t, e.hub)
	// Keep publishing until the hub lets go of the stream: its queue overflows (Dropped) and its write times out.
	data := strings.Repeat("y", 256<<10)
	for e.hub.stats.Subscribers.Load() > 0 {
		if time.Since(start) > wait {
			t.Fatal("the stalled stream was never closed")
		}
		e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: data})
		time.Sleep(time.Millisecond)
	}
	if e.hub.Stats().Dropped == 0 {
		t.Fatal("the overflowing queue was not counted as a drop")
	}
	// The hub keeps working for everyone else.
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	e.publish(t, "after", "t")
	c.expect("after")
}

func TestStalledClientWriteTimeoutWithoutOverflow(t *testing.T) {
	// A large queue: the stream is lost to the write deadline alone.
	e := newEnv(t, Config{WriteTimeout: 150 * time.Millisecond, DispatchBuffer: 100000, HistorySize: -1})
	stalledClient(t, e, tokenFor(t, nil, all), "t")
	waitSubscribers(t, e.hub, 1)
	blockWrites(t, e.hub)
	waitSubscribers(t, e.hub, 0)
	if e.hub.Stats().Dropped != 0 {
		t.Fatal("dropped though the queue never filled")
	}
}

// TestCloseEndsStalledStreams: a stream blocked writing to a client that never reads ends at once when the hub
// closes, not at its write timeout.
func TestCloseEndsStalledStreams(t *testing.T) {
	e := newEnv(t, Config{WriteTimeout: time.Minute, DispatchBuffer: 1000, HistorySize: -1})
	conn := stalledClient(t, e, tokenFor(t, nil, all), "t")
	defer conn.Close()
	waitSubscribers(t, e.hub, 1)
	blockWrites(t, e.hub)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := e.hub.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close waited %v for a stalled stream", d)
	}
}

func TestStalledClientDoesNotDelayOthers(t *testing.T) {
	e := newEnv(t, Config{WriteTimeout: time.Minute, DispatchBuffer: 100000, HistorySize: -1})
	stalledClient(t, e, tokenFor(t, nil, all), "t")
	waitSubscribers(t, e.hub, 1)
	good := e.subscribe(t, tokenFor(t, nil, all), "t")
	blockWrites(t, e.hub)
	start := time.Now()
	for i := 0; i < 20; i++ {
		e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: strconv.Itoa(i)})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("publishing took %v with one stalled stream", d)
	}
	// The good stream got the large updates too; find the small ones.
	seen := 0
	for seen < 20 {
		ev := good.mustNext()
		if len(ev.Data) < 10 {
			seen++
		}
	}
}

// TestFanoutExactlyOnceInOrder: many publishers (through the Go API and HTTP) and many subscribers (exact, template,
// star and multi-selector); every subscriber gets every matching update exactly once, and each publisher's updates in
// the order it sent them.
func TestFanoutExactlyOnceInOrder(t *testing.T) {
	e := newEnv(t, Config{DispatchBuffer: 1 << 16, HistorySize: 1 << 16})
	const publishers, per = 8, 80
	topicOf := func(p, i int) []string {
		switch (p + i) % 4 {
		case 0:
			return []string{"chat/1"}
		case 1:
			return []string{"chat/2"}
		case 2:
			return []string{"chat/3", "chat/1"} // alternate
		default:
			return []string{"other/9"}
		}
	}
	type subSpec struct {
		name      string
		selectors []string
		match     func(topics []string) bool
	}
	has := func(topics []string, f func(string) bool) bool {
		for _, t := range topics {
			if f(t) {
				return true
			}
		}
		return false
	}
	specs := []subSpec{
		{"exact1", []string{"chat/1"}, func(ts []string) bool { return has(ts, func(s string) bool { return s == "chat/1" }) }},
		{"exact2", []string{"chat/2"}, func(ts []string) bool { return has(ts, func(s string) bool { return s == "chat/2" }) }},
		{"multi", []string{"chat/1", "chat/2"}, func(ts []string) bool {
			return has(ts, func(s string) bool { return s == "chat/1" || s == "chat/2" })
		}},
		{"template", []string{"chat/{n}"}, func(ts []string) bool { return has(ts, func(s string) bool { return strings.HasPrefix(s, "chat/") }) }},
		{"star", []string{"*"}, func([]string) bool { return true }},
		{"overlap", []string{"chat/1", "chat/{n}", "*"}, func([]string) bool { return true }},
		{"exact1 again", []string{"chat/1"}, func(ts []string) bool { return has(ts, func(s string) bool { return s == "chat/1" }) }},
		{"other", []string{"other/9"}, func(ts []string) bool { return has(ts, func(s string) bool { return s == "other/9" }) }},
	}
	clients := make([]*sseClient, len(specs))
	for i, sp := range specs {
		clients[i] = e.subscribe(t, tokenFor(t, nil, all), append(append([]string(nil), sp.selectors...), "end")...)
	}
	pub := tokenFor(t, all, nil)
	var wg sync.WaitGroup
	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				data := fmt.Sprintf("%d-%d", p, i)
				topics := topicOf(p, i)
				if p%2 == 0 {
					if _, err := e.hub.Publish(t.Context(), &Update{Topics: topics, Data: data}); err != nil {
						t.Error(err)
						return
					}
					continue
				}
				req, _ := http.NewRequest("POST", e.hubURL(), strings.NewReader(url.Values{"topic": topics, "data": {data}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Authorization", "Bearer "+pub)
				r, err := e.client.Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				r.Body.Close()
				if r.StatusCode != 200 {
					t.Errorf("publish: %d", r.StatusCode)
					return
				}
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	e.publish(t, "end", "end")
	for i, sp := range specs {
		want := map[string]bool{}
		for p := 0; p < publishers; p++ {
			for j := 0; j < per; j++ {
				if sp.match(topicOf(p, j)) {
					want[fmt.Sprintf("%d-%d", p, j)] = true
				}
			}
		}
		got := clients[i].drain("end")
		last := map[string]int{}
		seen := map[string]bool{}
		for _, d := range got {
			if seen[d] {
				t.Fatalf("%s: %s delivered twice", sp.name, d)
			}
			seen[d] = true
			pr, seq, _ := strings.Cut(d, "-")
			n, _ := strconv.Atoi(seq)
			if prev, ok := last[pr]; ok && n < prev {
				t.Fatalf("%s: publisher %s out of order: %d after %d", sp.name, pr, n, prev)
			}
			last[pr] = n
			if !want[d] {
				t.Fatalf("%s: unexpected update %s", sp.name, d)
			}
		}
		if len(seen) != len(want) {
			t.Fatalf("%s: %d updates, want %d", sp.name, len(seen), len(want))
		}
	}
	if e.hub.Stats().Dropped != 0 {
		t.Fatal("subscribers dropped")
	}
}

// TestSubscriberChurn: streams opening and closing while updates flow must neither panic nor leak a registration.
func TestSubscriberChurn(t *testing.T) {
	e := newEnv(t, Config{Subscriptions: true, Heartbeat: 5 * time.Millisecond})
	stop := make(chan struct{})
	var pubs sync.WaitGroup
	for i := 0; i < 3; i++ {
		pubs.Add(1)
		go func() {
			defer pubs.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				e.hub.Publish(t.Context(), &Update{Topics: []string{"t", "u" + strconv.Itoa(n%5)}, Data: "x"})
			}
		}()
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 15; n++ {
				ctx, cancel := context.WithCancel(t.Context())
				req, _ := http.NewRequestWithContext(ctx, "GET", e.hubURL()+"?topic=t&topic=u{k}", nil)
				req.Header.Set("Authorization", "Bearer "+tokenFor(t, nil, all))
				resp, err := e.client.Do(req)
				if err == nil {
					buf := make([]byte, 64)
					resp.Body.Read(buf)
					resp.Body.Close()
				}
				cancel()
			}
		}()
	}
	wg.Wait()
	close(stop)
	pubs.Wait()
	waitSubscribers(t, e.hub, 0)
	e.hub.mu.RLock()
	defer e.hub.mu.RUnlock()
	if len(e.hub.subs)+len(e.hub.exact)+len(e.hub.patterned) != 0 {
		t.Fatalf("registrations leaked: %d %d %d", len(e.hub.subs), len(e.hub.exact), len(e.hub.patterned))
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	settleGoroutines(0) // let earlier tests' stragglers go
	baseline := runtime.NumGoroutine()
	func() {
		e := newEnv(t, Config{Subscriptions: true, WriteTimeout: 200 * time.Millisecond, DispatchBuffer: 4, HistorySize: 100, CloseOnTokenExpiry: true, Heartbeat: 10 * time.Millisecond})
		tok := tokenFor(t, nil, all)
		var clients []*sseClient
		for i := 0; i < 20; i++ {
			clients = append(clients, e.subscribe(t, tok, "t", fmt.Sprintf("x{n}%d", i)))
		}
		for i := 0; i < 50; i++ {
			e.publish(t, "x", "t")
		}
		for _, c := range clients[:10] {
			c.close()
		}
		stalledClient(t, e, tok, "t")
		waitSubscribers(t, e.hub, 11)
		blockWrites(t, e.hub)
		e.shutdown(t)
		for _, c := range clients {
			c.close()
		}
	}()
	if n := settleGoroutines(baseline); n > baseline {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("%d goroutines remain, %d before:\n%s", n, baseline, buf)
	}
}

func TestHubAuthJWKSOnlyKeyConfig(t *testing.T) {
	// A key config naming only a JWK Set URL counts as configured: New builds a verifier (and its first fetch fails
	// harmlessly, so tokens are refused until a key set loads).
	key := auth.KeyConfig{JWKSURL: "http://127.0.0.1:1/jwks", HTTPClient: &http.Client{Timeout: 200 * time.Millisecond}}
	if _, err := New(Config{PublisherKey: key}); err == nil {
		t.Fatal("a plain-HTTP JWK Set URL was accepted without AllowInsecureKeyURLs")
	}
	log := &recLogger{}
	h, err := New(Config{PublisherKey: key, Protocol: ProtocolBoth, AllowInsecureKeyURLs: true, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(t.Context())
	w := serve(t, h, "POST", "/.well-known/mercure", map[string]string{"Authorization": "Bearer " + tokenFor(t, all, nil)})
	if w.Code != 401 {
		t.Fatalf("status %d", w.Code)
	}
	// The failure is counted and logged, not left to the debug log of each refused token.
	eventually(t, "the key set failure to be seen", func() bool {
		return h.Stats().KeySetsFailing > 0 && log.has("key set fetch failing")
	})
}
