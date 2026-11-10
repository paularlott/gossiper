package gossiper

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/logger"
)

// testSecret is the HMAC key the test hubs verify tokens with (32 bytes: not "weak" for HS256).
const testSecret = "0123456789abcdef0123456789abcdef"

// wait is the deadline tests give an asynchronous effect to show up.
const wait = 10 * time.Second

// signJWT signs claims with an HS256 secret.
func signJWT(t testing.TB, secret string, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// mercureClaims returns claims with a mercure object. A nil pub or sub leaves the key out; an empty one is an
// empty array.
func mercureClaims(pub, sub []string) jwt.MapClaims {
	m := map[string]any{}
	if pub != nil {
		m["publish"] = pub
	}
	if sub != nil {
		m["subscribe"] = sub
	}
	return jwt.MapClaims{"mercure": m, "exp": time.Now().Add(time.Hour).Unix()}
}

// tokenFor returns a valid token with the given publish and subscribe selectors.
func tokenFor(t testing.TB, pub, sub []string) string {
	t.Helper()
	return signJWT(t, testSecret, mercureClaims(pub, sub))
}

// all is the selector list of a token that may do anything.
var all = []string{"*"}

// env is a hub served by a real HTTP server.
type env struct {
	hub    *Hub
	srv    *httptest.Server
	client *http.Client
	tr     *http.Transport
	once   sync.Once
}

// newEnv starts a hub with cfg (the test key is filled in when cfg has none) behind an httptest server. The hub
// and server are closed when the test ends.
func newEnv(t testing.TB, cfg Config) *env {
	t.Helper()
	if cfg.Protocol == ProtocolDefault { // the tests speak draft-07 unless they choose a protocol
		cfg.Protocol = ProtocolBoth
	}
	if !hasKey(cfg.PublisherKey) {
		cfg.PublisherKey = auth.KeyConfig{Key: testSecret}
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	tr := &http.Transport{MaxIdleConnsPerHost: 64}
	e := &env{hub: h, srv: srv, client: &http.Client{Transport: tr}, tr: tr}
	t.Cleanup(func() { e.shutdown(t) })
	return e
}

// shutdown closes the hub, then the server and the client's connections. It runs once, whether a test calls it or
// the cleanup does.
func (e *env) shutdown(t testing.TB) {
	e.once.Do(func() {
		e.tr.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		if err := e.hub.Close(ctx); err != nil {
			t.Errorf("hub close: %v", err)
		}
		e.srv.CloseClientConnections()
		e.srv.Close()
		e.tr.CloseIdleConnections()
	})
}

// hubURL is the hub's URL on the test server.
func (e *env) hubURL() string { return e.srv.URL + hubPath }

// bearer returns request headers carrying tok as a bearer token.
func bearer(tok string) http.Header {
	if tok == "" {
		return nil
	}
	return http.Header{"Authorization": {"Bearer " + tok}}
}

// result is a completed HTTP exchange.
type result struct {
	code   int
	body   string
	header http.Header
}

// do sends a request and reads the whole response.
func (e *env) do(t testing.TB, method, target string, hdr http.Header, body string) result {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	if method == http.MethodPost && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, string(b), resp.Header}
}

// post publishes form with tok as a bearer token.
func (e *env) post(t testing.TB, tok string, form url.Values) result {
	t.Helper()
	return e.do(t, http.MethodPost, e.hubURL(), bearer(tok), form.Encode())
}

// publish publishes one public update and returns its id; it fails the test unless the hub accepts it.
func (e *env) publish(t testing.TB, data string, topics ...string) string {
	t.Helper()
	r := e.post(t, tokenFor(t, all, nil), url.Values{"topic": topics, "data": {data}})
	if r.code != 200 {
		t.Fatalf("publish: %d %s", r.code, r.body)
	}
	return r.body
}

// sseEvent is one event read from a stream.
type sseEvent struct {
	ID, Type, Data, Retry string
	HasRetry              bool
	Raw                   string // the frame as sent, up to and including the blank line
}

// parseFrame parses one SSE frame (the lines of an event, each ending in "\n", and the blank line) as an
// EventSource does. It reports an error for anything an EventSource would take for another field or event.
func parseFrame(raw string) (sseEvent, error) {
	ev := sseEvent{Raw: raw}
	if !strings.HasSuffix(raw, "\n\n") {
		return ev, fmt.Errorf("frame does not end with a blank line: %q", raw)
	}
	if strings.Contains(raw, "\r") {
		return ev, fmt.Errorf("frame holds a CR: %q", raw)
	}
	var data []string
	ids, types := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n\n"), "\n") {
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			return ev, fmt.Errorf("line without a colon: %q", line)
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			ids++
			ev.ID = value
		case "event":
			types++
			ev.Type = value
		case "retry":
			ev.Retry, ev.HasRetry = value, true
		case "data":
			data = append(data, value)
		default:
			return ev, fmt.Errorf("unexpected field %q in %q", field, raw)
		}
	}
	if ids != 1 || types > 1 || len(data) == 0 {
		return ev, fmt.Errorf("bad frame (id %d, event %d, data lines %d): %q", ids, types, len(data), raw)
	}
	ev.Data = strings.Join(data, "\n")
	return ev, nil
}

// sseClient reads a Server-Sent Events stream.
type sseClient struct {
	t        testing.TB
	resp     *http.Response
	cancel   context.CancelFunc
	events   chan sseEvent
	closed   chan struct{} // closed when the stream ends
	comments atomic.Int64
	bad      atomic.Value // a frame that did not parse
}

// tryDial opens the stream; the caller owns the response.
func (e *env) tryDial(query url.Values, hdr http.Header) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.hubURL()+"?"+query.Encode(), nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := e.client.Do(req)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return resp, cancel, nil
}

// dial opens a stream that must succeed, and waits for its first comment (the stream is then registered). The
// client is closed when the test ends.
func (e *env) dial(t testing.TB, query url.Values, hdr http.Header) *sseClient {
	t.Helper()
	resp, cancel, err := e.tryDial(query, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		t.Fatalf("subscribe: %d %s", resp.StatusCode, b)
	}
	c := &sseClient{t: t, resp: resp, cancel: cancel, events: make(chan sseEvent, 1<<14), closed: make(chan struct{})}
	go c.read()
	t.Cleanup(c.close)
	eventually(t, "the stream's first comment", func() bool { return c.comments.Load() > 0 })
	return c
}

// subscribe opens a stream for the topic selectors with tok (none when empty).
func (e *env) subscribe(t testing.TB, tok string, topics ...string) *sseClient {
	t.Helper()
	return e.dial(t, url.Values{"topic": topics}, bearer(tok))
}

func (c *sseClient) read() {
	defer close(c.closed)
	r := bufio.NewReader(c.resp.Body)
	var frame strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch {
		case strings.HasPrefix(line, ":"):
			c.comments.Add(1)
		case line == "\n":
			if frame.Len() == 0 {
				continue
			}
			frame.WriteString(line)
			ev, perr := parseFrame(frame.String())
			if perr != nil {
				c.bad.Store(perr.Error())
			}
			frame.Reset()
			c.events <- ev
		default:
			frame.WriteString(line)
		}
	}
}

func (c *sseClient) close() {
	c.cancel()
	c.resp.Body.Close()
	<-c.closed
}

// next returns the next event, or false when none comes within d or the stream ended.
func (c *sseClient) next(d time.Duration) (sseEvent, bool) {
	select {
	case ev := <-c.events:
		return ev, true
	default:
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case ev := <-c.events:
		return ev, true
	case <-c.closed:
		select {
		case ev := <-c.events:
			return ev, true
		default:
			return sseEvent{}, false
		}
	case <-timer.C:
		return sseEvent{}, false
	}
}

// mustNext returns the next event or fails the test.
func (c *sseClient) mustNext() sseEvent {
	c.t.Helper()
	ev, ok := c.next(wait)
	if !ok {
		c.t.Fatal("no event received")
	}
	if b := c.bad.Load(); b != nil {
		c.t.Fatalf("malformed frame: %v", b)
	}
	return ev
}

// expect fails the test unless the next events carry exactly the data values, in order.
func (c *sseClient) expect(data ...string) {
	c.t.Helper()
	for i, want := range data {
		if got := c.mustNext().Data; got != want {
			c.t.Fatalf("event %d: data %q, want %q", i, got, want)
		}
	}
}

// drain reads events up to and including the one whose data is the sentinel, and returns the data of those before
// it. Since a stream delivers in order, it shows what the stream was sent (and not) before the sentinel.
func (c *sseClient) drain(sentinel string) []string {
	c.t.Helper()
	var got []string
	for {
		ev := c.mustNext()
		if ev.Data == sentinel {
			return got
		}
		got = append(got, ev.Data)
	}
}

// waitClosed reports whether the stream ends within d.
func (c *sseClient) waitClosed(d time.Duration) bool {
	select {
	case <-c.closed:
		return true
	case <-time.After(d):
		return false
	}
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitSubscribers waits until the hub has n open streams.
func waitSubscribers(t testing.TB, h *Hub, n int) {
	t.Helper()
	eventually(t, fmt.Sprintf("%d subscribers", n), func() bool { return h.stats.Subscribers.Load() == int64(n) })
}

// settleGoroutines polls until the goroutine count is at most limit, and reports the final count.
func settleGoroutines(limit int) int {
	deadline := time.Now().Add(wait)
	n := runtime.NumGoroutine()
	for n > limit && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

// fakeTransport is a Transport that lets tests act as the other nodes.
type fakeTransport struct {
	id string

	mu        sync.Mutex
	hub       Host
	published []*Update
	closed    bool

	startErr, publishErr, closeErr error
	remote                         []Subscription
	complete                       bool
	remoteErr                      error
	deliverLocal                   bool // Publish applies the update on this node, as a real transport does
}

func newFakeTransport(id string) *fakeTransport {
	return &fakeTransport{id: id, complete: true, deliverLocal: true}
}

func (f *fakeTransport) Start(h Host) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hub = h
	return f.startErr
}

func (f *fakeTransport) Publish(_ context.Context, u *Update) error {
	if f.publishErr != nil {
		return f.publishErr
	}
	f.mu.Lock()
	f.published = append(f.published, u)
	h, deliver := f.hub, f.deliverLocal
	f.mu.Unlock()
	if deliver {
		h.Apply(u)
	}
	return nil
}

func (f *fakeTransport) RemoteSubscriptions(context.Context) ([]Subscription, bool, error) {
	return f.remote, f.complete, f.remoteErr
}

func (f *fakeTransport) NodeID() string { return f.id }

func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

func (f *fakeTransport) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// recLogger records the messages of the logs it receives.
type recLogger struct {
	logger.NullLogger
	mu   sync.Mutex
	msgs []string
}

func (r *recLogger) add(level, msg string) {
	r.mu.Lock()
	r.msgs = append(r.msgs, level+": "+msg)
	r.mu.Unlock()
}

func (r *recLogger) Warn(msg string, _ ...any)  { r.add("warn", msg) }
func (r *recLogger) Debug(msg string, _ ...any) { r.add("debug", msg) }
func (r *recLogger) With(string, any) logger.Logger {
	return r
}

// String lists the messages recorded so far.
func (r *recLogger) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprint(r.msgs)
}

func (r *recLogger) has(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// jwtNoExp returns claims with a mercure object and no expiry.
func jwtNoExp() jwt.MapClaims {
	c := mercureClaims(nil, all)
	delete(c, "exp")
	return c
}

// challenge returns a WWW-Authenticate value without its resource_metadata parameter, which only says where the
// protected resource metadata is.
func challenge(v string) string {
	i := strings.Index(v, "resource_metadata=")
	if i < 0 {
		return v
	}
	v = strings.TrimRight(v[:i], ", ")
	return v
}
