package cluster_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/gossiper/cluster"
	"github.com/paularlott/logger"
)

const (
	hubPath    = "/.well-known/mercure"
	subsPath   = "/.well-known/mercure/subscriptions"
	testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef" // an HS256 key long enough for the hub's check

	// waitMax bounds every wait for the cluster to converge or for an event to arrive. It is generous: a wait ends
	// as soon as its condition holds, so it only costs time when a test fails.
	waitMax = 20 * time.Second
	// settle is how long a test watches for a duplicate or an unexpected event after the expected ones arrived.
	settle = 250 * time.Millisecond
)

// waitFor polls cond until it holds, failing the test after d.
func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- gossip and hub configuration -------------------------------------------------------------------------------

// freePort returns a TCP port on 127.0.0.1 that was free a moment ago.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// gossipConfig is a fast gossip configuration: short intervals so a cluster converges in well under a second, a
// dead-node timeout far beyond any test (a node under -race load may be suspected, never declared dead), TCP only
// (no UDP port to bind or lose), and send/receive queues deep enough that a burst of publishes is never dropped.
func gossipConfig(addr string) *gossip.Config {
	c := gossip.DefaultConfig()
	c.BindAddr = addr
	c.AdvertiseAddr = addr
	c.MsgCodec = shamaton.New()
	c.ForceReliableTransport = true
	c.GossipInterval = 100 * time.Millisecond
	c.GossipMaxInterval = 300 * time.Millisecond
	c.MetadataGossipInterval = 50 * time.Millisecond
	c.StateGossipInterval = 500 * time.Millisecond
	c.HealthCheckInterval = 300 * time.Millisecond
	c.PingTimeout = 300 * time.Millisecond
	c.SuspectTimeout = time.Second
	c.SuspectRetryInterval = 300 * time.Millisecond
	c.DeadNodeTimeout = time.Minute
	c.DeadNodeRetryInterval = time.Second
	c.TCPDialTimeout = time.Second
	c.TCPDeadline = 3 * time.Second
	c.LeavingNodeTimeout = 2 * time.Second
	c.NodeCleanupInterval = time.Second
	c.SendQueueSize = 16384
	c.IncomingPacketQueueDepth = 16384
	return c
}

// nodeOpts customises one node; every field is optional.
type nodeOpts struct {
	gossip func(*gossip.Config)
	hub    func(*gossiper.Config)
	tr     func(*cluster.Options)
}

// recorder keeps the warnings and errors a library logged.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(level, msg string, kv []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, strings.TrimSpace(fmt.Sprint(level, " ", msg, " ", kv)))
}

// logged returns what was logged at warning level or above.
func (r *recorder) logged() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.lines)
}

type recLogger struct{ r *recorder }

func (l recLogger) Trace(string, ...any)           {}
func (l recLogger) Debug(string, ...any)           {}
func (l recLogger) Info(string, ...any)            {}
func (l recLogger) Warn(msg string, kv ...any)     { l.r.add("WARN", msg, kv) }
func (l recLogger) Error(msg string, kv ...any)    { l.r.add("ERROR", msg, kv) }
func (l recLogger) Fatal(msg string, kv ...any)    { l.r.add("FATAL", msg, kv) }
func (l recLogger) With(string, any) logger.Logger { return l }
func (l recLogger) WithError(error) logger.Logger  { return l }
func (l recLogger) WithGroup(string) logger.Logger { return l }

// testNode is one hub: a gossip node, the transport over it, the hub and an HTTP server serving the hub.
type testNode struct {
	t    testing.TB
	gc   *gossip.Cluster
	tr   *cluster.Transport
	hub  *gossiper.Hub
	srv  *httptest.Server
	addr string
	once sync.Once

	hubLog, gossipLog recorder // warnings and errors of the hub and of gossip
}

// newNode starts a gossip node and a hub over it, not yet joined to anyone. It is closed when the test ends.
func newNode(t testing.TB, o nodeOpts) *testNode {
	t.Helper()
	n := &testNode{t: t}
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
		cfg.Logger = recLogger{&n.gossipLog}
		if o.gossip != nil {
			o.gossip(cfg)
		}
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
	n.gc, n.addr = gc, addr
	opts := cluster.Options{}
	if o.tr != nil {
		o.tr(&opts)
	}
	n.tr = cluster.New(gc, opts)
	hc := gossiper.Config{
		PublisherKey:   auth.KeyConfig{Key: testSecret},
		Anonymous:      true,
		Heartbeat:      -1,
		DispatchBuffer: 8192,
		Transport:      n.tr,
		Logger:         recLogger{&n.hubLog},
	}
	if o.hub != nil {
		o.hub(&hc)
	}
	var err error
	if n.hub, err = gossiper.New(hc); err != nil {
		gc.Stop()
		t.Fatal(err)
	}
	n.srv = httptest.NewServer(n.hub)
	t.Cleanup(n.close)
	return n
}

// startCluster starts gc, turning the panic of a port that cannot be bound into an error.
func startCluster(gc *gossip.Cluster) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	gc.Start()
	return nil
}

// close stops the node: the hub (ending its streams and its transport), the HTTP server, then gossip.
func (n *testNode) close() {
	n.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.hub.Close(ctx); err != nil {
			n.t.Errorf("hub close: %v", err)
		}
		n.srv.Close()
		n.gc.Stop()
	})
}

func (n *testNode) url() string { return n.srv.URL + hubPath }

// clusterOpts describes a test cluster.
type clusterOpts struct {
	n    int
	node func(i int, o *nodeOpts)
}

// newCluster starts the nodes, joins them through the first and waits until every hub sees the others.
func newCluster(t testing.TB, co clusterOpts) []*testNode {
	t.Helper()
	nodes := make([]*testNode, co.n)
	for i := range nodes {
		o := nodeOpts{}
		if co.node != nil {
			co.node(i, &o)
		}
		nodes[i] = newNode(t, o)
	}
	for _, n := range nodes[1:] {
		if err := n.gc.Join([]string{nodes[0].addr}); err != nil {
			t.Fatalf("join: %v", err)
		}
	}
	waitConverged(t, nodes)
	return nodes
}

// waitConverged waits until every node's transport lists exactly the other nodes.
func waitConverged(t testing.TB, nodes []*testNode) {
	t.Helper()
	waitFor(t, waitMax, "every hub to see the others", func() bool {
		for _, n := range nodes {
			if len(n.tr.Peers()) != len(nodes)-1 {
				return false
			}
		}
		return true
	})
}

// peerIDs returns the gossip ids of n's peers, sorted.
func (n *testNode) peerIDs() []string {
	var ids []string
	for _, p := range n.tr.Peers() {
		ids = append(ids, p.ID.String())
	}
	slices.Sort(ids)
	return ids
}

// waitApplied waits until every node has applied at least want updates.
func waitApplied(t testing.TB, nodes []*testNode, want uint64) {
	t.Helper()
	waitFor(t, waitMax, fmt.Sprintf("every node to apply %d updates", want), func() bool {
		for _, n := range nodes {
			if n.hub.Stats().Applied < want {
				return false
			}
		}
		return true
	})
}

// ---- tokens and publishing --------------------------------------------------------------------------------------

func mintToken(t testing.TB, mercure map[string]any) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": mercure}).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func subscriberToken(t testing.TB, selectors ...string) string {
	return mintToken(t, map[string]any{"subscribe": selectors})
}

// newClient returns an HTTP client with its own connection pool, closed when the test ends.
func newClient(t testing.TB) *http.Client {
	tr := &http.Transport{MaxIdleConnsPerHost: 64}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// publish POSTs an update to the node's hub and returns the event ID it answers.
func (n *testNode) publish(t testing.TB, c *http.Client, form url.Values) string {
	t.Helper()
	id, status, err := n.tryPublish(c, form)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("publish: status %d: %s", status, id)
	}
	return id
}

// tryPublish is publish for callers that are not the test goroutine.
func (n *testNode) tryPublish(c *http.Client, form url.Values) (body string, status int, err error) {
	req, err := http.NewRequest(http.MethodPost, n.url(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+pubTokenCached)
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, err
}

var pubTokenCached = func() string {
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}).
		SignedString([]byte(testSecret))
	if err != nil {
		panic(err)
	}
	return tok
}()

// ---- SSE subscribers --------------------------------------------------------------------------------------------

// sseEvent is one event a subscriber received.
type sseEvent struct {
	ID, Type, Data, Retry string
	Frame                 string // the event's lines as received, without comments, ending in the blank line
}

type subOpts struct {
	topics      []string
	token       string
	lastEventID string
}

// sseClient is an open subscription to one node.
type sseClient struct {
	t      testing.TB
	node   *testNode
	cancel context.CancelFunc
	done   chan struct{}
	header http.Header

	mu     sync.Mutex
	events []sseEvent
}

// subscribe opens a stream and returns once the hub has registered it (the response headers have arrived).
func (n *testNode) subscribe(t testing.TB, o subOpts) *sseClient {
	t.Helper()
	c, status, err := n.trySubscribe(t, o)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("subscribe: status %d", status)
	}
	return c
}

func (n *testNode) trySubscribe(t testing.TB, o subOpts) (*sseClient, int, error) {
	q := url.Values{"topic": o.topics}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.url()+"?"+q.Encode(), nil)
	if err != nil {
		cancel()
		return nil, 0, err
	}
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}
	if o.lastEventID != "" {
		req.Header.Set("Last-Event-ID", o.lastEventID)
	}
	hc := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := hc.Do(req)
	if err != nil {
		cancel()
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, resp.StatusCode, nil
	}
	c := &sseClient{t: t, node: n, cancel: cancel, done: make(chan struct{}), header: resp.Header}
	go c.read(resp.Body)
	t.Cleanup(c.close)
	return c, resp.StatusCode, nil
}

func (c *sseClient) read(body io.ReadCloser) {
	defer close(c.done)
	defer body.Close()
	br := bufio.NewReaderSize(body, 64<<10)
	var ev sseEvent
	var data []string
	var frame strings.Builder
	have := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			if have {
				ev.Data = strings.Join(data, "\n")
				frame.WriteByte('\n')
				ev.Frame = frame.String()
				c.mu.Lock()
				c.events = append(c.events, ev)
				c.mu.Unlock()
			}
			ev, data, have = sseEvent{}, nil, false
			frame.Reset()
			continue
		}
		if line[0] == ':' {
			continue
		}
		have = true
		frame.WriteString(line)
		frame.WriteByte('\n')
		field, val, _ := strings.Cut(line, ":")
		val = strings.TrimPrefix(val, " ")
		switch field {
		case "id":
			ev.ID = val
		case "event":
			ev.Type = val
		case "retry":
			ev.Retry = val
		case "data":
			data = append(data, val)
		}
	}
}

// close ends the stream and waits for its reader.
func (c *sseClient) close() {
	c.cancel()
	<-c.done
}

func (c *sseClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *sseClient) all() []sseEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.events)
}

func (c *sseClient) ids() []string {
	var ids []string
	for _, e := range c.all() {
		ids = append(ids, e.ID)
	}
	return ids
}

// wait waits until the client has received at least n events.
func (c *sseClient) wait(t testing.TB, n int) {
	t.Helper()
	deadline := time.Now().Add(waitMax)
	for c.count() < n {
		select {
		case <-c.done:
			if c.count() >= n {
				return
			}
			t.Fatalf("stream on %s ended with %d of %d events: %v", c.node.addr, c.count(), n, c.ids())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("subscriber on %s: %d of %d events after %v: %v", c.node.addr, c.count(), n, waitMax, c.ids())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// expect waits for exactly n events: n arrive, then no more within settle.
func (c *sseClient) expect(t testing.TB, n int) []sseEvent {
	t.Helper()
	c.wait(t, n)
	time.Sleep(settle)
	if got := c.count(); got != n {
		t.Fatalf("subscriber on %s: %d events, want exactly %d: %v", c.node.addr, got, n, c.ids())
	}
	return c.all()
}

// expectAll waits for exactly n events at every client: n arrive at each, then no more within one settle period.
func expectAll(t testing.TB, n int, clients ...*sseClient) [][]sseEvent {
	t.Helper()
	for _, c := range clients {
		c.wait(t, n)
	}
	time.Sleep(settle)
	out := make([][]sseEvent, len(clients))
	for i, c := range clients {
		if got := c.count(); got != n {
			t.Fatalf("subscriber on %s: %d events, want exactly %d: %v", c.node.addr, got, n, c.ids())
		}
		out[i] = c.all()
	}
	return out
}

// ---- goroutine leaks --------------------------------------------------------------------------------------------

// leakedGoroutines returns the stacks of goroutines that belong to the hub, the gossip library or an HTTP
// connection and have not ended.
func leakedGoroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "cluster_test.TestMain") || strings.Contains(g, "testing.(*M).Run") ||
			strings.Contains(g, "testing.tRunner") || strings.Contains(g, "testing.(*B).") ||
			strings.Contains(g, "leakedGoroutines") {
			continue
		}
		for _, marker := range []string{"paularlott/gossip", "paularlott/gossiper", "net/http.(*persistConn)", "net/http.(*conn).serve", "net/http/httptest"} {
			if strings.Contains(g, marker) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// waitNoLeaks waits for every goroutine of the hubs, gossip and HTTP to end, failing with their stacks otherwise.
func waitNoLeaks(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		leaked := leakedGoroutines()
		if len(leaked) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines left running:\n\n%s", len(leaked), strings.Join(leaked, "\n\n"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}
