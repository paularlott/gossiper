//go:build failover

// Package failover runs the gossiper binary as real processes (a 3-node cluster, or a single node) and kills,
// terminates and restarts them while Mercure clients publish and subscribe, then checks what the clients saw. Run
// with:
//
//	go test -tags failover -v -count=1 -timeout 20m ./test/failover/
//
// Nodes use ports 14500-14599 on 127.0.0.1. Every test prints its timings with t.Log (see -v).
package failover

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	secret     = "failover-secret-failover-secret-0123456789"
	clusterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes, base64
	portLow    = 14500
	portHigh   = 14599
	hubPath    = "/.well-known/mercure"
	topic      = "https://example.com/failover"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gossiper-failover-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	binPath = filepath.Join(dir, "gossiper")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/gossiper")
	build.Dir = root
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// --- ports ---

var (
	portMu   sync.Mutex
	portUsed = map[int]bool{}
)

// ports returns n ports of 14500-14599 free for both TCP and UDP (gossip binds both) on 127.0.0.1, released when
// the test ends.
func ports(t *testing.T, n int) []int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()
	var got []int
	for p := portLow; p <= portHigh && len(got) < n; p++ {
		if portUsed[p] {
			continue
		}
		addr := "127.0.0.1:" + strconv.Itoa(p)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		pc, err := net.ListenPacket("udp", addr)
		ln.Close()
		if err != nil {
			continue
		}
		pc.Close()
		portUsed[p] = true
		got = append(got, p)
	}
	if len(got) < n {
		t.Fatalf("no %d free ports in %d-%d", n, portLow, portHigh)
	}
	t.Cleanup(func() {
		portMu.Lock()
		defer portMu.Unlock()
		for _, p := range got {
			delete(portUsed, p)
		}
	})
	return got
}

// --- nodes ---

// node is one gossiper process; start and restart keep its id, ports and data directory.
type node struct {
	t            *testing.T
	idx          int
	id           string
	http, gossip int
	dir          string
	args         []string
	logPath      string

	mu     sync.Mutex
	cmd    *exec.Cmd
	exited chan struct{}
	exit   error
	starts int
}

func (n *node) httpURL() string { return fmt.Sprintf("http://127.0.0.1:%d", n.http) }

func (n *node) start() {
	n.t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	args := append([]string{}, n.args...)
	n.starts++
	lf, err := os.OpenFile(n.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		n.t.Fatal(err)
	}
	fmt.Fprintf(lf, "=== start %d at %s\n", n.starts, time.Now().Format(time.RFC3339Nano))
	cmd := exec.Command(binPath, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.Dir = n.dir
	if err := cmd.Start(); err != nil {
		n.t.Fatal(err)
	}
	exited := make(chan struct{})
	n.cmd, n.exited, n.exit = cmd, exited, nil
	go func() {
		err := cmd.Wait()
		lf.Close()
		n.mu.Lock()
		n.exit = err
		n.mu.Unlock()
		close(exited)
	}()
}

func (n *node) alive() bool {
	n.mu.Lock()
	ex := n.exited
	n.mu.Unlock()
	if ex == nil {
		return false
	}
	select {
	case <-ex:
		return false
	default:
		return true
	}
}

// signal sends sig and waits up to d for the process to exit, returning the time it took.
func (n *node) signal(sig syscall.Signal, d time.Duration) (time.Duration, error) {
	n.mu.Lock()
	cmd, ex := n.cmd, n.exited
	n.mu.Unlock()
	start := time.Now()
	if err := cmd.Process.Signal(sig); err != nil {
		return 0, err
	}
	select {
	case <-ex:
		return time.Since(start), nil
	case <-time.After(d):
		cmd.Process.Kill()
		<-ex
		return time.Since(start), fmt.Errorf("node %d ignored %v for %v", n.idx, sig, d)
	}
}

// kill is kill -9.
func (n *node) kill() time.Time {
	n.t.Helper()
	t0 := time.Now()
	if _, err := n.signal(syscall.SIGKILL, 10*time.Second); err != nil {
		n.t.Fatal(err)
	}
	return t0
}

// term is SIGTERM; it returns when the process exited and how long that took.
func (n *node) term() (time.Time, time.Duration) {
	n.t.Helper()
	t0 := time.Now()
	d, err := n.signal(syscall.SIGTERM, 30*time.Second)
	if err != nil {
		n.t.Fatal(err)
	}
	return t0, d
}

func (n *node) exitStatus() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.exit
}

// logLines returns the node's log (all its starts).
func (n *node) logText() string {
	b, _ := os.ReadFile(n.logPath)
	return string(b)
}

// logCounts counts the JSON log lines by level from byte offset from.
func (n *node) logLevels(from int) (counts map[string]int, lines map[string][]string) {
	counts, lines = map[string]int{}, map[string][]string{}
	txt := n.logText()
	if from > len(txt) {
		from = len(txt)
	}
	for _, l := range strings.Split(txt[from:], "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		lvl := strings.ToUpper(fmt.Sprint(m["level"]))
		counts[lvl]++
		if lvl == "WARN" || lvl == "ERROR" {
			lines[lvl] = append(lines[lvl], l)
		}
	}
	return
}

// metric returns a series of the node's /metrics.
func (n *node) metric(name string) (float64, bool) {
	resp, err := probe.Get(n.httpURL() + "/metrics")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, name+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return f, err == nil
		}
	}
	return 0, false
}

func (n *node) status(path string) int {
	resp, err := probe.Get(n.httpURL() + path)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body) // read it all so the connection is reused
	resp.Body.Close()
	return resp.StatusCode
}

// probe polls health and metrics. One transport with keep-alive: a poll loop must not leave a socket in TIME_WAIT
// per request (the ephemeral port range is only 16k wide on macOS).
var probe = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 16}}

// waitHTTP waits for /healthz.
func (n *node) waitHTTP(d time.Duration) time.Duration {
	n.t.Helper()
	start := time.Now()
	waitFor(n.t, d, fmt.Sprintf("node %d healthz", n.idx), func() bool { return n.status("/healthz") == 200 })
	return time.Since(start)
}

type cluster struct {
	t     *testing.T
	nodes []*node
}

type clusterOpts struct {
	size  int
	extra []string
}

// newCluster starts size nodes; size 1 is a single node with no cluster flags.
func newCluster(t *testing.T, o clusterOpts) *cluster {
	t.Helper()
	c := &cluster{t: t}
	pp := ports(t, 2*o.size)
	var peers []string
	for i := 0; i < o.size; i++ {
		peers = append(peers, fmt.Sprintf("127.0.0.1:%d", pp[2*i+1]))
	}
	for i := 0; i < o.size; i++ {
		dir := t.TempDir()
		n := &node{t: t, idx: i, id: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), http: pp[2*i], gossip: pp[2*i+1], dir: dir,
			logPath: filepath.Join(dir, "gossiper.log")}
		n.args = []string{"serve",
			"--config", filepath.Join(dir, "none.toml"),
			"--listen", fmt.Sprintf("127.0.0.1:%d", n.http), "--http-only",
			"--publisher-key", secret, "--protocol", "both", "--anonymous", "--metrics",
			"--log-format", "json", "--log-level", "info", "--shutdown-timeout", "10s",
			"--resource-identifier", "https://failover.test/.well-known/mercure",
		}
		if o.size > 1 {
			n.args = append(n.args, "--cluster-bind", peers[i], "--cluster-peers", strings.Join(peers, ","),
				"--cluster-key", clusterKey)
		}
		n.args = append(n.args, o.extra...)
		c.nodes = append(c.nodes, n)
	}
	t.Cleanup(func() {
		for _, n := range c.nodes {
			if n.alive() {
				n.signal(syscall.SIGKILL, 10*time.Second)
			}
		}
		if t.Failed() {
			for _, n := range c.nodes {
				txt := n.logText()
				if len(txt) > 6000 {
					txt = "...\n" + txt[len(txt)-6000:]
				}
				t.Logf("--- log of node %d:\n%s", n.idx, txt)
			}
		}
	})
	for _, n := range c.nodes {
		n.start()
	}
	for _, n := range c.nodes {
		n.waitHTTP(20 * time.Second)
	}
	c.waitMeshed(c.nodes, 30*time.Second)
	return c
}

// waitMeshed waits until every one of nodes sees all of them as gossip members.
func (c *cluster) waitMeshed(nodes []*node, d time.Duration) time.Duration {
	c.t.Helper()
	start := time.Now()
	if len(c.nodes) == 1 {
		return 0
	}
	waitFor(c.t, d, "cluster meshed", func() bool {
		for _, n := range nodes {
			if v, _ := n.metric("gossiper_cluster_nodes"); int(v) != len(nodes) {
				return false
			}
		}
		return true
	})
	return time.Since(start)
}

func (c *cluster) survivors(dead ...int) []*node {
	var out []*node
next:
	for _, n := range c.nodes {
		for _, d := range dead {
			if n.idx == d {
				continue next
			}
		}
		out = append(out, n)
	}
	return out
}

func (c *cluster) httpURLs(first int) []string { return c.rotated(first, (*node).httpURL) }

// rotated lists every node's address, starting with node first.
func (c *cluster) rotated(first int, f func(*node) string) []string {
	var out []string
	for i := range c.nodes {
		out = append(out, f(c.nodes[(first+i)%len(c.nodes)]))
	}
	return out
}

func waitFor(t *testing.T, d time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --- Mercure clients ---

type sseEvent struct {
	ID, Data string
	At       time.Time
	Node     string // the URL of the node it came from
}

type sseReconnect struct {
	Lost      time.Time // the stream ended
	Connected time.Time // the next stream answered 200
	FirstData time.Time // its first event
	To        string
	Resumed   bool // sent a Last-Event-ID
}

// sseClient subscribes to topic, and when its stream ends or fails reconnects to the next node of urls with
// Last-Event-ID: a client that retries a list.
type sseClient struct {
	name string
	urls []string

	mu         sync.Mutex
	events     []sseEvent
	seen       map[string]bool
	dups       int
	lastID     string
	reconnects []sseReconnect
	connected  bool
	cur        string
	cancel     context.CancelFunc
	done       chan struct{}
}

func startSSE(name string, urls []string) *sseClient { return startSSEFrom(name, urls, "") }

// startSSEFrom is startSSE resuming from lastID.
func startSSEFrom(name string, urls []string, lastID string) *sseClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &sseClient{name: name, urls: urls, seen: map[string]bool{}, lastID: lastID, cancel: cancel, done: make(chan struct{})}
	go c.run(ctx)
	return c
}

func (c *sseClient) stop() { c.cancel(); <-c.done }

func (c *sseClient) run(ctx context.Context) {
	defer close(c.done)
	hc := &http.Client{} // no timeout: the stream is long-lived
	i := 0
	first := true
	var lost time.Time
	for ctx.Err() == nil {
		base := c.urls[i%len(c.urls)]
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+hubPath+"?topic="+url.QueryEscape(topic), nil)
		c.mu.Lock()
		last := c.lastID
		c.mu.Unlock()
		if last != "" {
			req.Header.Set("Last-Event-ID", last)
		}
		resp, err := hc.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			if lost.IsZero() {
				lost = time.Now()
			}
			i++
			sleep(ctx, 50*time.Millisecond)
			continue
		}
		rc := sseReconnect{Lost: lost, Connected: time.Now(), To: base, Resumed: last != ""}
		c.mu.Lock()
		c.connected, c.cur = true, base
		idx := -1
		if !first {
			c.reconnects = append(c.reconnects, rc)
			idx = len(c.reconnects) - 1
		}
		c.mu.Unlock()
		first = false
		c.read(resp.Body, base, idx)
		resp.Body.Close()
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
		lost = time.Now()
		i++
		sleep(ctx, 20*time.Millisecond)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (c *sseClient) read(body io.Reader, base string, reconIdx int) {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var id, data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if data != "" {
				now := time.Now()
				c.mu.Lock()
				if id != "" {
					c.lastID = id
				}
				if id != "" && c.seen[id] {
					c.dups++
				} else {
					c.seen[id] = true
					c.events = append(c.events, sseEvent{ID: id, Data: data, At: now, Node: base})
					if reconIdx >= 0 && c.reconnects[reconIdx].FirstData.IsZero() {
						c.reconnects[reconIdx].FirstData = now
					}
				}
				c.mu.Unlock()
			}
			id, data = "", ""
		case strings.HasPrefix(line, "id:"):
			id = strings.TrimSpace(line[3:])
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		}
	}
}

func (c *sseClient) isConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *sseClient) snapshot() (evs []sseEvent, recs []sseReconnect, dups int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sseEvent(nil), c.events...), append([]sseReconnect(nil), c.reconnects...), c.dups
}

// datas returns the set of event payloads received.
func (c *sseClient) datas() map[string]bool {
	evs, _, _ := c.snapshot()
	m := make(map[string]bool, len(evs))
	for _, e := range evs {
		m[e.Data] = true
	}
	return m
}

func publisherToken() string {
	s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}).SignedString([]byte(secret))
	return s
}

// mercurePublish posts one update to the first of urls that takes it (tried in order) and returns the node used.
func mercurePublish(hc *http.Client, urls []string, data string) (id, node string, err error) {
	var last error
	for _, base := range urls {
		req, _ := http.NewRequest(http.MethodPost, base+hubPath, strings.NewReader(url.Values{"topic": {topic}, "data": {data}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+publisherToken())
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return strings.TrimSpace(string(b)), base, nil
		}
		last = fmt.Errorf("%s: %d %s", base, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return "", "", last
}

// --- publishers ---

// sent records what a publisher published: sequence number -> time.
type sent struct {
	mu   sync.Mutex
	at   map[int]time.Time
	node map[int]string
	fail int
	max  int
}

func newSent() *sent { return &sent{at: map[int]time.Time{}, node: map[int]string{}} }

func (s *sent) record(seq int, node string) {
	s.mu.Lock()
	s.at[seq], s.node[seq] = time.Now(), node
	if seq > s.max {
		s.max = seq
	}
	s.mu.Unlock()
}

func (s *sent) failed() { s.mu.Lock(); s.fail++; s.mu.Unlock() }

func (s *sent) seqs() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.at))
	for q := range s.at {
		out = append(out, q)
	}
	sort.Ints(out)
	return out
}

func (s *sent) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.at) }

// publishers run a Mercure publisher (every node tried in turn, starting with a rotating one) at a steady rate until
// stopped.
type publishers struct {
	cluster  *cluster
	interval time.Duration
	mercure  *sent
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	maxGap   atomic.Int64 // longest gap between Mercure publish acks, ns
}

func startPublishers(t *testing.T, c *cluster, interval time.Duration) *publishers {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &publishers{cluster: c, interval: interval, mercure: newSent(), cancel: cancel}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		hc := &http.Client{Timeout: 3 * time.Second, Transport: pubTransport}
		tick := time.NewTicker(interval)
		defer tick.Stop()
		var lastAck time.Time
		for seq := 1; ; seq++ {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			urls := c.httpURLs(seq % len(c.nodes))
			_, node, err := mercurePublish(hc, urls, strconv.Itoa(seq))
			if err != nil {
				p.mercure.failed()
				continue
			}
			now := time.Now()
			if !lastAck.IsZero() && int64(now.Sub(lastAck)) > p.maxGap.Load() {
				p.maxGap.Store(int64(now.Sub(lastAck)))
			}
			lastAck = now
			p.mercure.record(seq, node)
		}
	}()
	return p
}

func (p *publishers) stop() {
	p.cancel()
	p.wg.Wait()
}

// sleepFor is time.Sleep with a name that reads as intent in the scenarios.
func sleepFor(d time.Duration) { time.Sleep(d) }

func ms(d time.Duration) string { return fmt.Sprintf("%dms", d.Milliseconds()) }

// newHTTP is a publishing client; all of them share one connection pool.
func newHTTP() *http.Client { return &http.Client{Timeout: 5 * time.Second, Transport: pubTransport} }

var pubTransport = &http.Transport{MaxIdleConnsPerHost: 32}
