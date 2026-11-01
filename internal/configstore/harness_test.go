package configstore_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossiper/internal/configstore"
	"github.com/paularlott/logger"
)

// waitMax bounds every wait for the cluster to converge. A wait ends as soon as its condition holds, so the bound
// only costs time when a test fails.
const waitMax = 30 * time.Second

// TestMain fails the run when a goroutine of a store or of gossip outlives every test.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		deadline := time.Now().Add(15 * time.Second)
		for {
			leaked := leakedGoroutines()
			if len(leaked) == 0 {
				break
			}
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr, "FAIL: %d goroutines of a store or gossip left running:\n\n%s\n", len(leaked), strings.Join(leaked, "\n\n"))
				code = 1
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	os.Exit(code)
}

// leakedGoroutines returns the stacks of goroutines that belong to a store or to gossip.
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
		if strings.Contains(g, "configstore_test.TestMain") || strings.Contains(g, "testing.(*M).Run") ||
			strings.Contains(g, "testing.tRunner") || strings.Contains(g, "leakedGoroutines") {
			continue
		}
		if strings.Contains(g, "paularlott/gossip") {
			out = append(out, g)
		}
	}
	return out
}

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

// ---- gossip configuration and the network between nodes ---------------------------------------------------------

// gossipConfig is a fast gossip configuration over TCP only: a cluster converges in well under a second, and a node
// cut off for a second or two is declared dead (and taken back when it returns).
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
	c.PeerRecoveryInterval = time.Second
	c.TCPDialTimeout = time.Second
	c.TCPDeadline = 3 * time.Second
	c.LeavingNodeTimeout = 2 * time.Second
	c.NodeCleanupInterval = time.Second
	c.SendQueueSize = 16384
	c.IncomingPacketQueueDepth = 16384
	return c
}

// testNet is the network between the gossip nodes of a test: every connection a node dials goes through it, so a
// node can be cut off from the others and later reconnected.
type testNet struct {
	mu    sync.Mutex
	down  map[string]bool // nodes cut off from everyone
	conns map[*netConn]struct{}
}

type netConn struct {
	net.Conn
	from, to string
}

// SyscallConn exposes the socket so gossip can pool the connection (it does not pool one that hides its socket).
func (c *netConn) SyscallConn() (syscall.RawConn, error) { return c.Conn.(syscall.Conn).SyscallConn() }

func newTestNet() *testNet {
	return &testNet{down: map[string]bool{}, conns: map[*netConn]struct{}{}}
}

func (n *testNet) dialer(from string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		n.mu.Lock()
		blocked := n.down[from] || n.down[addr]
		n.mu.Unlock()
		if blocked {
			return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("network down")}
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		nc := &netConn{Conn: c, from: from, to: addr}
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.down[from] || n.down[addr] {
			c.Close()
			return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("network down")}
		}
		n.conns[nc] = struct{}{}
		return nc, nil
	}
}

// isolate cuts node (a gossip address) off from every other node and drops its connections.
func (n *testNet) isolate(node string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.down[node] = true
	for c := range n.conns {
		if c.from == node || c.to == node {
			c.Conn.Close()
			delete(n.conns, c)
		}
	}
}

// heal reconnects node to the others.
func (n *testNet) heal(node string) {
	n.mu.Lock()
	delete(n.down, node)
	n.mu.Unlock()
}

// ---- nodes ------------------------------------------------------------------------------------------------------

// recorder keeps the warnings and errors a node logged.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(level, msg string, kv []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, strings.TrimSpace(fmt.Sprint(level, " ", msg, " ", kv)))
}

func (r *recorder) all() []string {
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

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func freeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// changes records what OnChange was called with.
type changes struct {
	mu    sync.Mutex
	calls [][]string
	seen  map[string]int
}

func (c *changes) add(keys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.calls = append(c.calls, keys)
	for _, k := range keys {
		c.seen[k]++
	}
}

// has reports whether OnChange has been given every one of keys.
func (c *changes) has(keys ...string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		if c.seen[k] == 0 {
			return false
		}
	}
	return true
}

// nodeCfg customises a node; every field is optional.
type nodeCfg struct {
	store func(*configstore.Options)
}

// tnode is one store over one gossip node. Its identity (gossip ID, address, database file) is stable across
// restarts.
type tnode struct {
	tb   testing.TB
	net  *testNet
	cfg  nodeCfg
	id   string
	addr string
	path string
	ch   *changes
	log  *recorder

	mu sync.Mutex
	g  *gossip.Cluster
	s  *configstore.Store
}

func (n *tnode) store() *configstore.Store { n.mu.Lock(); defer n.mu.Unlock(); return n.s }

// boot starts the gossip node and opens the store over it, then joins peers.
func (n *tnode) boot(peers []string) {
	n.tb.Helper()
	var err error
	for attempt := 0; ; attempt++ {
		if err = n.tryBoot(); err == nil {
			break
		}
		if attempt == 50 {
			n.tb.Fatalf("boot %s: %v", n.addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(peers) > 0 {
		if err := n.g.Join(peers); err != nil {
			n.tb.Fatalf("join: %v", err)
		}
	}
}

func (n *tnode) tryBoot() error {
	gc := gossipConfig(n.addr)
	gc.NodeID = n.id
	gc.DialFunc = n.net.dialer(n.addr)
	gc.Transport = gossip.NewSocketTransport(gc)
	gc.Logger = recLogger{&recorder{}} // gossip's own warnings are not the store's
	g, err := gossip.NewCluster(gc)
	if err != nil {
		return err
	}
	if err = startGossip(g); err != nil {
		return err
	}
	o := configstore.Options{
		Path: n.path, Cluster: g, OnChange: n.ch.add, Logger: recLogger{n.log},
		SyncInterval: time.Hour, // the tests that rely on periodic rounds ask for them
	}
	if n.cfg.store != nil {
		n.cfg.store(&o)
	}
	s, err := configstore.Open(o)
	if err != nil {
		g.Stop()
		return err
	}
	n.mu.Lock()
	n.g, n.s = g, s
	n.mu.Unlock()
	return nil
}

func startGossip(g *gossip.Cluster) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	g.Start()
	return nil
}

// stop closes the store and stops gossip (the node leaves the cluster).
func (n *tnode) stop() {
	n.mu.Lock()
	g, s := n.g, n.s
	n.g = nil
	n.mu.Unlock()
	if g == nil {
		return
	}
	if err := s.Close(); err != nil {
		n.tb.Errorf("close %s: %v", n.addr, err)
	}
	g.Stop()
}

// tcluster is a set of nodes.
type tcluster struct {
	t     testing.TB
	net   *testNet
	nodes []*tnode
}

// newCluster starts n nodes joined through the first and waits until every store sees the others.
func newCluster(t testing.TB, n int, cfgs ...nodeCfg) *tcluster {
	t.Helper()
	tc := &tcluster{t: t, net: newTestNet()}
	t.Cleanup(tc.close)
	for i := range n {
		var cfg nodeCfg
		if i < len(cfgs) {
			cfg = cfgs[i]
		} else if len(cfgs) > 0 {
			cfg = cfgs[len(cfgs)-1]
		}
		tc.add(cfg)
	}
	tc.waitPeers(tc.nodes...)
	return tc
}

// add starts one more node with an empty database and joins it to the running ones.
func (tc *tcluster) add(cfg nodeCfg) *tnode {
	tc.t.Helper()
	n := &tnode{
		tb: tc.t, net: tc.net, cfg: cfg, id: newUUID(), addr: freeAddr(),
		path: filepath.Join(tc.t.TempDir(), "config.db"), ch: &changes{}, log: &recorder{},
	}
	var seeds []string
	for _, m := range tc.nodes {
		if m.store() != nil {
			seeds = append(seeds, m.addr)
		}
	}
	tc.nodes = append(tc.nodes, n)
	n.boot(seeds)
	return n
}

// waitPeers waits until every one of nodes sees the others among them as peers.
func (tc *tcluster) waitPeers(nodes ...*tnode) {
	tc.t.Helper()
	waitFor(tc.t, waitMax, "every store to see the others", func() bool {
		for _, n := range nodes {
			if n.store().Stats().Peers != len(nodes)-1 {
				return false
			}
		}
		return true
	})
}

func (tc *tcluster) close() {
	for _, n := range tc.nodes {
		n.stop()
	}
	for _, n := range tc.nodes {
		for _, l := range n.log.all() {
			tc.t.Errorf("%s logged: %s", n.addr, l)
		}
	}
}

// ---- store helpers ----------------------------------------------------------------------------------------------

func put(t testing.TB, s *configstore.Store, kv ...string) {
	t.Helper()
	err := s.Update(context.Background(), func(tx *configstore.Tx) error {
		for i := 0; i < len(kv); i += 2 {
			tx.Put(kv[i], []byte(kv[i+1]))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
}

func del(t testing.TB, s *configstore.Store, keys ...string) {
	t.Helper()
	err := s.Update(context.Background(), func(tx *configstore.Tx) error {
		for _, k := range keys {
			tx.Delete(k)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// value returns key's value in s; "" with false when it has no live record.
func value(s *configstore.Store, key string) (string, bool) {
	r, ok := s.Get(key)
	return string(r.Value), ok
}

// dump renders every record of s, tombstones too, for comparing stores.
func dump(s *configstore.Store) string {
	var b strings.Builder
	for _, r := range s.All() {
		fmt.Fprintf(&b, "%s=%q v%d %s del=%v\n", r.Key, r.Value, r.Version, r.Origin, r.Deleted)
	}
	return b.String()
}

// waitSame waits until every node's store holds the same records, tombstones and versions included.
func waitSame(t testing.TB, nodes ...*tnode) {
	t.Helper()
	deadline := time.Now().Add(waitMax)
	for {
		first := dump(nodes[0].store())
		same := true
		for _, n := range nodes[1:] {
			if dump(n.store()) != first {
				same = false
				break
			}
		}
		if same {
			return
		}
		if time.Now().After(deadline) {
			for _, n := range nodes {
				t.Logf("%s:\n%s", n.addr, dump(n.store()))
			}
			t.Fatalf("stores did not converge within %v", waitMax)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
