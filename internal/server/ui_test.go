package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// uiStatusOf fetches /ui/status.json from base, unauthenticated, and returns the raw body and its decoding.
func uiStatusOf(t *testing.T, base string) (string, uiStatusJSON) {
	t.Helper()
	resp, err := http.Get(base + "/ui/status.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("/ui/status.json: %d %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache control %q", cc)
	}
	var st uiStatusJSON
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return string(b), st
}

// The status page and its JSON are on the admin listener only, without a login; admin-ui=false turns them off, and
// without admin-listen they are not served at all (the admin routes are then on the public listener).
func TestUIOnlyOnAdminListener(t *testing.T) {
	s := adminSettings(t, "")
	s.AdminListen = "127.0.0.1:0"
	n := startNode(t, s)
	for _, path := range []string{"/", "/ui/status.json", "/ui/assets/x.js"} {
		if got := status(t, n.base+path); got != http.StatusNotFound {
			t.Errorf("public %s: %d, want 404", path, got)
		}
	}
	if got := status(t, n.admin+"/ui/status.json"); got != http.StatusOK {
		t.Errorf("admin /ui/status.json without a token: %d", got)
	}
	code, body := get(t, n.admin+"/")
	switch code {
	case http.StatusOK:
		if !strings.Contains(body, `x-data="status"`) {
			t.Errorf("/ is not the status page")
		}
	case http.StatusNotFound: // the web assets are not built: a plain message, and the JSON is still served
		if !strings.Contains(body, "/ui/status.json") {
			t.Errorf("unbuilt page: %q", body)
		}
	default:
		t.Errorf("admin /: %d", code)
	}
	// The admin listener's other routes are as they were; / is the page itself, nothing below it.
	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200, "/api/status": 401, "/nothing": 404,
		"/.well-known/mercure": 404} {
		if got := status(t, n.admin+path); got != want {
			t.Errorf("admin %s: %d, want %d", path, got, want)
		}
	}
	if resp, err := http.Post(n.admin+"/ui/status.json", "application/json", nil); err != nil {
		t.Fatal(err)
	} else if resp.Body.Close(); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /ui/status.json: %d", resp.StatusCode)
	}

	// Switched off.
	off := s
	off.AdminUI = false
	m := startNode(t, off)
	for _, path := range []string{"/", "/ui/status.json"} {
		if got := status(t, m.admin+path); got != http.StatusNotFound {
			t.Errorf("admin-ui off: admin %s: %d", path, got)
		}
	}
	if got := status(t, m.admin+"/healthz"); got != http.StatusOK {
		t.Errorf("admin-ui off: /healthz %d", got)
	}

	// No admin listener: the admin API is on the public listener, the status page nowhere.
	pub := s
	pub.AdminListen = ""
	p := startNode(t, pub)
	for _, path := range []string{"/", "/ui/status.json"} {
		if got := status(t, p.base+path); got != http.StatusNotFound {
			t.Errorf("without admin-listen: %s %d", path, got)
		}
	}
}

// The status page and its assets: a strict CSP, nothing from another origin, and the assets gzipped for a browser
// and plain for a client without gzip.
func TestUIPageAndAssets(t *testing.T) {
	s := settings()
	s.AdminListen = "127.0.0.1:0"
	n := startNode(t, s)
	resp, err := http.Get(n.admin + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	if resp.StatusCode == 404 {
		t.Skip("the web assets are not built (task webassets)")
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("/: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("CSP %q allows eval or inline scripts", csp)
	}
	if strings.Contains(body, "https://") || strings.Contains(body, "http://") {
		t.Errorf("the page references another origin")
	}
	if !strings.Contains(body, `<html lang="en" class="dark">`) {
		t.Errorf("the page does not start dark")
	}
	var assets []string
	for rest := body; ; {
		i := strings.Index(rest, "/ui/assets/")
		if i < 0 {
			break
		}
		rest = rest[i:]
		assets = append(assets, rest[:strings.IndexByte(rest, '"')])
		rest = rest[1:]
	}
	if !slices.ContainsFunc(assets, func(a string) bool { return strings.HasSuffix(a, ".js") }) ||
		!slices.ContainsFunc(assets, func(a string) bool { return strings.HasSuffix(a, ".css") }) {
		t.Fatalf("the page names no script and stylesheet: %v", assets)
	}
	tr := &http.Transport{DisableCompression: true}
	defer tr.CloseIdleConnections()
	for _, asset := range assets {
		req, _ := http.NewRequest("GET", n.admin+asset, nil)
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		gz, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || len(gz) < 2 || gz[0] != 0x1f || gz[1] != 0x8b {
			t.Errorf("%s gzipped: %d %q", asset, resp.StatusCode, resp.Header.Get("Content-Encoding"))
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
			t.Errorf("%s: cache control %q", asset, resp.Header.Get("Cache-Control"))
		}
		req, _ = http.NewRequest("GET", n.admin+asset, nil)
		resp, err = (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		plain, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" || len(plain) <= len(gz) {
			t.Errorf("%s plain: %d %q %d bytes", asset, resp.StatusCode, resp.Header.Get("Content-Encoding"), len(plain))
		}
		if strings.HasSuffix(asset, ".js") && !strings.Contains(string(plain), "/ui/status.json") {
			t.Errorf("%s does not poll /ui/status.json", asset)
		}
	}
	for _, path := range []string{"/ui/assets/nothing.js", "/ui/assets/..%2Fui%2Findex.html", "/ui/assets/.gitkeep"} {
		if got := status(t, n.admin+path); got != 404 {
			t.Errorf("%s: %d", path, got)
		}
	}
}

// A single hub: one node (this one), no tenants, no database; readiness follows /readyz.
func TestUIStatusSingleHub(t *testing.T) {
	s := settings()
	s.AdminListen = "127.0.0.1:0"
	n := startNode(t, s)
	publish(t, n.base, "https://example.com/books/1", "hello")
	_, st := uiStatusOf(t, n.admin)
	if st.Mode != "single" || st.MultiTenant || st.Tenants.Total != 0 || st.Store != nil || st.ReplicationDropped != nil {
		t.Errorf("single hub: %+v", st)
	}
	if st.Readiness != "ready" || st.Version == "" || st.Node == "" || st.Node != n.Hub.NodeID() {
		t.Errorf("status: %+v", st)
	}
	if st.NodeCount != 1 || st.NodesAlive != 1 || len(st.Nodes) != 1 || !st.Nodes[0].Local || st.Nodes[0].ID != st.Node {
		t.Errorf("nodes: %+v", st.Nodes)
	}
	if st.Hub.Published != 1 || st.Hub.HistoryUpdates != 1 || st.Hub.HistoryBytes <= 0 {
		t.Errorf("hub: %+v", st.Hub)
	}
	if _, err := time.Parse(time.RFC3339Nano, st.Now); err != nil {
		t.Errorf("now %q", st.Now)
	}
	n.draining.Store(true)
	defer n.draining.Store(false)
	if _, st := uiStatusOf(t, n.admin); st.Readiness != "draining" {
		t.Errorf("draining: %q", st.Readiness)
	}
	if code, body := get(t, n.admin+"/readyz"); code != 503 || body != "draining\n" {
		t.Errorf("/readyz while draining: %d %q", code, body)
	}
}

// uiTopic is a topic the leak test subscribes to and publishes on.
const uiTopic = "https://secret-topic.example/private/42"

// The JSON is for anyone on the admin network: it must never carry tenant names or hosts, keys or tokens, topics,
// client or node addresses, nor settings. Tenants from the file and the database, a subscriber and publishes, in a
// cluster (whose node addresses are known).
func TestUIStatusLeaksNothing(t *testing.T) {
	fileTN := newTN(t, "filetenantzulu", true, false)
	dbTN := newTN(t, "dbtenantyankee", false, false)
	binds := []string{freePort(t, "both"), freePort(t, "both")}
	var nodes []*node
	var sets []Settings
	for i := range binds {
		s := adminSettings(t, writeTenants(t, fileTN.spec(t)))
		s.AdminListen = "127.0.0.1:0"
		s.ClusterBind, s.ClusterKey, s.ClusterPeers = binds[i], testClusterKey, binds
		s.ClusterAdvertise = binds[i]
		s.Database = filepath.Join(t.TempDir(), fmt.Sprintf("leak%d.db", i))
		sets = append(sets, s)
		nodes = append(nodes, startNode(t, s))
	}
	eventually(t, 15*time.Second, "the nodes to meet", func() bool {
		return nodes[0].gossip.NumAliveNodes() == 2 && nodes[1].gossip.NumAliveNodes() == 2
	})
	api(t, nodes[0].admin, "POST", "/api/tenants", dbTN.spec(t), 201)
	eventually(t, 10*time.Second, "the tenant on both nodes", func() bool { return serves(t, nodes[1], dbTN) })
	sub := openStream(t, nodes[0].base, dbTN.host, dbTN.token(t, nil, []string{"*"}), url.Values{"topic": {uiTopic}}, "")
	defer sub.cancel()
	eventually(t, 10*time.Second, "the update delivered", func() bool {
		mustPost(t, nodes[1].base, dbTN.host, dbTN.token(t, []string{"*"}, nil), url.Values{"topic": {uiTopic}, "data": {"x"}})
		time.Sleep(50 * time.Millisecond)
		return len(sub.real()) > 0
	})
	mustPost(t, nodes[0].base, fileTN.host, fileTN.token(t, []string{"*"}, nil), url.Values{"topic": {uiTopic}, "data": {"y"}})

	for i, nd := range nodes {
		body, st := uiStatusOf(t, nd.admin)
		s := sets[i]
		forbidden := []string{
			fileTN.name, fileTN.host, fileTN.secret, dbTN.name, dbTN.host, dbTN.secret, // tenants
			"filetenant", "dbtenant", ".test", // and any part of them
			apiToken, s.ClusterKey, s.PublisherKey, secret, // keys and tokens
			uiTopic, "secret-topic", // topics
			"127.0.0.1", "localhost", s.ClusterBind, // addresses
			s.Database, filepath.Base(s.Database), s.TenantsFile, filepath.Base(s.TenantsFile), // settings
		}
		for _, b := range binds {
			_, port, _ := net.SplitHostPort(b)
			forbidden = append(forbidden, b, ":"+port)
		}
		for _, f := range forbidden {
			if f != "" && strings.Contains(body, f) {
				t.Errorf("node %d: /ui/status.json carries %q:\n%s", i, f, body)
			}
		}
		// Exactly the fields below, and no more: a new one is reviewed here.
		var raw map[string]json.RawMessage
		_ = json.Unmarshal([]byte(body), &raw)
		var keys []string
		for k := range raw {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		want := []string{"build_date", "hub", "mode", "multi_tenant", "node", "node_count", "nodes", "nodes_alive", "now",
			"readiness", "replication_dropped", "started", "store", "tenants", "uptime_seconds", "version"}
		if !slices.Contains(keys, "build_date") { // set at link time only
			want = slices.DeleteFunc(want, func(k string) bool { return k == "build_date" })
		}
		if !slices.Equal(keys, want) {
			t.Errorf("node %d: fields %v, want %v", i, keys, want)
		}
		var nodesRaw []map[string]any
		_ = json.Unmarshal(raw["nodes"], &nodesRaw)
		for _, nr := range nodesRaw {
			for k := range nr {
				if k != "id" && k != "state" && k != "since" && k != "local" {
					t.Errorf("node %d: a node carries %q", i, k)
				}
			}
		}
		if st.Tenants != (uiTenants{Total: 2, File: 1, Database: 1}) || !st.MultiTenant {
			t.Errorf("node %d: tenants %+v", i, st.Tenants)
		}
		if st.Hub.Subscribers != uint64(1-i) || st.Hub.Published == 0 || st.Hub.Delivered == 0 && i == 0 {
			t.Errorf("node %d: hub %+v", i, st.Hub)
		}
	}
}

// In a cluster, every node lists every node by id, with its state, and itself as local; the counts follow a node
// that leaves.
func TestUIStatusCluster(t *testing.T) {
	nodes := clusterNodes(t, 3, func(_ int, s *Settings) { s.AdminListen = "127.0.0.1:0" })
	ids := map[string]bool{}
	for _, nd := range nodes {
		ids[nd.gossip.LocalNode().ID.String()] = true
	}
	for i, nd := range nodes {
		eventually(t, 10*time.Second, "the cluster in the status", func() bool {
			_, st := uiStatusOf(t, nd.admin)
			return st.NodeCount == 3 && st.NodesAlive == 3 && st.Readiness == "ready"
		})
		_, st := uiStatusOf(t, nd.admin)
		if st.Mode != "cluster" || st.Node != nd.gossip.LocalNode().ID.String() || st.ReplicationDropped == nil {
			t.Errorf("node %d: %+v", i, st)
		}
		locals := 0
		for j, n := range st.Nodes {
			if !ids[n.ID] || n.State != "alive" {
				t.Errorf("node %d: %+v", i, n)
			}
			if n.Since == "" {
				t.Errorf("node %d: node %s has no since", i, n.ID)
			}
			if n.Local {
				locals++
				if j != 0 || n.ID != st.Node {
					t.Errorf("node %d: the local node is %s at %d", i, n.ID, j)
				}
			}
		}
		if locals != 1 {
			t.Errorf("node %d: %d local nodes", i, locals)
		}
	}
	// A node leaves: the others see it go.
	gone := nodes[2].gossip.LocalNode().ID.String()
	if err := nodes[2].stop(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, "the node to have left", func() bool {
		_, st := uiStatusOf(t, nodes[0].admin)
		if st.NodesAlive != 2 {
			return false
		}
		for _, n := range st.Nodes {
			if n.ID == gone {
				return n.State != "alive"
			}
		}
		return true // forgotten
	})
}
