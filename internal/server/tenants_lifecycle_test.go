package server

// DELETE /api/tenants/{tenant}: everything a tenant owns goes with it, and a tenant created again under the same
// name starts empty.

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

// historyRows counts the rows of the tenant in the history database file at path (opened read-only beside the
// server's own connection; WAL lets both read).
func historyRows(t *testing.T, path, tenant string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM history WHERE tenant = ?`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// replay opens a stream of every topic of d at base from "earliest", waits for the replay, and returns its events.
func replay(t *testing.T, base string, d tn) []string {
	t.Helper()
	s := openStream(t, base, d.host, d.token(t, nil, []string{"*"}), url.Values{"topic": {"*"}}, "earliest")
	time.Sleep(400 * time.Millisecond)
	s.cancel()
	<-s.closed
	return s.real()
}

// DELETE immediately followed by POST of the same name (a scripted "reset tenant"): the old hub goes, its streams
// closed, its history not replayed to the new tenant, though watchStore takes both changes together and the spec is
// the same (the record's creation time differs).
func TestDeleteThenRecreateSameSpecStartsAfresh(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := newTN(t, "alpha", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "alpha served", func() bool { return serves(t, n, a) })
	s := openStream(t, n.base, a.host, a.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	time.Sleep(100 * time.Millisecond)
	mustPost(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"before-delete"}})
	eventually(t, 5*time.Second, "the update", func() bool { return len(s.real()) == 1 })

	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 204)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	time.Sleep(500 * time.Millisecond)

	select {
	case <-s.closed:
	default:
		t.Error("a subscriber stream of the deleted tenant is still open (and now receives the new tenant's updates)")
	}
	if got := replay(t, n.base, a); slices.Contains(got, "before-delete") {
		t.Errorf("the re-created tenant replays the deleted tenant's history: %q", got)
	}
}

// The same with new keys: taken together, the delete and the create are not a change of keys, which would hand the
// old hub's history to the new one.
func TestDeleteThenRecreateNewKeysStartsAfresh(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := newTN(t, "alpha", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "alpha served", func() bool { return serves(t, n, a) })
	mustPost(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"old-owner-secret"}})

	b := a
	b.secret = "a-different-owner-secret-0123456789abcdef"
	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 204)
	api(t, n.base, "POST", "/api/tenants", b.spec(t), 201)
	eventually(t, 5*time.Second, "the new keys", func() bool { return serves(t, n, b) })

	if got := replay(t, n.base, b); slices.Contains(got, "old-owner-secret") {
		t.Errorf("the re-created tenant (new keys) replays the deleted tenant's history: %q", got)
	}
}

// Delete, wait for it to apply, re-create: the hub, its streams, its in-memory and its stored history are gone, and
// the new tenant starts empty (single node, history database).
func TestDeleteThenRecreateAfterApply(t *testing.T) {
	s := adminSettings(t, "")
	s.HistoryDB = filepath.Join(t.TempDir(), "history.db")
	n := startNode(t, s)
	a := newTN(t, "alpha", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "alpha served", func() bool { return serves(t, n, a) })
	st := openStream(t, n.base, a.host, a.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	mustPost(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"old"}})
	eventually(t, 5*time.Second, "rows stored", func() bool { return historyRows(t, s.HistoryDB, "alpha") == 1 })

	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 204)
	select {
	case <-st.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
	}
	eventually(t, 5*time.Second, "host gone", func() bool { return gone(t, n, a) })
	eventually(t, 5*time.Second, "rows dropped", func() bool { return historyRows(t, s.HistoryDB, "alpha") == 0 })
	if v, _ := metricValue(metricsText(t, n.base), "gossiper_history_updates"); v != "0" {
		t.Errorf("history_updates after delete: %s", v)
	}

	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "alpha served again", func() bool { return serves(t, n, a) })
	if got := replay(t, n.base, a); len(got) != 0 {
		t.Errorf("the re-created tenant replays: %q", got)
	}
}

// A node down while a tenant is deleted and created again (same spec) never sees the tombstone, only the new record:
// its creation time tells the node the tenant is new, so it drops the stored history of the former one, and the node
// that did the delete ignores the former tenant's updates the returning node sends it (stamped before the creation).
func TestOfflinePeerDropsDeletedTenantHistory(t *testing.T) {
	binds := []string{freePort(t, "both"), freePort(t, "both")}
	var sets []Settings
	for i := range 2 {
		s := adminSettings(t, "")
		s.NodeID = uuid.NewString()
		s.Database = filepath.Join(t.TempDir(), fmt.Sprintf("node%d.db", i))
		s.HistoryDB = filepath.Join(t.TempDir(), fmt.Sprintf("hist%d.db", i))
		s.ClusterBind = binds[i]
		s.ClusterKey = testClusterKey
		s.ClusterPeers = []string{binds[1-i]}
		sets = append(sets, s)
	}
	n0, n1 := startNode(t, sets[0]), startNode(t, sets[1])
	eventually(t, 15*time.Second, "the nodes to meet", func() bool {
		return n0.gossip.NumAliveNodes() == 2 && n1.gossip.NumAliveNodes() == 2
	})
	a := newTN(t, "alpha", false, false)
	api(t, n0.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 10*time.Second, "both serve alpha", func() bool { return serves(t, n0, a) && serves(t, n1, a) })
	mustPost(t, n0.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"deleted-tenant-data"}})
	eventually(t, 10*time.Second, "node 1 stored it", func() bool { return historyRows(t, sets[1].HistoryDB, "alpha") == 1 })

	if err := n1.stop(); err != nil {
		t.Fatal(err)
	}
	api(t, n0.base, "DELETE", "/api/tenants/alpha", nil, 204)
	eventually(t, 5*time.Second, "gone on node 0", func() bool { return gone(t, n0, a) })
	eventually(t, 5*time.Second, "node 0 dropped its rows", func() bool { return historyRows(t, sets[0].HistoryDB, "alpha") == 0 })
	api(t, n0.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "re-created on node 0", func() bool { return serves(t, n0, a) })
	if got := replay(t, n0.base, a); len(got) != 0 {
		t.Fatalf("precondition: node 0's new tenant replays %q", got)
	}

	n1 = startNode(t, sets[1])
	eventually(t, 15*time.Second, "node 1 back, synced", func() bool {
		st := api(t, n1.base, "GET", "/api/status", nil, 200)
		_, synced := st["last_sync"]
		return synced && n1.gossip.NumAliveNodes() == 2 && serves(t, n1, a)
	})
	time.Sleep(time.Second) // resyncs and backfill settle
	if got := replay(t, n1.base, a); slices.Contains(got, "deleted-tenant-data") {
		t.Errorf("node 1 replays the deleted tenant's history to the re-created tenant: %q", got)
	}
	if got := replay(t, n0.base, a); slices.Contains(got, "deleted-tenant-data") {
		t.Errorf("node 0 got the deleted tenant's history back from node 1: %q", got)
	}
}

// A database record shadowed by a tenants-file tenant of the same name (created through the API before the file
// named it, or on a node with another file) can be deleted, so it does not come back when the file drops the name.
func TestShadowedDatabaseTenantCanBeDeleted(t *testing.T) {
	s := adminSettings(t, "")
	n := startNode(t, s)
	db := newTN(t, "alpha", false, false)
	api(t, n.base, "POST", "/api/tenants", db.spec(t), 201)
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}

	file := tn{name: "alpha", host: "alpha-file.test", secret: "file-secret-alpha-0123456789abcdef0123456789"}
	s.TenantsFile = writeTenants(t, file.spec(t))
	n = startNode(t, s)
	code, out := call(t, n.base, "DELETE", "/api/tenants/alpha", apiToken, nil)
	if code == 409 {
		t.Errorf("the database record shadowed by the file cannot be deleted: %d %v", code, out)
	}
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}
	s.TenantsFile = ""
	n = startNode(t, s)
	if serves(t, n, db) {
		t.Error("the database tenant the operator tried to delete is served again once the file drops the name")
	}
}

// Prometheus counters never decrease: a deleted tenant's totals stay in /metrics.
func TestMetricsCountersSurviveDelete(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a, b := newTN(t, "alpha", false, false), newTN(t, "bravo", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	api(t, n.base, "POST", "/api/tenants", b.spec(t), 201)
	eventually(t, 5*time.Second, "served", func() bool { return serves(t, n, a) && serves(t, n, b) })
	for range 3 {
		mustPost(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"x"}})
	}
	published := func() int {
		v, _ := metricValue(metricsText(t, n.base), "gossiper_published_total")
		i, _ := strconv.Atoi(v)
		return i
	}
	before := published()
	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 204)
	eventually(t, 5*time.Second, "gone", func() bool { return gone(t, n, a) })
	if after := published(); after < before {
		t.Errorf("gossiper_published_total went from %d to %d on deleting a tenant", before, after)
	}
}

// A deleted tenant's HMAC secrets do not stay in the database file (secure_delete): not in free pages after a delete
// and a checkpoint (the server stopped).
func TestDeletedTenantSecretLeavesDisk(t *testing.T) {
	s := adminSettings(t, "")
	n := startNode(t, s)
	a := newTN(t, "alpha", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 204)
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{s.Database, s.Database + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte(a.secret)) {
			t.Errorf("%s still holds the deleted tenant's HMAC secret", filepath.Base(f))
		}
	}
}

// Delete on a cluster with both nodes up: the peer closes its streams and drops its stored history too.
func TestClusterDeleteDropsPeerState(t *testing.T) {
	binds := []string{freePort(t, "both"), freePort(t, "both")}
	var nodes []*node
	var hist []string
	for i := range 2 {
		s := adminSettings(t, "")
		s.NodeID = uuid.NewString()
		s.Database = filepath.Join(t.TempDir(), fmt.Sprintf("node%d.db", i))
		s.HistoryDB = filepath.Join(t.TempDir(), fmt.Sprintf("hist%d.db", i))
		s.ClusterBind = binds[i]
		s.ClusterKey = testClusterKey
		s.ClusterPeers = []string{binds[1-i]}
		hist = append(hist, s.HistoryDB)
		nodes = append(nodes, startNode(t, s))
	}
	eventually(t, 15*time.Second, "the nodes to meet", func() bool {
		return nodes[0].gossip.NumAliveNodes() == 2 && nodes[1].gossip.NumAliveNodes() == 2
	})
	a := newTN(t, "alpha", false, false)
	api(t, nodes[0].base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 10*time.Second, "both serve alpha", func() bool { return serves(t, nodes[0], a) && serves(t, nodes[1], a) })
	st := openStream(t, nodes[1].base, a.host, a.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	mustPost(t, nodes[0].base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"x"}})
	eventually(t, 10*time.Second, "stored on both", func() bool {
		return historyRows(t, hist[0], "alpha") == 1 && historyRows(t, hist[1], "alpha") == 1
	})
	api(t, nodes[0].base, "DELETE", "/api/tenants/alpha", nil, 204)
	select {
	case <-st.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the peer's stream did not end")
	}
	eventually(t, 10*time.Second, "rows dropped on both", func() bool {
		return historyRows(t, hist[0], "alpha") == 0 && historyRows(t, hist[1], "alpha") == 0
	})
	for _, nd := range nodes {
		if l := api(t, nd.base, "GET", "/api/tenants", nil, 200)["tenants"].([]any); len(l) != 0 {
			t.Errorf("%s still lists %v", nd.base, l)
		}
	}
}

// POST without a name is refused, as the OpenAPI document's NewTenantInput says (name required).
func TestPostWithoutNameRefused(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	code, out := call(t, n.base, "POST", "/api/tenants", apiToken, map[string]any{"hosts": []string{"n.test"},
		"mercure": map[string]any{"publisher_key": "no-name-secret-0123456789abcdef0123456789"}})
	if code != 400 {
		t.Errorf("POST without a name: %d %v, want 400", code, out)
	}
}
