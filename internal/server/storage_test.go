package server

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// History persistence needs the database to write to, and a flush interval above 0.
func TestHistoryPersistRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		mod  func(*Settings)
		want string
	}{
		"without a database": {func(s *Settings) { s.Database = "" }, "set database"},
		"flush of 0s":        {func(s *Settings) { s.HistoryFlush = "0s" }, "history flush"},
		"flush unreadable":   {func(s *Settings) { s.HistoryFlush = "soon" }, "history flush"},
	} {
		t.Run(name, func(t *testing.T) {
			s := settings()
			s.Database = filepath.Join(t.TempDir(), "gossiper.db")
			s.HistoryPersist = true
			tc.mod(&s)
			if srv, err := New(s, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				if srv != nil {
					srv.Close(t.Context())
				}
				t.Fatalf("%v, want an error saying %q", err, tc.want)
			}
		})
	}
}

// A database on its own does not make tenants: with the server's own keys it is a single hub, which writes its
// history there (all of it on a clean stop) and has it back after a restart.
func TestSingleHubPersistsHistory(t *testing.T) {
	s := settings()
	s.Database = filepath.Join(t.TempDir(), "gossiper.db")
	s.HistoryPersist, s.HistoryFlush = true, "20ms"
	s.HistoryFlush = "1h" // nothing written by the timer: the clean stop writes it all
	n := startNode(t, s)
	for i := range 3 {
		publish(t, n.base, "https://example.com/a", fmt.Sprint("u", i))
	}
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}
	n = startNode(t, s)
	st := openStream(t, n.base, "", "", url.Values{"topic": {"https://example.com/a"}}, "earliest")
	eventually(t, 5*time.Second, "the history back after a restart", func() bool {
		return slices.Equal(st.got(), []string{"u0", "u1", "u2"})
	})
}

// The tenants and the history are in one file.
func TestOneDatabaseFile(t *testing.T) {
	s := adminSettings(t, "")
	s.HistoryPersist, s.HistoryFlush = true, "20ms"
	n := startNode(t, s)
	a := newTN(t, "alpha", true, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "alpha served", func() bool { return serves(t, n, a) })
	mustPost(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"x"}})
	eventually(t, 5*time.Second, "the history row", func() bool { return historyRows(t, s.Database, "alpha") == 1 })
	db, err := sql.Open("sqlite", "file:"+s.Database+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tenants int
	if err := db.QueryRow(`SELECT count(*) FROM records WHERE key LIKE 'tenant/%' AND deleted = 0`).Scan(&tenants); err != nil || tenants != 1 {
		t.Fatalf("tenant records in the file: %d %v", tenants, err)
	}
}

// Without a database the admin API keeps the tenants in memory; in a cluster a node that restarts gets them back from
// the others.
func TestTenantsInMemoryAcrossCluster(t *testing.T) {
	binds := []string{freePort(t, "both"), freePort(t, "both")}
	var sets []Settings
	for i := range 2 {
		s := adminSettings(t, "")
		s.Database = ""
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
	if err := n1.stop(); err != nil {
		t.Fatal(err)
	}
	n1 = startNode(t, sets[1])
	eventually(t, 15*time.Second, "the restarted node serves alpha again", func() bool { return serves(t, n1, a) })
}

// A cluster whose nodes all stop at once has its history back when they start again: each node loads what it wrote.
func TestClusterHistoryPersistsThroughFullRestart(t *testing.T) {
	binds := []string{freePort(t, "both"), freePort(t, "both")}
	var sets []Settings
	for i := range 2 {
		s := adminSettings(t, "")
		s.Database = filepath.Join(t.TempDir(), fmt.Sprintf("node%d.db", i))
		s.HistoryPersist, s.HistoryFlush = true, "20ms"
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
	for i := range 3 {
		mustPost(t, n0.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {fmt.Sprint("u", i)}})
	}
	eventually(t, 10*time.Second, "both nodes wrote it", func() bool {
		return historyRows(t, sets[0].Database, "alpha") == 3 && historyRows(t, sets[1].Database, "alpha") == 3
	})
	for _, n := range []*node{n0, n1} {
		if err := n.stop(); err != nil {
			t.Fatal(err)
		}
	}
	n0, n1 = startNode(t, sets[0]), startNode(t, sets[1])
	for _, n := range []*node{n0, n1} {
		eventually(t, 15*time.Second, "the history back on "+n.base, func() bool {
			return slices.Equal(replay(t, n.base, a), []string{"u0", "u1", "u2"})
		})
	}
}
