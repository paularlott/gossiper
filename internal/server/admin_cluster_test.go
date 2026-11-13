package server

import (
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// adminCluster starts n nodes with a database each and the API, joined in one cluster. It returns the
// nodes and their settings, so a test can restart one.
func adminCluster(t *testing.T, n int) ([]*node, []Settings) {
	t.Helper()
	binds := make([]string, n)
	for i := range binds {
		binds[i] = freePort(t, "both")
	}
	var nodes []*node
	var sets []Settings
	for i := range n {
		s := adminSettings(t, "")
		s.Database = filepath.Join(t.TempDir(), fmt.Sprintf("node%d.db", i))
		s.ClusterBind = binds[i]
		s.ClusterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
		for j, b := range binds {
			if j != i {
				s.ClusterPeers = append(s.ClusterPeers, b)
			}
		}
		sets = append(sets, s)
		nodes = append(nodes, startNode(t, s))
	}
	eventually(t, 15*time.Second, "the nodes to meet", func() bool {
		for _, nd := range nodes {
			if nd.gossip.NumAliveNodes() < n {
				return false
			}
		}
		return true
	})
	return nodes, sets
}

// serves reports whether node nd serves tenant d's hub on its host.
func serves(t *testing.T, nd *node, d tn) bool {
	return hubStatus(t, nd.base, d.host, d.token(t, nil, []string{"*"})) == 200
}

// gone reports whether node nd no longer serves tenant d.
func gone(t *testing.T, nd *node, d tn) bool {
	return hubStatus(t, nd.base, d.host, d.token(t, nil, []string{"*"})) == 404
}

// A tenant added through any node's API is served by every node, across the cluster, and isolated from the others;
// a change and a delete reach every node too.
func TestAdminAPIClusterReplicates(t *testing.T) {
	nodes, _ := adminCluster(t, 3)
	a, b := newTN(t, "alpha", false, false), newTN(t, "bravo", false, false)
	api(t, nodes[0].base, "POST", "/api/tenants", a.spec(t), 201)
	api(t, nodes[1].base, "POST", "/api/tenants", b.spec(t), 201)
	for _, nd := range nodes {
		eventually(t, 10*time.Second, "every node to serve both tenants", func() bool { return serves(t, nd, a) && serves(t, nd, b) })
	}
	// Mercure across nodes, isolated: a subscriber of a on node 3, publishes of a and b on node 1.
	sa := openStream(t, nodes[2].base, a.host, a.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	sb := openStream(t, nodes[2].base, b.host, b.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	eventually(t, 10*time.Second, "updates across the cluster", func() bool {
		mustPost(t, nodes[0].base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"a"}})
		mustPost(t, nodes[0].base, b.host, b.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"b"}})
		time.Sleep(100 * time.Millisecond)
		return len(sa.real()) > 0 && len(sb.real()) > 0
	})
	for _, e := range sa.real() {
		if e != "a" {
			t.Fatalf("tenant a's subscriber got %q", e)
		}
	}
	for _, e := range sb.real() {
		if e != "b" {
			t.Fatalf("tenant b's subscriber got %q", e)
		}
	}
	// The list is the same everywhere.
	for _, nd := range nodes {
		if l := api(t, nd.base, "GET", "/api/tenants", nil, 200)["tenants"].([]any); len(l) != 2 {
			t.Errorf("node %s lists %d tenants", nd.base, len(l))
		}
	}
	// Deleted through node 2: gone everywhere.
	api(t, nodes[1].base, "DELETE", "/api/tenants/alpha", nil, 204)
	for _, nd := range nodes {
		eventually(t, 10*time.Second, "tenant a to be gone everywhere", func() bool { return gone(t, nd, a) })
	}
	if !serves(t, nodes[0], b) {
		t.Error("deleting a dropped b")
	}
}

// A node that was down when tenants changed catches up when it returns, from its own database and the others'.
func TestAdminAPIClusterCatchUp(t *testing.T) {
	nodes, sets := adminCluster(t, 3)
	a, b, c := newTN(t, "alpha", false, false), newTN(t, "bravo", false, false), newTN(t, "charlie", false, false)
	api(t, nodes[0].base, "POST", "/api/tenants", a.spec(t), 201)
	api(t, nodes[0].base, "POST", "/api/tenants", b.spec(t), 201)
	eventually(t, 10*time.Second, "node 3 to serve a and b", func() bool { return serves(t, nodes[2], a) && serves(t, nodes[2], b) })

	if err := nodes[2].stop(); err != nil {
		t.Fatal(err)
	}
	api(t, nodes[0].base, "POST", "/api/tenants", c.spec(t), 201)   // added while it is down
	api(t, nodes[1].base, "DELETE", "/api/tenants/alpha", nil, 204) // and one deleted
	time.Sleep(200 * time.Millisecond)

	back := startNode(t, sets[2])
	// From its own database at once: b; from the others within a sync: c, and a gone.
	if !serves(t, back, b) {
		t.Error("the returning node does not serve what its database holds")
	}
	eventually(t, 20*time.Second, "the returning node to catch up", func() bool {
		return serves(t, back, c) && gone(t, back, a)
	})
}

// Two nodes cut off from each other change the same tenant: once they meet again, every node serves the same,
// later change.
func TestAdminAPIClusterConcurrentChanges(t *testing.T) {
	nodes, _ := adminCluster(t, 2)
	a := newTN(t, "alpha", false, false)
	api(t, nodes[0].base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 10*time.Second, "both nodes to serve a", func() bool { return serves(t, nodes[0], a) && serves(t, nodes[1], a) })
	first := a.spec(t)
	first.Hosts = []string{"first.test"}
	second := a.spec(t)
	second.Hosts = []string{"second.test"}
	api(t, nodes[0].base, "PUT", "/api/tenants/alpha", first, 200)
	api(t, nodes[1].base, "PUT", "/api/tenants/alpha", second, 200)
	host := func(nd *node) string {
		for _, h := range []string{"first.test", "second.test"} {
			if code := hubStatus(t, nd.base, h, a.token(t, nil, []string{"*"})); code == 200 {
				return h
			}
		}
		return ""
	}
	eventually(t, 15*time.Second, "both nodes to agree", func() bool {
		h0, h1 := host(nodes[0]), host(nodes[1])
		return h0 != "" && h0 == h1
	})
}
