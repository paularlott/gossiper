//go:build failover

package failover

import (
	"strconv"
	"testing"
	"time"
)

// A 3-node cluster at rest: Mercure subscribers on every node receive what is published on any node.
func TestSteadyState(t *testing.T) {
	c := newCluster(t, clusterOpts{size: 3})
	m := startMeshClients(t, c)
	m.warm(t, c.nodes, 20*time.Second)

	const n = 100
	hc := newHTTP()
	for i, node := range c.nodes {
		for seq := 1; seq <= n; seq++ {
			if _, _, err := mercurePublish(hc, []string{node.httpURL()}, "s"+strconv.Itoa(i)+"-"+strconv.Itoa(seq)); err != nil {
				t.Fatal(err)
			}
		}
	}
	waitFor(t, 20*time.Second, "every subscriber has every message", func() bool {
		for j := range c.nodes {
			datas := m.sse[j].datas()
			for i := range c.nodes {
				for seq := 1; seq <= n; seq++ {
					if !datas["s"+strconv.Itoa(i)+"-"+strconv.Itoa(seq)] {
						return false
					}
				}
			}
		}
		return true
	})
	for j := range c.nodes {
		if _, _, d := m.sse[j].snapshot(); d != 0 {
			t.Errorf("sse subscriber %d saw %d duplicates", j, d)
		}
		if v, _ := c.nodes[j].metric("gossiper_cluster_nodes"); v == 0 {
			t.Errorf("node %d: gossiper_cluster_nodes = 0", j)
		}
	}
	for _, node := range c.nodes {
		counts, lines := node.logLevels(0)
		if counts["ERROR"] > 0 {
			t.Errorf("node %d logged errors: %v", node.idx, lines["ERROR"])
		}
	}
}
