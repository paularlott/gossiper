//go:build failover

package failover

import (
	"strconv"
	"testing"
	"time"
)

// meshClients is a Mercure subscriber on every node, each preferring its own node and falling back to the others.
type meshClients struct {
	cluster *cluster
	sse     []*sseClient
}

func startMeshClients(t *testing.T, c *cluster) *meshClients {
	t.Helper()
	m := &meshClients{cluster: c}
	for i := range c.nodes {
		m.sse = append(m.sse, startSSE("sse"+strconv.Itoa(i), c.httpURLs(i)))
	}
	t.Cleanup(func() {
		for _, s := range m.sse {
			s.stop()
		}
	})
	waitFor(t, 10*time.Second, "SSE clients connected", func() bool {
		for _, s := range m.sse {
			if !s.isConnected() {
				return false
			}
		}
		return true
	})
	return m
}

// warm publishes probes on every node until every subscriber has seen one from every node: the interest and the
// history are known cluster-wide.
func (m *meshClients) warm(t *testing.T, nodes []*node, timeout time.Duration) {
	t.Helper()
	hc := newHTTP()
	for _, n := range nodes {
		i := n.idx
		waitFor(t, timeout, "warm-up probes from node "+n.id, func() bool {
			mercurePublish(hc, []string{n.httpURL()}, "warm"+strconv.Itoa(i))
			time.Sleep(100 * time.Millisecond)
			for j := range m.sse {
				if !m.cluster.nodes[j].alive() {
					continue
				}
				if !m.sse[j].datas()["warm"+strconv.Itoa(i)] {
					return false
				}
			}
			return true
		})
	}
}
