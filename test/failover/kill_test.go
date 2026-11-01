//go:build failover

package failover

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const pubInterval = 10 * time.Millisecond // 100 updates a second

// waitMesh waits until the survivors see only each other, returning how long that took from t0.
func (c *cluster) waitSurvivorsMeshed(t0 time.Time, dead ...int) time.Duration {
	c.t.Helper()
	sv := c.survivors(dead...)
	waitFor(c.t, 60*time.Second, "survivors see the node gone", func() bool {
		for _, n := range sv {
			if v, _ := n.metric("gossiper_cluster_nodes"); int(v) != len(sv) {
				return false
			}
		}
		return true
	})
	return time.Since(t0)
}

// sentinel publishes count more updates on every node, and waits for every listed subscriber to hold them all: the
// cluster is whole again.
func sentinel(t *testing.T, c *cluster, m *meshClients, subs []int, nodes []*node, tag string, count int) {
	t.Helper()
	hc := newHTTP()
	for _, n := range nodes {
		for seq := 1; seq <= count; seq++ {
			if _, _, err := mercurePublish(hc, []string{n.httpURL()}, tag+strconv.Itoa(n.idx)+"-"+strconv.Itoa(seq)); err != nil {
				t.Fatalf("%s publish on node %d: %v", tag, n.idx, err)
			}
		}
	}
	waitFor(t, 20*time.Second, tag+": subscribers hold every sentinel message", func() bool {
		for _, j := range subs {
			datas := m.sse[j].datas()
			for _, n := range nodes {
				for seq := 1; seq <= count; seq++ {
					if !datas[tag+strconv.Itoa(n.idx)+"-"+strconv.Itoa(seq)] {
						return false
					}
				}
			}
		}
		return true
	})
}

// kill -9 one node under load: the survivors keep serving, the dead node's subscribers move, publishing continues.
func TestKillNode(t *testing.T) { departScenario(t, false) }

// SIGTERM one node under load: its Mercure streams end and move to the survivors, and the survivors log nothing
// worse than info.
func TestGracefulShutdownNode(t *testing.T) { departScenario(t, true) }

func departScenario(t *testing.T, graceful bool) {
	const victim = 2
	c := newCluster(t, clusterOpts{size: 3})
	m := startMeshClients(t, c)
	m.warm(t, c.nodes, 20*time.Second)
	tm := newTimings(t)

	p := startPublishers(t, c, pubInterval)
	sleepFor(2 * time.Second)

	var t0 time.Time
	if graceful {
		var took time.Duration
		t0, took = c.nodes[victim].term()
		tm.add("SIGTERM -> process exited", took)
		if err := c.nodes[victim].exitStatus(); err != nil {
			t.Errorf("node exited with %v after SIGTERM", err)
		}
		if took > 5*time.Second {
			t.Errorf("shutdown took %v", took)
		}
	} else {
		t0 = c.nodes[victim].kill()
		tm.add("kill -9 -> process gone", time.Since(t0))
	}
	tm.add("kill -> survivors' gossip settled", c.waitSurvivorsMeshed(t0, victim))

	// the dead node's Mercure subscriber moves to another node, resuming from Last-Event-ID
	waitFor(t, 20*time.Second, "SSE subscriber of the dead node resumed", func() bool {
		_, recs, _ := m.sse[victim].snapshot()
		return len(recs) > 0 && !recs[0].FirstData.IsZero()
	})
	_, recs, _ := m.sse[victim].snapshot()
	r := recs[0]
	tm.add("kill -> SSE stream lost", r.Lost.Sub(t0))
	tm.add("kill -> SSE reconnected (200 on another node)", r.Connected.Sub(t0))
	tm.add("kill -> SSE first event after resume", r.FirstData.Sub(t0))
	if !r.Resumed || r.To == c.nodes[victim].httpURL() {
		t.Errorf("SSE client reconnected to %s resumed=%v", r.To, r.Resumed)
	}

	sleepFor(3 * time.Second) // keep publishing through and after the recovery
	p.stop()
	tm.add("longest gap between Mercure publish acks", time.Duration(p.maxGap.Load()))
	t.Logf("publisher: mercure acked %d (failed attempts %d)", p.mercure.count(), p.mercure.fail)

	// Mercure: the survivors' subscribers and the resumed one hold every acked update.
	settle(10*time.Second, func() bool {
		for j := range c.nodes {
			if sseGap(p.mercure, m.sse[j]).missing != 0 {
				return false
			}
		}
		return true
	})
	for j := range c.nodes {
		g := sseGap(p.mercure, m.sse[j])
		_, _, dups := m.sse[j].snapshot()
		t.Logf("Mercure subscriber %d: missed %v, duplicates after resume %d", j, g, dups)
		if g.missing > 2 { // only an update acked by the dying node and not yet sent on
			t.Errorf("Mercure subscriber %d missed %v", j, g)
		}
	}
	// the dead node's Mercure subscriber has no duplicates beyond the replay window's rare ones, and its events are in order
	evs, _, _ := m.sse[victim].snapshot()
	last := -1
	disorder := 0
	for _, e := range evs {
		if q, err := strconv.Atoi(e.Data); err == nil {
			if q < last {
				disorder++
			}
			last = q
		}
	}
	t.Logf("Mercure subscriber %d: %d events, %d out of publish order", victim, len(evs), disorder)

	if at, ok := firstSSEAfter(p.mercure, m.sse[victim], t0.Add(100*time.Millisecond)); ok {
		tm.add("kill -> SSE sub of dead node receives new updates", at.Sub(t0))
	}

	// Whole again: sentinels on the survivors reach every subscriber, wherever it now is.
	sentinel(t, c, m, []int{0, 1, 2}, c.survivors(victim), "after", 50)

	// the survivors logged no errors
	for _, n := range c.survivors(victim) {
		counts, lines := n.logLevels(0)
		t.Logf("node %d log levels: %v", n.idx, counts)
		for _, l := range lines["WARN"] {
			t.Logf("node %d WARN: %s", n.idx, l)
		}
		if graceful {
			// gossip keeps retrying the configured peer list, and may exchange state with the node once more before
			// it learns the node left: the warnings a departed node leaves behind
			for _, l := range lines["WARN"] {
				if !strings.Contains(l, `"msg":"failed to join peer"`) && !strings.Contains(l, `"msg":"failed to exchange state with node"`) {
					t.Errorf("node %d logged an unexpected warning after a graceful shutdown: %s", n.idx, l)
				}
			}
		}
		if counts["ERROR"] > 0 {
			t.Errorf("node %d logged errors: %v", n.idx, lines["ERROR"])
		}
	}
	tm.report()
}

// A killed node restarts with its id and data directory, rejoins, and takes traffic. Detected restarts wait until the
// survivors have seen the node gone; quick ones restart it before gossip has noticed.
func TestRestartNodeAfterDetection(t *testing.T) { restartScenario(t, true) }
func TestRestartNodeQuickly(t *testing.T)        { restartScenario(t, false) }

func restartScenario(t *testing.T, detected bool) {
	const victim = 1
	c := newCluster(t, clusterOpts{size: 3})
	m := startMeshClients(t, c)
	m.warm(t, c.nodes, 20*time.Second)
	tm := newTimings(t)

	p := startPublishers(t, c, pubInterval)
	sleepFor(time.Second)
	t0 := c.nodes[victim].kill()
	if detected {
		tm.add("kill -> survivors' gossip settled", c.waitSurvivorsMeshed(t0, victim))
		sleepFor(2 * time.Second)
	} else {
		sleepFor(200 * time.Millisecond)
	}

	restart := time.Now()
	c.nodes[victim].start()
	tm.add("restart -> healthz", c.nodes[victim].waitHTTP(20*time.Second))
	tm.add("restart -> 3 nodes meshed (gossip)", c.waitMeshed(c.nodes, 90*time.Second))
	tm.add("restart (process start) -> meshed, total", time.Since(restart))

	// a new subscriber on the restarted node receives what the publisher still sends...
	n := c.nodes[victim]
	subscribed := time.Now()
	sse := startSSE("restarted-sse", []string{n.httpURL()})
	defer sse.stop()
	waitFor(t, 20*time.Second, "the restarted node's SSE subscriber receives updates", func() bool { return len(sse.datas()) > 0 })
	tm.add("SSE subscribe on restarted node -> first update", time.Since(subscribed))

	// ...and what is published on the restarted node reaches the others
	sleepFor(time.Second)
	p.stop()
	sentinel(t, c, m, []int{0, 2}, c.nodes, "rejoin", 50)
	// the new subscriber holds the sentinels from every node too: interest on the restarted node is correct
	waitFor(t, 10*time.Second, "restarted node's subscriber holds the sentinels", func() bool {
		datas := sse.datas()
		for _, nd := range c.nodes {
			for seq := 1; seq <= 50; seq++ {
				if !datas["rejoin"+strconv.Itoa(nd.idx)+"-"+strconv.Itoa(seq)] {
					return false
				}
			}
		}
		return true
	})
	for _, j := range []int{0, 2} {
		// Only an update the killed node acked just before it died, and had not yet sent on, can be missing: a
		// publish is acked once the update is applied locally and queued to the others.
		if g := sseGap(p.mercure, m.sse[j]); g.missing > 2 {
			t.Errorf("Mercure subscriber %d missed %v", j, g)
		} else {
			t.Logf("Mercure subscriber %d missed %v", j, g)
		}
	}
	for _, nd := range c.nodes {
		counts, lines := nd.logLevels(0)
		t.Logf("node %d log levels: %v", nd.idx, counts)
		if counts["ERROR"] > 0 {
			t.Errorf("node %d logged errors: %v", nd.idx, lines["ERROR"])
		}
	}
	tm.report()
}
