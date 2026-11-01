//go:build failover

package failover

import (
	"strconv"
	"testing"
	"time"
)

// A single node (no cluster flags) serves Mercure; killed or terminated and restarted, its clients reconnect.
func TestSingleNodeKillAndRestart(t *testing.T)      { singleNodeScenario(t, false) }
func TestSingleNodeTerminateAndRestart(t *testing.T) { singleNodeScenario(t, true) }

func singleNodeScenario(t *testing.T, graceful bool) {
	c := newCluster(t, clusterOpts{size: 1})
	n := c.nodes[0]
	tm := newTimings(t)

	sse := startSSE("sse", []string{n.httpURL()})
	defer sse.stop()
	waitFor(t, 5*time.Second, "SSE connected", sse.isConnected)

	p := startPublishers(t, c, pubInterval)
	waitFor(t, 10*time.Second, "traffic flowing", func() bool { return len(sse.datas()) > 20 })

	var t0 time.Time
	if graceful {
		var took time.Duration
		t0, took = n.term()
		tm.add("SIGTERM -> process exited", took)
		if err := n.exitStatus(); err != nil {
			t.Errorf("node exited with %v after SIGTERM", err)
		}
	} else {
		t0 = n.kill()
	}
	waitFor(t, 5*time.Second, "SSE stream ends", func() bool { return !sse.isConnected() })
	tm.add("stop -> SSE stream ended", time.Since(t0))
	sleepFor(time.Second) // clients retrying against a node that is down

	restart := time.Now()
	n.start()
	tm.add("restart -> healthz", n.waitHTTP(20*time.Second))
	waitFor(t, 20*time.Second, "SSE client reconnected", func() bool {
		_, recs, _ := sse.snapshot()
		return len(recs) > 0 && !recs[len(recs)-1].Connected.IsZero() && sse.isConnected()
	})
	_, recs, _ := sse.snapshot()
	rc := recs[len(recs)-1].Connected
	tm.add("restart -> SSE client reconnected", rc.Sub(restart))

	// publishing resumes, and the client's subscription came back with it
	waitFor(t, 20*time.Second, "new updates reach the client", func() bool {
		evs, _, _ := sse.snapshot()
		return len(evs) > 0 && evs[len(evs)-1].At.After(rc)
	})
	sleepFor(time.Second)
	p.stop()
	if at, ok := firstSSEAfter(p.mercure, sse, restart); ok {
		tm.add("restart -> first Mercure update received", at.Sub(restart))
	}
	t.Logf("Mercure: %d acked, %d refused while the node was down", p.mercure.count(), p.mercure.fail)
	sg := sseGap(p.mercure, sse)
	if sg.missing > 0 {
		datas := sse.datas()
		var miss []int
		for _, q := range p.mercure.seqs() {
			if !datas[strconv.Itoa(q)] {
				miss = append(miss, q)
			}
		}
		_, recs, _ := sse.snapshot()
		t.Logf("Mercure updates missed: %v; SSE reconnects: %d", miss, len(recs))
	}
	t.Logf("Mercure subscriber missed %v of what was acked (history is in memory: a restarted node has none)", sg)
	if v, ok := n.metric("gossiper_replay_misses_total"); ok {
		t.Logf("restarted node: replay misses %v", v)
	}
	// after the restart nothing is lost any more
	sentinel(t, c, &meshClients{cluster: c, sse: []*sseClient{sse}}, []int{0}, c.nodes, "single", 50)
	if counts, lines := n.logLevels(0); counts["ERROR"] > 0 {
		t.Errorf("node logged errors: %v", lines["ERROR"])
	}
	tm.report()
}
