//go:build failover

package failover

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// composeCmd runs docker compose against examples/cluster with the test's project name and ports.
func composeCmd(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "examples", "cluster")
	cmd := exec.Command("docker", append([]string{"compose", "-p", "gossiper-failover", "-f", filepath.Join(dir, "docker-compose.yml")}, args...)...)
	cmd.Env = append(os.Environ(),
		"GOSSIPER_PUBLISHER_KEY="+secret, "GOSSIPER_CLUSTER_KEY="+clusterKey,
		"GOSSIPER_HTTP_PORT="+strconv.Itoa(composeHTTP))
	return cmd
}

const composeHTTP = 14590

func compose(t *testing.T, args ...string) {
	t.Helper()
	out, err := composeCmd(t, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// The examples/cluster stack (3 Mercure nodes behind Caddy) with real containers: a node is killed and stopped, and
// publishing and subscribing carry on. Needs Docker and a network to build the image; run it with
//
//	FAILOVER_COMPOSE=1 go test -tags failover -run TestComposeExample -v ./test/failover/
//
// It uses the compose project gossiper-failover and the host port 14590, and removes them when it ends.
func TestComposeExample(t *testing.T) {
	if os.Getenv("FAILOVER_COMPOSE") == "" {
		t.Skip("set FAILOVER_COMPOSE=1 to run the docker compose scenario")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	t.Cleanup(func() {
		out, err := composeCmd(t, "down", "-v", "--remove-orphans", "--rmi", "local").CombinedOutput()
		if err != nil {
			t.Errorf("docker compose down: %v\n%s", err, out)
		}
	})
	start := time.Now()
	compose(t, "up", "-d", "--build")
	t.Logf("TIMING compose up --build %s", ms(time.Since(start)))

	// the nodes as the clients see them: all three through Caddy
	c := &cluster{t: t}
	for i := 0; i < 3; i++ {
		n := &node{t: t, idx: i, id: "node" + strconv.Itoa(i+1), http: composeHTTP, exited: make(chan struct{})}
		c.nodes = append(c.nodes, n)
	}
	waitFor(t, 60*time.Second, "Caddy answering", func() bool { return c.nodes[0].status("/healthz") == 200 })
	tm := newTimings(t)
	m := startMeshClients(t, c)
	m.warm(t, c.nodes, 60*time.Second)
	p := startPublishers(t, c, pubInterval)
	sleepFor(2 * time.Second)

	// abrupt: kill node2's container
	t0 := time.Now()
	compose(t, "kill", "node2")
	tm.add("docker kill node2 (command)", time.Since(t0))
	// Caddy spreads the three SSE streams over the nodes: whichever were on node2 ended and came back through Caddy
	sleepFor(3 * time.Second)
	moved := 0
	for j, s := range m.sse {
		_, recs, _ := s.snapshot()
		if len(recs) == 0 {
			continue
		}
		moved++
		tm.add(fmt.Sprintf("kill -> SSE %d reconnected through Caddy", j), recs[0].Connected.Sub(t0))
		tm.add(fmt.Sprintf("kill -> SSE %d first event after resume", j), recs[0].FirstData.Sub(t0))
		if !recs[0].Resumed {
			t.Errorf("SSE %d did not resume with Last-Event-ID", j)
		}
	}
	t.Logf("%d of the 3 SSE streams were on the killed node", moved)
	sleepFor(3 * time.Second)
	t.Logf("Mercure through Caddy: %d acked, %d failed attempts; longest gap between acks %v", p.mercure.count(), p.mercure.fail, time.Duration(p.maxGap.Load()))
	tm.add("longest gap between Mercure acks through Caddy", time.Duration(p.maxGap.Load()))

	// bring node2 back once the others have seen it gone, then stop node1 gracefully
	waitComposeNodes(t, c, 2, 60*time.Second)
	compose(t, "start", "node2")
	waitComposeNodes(t, c, 3, 60*time.Second)
	tm.add("kill -> node2 back in the cluster", time.Since(t0))
	t1 := time.Now()
	compose(t, "stop", "node1")
	tm.add("docker stop node1 (command, graceful)", time.Since(t1))
	sleepFor(3 * time.Second)
	p.stop()

	// whole again with node1 down: sentinels reach every subscriber
	sentinel(t, c, m, []int{0, 1, 2}, c.survivors(0), "compose", 50)
	compose(t, "start", "node1")
	waitComposeNodes(t, c, 3, 60*time.Second)
	m.warm(t, c.nodes, 60*time.Second)
	sentinel(t, c, m, []int{0, 1, 2}, c.nodes, "composeall", 50)
	for j := range c.nodes {
		g := sseGap(p.mercure, m.sse[j])
		t.Logf("Mercure subscriber %d (through Caddy) missed %v", j, g)
	}
	tm.report()
}

// waitComposeNodes waits until the nodes Caddy reaches all report want gossip members: the nodes are not published
// on the host one by one, so it takes several consecutive /metrics reads through Caddy (round robin) to agree.
func waitComposeNodes(t *testing.T, c *cluster, want int, d time.Duration) {
	t.Helper()
	agree := 0
	waitFor(t, d, fmt.Sprintf("the cluster at %d nodes", want), func() bool {
		if v, ok := c.nodes[0].metric("gossiper_cluster_nodes"); ok && int(v) == want {
			agree++
		} else {
			agree = 0
		}
		return agree >= 6
	})
}
