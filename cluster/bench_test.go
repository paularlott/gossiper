package cluster_test

import (
	"context"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossiper"
)

// inFlightWindow bounds how far the publishers run ahead of the slowest node, so a benchmark measures replication
// throughput rather than the depth of gossip's send queue.
const inFlightWindow = 1000

func benchCluster(b *testing.B, n int) []*testNode {
	b.Helper()
	nodes := newCluster(b, clusterOpts{n: n})
	for _, nd := range nodes {
		nd.subscribe(b, subOpts{topics: []string{topicA}})
	}
	return nodes
}

// throttle waits while more than inFlightWindow updates are published and not yet applied on every node.
func throttle(b *testing.B, nodes []*testNode, published *atomic.Int64) {
	for {
		slowest := ^uint64(0)
		for _, n := range nodes {
			slowest = min(slowest, n.hub.Stats().Applied)
		}
		if uint64(published.Load())-slowest < inFlightWindow {
			return
		}
		runtime.Gosched()
		time.Sleep(50 * time.Microsecond)
	}
}

func finishBench(b *testing.B, nodes []*testNode, start time.Time) {
	b.Helper()
	waitApplied(b, nodes, uint64(b.N))
	b.StopTimer()
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "updates/s")
	for _, n := range nodes {
		if st := n.hub.Stats(); st.Dropped != 0 || st.Duplicates != 0 {
			b.Fatalf("node %s dropped %d subscribers and saw %d duplicates", n.addr, st.Dropped, st.Duplicates)
		}
	}
}

// BenchmarkCrossNodePublish: one publisher on one node of three; the time until every node has applied the update.
func BenchmarkCrossNodePublish(b *testing.B) {
	nodes := benchCluster(b, 3)
	payload := strings.Repeat("x", 256)
	var published atomic.Int64
	b.ResetTimer()
	start := time.Now()
	for range b.N {
		throttle(b, nodes, &published)
		if _, err := nodes[0].hub.Publish(context.Background(), &gossiper.Update{Topics: []string{topicA}, Data: payload}); err != nil {
			b.Fatal(err)
		}
		published.Add(1)
	}
	finishBench(b, nodes, start)
}

// BenchmarkCrossNodePublishParallel: publishers on every node of three at once.
func BenchmarkCrossNodePublishParallel(b *testing.B) {
	nodes := benchCluster(b, 3)
	payload := strings.Repeat("x", 256)
	var published, next atomic.Int64
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		n := nodes[int(next.Add(1))%len(nodes)]
		for pb.Next() {
			throttle(b, nodes, &published)
			if _, err := n.hub.Publish(context.Background(), &gossiper.Update{Topics: []string{topicA}, Data: payload}); err != nil {
				b.Error(err)
				return
			}
			published.Add(1)
		}
	})
	finishBench(b, nodes, start)
}

// BenchmarkCrossNodePublishLarge: 64 KiB updates from one node of three.
func BenchmarkCrossNodePublishLarge(b *testing.B) {
	nodes := benchCluster(b, 3)
	payload := largeData(64 << 10)
	b.SetBytes(int64(len(payload)))
	var published atomic.Int64
	b.ResetTimer()
	start := time.Now()
	for range b.N {
		throttle(b, nodes, &published)
		if _, err := nodes[0].hub.Publish(context.Background(), &gossiper.Update{Topics: []string{topicA}, Data: payload}); err != nil {
			b.Fatal(err)
		}
		published.Add(1)
	}
	finishBench(b, nodes, start)
}
