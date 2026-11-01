//go:build failover

package failover

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossiper/client"
)

// kill -9 the node a service publishes to, with copies asked for: every publish answered before the kill reached
// another node, and what the service publishes again (by its ID, through a survivor) is delivered once, so a
// subscriber elsewhere holds every update exactly once.
func TestKillWithCopies(t *testing.T) {
	c := newCluster(t, clusterOpts{size: 3})
	sub := startSSE("sub", c.rotated(2, (*node).httpURL))
	defer sub.stop()
	waitFor(t, 10*time.Second, "subscriber connected", sub.isConnected)

	publisher := func(n *node) *client.Client {
		pc, err := client.New(client.Options{URL: n.httpURL() + hubPath, Token: publisherToken(), Transport: client.Stream})
		if err != nil {
			t.Fatal(err)
		}
		return pc
	}
	const total = 3000
	update := func(i int) client.Update {
		return client.Update{ID: fmt.Sprintf("urn:copy:%d", i), Topics: []string{topic}, Data: fmt.Sprintf("copy-%d", i), Replicas: 2}
	}

	var mu sync.Mutex
	acked := map[int]bool{}
	var wg sync.WaitGroup
	first := publisher(c.nodes[0])
	killed := make(chan struct{})
	go func() { // kill node 0 once a third has been answered
		waitFor(t, 30*time.Second, "a third published", func() bool { mu.Lock(); defer mu.Unlock(); return len(acked) >= total/3 })
		c.nodes[0].kill()
		close(killed)
	}()
	for i := range total {
		wg.Add(1)
		err := first.PublishAsync(context.Background(), update(i), func(_ string, err error) {
			defer wg.Done()
			if err == nil {
				mu.Lock()
				acked[i] = true
				mu.Unlock()
			}
		})
		if err != nil {
			wg.Done()
		}
		if i%100 == 99 {
			time.Sleep(5 * time.Millisecond) // about 20k a second: the kill lands mid-stream
		}
	}
	wg.Wait()
	<-killed
	first.Close()
	before := map[int]bool{}
	mu.Lock()
	for i := range acked {
		before[i] = true
	}
	mu.Unlock()
	t.Logf("%d of %d answered by node 0 before the kill", len(before), total)

	// The service publishes again, through a survivor, what it got no answer for.
	again := publisher(c.nodes[1])
	defer again.Close()
	retried := 0
	for i := range total {
		if before[i] {
			continue
		}
		retried++
		if _, err := again.Publish(context.Background(), update(i)); err != nil {
			t.Fatalf("publish %d again: %v", i, err)
		}
	}

	waitFor(t, 30*time.Second, "the subscriber holds every update", func() bool { return len(sub.datas()) >= total })
	time.Sleep(time.Second) // a late duplicate would arrive by now
	evs, _, _ := sub.snapshot()
	count := map[string]int{}
	for _, e := range evs {
		count[e.Data]++
	}
	for i := range total {
		if n := count[fmt.Sprintf("copy-%d", i)]; n != 1 {
			t.Errorf("update %d received %d times (answered before the kill: %v)", i, n, before[i])
		}
	}
	t.Logf("%d published again through node 1; %d events received", retried, len(evs))
}
