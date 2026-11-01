package cluster_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/cluster"
)

// TestNoGoroutineLeaks: once a cluster of hubs, with subscribers, publishers and subscription requests, is closed,
// no goroutine of the hubs, gossip or HTTP is left.
func TestNoGoroutineLeaks(t *testing.T) {
	waitNoLeaks(t) // nothing from the tests before

	t.Run("cluster", func(t *testing.T) {
		nodes := newCluster(t, clusterOpts{n: 4, node: withSubscriptions})
		hc := newClient(t)
		var subs []*sseClient
		for _, n := range nodes {
			subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
		}
		for i := range 20 {
			nodes[i%4].publish(t, hc, url.Values{"topic": {topicA}, "data": {fmt.Sprint(i)}})
		}
		expectAll(t, 20, subs...)
		listSubscriptions(t, nodes[0], "")
		// A node that leaves early, and a stream that ends early.
		nodes[3].close()
		subs[1].close()
		nodes[0].publish(t, hc, url.Values{"topic": {topicA}, "data": {"after"}})
	})

	waitNoLeaks(t)
}

// TestHubAndGossipShutdownOrder: closing the gossip node before the hub does not hang or panic; the hub's close is
// still clean.
func TestHubAndGossipShutdownOrder(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	hc := newClient(t)
	nodes[0].subscribe(t, subOpts{topics: []string{topicA}})
	nodes[1].publish(t, hc, url.Values{"topic": {topicA}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		nodes[2].gc.Stop() // gossip first
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := nodes[2].hub.Close(ctx); err != nil {
			t.Errorf("hub close after gossip stop: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("closing the hub after its gossip node stopped hung")
	}
}

// TestPublishRacesClose: publishers racing a hub's Close see only ErrClosed (or success), and nothing is applied
// after the hub says it is closed. Run with -race.
func TestPublishRacesClose(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	a := nodes[0]
	var unexpected atomic.Value
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := a.hub.Publish(context.Background(), &gossiper.Update{Topics: []string{topicA}, Data: "x"})
				if err != nil && !errors.Is(err, gossiper.ErrClosed) {
					unexpected.Store(err)
					return
				}
				if errors.Is(err, gossiper.ErrClosed) {
					return
				}
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	a.hubClose(t)
	close(stop)
	wg.Wait()
	if err := unexpected.Load(); err != nil {
		t.Errorf("publish failed with %v", err)
	}
	applied := a.hub.Stats().Applied
	time.Sleep(settle)
	if got := a.hub.Stats().Applied; got != applied {
		t.Errorf("a closed hub applied %d more updates", got-applied)
	}
}

// TestIdentity: the hub names itself by its gossip node's id, and the updates it publishes carry it.
func TestIdentity(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	for _, n := range nodes {
		id := n.gc.LocalNode().ID.String()
		if n.tr.NodeID() != id || n.hub.NodeID() != id {
			t.Errorf("transport id %q, hub id %q, gossip id %q", n.tr.NodeID(), n.hub.NodeID(), id)
		}
	}
	if nodes[0].hub.NodeID() == nodes[1].hub.NodeID() {
		t.Error("two nodes share an id")
	}
}

// TestTransportStartFailsOnReservedMessageType: gossip refuses message types in its reserved range, so the hub
// does not start over them.
func TestTransportStartFailsOnReservedMessageType(t *testing.T) {
	n := newNode(t, nodeOpts{})
	tr := cluster.New(n.gc, cluster.Options{MsgBase: 1}) // below gossip.UserMsg
	h, err := gossiper.New(gossiper.Config{Transport: tr})
	if err == nil {
		_ = h.Close(context.Background())
		t.Fatal("a transport over reserved message types started")
	}
}

// TestTransportStartFailureUnregisters: when the transport cannot register all its handlers (MsgBase 65535 leaves no
// room for the next type), it registers none and the hub does not start.
func TestTransportStartFailureUnregisters(t *testing.T) {
	n := newNode(t, nodeOpts{})
	tr := cluster.New(n.gc, cluster.Options{MsgBase: 65535})
	if h, err := gossiper.New(gossiper.Config{Transport: tr}); err == nil {
		_ = h.Close(context.Background())
		t.Fatal("a transport over message types 65535 and 0 started")
	}
	if n.gc.UnregisterMessageType(65535) {
		t.Error("the handler of the first message type was left registered after Start failed")
	}
}
