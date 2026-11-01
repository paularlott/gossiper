package cluster_test

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/compression/snappy"
	"github.com/paularlott/gossip/encryption/aes"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/cluster"
)

// largeData returns about size bytes of ASCII text in lines of 79 characters (so a data field of many lines), the
// same for the same size.
func largeData(size int) string {
	var b strings.Builder
	b.Grow(size)
	x := uint32(2463534242)
	for b.Len() < size-80 {
		for range 78 {
			x ^= x << 13
			x ^= x >> 17
			x ^= x << 5
			b.WriteByte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[x%62])
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func encrypted(key string, withSnappy bool) func(int, *nodeOpts) {
	return func(_ int, o *nodeOpts) {
		o.gossip = func(c *gossip.Config) {
			c.EncryptionKey = []byte(key)
			c.Cipher = aes.New()
			if withSnappy {
				c.Compressor = snappy.New()
			}
		}
	}
}

// TestLargePayloadReplicates: an update of about 900 KiB (a publish request's limit is 1 MiB) reaches every node
// intact, in plain, encrypted and encrypted and compressed clusters.
func TestLargePayloadReplicates(t *testing.T) {
	for _, tc := range []struct {
		name string
		node func(int, *nodeOpts)
	}{
		{"plain", nil},
		{"encrypted", encrypted("0123456789abcdef0123456789abcdef", false)},
		{"encrypted and compressed", encrypted("0123456789abcdef0123456789abcdef", true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := newCluster(t, clusterOpts{n: 3, node: tc.node})
			hc := newClient(t)
			var subs []*sseClient
			for _, n := range nodes {
				subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
			}
			data := largeData(900 << 10)
			id := nodes[0].publish(t, hc, url.Values{"topic": {topicA}, "data": {data}})
			first := expectAll(t, 1, subs...)
			for i, evs := range first {
				e := evs[0]
				if e.ID != id || e.Data != data {
					t.Errorf("subscriber %d on %s: id %s data %d bytes, want id %s data %d bytes", i, subs[i].node.addr, e.ID, len(e.Data), id, len(data))
				}
				if e.Frame != first[0][0].Frame {
					t.Errorf("subscriber %d on %s received a different frame", i, subs[i].node.addr)
				}
			}
			// Several in a row, from another node.
			for range 3 {
				nodes[2].publish(t, hc, url.Values{"topic": {topicA}, "data": {data}})
			}
			expectAll(t, 4, subs...)
		})
	}
}

// TestUpdateBeyondGossipPacketLimit: an update too large for one gossip packet (4 MiB by default) cannot reach the
// other nodes, so publishing it must fail rather than apply it on one node only.
func TestUpdateBeyondGossipPacketLimit(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2, node: func(_ int, o *nodeOpts) {
		o.hub = func(c *gossiper.Config) { c.MaxPublishBytes = 16 << 20 }
	}})
	a, b := nodes[0], nodes[1]
	hc := newClient(t)
	sa := a.subscribe(t, subOpts{topics: []string{topicA}})
	sb := b.subscribe(t, subOpts{topics: []string{topicA}})

	// Just under the limit works.
	a.publish(t, hc, url.Values{"topic": {topicA}, "data": {largeData(4<<20 - 16<<10 - 1024)}})
	expectAll(t, 1, sa, sb)

	_, err := a.hub.Publish(t.Context(), &gossiper.Update{Topics: []string{topicA}, Data: largeData(5 << 20)})
	time.Sleep(2 * settle)
	if !errors.Is(err, cluster.ErrUpdateTooLarge) {
		t.Fatalf("publish of an update over the gossip packet limit: %v, want ErrUpdateTooLarge (a has %d events, b has %d)", err, sa.count(), sb.count())
	}
	// Refused: nothing was applied anywhere.
	if sa.count() != 1 || sb.count() != 1 || a.hub.Stats().Applied != 1 || b.hub.Stats().Applied != 1 {
		t.Errorf("a received %d events and applied %d, b received %d and applied %d; want 1 each", sa.count(), a.hub.Stats().Applied, sb.count(), b.hub.Stats().Applied)
	}

	// Over HTTP the publisher is told.
	_, status, err := a.tryPublish(hc, url.Values{"topic": {topicA}, "data": {largeData(5 << 20)}})
	if err != nil || status == 200 {
		t.Errorf("publish request of an oversized update: status %d, %v; want a failure", status, err)
	}
}

// TestMaxUpdateBytesOption: the limit is an option.
func TestMaxUpdateBytesOption(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2, node: func(_ int, o *nodeOpts) {
		o.tr = func(o *cluster.Options) { o.MaxUpdateBytes = 1000 }
	}})
	if _, err := nodes[0].hub.Publish(t.Context(), &gossiper.Update{Topics: []string{topicA}, Data: strings.Repeat("x", 2000)}); !errors.Is(err, cluster.ErrUpdateTooLarge) {
		t.Errorf("2000 bytes over a 1000 byte limit: %v", err)
	}
	if _, err := nodes[0].hub.Publish(t.Context(), &gossiper.Update{Topics: []string{topicA}, Data: strings.Repeat("x", 500)}); err != nil {
		t.Errorf("500 bytes: %v", err)
	}
}

// TestEncryptedCluster: gossip encryption works for replication, and a node with another key, or none, does not
// join the group.
func TestEncryptedCluster(t *testing.T) {
	for _, key := range []string{"0123456789abcdef", "0123456789abcdef01234567", "0123456789abcdef0123456789abcdef"} {
		t.Run(fmt.Sprintf("aes-%d", len(key)*8), func(t *testing.T) {
			nodes := newCluster(t, clusterOpts{n: 3, node: encrypted(key, false)})
			hc := newClient(t)
			var subs []*sseClient
			for _, n := range nodes {
				subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
			}
			id := nodes[1].publish(t, hc, url.Values{"topic": {topicA}, "data": {"secret"}})
			for i, evs := range expectAll(t, 1, subs...) {
				if evs[0].ID != id || evs[0].Data != "secret" {
					t.Errorf("subscriber %d received %+v", i, evs[0])
				}
			}
		})
	}

	t.Run("other keys", func(t *testing.T) {
		const key = "0123456789abcdef0123456789abcdef"
		good := newCluster(t, clusterOpts{n: 2, node: encrypted(key, false)})
		wrong := newNode(t, nodeOpts{gossip: func(c *gossip.Config) {
			c.EncryptionKey = []byte("fedcba9876543210fedcba9876543210")
			c.Cipher = aes.New()
		}})
		plain := newNode(t, nodeOpts{})
		for _, n := range []*testNode{wrong, plain} {
			_ = n.gc.Join([]string{good[0].addr}) // refused or ignored: the error does not matter
		}
		time.Sleep(time.Second)
		for _, n := range good {
			if got := len(n.tr.Peers()); got != 1 {
				t.Errorf("node %s has %d peers, want 1: a node with another key must not join", n.addr, got)
			}
		}
		hc := newClient(t)
		good[0].publish(t, hc, url.Values{"topic": {topicA}, "data": {"x"}})
		waitApplied(t, good, 1)
		time.Sleep(settle)
		for _, n := range []*testNode{wrong, plain} {
			if got := n.hub.Stats().Applied; got != 0 {
				t.Errorf("node %s with another key applied %d updates", n.addr, got)
			}
		}
	})
}
