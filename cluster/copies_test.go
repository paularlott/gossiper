package cluster_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossiper"
)

// A publish that asks for copies is answered once that many nodes hold the update, and refused when the cluster has
// fewer nodes.
func TestCopies(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	s := nodes[2].subscribe(t, subOpts{topics: []string{topicA}})
	ctx := context.Background()
	if _, err := nodes[0].hub.Publish(ctx, &gossiper.Update{Topics: []string{topicA}, Data: "three", Replicas: 3}); err != nil {
		t.Fatalf("3 copies on 3 nodes: %v", err)
	}
	_, err := nodes[0].hub.Publish(ctx, &gossiper.Update{Topics: []string{topicA}, Replicas: 4})
	if !errors.Is(err, gossiper.ErrTooFewNodes) || !strings.Contains(err.Error(), "3 of 4") {
		t.Fatalf("4 copies on 3 nodes: %v", err)
	}
	if evs := expectAll(t, 1, s); evs[0][0].Data != "three" {
		t.Fatalf("received %+v", evs[0])
	}
}

// A peer that is a member but cannot be reached makes no copy: a publish asking for it fails in time, saying how
// many nodes it reached, and one asking for fewer copies succeeds.
func TestCopiesUnreachablePeer(t *testing.T) {
	var cut *partition
	nodes := newCluster(t, clusterOpts{n: 3, node: func(i int, o *nodeOpts) {
		if i == 0 {
			o.gossip = func(c *gossip.Config) {
				cut = &partition{Transport: c.Transport}
				c.Transport = cut
			}
		}
	}})
	cut.set(nodes[2].gc.LocalNode().ID, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := nodes[0].hub.Publish(ctx, &gossiper.Update{Topics: []string{topicA}, Replicas: 3})
	if !errors.Is(err, gossiper.ErrNotReplicated) || !strings.Contains(err.Error(), "2 of 3") {
		t.Fatalf("3 copies, one peer unreachable: %v", err)
	}
	if _, err := nodes[0].hub.Publish(context.Background(), &gossiper.Update{Topics: []string{topicA}, Replicas: 2}); err != nil {
		t.Fatalf("2 copies, one peer unreachable: %v", err)
	}
}

// An update published again with its ID, through another node, is answered as the first and delivered once.
func TestCopiesIdempotentAcrossNodes(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	s := nodes[2].subscribe(t, subOpts{topics: []string{topicA}})
	for _, n := range nodes[:2] {
		id, err := n.hub.Publish(context.Background(), &gossiper.Update{ID: "urn:order:1", Topics: []string{topicA}, Data: "order", Replicas: 2})
		if err != nil || id != "urn:order:1" {
			t.Fatalf("publish through %s: %q %v", n.addr, id, err)
		}
	}
	nodes[0].hub.Publish(context.Background(), &gossiper.Update{Topics: []string{topicA}, Data: "sentinel"})
	evs := expectAll(t, 2, s)[0]
	if evs[0].Data != "order" || evs[1].Data != "sentinel" {
		t.Fatalf("received %+v, want the order once, then the sentinel", evs)
	}
}
