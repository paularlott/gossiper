package cluster_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper"
)

// TestMalformedMessagesAreIgnored: a gossip message of the transport's types that is not what the transport sends
// is dropped without harming the hub; a well-formed update from any member of the gossip cluster is applied.
func TestMalformedMessagesAreIgnored(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	a, b := nodes[0], nodes[1]
	sb := b.subscribe(t, subOpts{topics: []string{topicA}})
	target := a.gc.GetNode(b.gc.LocalNode().ID)

	const msgPub = gossip.UserMsg + 64
	raw := func(payload any) {
		t.Helper()
		if err := a.gc.SendToReliable(target, msgPub, payload); err != nil {
			t.Fatal(err)
		}
	}
	send := func(u *gossiper.Update) { t.Helper(); raw(map[string]any{"u": [][]byte{encode(t, u)}}) } // a batch of one
	raw("not an update")
	raw(42)
	raw(&gossiper.Update{ID: "single", Topics: []string{topicA}, Stamp: 3, Origin: "x"})                             // not in a batch
	raw(map[string]any{"u": []*gossiper.Update{{ID: "unencoded", Topics: []string{topicA}, Stamp: 4, Origin: "x"}}}) // not encoded
	raw(map[string]any{"u": [][]byte{{0xc1}, []byte("junk")}})                                                       // not updates
	send(&gossiper.Update{ID: "no-topics", Stamp: 1, Origin: "x"})                                                   // no topic
	send(&gossiper.Update{Topics: []string{topicA}, Stamp: 2, Origin: "x"})                                          // no ID
	time.Sleep(2 * settle)
	if got := b.hub.Stats().Applied; got != 0 || sb.count() != 0 {
		t.Fatalf("malformed messages: applied %d, delivered %d, want none", got, sb.count())
	}

	// The same channel still carries a good update.
	good := &gossiper.Update{ID: "good", Topics: []string{topicA}, Data: "ok", Stamp: uint64(hlc.Now()), Origin: "forger"}
	send(good)
	sb.wait(t, 1)
	if evs := expectAll(t, 1, sb)[0]; evs[0].ID != "good" || evs[0].Data != "ok" {
		t.Errorf("received %+v", evs[0])
	}

	// A stamp from far in the future is refused (it would sort after everything published until the skew passes),
	// and the hub warns about the clock.
	future := &gossiper.Update{ID: "future", Topics: []string{topicA}, Stamp: uint64(hlc.FromTime(time.Now().Add(time.Hour))), Origin: "forger"}
	send(future)
	deadline := time.Now().Add(10 * time.Second)
	for b.hub.Stats().Refused == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.hub.Stats().Refused != 1 {
		t.Fatalf("far-future update not refused: %+v", b.hub.Stats())
	}
	found := false
	for _, l := range b.hubLog.logged() {
		found = found || strings.Contains(l, "far ahead")
	}
	if !found {
		t.Errorf("no warning about the clock of the origin: %v", b.hubLog.logged())
	}

	// A subscriptions request that cannot be decoded gets no answer (the requester gives up at its deadline).
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	var resp struct{}
	if err := a.gc.SendToWithResponseContext(ctx, target, gossip.UserMsg+65, "garbage", &resp); err == nil {
		t.Error("a malformed subscriptions request was answered")
	}
	// And the hub still answers a good one.
	subs, complete, err := a.tr.RemoteSubscriptions(t.Context())
	if err != nil || !complete || len(subs) != 1 {
		t.Errorf("RemoteSubscriptions: %v %v %v", subs, complete, err)
	}
	if len(subs) == 1 && len(subs[0].Payload) != 0 {
		t.Errorf("an anonymous subscriber's subscription has payload %q", subs[0].Payload)
	}
}
