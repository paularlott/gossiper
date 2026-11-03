package cluster_test

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/cluster"
)

// A peer whose history pages hold null entries (a buggy or hostile member) does not crash a node copying its
// history: the nulls are skipped, the real update is restored, the copy resumes after it, and a page of nothing
// but nulls ends it.
func TestNullsInHistoryPage(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cfg := gossipConfig(addr)
	cfg.Transport = gossip.NewSocketTransport(cfg)
	cfg.Logger = recLogger{&recorder{}}
	peer, err := gossip.NewCluster(cfg)
	if err != nil {
		t.Fatal(err)
	}
	good := &gossiper.Update{ID: "good", Topics: []string{topicA}, Data: "ok", Stamp: uint64(hlc.Now()), Origin: "peer"}
	var pages atomic.Int32
	var resumed atomic.Value
	const msgHist = gossip.UserMsg + 64 + 2
	peer.HandleFuncWithReply(msgHist, func(_ *gossip.Node, p *gossip.Packet) (any, error) {
		var req struct {
			S uint64 `msgpack:"s"`
			O string `msgpack:"o"`
		}
		_ = p.Unmarshal(&req)
		switch pages.Add(1) {
		case 1:
			return map[string]any{"u": []*gossiper.Update{nil, good, nil}, "m": true, "r": true}, nil
		case 2:
			resumed.Store(fmt.Sprintf("%d/%s", req.S, req.O))
			return map[string]any{"u": []*gossiper.Update{nil}, "m": true, "r": true}, nil
		}
		return map[string]any{"r": true}, nil
	})
	peer.LocalMetadata().SetString("gossiper.hub", "on") // a hub: asked for its history
	if err := startCluster(peer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Stop)

	n := newNode(t, nodeOpts{tr: func(o *cluster.Options) { o.Backfill = 10 * time.Second }})
	if err := n.gc.Join([]string{addr}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, waitMax, "the backfill", n.tr.Ready)
	if got := n.hub.Stats().HistoryLen; got != 1 {
		t.Errorf("history: %d updates, want the peer's one", got)
	}
	if got, want := resumed.Load(), fmt.Sprintf("%d/%s", good.Stamp, good.Origin); got != want {
		t.Errorf("resumed after %v, want after the last real update (%s)", got, want)
	}
	if got := pages.Load(); got != 2 {
		t.Errorf("%d pages asked for, want 2 (a page of nulls ends the copy)", got)
	}
}
