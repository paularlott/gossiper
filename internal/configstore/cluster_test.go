package configstore_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossiper/internal/configstore"
)

// pushOnly is a node that only gets records by push: no periodic rounds (the harness default), and a push timeout
// no -race slowdown reaches.
var pushOnly = nodeCfg{store: func(o *configstore.Options) { o.PushTimeout = 10 * time.Second }}

// periodic is a node with frequent anti-entropy rounds and short push timeouts.
func periodic() nodeCfg {
	return nodeCfg{store: func(o *configstore.Options) {
		o.SyncInterval = 200 * time.Millisecond
		o.PushTimeout = 200 * time.Millisecond
	}}
}

// Writes on every node reach every other node by push alone.
func TestWritesConvergeByPush(t *testing.T) {
	tc := newCluster(t, 3, pushOnly)
	n := tc.nodes
	// Let the rounds run as the nodes joined finish, so that none can see the writes.
	waitFor(t, waitMax, "the join rounds", func() bool {
		for _, nd := range n {
			if nd.store().Stats().PeersSynced != 2 {
				return false
			}
		}
		return true
	})
	for i, nd := range n {
		put(t, nd.store(), fmt.Sprintf("node/%d", i), fmt.Sprint("value", i), "shared/"+fmt.Sprint(i), "x")
	}
	waitSame(t, n...)
	for i, nd := range n {
		for j := range n {
			if v, ok := value(nd.store(), fmt.Sprintf("node/%d", j)); !ok || v != fmt.Sprint("value", j) {
				t.Fatalf("node %d: node/%d = %q, %v", i, j, v, ok)
			}
		}
		// Remote records reach OnChange too.
		waitFor(t, waitMax, "OnChange for every key", func() bool { return nd.ch.has("node/0", "node/1", "node/2") })
		st := nd.store().Stats()
		if st.Pushes < 2 || st.PushErrors != 0 || st.Received != 4 || st.Records != 6 || st.Peers != 2 {
			t.Fatalf("node %d stats %+v", i, st)
		}
		if st.Repairs != 0 {
			t.Fatalf("node %d: an anti-entropy round repaired something: %+v", i, st)
		}
	}
	// A write that changes nothing (an empty transaction) sends nothing.
	before := n[0].store().Stats().Pushes
	if err := n[0].store().Update(context.Background(), func(*configstore.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := n[0].store().Stats().Pushes; got != before {
		t.Fatalf("an empty Update pushed: %d -> %d", before, got)
	}
}

// Two nodes write the same keys at the same time: every node ends with the same winner for each.
func TestConcurrentWritesSameKey(t *testing.T) {
	tc := newCluster(t, 3, pushOnly)
	n := tc.nodes
	const keys = 20
	var wg sync.WaitGroup
	for w := range 2 {
		s := n[w].store()
		wg.Go(func() {
			for round := range 5 {
				for k := range keys {
					err := s.Update(context.Background(), func(tx *configstore.Tx) error {
						tx.Put(fmt.Sprintf("k/%d", k), []byte(fmt.Sprintf("writer%d-round%d", w, round)))
						return nil
					})
					if err != nil {
						t.Error(err)
						return
					}
				}
			}
		})
	}
	wg.Wait()
	waitSame(t, n...) // same value, version and origin for every key everywhere
	for k := range keys {
		r, ok := n[2].store().Get(fmt.Sprintf("k/%d", k))
		if !ok || !strings.HasSuffix(string(r.Value), "-round4") {
			t.Fatalf("k/%d = %q: the winner is not a last write", k, r.Value)
		}
	}
}

// A delete replicates, and a put older than the tombstone that arrives later does not bring the key back.
func TestDeleteReplicates(t *testing.T) {
	tc := newCluster(t, 3, pushOnly)
	n := tc.nodes
	put(t, n[0].store(), "tenant/1", "t1", "tenant/1/user/a", "ua", "tenant/1/user/b", "ub", "tenant/2", "t2")
	waitSame(t, n...)
	old, _ := n[2].store().Get("tenant/1/user/a")

	if err := n[1].store().Update(context.Background(), func(tx *configstore.Tx) error {
		deletePrefix(tx, "tenant/1")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitSame(t, n...)
	for i, nd := range n {
		if got := keysOf(nd.store().List("")); len(got) != 1 || got[0] != "tenant/2" {
			t.Fatalf("node %d after delete: %v", i, got)
		}
		if st := nd.store().Stats(); st.Tombstones != 3 {
			t.Fatalf("node %d stats %+v", i, st)
		}
	}
	for i, nd := range n {
		if applied, err := nd.store().Merge([]configstore.Record{old}); err != nil || applied != 0 {
			t.Fatalf("node %d: merging the old put = %d, %v", i, applied, err)
		}
		if _, ok := nd.store().Get("tenant/1/user/a"); ok {
			t.Fatalf("node %d: an old put undid the delete", i)
		}
	}
}

// A node that was down catches up when it returns: with periodic rounds off, by the round run when it rejoins.
func TestNodeDownCatchesUp(t *testing.T) {
	tc := newCluster(t, 3, pushOnly)
	n := tc.nodes
	put(t, n[0].store(), "a", "1", "b", "2", "c", "3")
	waitSame(t, n...)
	originC := n[2].store().NodeID()

	n[2].stop()
	tc.waitPeers(n[0], n[1])
	put(t, n[0].store(), "a", "1b", "d", "4")
	del(t, n[1].store(), "b")
	put(t, n[1].store(), "e", "5")

	n[2].boot([]string{n[0].addr, n[1].addr}) // same id, address and database
	waitSame(t, n...)
	if n[2].store().NodeID() != originC {
		t.Fatalf("restarted node writes as %s, was %s", n[2].store().NodeID(), originC)
	}
	if got := keysOf(n[2].store().List("")); strings.Join(got, ",") != "a,c,d,e" {
		t.Fatalf("restarted node holds %v", got)
	}
	if v, _ := value(n[2].store(), "a"); v != "1b" {
		t.Fatalf("a = %q", v)
	}
	waitFor(t, waitMax, "OnChange on the restarted node", func() bool { return n[2].ch.has("a", "b", "d", "e") })
	waitFor(t, waitMax, "a round with each peer", func() bool {
		st := n[2].store().Stats()
		return st.PeersSynced == 2 && st.Repairs > 0 && !st.LastSync.IsZero()
	})

	// It takes writes again, pushed as before.
	put(t, n[2].store(), "f", "6")
	waitSame(t, n...)
}

// A node that restarts while its peer cannot answer rounds yet (still starting, say) keeps trying, beyond a few
// seconds, until a round completes: without periodic rounds, the peer is counted synced again.
func TestRejoinSyncsWhenPeerAnswersLate(t *testing.T) {
	tc := newCluster(t, 2, pushOnly) // no periodic rounds: only the rounds queued at join can do it
	n := tc.nodes
	waitFor(t, waitMax, "the join rounds", func() bool {
		return n[0].store().Stats().PeersSynced == 1 && n[1].store().Stats().PeersSynced == 1
	})

	n[1].stop()
	tc.waitPeers(n[0])
	n[0].store().RefuseRoundsFor(12 * time.Second) // well past three tries a second apart
	n[1].boot([]string{n[0].addr})
	waitFor(t, waitMax, "the restarted node's round with its peer", func() bool {
		return n[1].store().Stats().PeersSynced == 1
	})
	if st := n[1].store().Stats(); st.SyncErrors < 3 {
		t.Fatalf("the peer refused rounds, yet only %d failed: %+v", st.SyncErrors, st)
	}
}

// A peer counted synced that stops answering is found out by the periodic rounds, even while another peer keeps
// failing (whose retries must not take every round).
func TestSyncedPeerThatStopsAnsweringIsUncounted(t *testing.T) {
	tc := newCluster(t, 3, periodic())
	n := tc.nodes
	waitFor(t, waitMax, "every round", func() bool { return n[0].store().Stats().PeersSynced == 2 })
	n[2].store().RefuseRoundsFor(time.Hour)
	waitFor(t, waitMax, "the refusing peer to be uncounted", func() bool { return n[0].store().Stats().PeersSynced == 1 })
	n[1].store().RefuseRoundsFor(time.Hour)
	waitFor(t, waitMax, "the second refusing peer to be uncounted", func() bool { return n[0].store().Stats().PeersSynced == 0 })
}

// Writes made on both sides of a partition reach every node once it heals.
func TestPartitionedWritesPropagate(t *testing.T) {
	tc := newCluster(t, 3, periodic())
	n := tc.nodes
	put(t, n[0].store(), "shared", "before", "gone", "x")
	waitSame(t, n...)

	tc.net.isolate(n[2].addr)
	// Writes on the cut-off node succeed: a push nobody acknowledges does not fail the write.
	started := time.Now()
	put(t, n[2].store(), "from-c", "c", "shared", "c-wins-if-last")
	del(t, n[2].store(), "gone")
	if d := time.Since(started); d > 5*time.Second {
		t.Fatalf("writes on the isolated node took %v", d)
	}
	put(t, n[0].store(), "from-a", "a")
	put(t, n[1].store(), "from-b", "b")
	time.Sleep(300 * time.Millisecond)
	if _, ok := n[0].store().Get("from-c"); ok {
		t.Fatal("a record crossed the partition")
	}

	tc.net.heal(n[2].addr)
	waitSame(t, n...)
	for _, k := range []string{"from-a", "from-b", "from-c"} {
		if _, ok := n[1].store().Get(k); !ok {
			t.Fatalf("%s missing after the partition healed", k)
		}
	}
	if _, ok := n[0].store().Get("gone"); ok {
		t.Fatal("a delete made on the cut-off node did not propagate")
	}
	if v, _ := value(n[0].store(), "shared"); v != "c-wins-if-last" {
		t.Fatalf("shared = %q", v)
	}
}

// A node with an empty database that joins an established cluster gets every record, tombstones too.
func TestEmptyNodeJoins(t *testing.T) {
	tc := newCluster(t, 2, pushOnly)
	n := tc.nodes
	for i := range 50 {
		put(t, n[i%2].store(), fmt.Sprintf("r/%02d", i), fmt.Sprint(i))
	}
	del(t, n[0].store(), "r/00", "r/01")
	waitSame(t, n...)

	c := tc.add(pushOnly)
	tc.waitPeers(tc.nodes...)
	waitSame(t, tc.nodes...)
	if st := c.store().Stats(); st.Records != 48 || st.Tombstones != 2 || st.Received != 50 {
		t.Fatalf("joined node stats %+v", st)
	}
}

// 3000 records replicate both by push (one transaction writing them all) and by anti-entropy to a node that joins
// late, in chunks well under gossip's packet limit.
func TestLargeTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("large transfer")
	}
	tc := newCluster(t, 2, pushOnly)
	n := tc.nodes
	const count = 3000
	val := []byte(strings.Repeat("v", 1024))
	// Long keys: the summary needs more than one page.
	key := func(i int) string { return fmt.Sprintf("tenant/%04d/%s", i, strings.Repeat("k", 150)) }
	if err := n[0].store().Update(context.Background(), func(tx *configstore.Tx) error {
		for i := range count {
			tx.Put(key(i), val)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := n[0].store().Stats(); st.Pushes < 6 || st.PushErrors != 0 { // ~3.5 MB in chunks of 512 KiB
		t.Fatalf("push stats %+v", st)
	}
	if st := n[1].store().Stats(); st.Records != count {
		t.Fatalf("peer holds %d records after the push, want %d", st.Records, count)
	}
	del(t, n[1].store(), key(0), key(1))

	c := tc.add(pushOnly)
	tc.waitPeers(tc.nodes...)
	waitFor(t, waitMax, "the late node to get every record", func() bool {
		st := c.store().Stats()
		return st.Records+st.Tombstones == count
	})
	waitSame(t, tc.nodes...)
	if st := c.store().Stats(); st.Records != count-2 || st.Tombstones != 2 {
		t.Fatalf("late node stats %+v", st)
	}
}

// A node that announces a store but has none (no handlers) neither fails nor holds up writes: a push to it
// times out after PushTimeout and the rounds with it fail quietly.
func TestPeerWithoutStore(t *testing.T) {
	tc := newCluster(t, 2, periodic())
	n := tc.nodes

	addr := freeAddr()
	gc := gossipConfig(addr)
	gc.Transport = gossip.NewSocketTransport(gc)
	gc.Logger = recLogger{&recorder{}}
	bare, err := gossip.NewCluster(gc)
	if err != nil {
		t.Fatal(err)
	}
	if err := startGossip(bare); err != nil {
		t.Fatal(err)
	}
	defer bare.Stop()
	bare.LocalMetadata().SetString("gossiper.configstore", "on")
	if err := bare.Join([]string{n[0].addr}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, waitMax, "the bare node to join", func() bool {
		return n[0].store().Stats().Peers == 2 && n[1].store().Stats().Peers == 2
	})

	started := time.Now()
	put(t, n[0].store(), "k", "v")
	if d := time.Since(started); d > 3*time.Second {
		t.Fatalf("Update took %v with a peer that never answers", d)
	}
	waitFor(t, waitMax, "k to replicate", func() bool { _, ok := n[1].store().Get("k"); return ok })
	if st := n[0].store().Stats(); st.PushErrors == 0 {
		t.Fatalf("no push error counted: %+v", st)
	}
}

// Many goroutines update and read the stores of a cluster at once.
func TestConcurrentUpdatesCluster(t *testing.T) {
	tc := newCluster(t, 2, periodic())
	concurrentCounter(t, []*configstore.Store{tc.nodes[0].store(), tc.nodes[1].store()})
	waitSame(t, tc.nodes...)
}
