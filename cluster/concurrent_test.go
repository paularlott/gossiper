package cluster_test

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// TestConcurrentPublishersOnEveryNode: publishers on every node at once; every subscriber on every node receives
// every update exactly once.
func TestConcurrentPublishersOnEveryNode(t *testing.T) {
	const (
		nodeCount  = 4
		workers    = 3  // publishers per node
		perWorker  = 40 // updates per publisher
		subsPerHub = 2
	)
	total := nodeCount * workers * perWorker
	nodes := newCluster(t, clusterOpts{n: nodeCount})

	var subs []*sseClient
	for _, n := range nodes {
		for range subsPerHub {
			subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
		}
	}

	var (
		mu        sync.Mutex
		published = map[string]string{} // event ID -> data
		failures  []string
		wg        sync.WaitGroup
	)
	for ni, n := range nodes {
		hc := newClient(t)
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range perWorker {
					data := fmt.Sprintf("n%d/w%d/%d", ni, w, i)
					id, status, err := n.tryPublish(hc, url.Values{"topic": {topicA}, "data": {data}})
					mu.Lock()
					switch {
					case err != nil:
						failures = append(failures, err.Error())
					case status != http.StatusOK:
						failures = append(failures, fmt.Sprintf("status %d: %s", status, id))
					default:
						published[id] = data
					}
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d publishes failed, first: %s", len(failures), failures[0])
	}
	if len(published) != total {
		t.Fatalf("%d distinct event IDs for %d publishes", len(published), total)
	}

	for i, evs := range expectAll(t, total, subs...) {
		seen := make(map[string]string, total)
		for _, e := range evs {
			if _, dup := seen[e.ID]; dup {
				t.Errorf("subscriber %d (%s): event %s delivered twice", i, subs[i].node.addr, e.ID)
			}
			seen[e.ID] = e.Data
		}
		if len(seen) != len(published) {
			t.Errorf("subscriber %d (%s): %d distinct events, want %d", i, subs[i].node.addr, len(seen), len(published))
		}
		for id, data := range published {
			if got, ok := seen[id]; !ok {
				t.Errorf("subscriber %d (%s): missing event %s (%s)", i, subs[i].node.addr, id, data)
			} else if got != data {
				t.Errorf("subscriber %d (%s): event %s has data %q, want %q", i, subs[i].node.addr, id, got, data)
			}
		}
	}

	for _, n := range nodes {
		st := n.hub.Stats()
		if st.Applied != uint64(total) || st.Duplicates != 0 || st.Dropped != 0 || st.HistoryLen != total {
			t.Errorf("node %s: applied %d (want %d), duplicates %d, dropped %d, history %d", n.addr, st.Applied, total, st.Duplicates, st.Dropped, st.HistoryLen)
		}
		if st.Published != uint64(workers*perWorker) {
			t.Errorf("node %s published %d, want %d", n.addr, st.Published, workers*perWorker)
		}
	}

	// Replication is not ordered across nodes (gossip sends from several workers), but each node's history is:
	// the order of the stamps. Every node's replay therefore lists the same updates in the same order.
	var first []string
	for i, n := range nodes {
		c := n.subscribe(t, subOpts{topics: []string{topicA}, lastEventID: "earliest"})
		evs := expectAll(t, total, c)[0]
		ids := idsOf(evs)
		if i == 0 {
			first = ids
			continue
		}
		for j := range ids {
			if ids[j] != first[j] {
				t.Fatalf("node %s replays a different order from node %s at position %d", n.addr, nodes[0].addr, j)
			}
		}
	}
}
