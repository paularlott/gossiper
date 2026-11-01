package cluster_test

import (
	"github.com/paularlott/gossiper"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const topicA = "https://example.com/books/1"

// TestPublishReplicatesToEveryNode publishes through one node and checks that subscribers of every node receive the
// update once, with the ID the publisher was given and the same SSE frame.
func TestPublishReplicatesToEveryNode(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 4})
	hc := newClient(t)

	const alt = "https://example.com/authors/9"
	cases := []struct {
		name  string
		form  url.Values
		frame func(id string) string
	}{
		{
			name: "plain",
			form: url.Values{"topic": {topicA}, "data": {"hello"}},
			frame: func(id string) string {
				return "id: " + id + "\ndata: hello\n\n"
			},
		},
		{
			name: "every field",
			form: url.Values{
				"topic": {topicA, alt}, "id": {"custom-id-1"}, "type": {"book.updated"}, "retry": {"1500"},
				"data": {"line1\r\nline2\rline3\nünï ✓"},
			},
			frame: func(string) string {
				return "event: book.updated\nretry: 1500\nid: custom-id-1\n" +
					"data: line1\ndata: line2\ndata: line3\ndata: ünï ✓\n\n"
			},
		},
		{
			name: "no data",
			form: url.Values{"topic": {topicA}},
			frame: func(id string) string {
				return "id: " + id + "\ndata: \n\n"
			},
		},
		{
			name: "retry zero",
			form: url.Values{"topic": {topicA}, "retry": {"0"}, "data": {"x"}},
			frame: func(id string) string {
				return "retry: 0\nid: " + id + "\ndata: x\n\n"
			},
		},
	}

	// Two subscribers per node: one on the canonical topic, one on the alternate only.
	var onTopic, onAlt []*sseClient
	for _, n := range nodes {
		onTopic = append(onTopic, n.subscribe(t, subOpts{topics: []string{topicA}}), n.subscribe(t, subOpts{topics: []string{topicA}}))
		onAlt = append(onAlt, n.subscribe(t, subOpts{topics: []string{alt}}))
	}

	var wantFrames []string
	var wantIDs []string
	var altFrames []string
	for _, tc := range cases {
		id := nodes[0].publish(t, hc, tc.form)
		if !strings.HasPrefix(id, "urn:uuid:") && tc.form.Get("id") == "" {
			t.Fatalf("%s: hub-assigned ID %q is not a UUID URN", tc.name, id)
		}
		if want := tc.form.Get("id"); want != "" && id != want {
			t.Fatalf("%s: publish answered ID %q, want %q", tc.name, id, want)
		}
		wantIDs = append(wantIDs, id)
		wantFrames = append(wantFrames, tc.frame(id))
		if len(tc.form["topic"]) > 1 {
			altFrames = append(altFrames, tc.frame(id))
		}
		// One at a time, so the order each subscriber sees is the order of publication.
		for _, c := range onTopic {
			c.wait(t, len(wantIDs))
		}
	}

	for ci, evs := range expectAll(t, len(cases), onTopic...) {
		c := onTopic[ci]
		for i, e := range evs {
			if e.ID != wantIDs[i] {
				t.Errorf("node %s event %d: ID %q, want %q", c.node.addr, i, e.ID, wantIDs[i])
			}
			if e.Frame != wantFrames[i] {
				t.Errorf("node %s event %d: frame %q, want %q", c.node.addr, i, e.Frame, wantFrames[i])
			}
		}
	}
	for ci, evs := range expectAll(t, len(altFrames), onAlt...) {
		c := onAlt[ci]
		for i, e := range evs {
			if e.Frame != altFrames[i] {
				t.Errorf("node %s alternate event %d: frame %q, want %q", c.node.addr, i, e.Frame, altFrames[i])
			}
		}
	}

	// Every node applied each update exactly once: the transport never delivered one twice.
	for _, n := range nodes {
		st := n.hub.Stats()
		if st.Applied != uint64(len(cases)) || st.Duplicates != 0 {
			t.Errorf("node %s: applied %d (want %d), duplicates %d (want 0)", n.addr, st.Applied, len(cases), st.Duplicates)
		}
		if st.HistoryLen != len(cases) {
			t.Errorf("node %s: history holds %d updates, want %d", n.addr, st.HistoryLen, len(cases))
		}
	}
	if got := nodes[0].hub.Stats().Published; got != uint64(len(cases)) {
		t.Errorf("origin published %d, want %d", got, len(cases))
	}
	for _, n := range nodes[1:] {
		if got := n.hub.Stats().Published; got != 0 {
			t.Errorf("node %s published %d, want 0 (it only applied replicated updates)", n.addr, got)
		}
	}
}

// TestPublishFromEveryNode publishes through each node in turn: whichever node takes the publish, all see it.
func TestPublishFromEveryNode(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	hc := newClient(t)
	var subs []*sseClient
	for _, n := range nodes {
		subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
	}
	var want []string
	for i, n := range nodes {
		want = append(want, n.publish(t, hc, url.Values{"topic": {topicA}, "data": {"from " + n.addr}}))
		for _, s := range subs {
			s.wait(t, i+1)
		}
	}
	for i, got := range expectAll(t, len(nodes), subs...) {
		if !slices.Equal(idsOf(got), want) {
			t.Errorf("node %s received %v, want %v", subs[i].node.addr, idsOf(got), want)
		}
	}
}

// TestSamePublisherIDFromTwoNodes: a publisher may reuse an ID; the hub tells publications apart by origin and
// stamp, so both are delivered everywhere.
func TestSamePublisherIDFromTwoNodes(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	hc := newClient(t)
	var subs []*sseClient
	for _, n := range nodes {
		subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA}}))
	}
	nodes[0].publish(t, hc, url.Values{"topic": {topicA}, "id": {"same"}, "data": {"first"}})
	nodes[1].publish(t, hc, url.Values{"topic": {topicA}, "id": {"same"}, "data": {"second"}})
	for i, evs := range expectAll(t, 2, subs...) {
		s := subs[i]
		var data []string
		for _, e := range evs {
			data = append(data, e.Data)
		}
		slices.Sort(data)
		if !slices.Equal(data, []string{"first", "second"}) {
			t.Errorf("node %s received %v", s.node.addr, data)
		}
	}
}

// TestHubPublishAPIReplicates: Hub.Publish (the Go API, no HTTP) replicates like a publish request.
func TestHubPublishAPIReplicates(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3})
	subs := []*sseClient{
		nodes[1].subscribe(t, subOpts{topics: []string{topicA}}),
		nodes[2].subscribe(t, subOpts{topics: []string{topicA}}),
	}
	id, err := nodes[0].hub.Publish(t.Context(), &gossiper.Update{Topics: []string{topicA}, Data: "api"})
	if err != nil {
		t.Fatal(err)
	}
	for i, evs := range expectAll(t, 1, subs...) {
		s := subs[i]
		if evs[0].ID != id || evs[0].Data != "api" {
			t.Errorf("node %s received %+v, want id %s", s.node.addr, evs[0], id)
		}
	}
}

func idsOf(evs []sseEvent) []string {
	var ids []string
	for _, e := range evs {
		ids = append(ids, e.ID)
	}
	return ids
}
