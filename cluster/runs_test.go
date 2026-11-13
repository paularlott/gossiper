package cluster_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/cluster"
)

// topicA2 is a second topic that, like topicA, matches the template https://example.com/{x}/{y}.
const topicA2 = "https://example.com/books/2"

// streamAck is a line of a streaming publish's answer.
type streamAck struct {
	ID     string `json:"id"`
	Line   int    `json:"line"`
	Status int    `json:"status"`
	Error  string `json:"error"`
}

// streamPublish posts lines to target as one streaming publish (a body that ends: the hub reads lines in a row, and
// publishes them in runs) and returns the answers. host, when set, is the request's Host (a tenant's).
func streamPublish(t testing.TB, target, host, tok string, lines []string) []streamAck {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(strings.Join(lines, "\n")+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: waitMax}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream: status %d", resp.StatusCode)
	}
	var out []streamAck
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var a streamAck
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatalf("answer %q: %v", sc.Text(), err)
		}
		out = append(out, a)
	}
	return out
}

// streamLine is a line of a streaming publish.
func streamLine(topic, data string) string {
	b, _ := json.Marshal(map[string]any{"topic": []string{topic}, "data": data})
	return string(b)
}

// datas returns the data of each event.
func datas(evs []sseEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Data
	}
	return out
}

// expectData waits for exactly the events whose data is want, in that order.
func expectData(t *testing.T, c *sseClient, want []string) {
	t.Helper()
	if got := datas(c.expect(t, len(want))); !slices.Equal(got, want) {
		t.Fatalf("subscriber on %s received out of order or not what was published:\n got %v\nwant %v", c.node.addr, got, want)
	}
}

// A streaming publish's runs cross the cluster as batches, and every node applies each as a run: every subscriber,
// whatever mix of the run's topics it receives, gets its updates in the order published, and every line is answered
// in order, a refused one (by the hub, or by the transport: too large to replicate) with its own line.
func TestStreamRunsAcrossCluster(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3, node: func(i int, o *nodeOpts) {
		o.tr = func(opts *cluster.Options) { opts.MaxUpdateBytes = 4096 }
	}})
	type subs struct{ both, onlyA, pattern *sseClient }
	var all []subs
	for _, n := range nodes {
		all = append(all, subs{
			both:    n.subscribe(t, subOpts{topics: []string{topicA, topicA2}}),
			onlyA:   n.subscribe(t, subOpts{topics: []string{topicA}}),
			pattern: n.subscribe(t, subOpts{topics: []string{"https://example.com/{x}/{y}"}}),
		})
	}
	const n = 640 // ten runs and more
	var lines, wantBoth, wantA []string
	for i := range n {
		switch i {
		case 100:
			lines = append(lines, "{nope")
		case 300:
			lines = append(lines, streamLine(topicA, strings.Repeat("x", 5000))) // over MaxUpdateBytes
		default:
			data := strconv.Itoa(i)
			topic := topicA
			if i%3 == 0 {
				topic = topicA2
			} else {
				wantA = append(wantA, data)
			}
			wantBoth = append(wantBoth, data)
			lines = append(lines, streamLine(topic, data))
		}
	}
	got := streamPublish(t, nodes[0].url(), "", pubTokenCached, lines)
	if len(got) != n {
		t.Fatalf("%d answers, want %d", len(got), n)
	}
	for i, a := range got {
		switch i {
		case 100:
			if a.Line != 101 || a.Status != http.StatusBadRequest {
				t.Errorf("answer %d: %+v", i, a)
			}
		case 300:
			if a.Line != 301 || a.Status != http.StatusRequestEntityTooLarge || a.ID != "" {
				t.Errorf("answer %d: %+v", i, a)
			}
		default:
			if a.ID == "" || a.Status != 0 {
				t.Errorf("answer %d: %+v", i, a)
			}
		}
	}
	for _, s := range all {
		expectData(t, s.both, wantBoth)
		expectData(t, s.onlyA, wantA)
		expectData(t, s.pattern, wantBoth)
	}
	for _, node := range nodes[1:] {
		batches, updates := node.tr.Received()
		if updates != uint64(len(wantBoth)) || batches > updates/4 {
			t.Errorf("node %s received %d updates in %d batches: the runs did not cross as batches", node.addr, updates, batches)
		}
	}
	for _, node := range nodes {
		if d := node.tr.Dropped(); d != 0 {
			t.Errorf("node %s dropped %d", node.addr, d)
		}
	}
}

// A run larger than a batch (batchBytes, 1 MiB) is split over several, and still arrives whole and in order.
func TestStreamRunSplit(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 2})
	sub := nodes[1].subscribe(t, subOpts{topics: []string{topicA}})
	var lines, want []string
	for i := range 64 { // one run, of about 2.5 MiB
		data := fmt.Sprintf("%03d-%s", i, strings.Repeat("y", 40<<10))
		want = append(want, data)
		lines = append(lines, streamLine(topicA, data))
	}
	for i, a := range streamPublish(t, nodes[0].url(), "", pubTokenCached, lines) {
		if a.ID == "" || a.Status != 0 {
			t.Fatalf("answer %d: %+v", i, a)
		}
	}
	expectData(t, sub, want)
	if batches, updates := nodes[1].tr.Received(); updates != 64 || batches < 3 {
		t.Errorf("received %d updates in %d batches, want 64 in 3 or more", updates, batches)
	}
	if d := nodes[0].tr.Dropped(); d != 0 {
		t.Errorf("dropped %d", d)
	}
}

// v030 is the cluster transport as a 0.3.0 node uses it: it neither publishes runs (it is not a
// gossiper.RunPublisher) nor applies them (the host it hands the transport is not a gossiper.RunApplier). The messages
// between the nodes are 0.3.0's either way: 0.4.0 sends a run in the batches 0.3.0 already sent.
type v030 struct{ tr *cluster.Transport }

type hostOnly struct{ gossiper.Host }

func (v v030) Start(h gossiper.Host) error { return v.tr.Start(hostOnly{h}) }
func (v v030) Publish(ctx context.Context, u *gossiper.Update) error {
	return v.tr.Publish(ctx, u)
}
func (v v030) PublishCopies(ctx context.Context, u *gossiper.Update, n int) (func(context.Context) error, error) {
	return v.tr.PublishCopies(ctx, u, n)
}
func (v v030) RemoteSubscriptions(ctx context.Context) ([]gossiper.Subscription, bool, error) {
	return v.tr.RemoteSubscriptions(ctx)
}
func (v v030) NodeID() string { return v.tr.NodeID() }
func (v v030) Close() error   { return v.tr.Close() }

// A cluster in a rolling upgrade: a node that publishes and applies an update at a time (0.3.0) and nodes that do
// both in runs exchange updates both ways, every subscriber getting them in order, each once.
func TestStreamRunsMixedVersions(t *testing.T) {
	nodes := newCluster(t, clusterOpts{n: 3, node: func(i int, o *nodeOpts) {
		if i == 2 {
			o.hub = func(c *gossiper.Config) { c.Transport = v030{c.Transport.(*cluster.Transport)} }
		}
	}})
	var subs []*sseClient
	for _, n := range nodes {
		subs = append(subs, n.subscribe(t, subOpts{topics: []string{topicA, topicB}}))
	}
	c := newClient(t)
	var want []string
	for _, from := range []int{0, 2, 1} {
		var lines []string
		for i := range 300 {
			data := fmt.Sprintf("n%d-%d", from, i)
			topic := topicA
			if i%4 == 0 {
				topic = topicB
			}
			want = append(want, data)
			lines = append(lines, streamLine(topic, data))
		}
		for i, a := range streamPublish(t, nodes[from].url(), "", pubTokenCached, lines) {
			if a.ID == "" || a.Status != 0 {
				t.Fatalf("node %d, answer %d: %+v", from, i, a)
			}
		}
		// And a POST after the stream, as a browser publishes.
		data := fmt.Sprintf("n%d-post", from)
		nodes[from].publish(t, c, url.Values{"topic": {topicA}, "data": {data}})
		want = append(want, data)
		for _, s := range subs {
			s.wait(t, len(want))
		}
	}
	for _, s := range subs {
		expectData(t, s, want)
	}
	for _, n := range nodes {
		if d := n.tr.Dropped(); d != 0 {
			t.Errorf("node %s dropped %d", n.addr, d)
		}
	}
}

// Tenants over the cluster transport publish a tenant's stream in runs, and the other nodes apply each batch as runs
// of its tenant's hub: the tenant's subscribers there get every update in order, the other tenant's none.
func TestStreamRunsTenantsCluster(t *testing.T) {
	n1, n2 := newTenantNode(t), newTenantNode(t)
	if err := n2.gc.Join([]string{n1.addr}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, waitMax, "the nodes to see each other", func() bool { return len(n1.tr.Peers()) == 1 && len(n2.tr.Peers()) == 1 })
	for _, n := range []*tenantNode{n1, n2} {
		for _, name := range []string{"acme", "globex"} {
			if err := n.ts.Set(liveTenant(name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	acme, globex := n2.subscribe(t, "acme"), n2.subscribe(t, "globex")
	local := n1.subscribe(t, "acme")
	var lines, want []string
	for i := range 400 {
		data := strconv.Itoa(i)
		want = append(want, data)
		lines = append(lines, streamLine(liveTopic, data))
	}
	tok := liveToken(t, "acme", map[string]any{"publish": []string{"*"}})
	for i, a := range streamPublish(t, n1.srv.URL+hubPath, "acme.test", tok, lines) {
		if a.ID == "" || a.Status != 0 {
			t.Fatalf("answer %d: %+v", i, a)
		}
	}
	expectData(t, acme, want)
	expectData(t, local, want)
	time.Sleep(settle)
	if got := globex.count(); got != 0 {
		t.Errorf("globex received %d events", got)
	}
	if batches, updates := n2.tr.Received(); updates < 400 || batches > updates/4 { // and the subscription events
		t.Errorf("node 2 received %d updates in %d batches: the runs did not cross as batches", updates, batches)
	}
}
