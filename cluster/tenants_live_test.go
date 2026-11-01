package cluster_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossip"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/gossiper/cluster"
)

// tenantNode is one node of a cluster that serves tenants: a gossip node, the transport over it, the Tenants (none at
// first) and an HTTP server serving them.
type tenantNode struct {
	gc   *gossip.Cluster
	tr   *cluster.Transport
	ts   *gossiper.Tenants
	srv  *httptest.Server
	addr string
	ref  *testNode // for the subscribers' failure messages
}

func newTenantNode(t *testing.T) *tenantNode {
	t.Helper()
	n := &tenantNode{}
	var addr string
	for attempt := 0; ; attempt++ {
		port, err := freePort()
		if err != nil {
			t.Fatal(err)
		}
		addr = fmt.Sprintf("127.0.0.1:%d", port)
		cfg := gossipConfig(addr)
		cfg.Transport = gossip.NewSocketTransport(cfg)
		if n.gc, err = gossip.NewCluster(cfg); err != nil {
			t.Fatal(err)
		}
		if startCluster(n.gc) == nil {
			break
		}
		if attempt == 5 {
			t.Fatal("could not bind a gossip port")
		}
	}
	n.tr = cluster.New(n.gc, cluster.Options{})
	var err error
	if n.ts, err = gossiper.NewTenants(nil, n.tr); err != nil {
		n.gc.Stop()
		t.Fatal(err)
	}
	n.srv = httptest.NewServer(n.ts)
	n.addr, n.ref = addr, &testNode{addr: addr}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.ts.Close(ctx); err != nil {
			t.Errorf("tenants close: %v", err)
		}
		n.srv.Close()
		n.gc.Stop()
	})
	return n
}

// liveTenant is a tenant with an HS256 key of its own.
func liveTenant(name string) gossiper.Tenant {
	return gossiper.Tenant{Name: name, Hosts: []string{name + ".test"}, Config: gossiper.Config{
		PublisherKey: auth.KeyConfig{Key: name + "-" + testSecret}, Subscriptions: true, Heartbeat: -1,
	}}
}

func liveToken(t *testing.T, name string, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": claims}).SignedString([]byte(name + "-" + testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// request sends a request for the tenant's host to the node.
func (n *tenantNode) request(t *testing.T, ctx context.Context, method, tenant, path string, q url.Values, tok string) *http.Response {
	t.Helper()
	var body io.Reader
	target := n.srv.URL + path
	if method == http.MethodPost {
		body = strings.NewReader(q.Encode())
	} else if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = tenant + ".test"
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// liveTopic is the topic the tests publish to and subscribe to (not "*": that would include subscription events).
const liveTopic = "https://example.com/live"

// subscribe opens a stream of liveTopic of the tenant on the node.
func (n *tenantNode) subscribe(t *testing.T, tenant string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	resp := n.request(t, ctx, http.MethodGet, tenant, hubPath, url.Values{"topic": {liveTopic}}, liveToken(t, tenant, map[string]any{"subscribe": []string{"*"}}))
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.Fatalf("subscribe to %s: %d", tenant, resp.StatusCode)
	}
	c := &sseClient{t: t, node: n.ref, cancel: cancel, done: make(chan struct{}), header: resp.Header}
	go c.read(resp.Body)
	t.Cleanup(c.close)
	return c
}

func (n *tenantNode) publish(t *testing.T, tenant, data string) {
	t.Helper()
	resp := n.request(t, context.Background(), http.MethodPost, tenant, hubPath, url.Values{"topic": {liveTopic}, "data": {data}},
		liveToken(t, tenant, map[string]any{"publish": []string{"*"}}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish to %s: %d", tenant, resp.StatusCode)
	}
}

// remoteSubscribers returns the number of subscriptions the node's subscriptions API lists for the tenant.
func (n *tenantNode) remoteSubscribers(t *testing.T, tenant string) int {
	t.Helper()
	resp := n.request(t, context.Background(), http.MethodGet, tenant, subsPath, nil, liveToken(t, tenant, map[string]any{"subscribe": []string{"*"}}))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subscriptions of %s: %d", tenant, resp.StatusCode)
	}
	var list struct {
		Subscriptions []gossiper.Subscription `json:"subscriptions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	return len(list.Subscriptions)
}

// TestTenantsAddedAtRuntime: tenants added to every node of a running cluster share their updates and subscriptions
// across the nodes, each kept to its own tenant.
func TestTenantsAddedAtRuntime(t *testing.T) {
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
	n1.publish(t, "acme", "acme-1")
	if evs := acme.expect(t, 1); evs[0].Data != "acme-1" {
		t.Errorf("acme received %q", evs[0].Data)
	}
	if got := globex.count(); got != 0 {
		t.Errorf("globex received %v", globex.all())
	}
	// Node 1 lists node 2's subscribers of each tenant, and only that tenant's.
	if got := n1.remoteSubscribers(t, "acme"); got != 1 {
		t.Errorf("node 1 lists %d acme subscriptions, want 1", got)
	}
	if got := n1.remoteSubscribers(t, "globex"); got != 1 {
		t.Errorf("node 1 lists %d globex subscriptions, want 1", got)
	}
}
