package server

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func status(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// With admin-listen the admin API, its docs and the metrics move to the admin listener; the hub and the health checks
// stay on the main one (and the health checks are on both).
func TestAdminListener(t *testing.T) {
	s := adminSettings(t, "")
	s.Metrics, s.AdminListen = true, "127.0.0.1:0"
	n := startNode(t, s)
	for _, path := range []string{"/metrics", "/api-docs/", "/api/openapi.json", "/api/status"} {
		if got := status(t, n.base+path); got != http.StatusNotFound {
			t.Errorf("main %s: %d, want 404", path, got)
		}
	}
	for path, want := range map[string]int{"/metrics": 200, "/api-docs/": 200, "/api/openapi.json": 200, "/api/status": 401,
		"/healthz": 200, "/readyz": 200, "/.well-known/mercure": 404} {
		if got := status(t, n.admin+path); got != want {
			t.Errorf("admin %s: %d, want %d", path, got, want)
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if got := status(t, n.base+path); got != http.StatusOK {
			t.Errorf("main %s: %d", path, got)
		}
	}
	if code, _ := call(t, n.admin, "GET", "/api/status", s.APIToken, nil); code != http.StatusOK {
		t.Errorf("admin API with the token: %d", code)
	}

	// Without it, everything is on the main listener.
	s.AdminListen = ""
	m := startNode(t, s)
	if m.AdminHandler != nil {
		t.Fatal("an admin handler without admin-listen")
	}
	for _, path := range []string{"/metrics", "/api-docs/"} {
		if got := status(t, m.base+path); got != http.StatusOK {
			t.Errorf("main %s without admin-listen: %d", path, got)
		}
	}
}

func TestClientIP(t *testing.T) {
	proxies, err := parseProxies([]string{"10.0.0.0/8", "192.168.1.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{proxies: proxies}
	for _, c := range []struct{ remote, xff, want string }{
		{"203.0.113.9:1234", "", "203.0.113.9"},
		{"203.0.113.9:1234", "198.51.100.1", "203.0.113.9"},        // not from a proxy: the header is the client's
		{"10.1.2.3:1234", "198.51.100.1", "198.51.100.1"},          // from a proxy
		{"10.1.2.3:1234", "6.6.6.6, 198.51.100.1", "198.51.100.1"}, // the client's own header is not believed
		{"10.1.2.3:1234", "198.51.100.1, 10.9.9.9", "198.51.100.1"},
		{"192.168.1.1:80", "198.51.100.1, 192.168.1.1", "198.51.100.1"},
		{"[::1]:80", "2001:db8::1", "2001:db8::1"},
		{"10.1.2.3:1234", "", "10.1.2.3"},
		{"10.1.2.3:1234", "junk", "10.1.2.3"},
		{"10.1.2.3:1234", "10.2.2.2", "10.2.2.2"},              // proxies all the way: the furthest one
		{"10.1.2.3:1234", "198.51.100.1:5678", "198.51.100.1"}, // with the port some proxies add
		{"10.1.2.3:1234", "[2001:db8::1]:443", "2001:db8::1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%s %q: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	if _, err := parseProxies([]string{"nonsense"}); err == nil {
		t.Error("nonsense accepted as a proxy")
	}
	if _, err := New(Settings{TrustedProxies: []string{"10.0.0.0/33"}}, nil); err == nil {
		t.Error("an invalid trusted proxy was accepted")
	}
}

// A node with peers to join is ready once it has copied a peer's history; the cluster's metrics include the updates
// not sent to a peer.
func TestClusterReadyAndMetrics(t *testing.T) {
	nodes := clusterNodes(t, 2, func(_ int, s *Settings) { s.Metrics = true })
	for _, n := range nodes {
		eventually(t, 15*time.Second, "ready", func() bool { return status(t, n.base+"/readyz") == http.StatusOK })
		if v, ok := metricValue(metricsText(t, n.base), "gossiper_replication_dropped_total"); !ok || v != "0" {
			t.Errorf("gossiper_replication_dropped_total: %q %v", v, ok)
		}
		if _, ok := metricValue(metricsText(t, n.base), "gossiper_history_bytes"); !ok {
			t.Error("no gossiper_history_bytes")
		}
	}
}

// The server speaks HTTP/2 without TLS: a streaming publish and a subscription share one connection.
func TestStreamingPublishOverH2C(t *testing.T) {
	n := startNode(t, settings())
	tr := &http.Transport{}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetUnencryptedHTTP2(true)
	c := &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()

	sub, err := c.Get(n.base + "/.well-known/mercure?topic=" + url.QueryEscape("https://h2c.test/a"))
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Body.Close()
	if sub.ProtoMajor != 2 {
		t.Fatalf("subscription over %s", sub.Proto)
	}
	events := bufio.NewScanner(sub.Body)

	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequest(http.MethodPost, n.base+"/.well-known/mercure", pr)
	req.Header.Set("Authorization", "Bearer "+token(t, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}))
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 {
		t.Fatalf("stream: %s %d", resp.Proto, resp.StatusCode)
	}
	answers := bufio.NewScanner(resp.Body)
	for i := range 3 {
		fmt.Fprintf(pw, `{"topic":["https://h2c.test/a"],"data":"d%d"}`+"\n", i)
		if !answers.Scan() || !strings.HasPrefix(answers.Text(), `{"id"`) {
			t.Fatalf("answer %d: %q", i, answers.Text())
		}
	}
	got := 0
	for got < 3 && events.Scan() {
		if strings.HasPrefix(events.Text(), "data: d") {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("the subscriber received %d of 3", got)
	}
}
