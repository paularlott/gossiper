package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/logger"
)

const secret = "server-test-secret-0123456789abcdef"

func token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func freePort(t *testing.T, network string) string {
	t.Helper()
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().String()
	default: // a port free for both TCP and UDP (gossip binds both)
		for range 50 {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			pc, err := net.ListenPacket("udp", addr)
			ln.Close()
			if err == nil {
				pc.Close()
				return addr
			}
		}
		t.Fatal("no free port")
		return ""
	}
}

// start runs a server on a free port until the test ends.
func start(t *testing.T, s Settings) (*Server, string) {
	t.Helper()
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("server did not stop")
		}
	})
	return srv, "http://" + ln.Addr().String()
}

func settings() Settings {
	s := Defaults()
	s.PublisherKey = secret
	s.Anonymous = true
	s.Metrics = true
	s.HTTPOnly = true   // the tests speak plain HTTP; tls_test.go has the HTTPS ones
	s.Protocol = "both" // and draft-07, unless they choose otherwise
	return s
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func publish(t *testing.T, base, topic, data string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/.well-known/mercure",
		strings.NewReader(url.Values{"topic": {topic}, "data": {data}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token(t, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish: %d %s", resp.StatusCode, b)
	}
	return string(b)
}

// subscribe opens a stream and returns a channel of the data lines it receives.
func subscribe(t *testing.T, ctx context.Context, base, topic string) <-chan string {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/mercure?topic="+url.QueryEscape(topic), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subscribe: %d", resp.StatusCode)
	}
	out := make(chan string, 100)
	go func() {
		defer resp.Body.Close()
		defer close(out)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				out <- d
			}
		}
	}()
	return out
}

func receive(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatalf("stream closed, want %q", want)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

func TestHealthAndMetrics(t *testing.T) {
	_, base := start(t, settings())
	if code, body := get(t, base+"/healthz"); code != 200 || body != "ok\n" {
		t.Fatalf("healthz: %d %q", code, body)
	}
	if code, _ := get(t, base+"/readyz"); code != 200 {
		t.Fatalf("readyz: %d", code)
	}
	publish(t, base, "https://example.com/a", "x")
	code, body := get(t, base+"/metrics")
	if code != 200 || !strings.Contains(body, "gossiper_published_total 1\n") ||
		!strings.Contains(body, "# TYPE gossiper_subscribers gauge") {
		t.Fatalf("metrics: %d\n%s", code, body)
	}
	if code, _ := get(t, base+"/nope"); code != 404 {
		t.Fatalf("unknown path: %d", code)
	}
}

func TestMetricsOffByDefault(t *testing.T) {
	s := settings()
	s.Metrics = false
	_, base := start(t, s)
	if code, _ := get(t, base+"/metrics"); code != 404 {
		t.Fatalf("metrics: %d", code)
	}
}

func TestPublishSubscribe(t *testing.T) {
	_, base := start(t, settings())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := subscribe(t, ctx, base, "https://example.com/books/{id}")
	time.Sleep(50 * time.Millisecond)
	publish(t, base, "https://example.com/books/1", "hello")
	receive(t, ch, "hello")
}

func TestShutdownEndsStreams(t *testing.T) {
	srv, err := New(settings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, nil) }()
	base := "http://" + ln.Addr().String()
	ch := subscribe(t, context.Background(), base, "*")
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown hung with an open stream")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("shutdown took %v", d)
	}
	for range ch { // the stream ends
	}
}

func TestSettingsErrors(t *testing.T) {
	for name, mod := range map[string]func(*Settings){
		"tls cert without key": func(s *Settings) { s.TLSCert = "cert.pem" },
		"bad heartbeat":        func(s *Settings) { s.Heartbeat = "soon" },
		"bad write timeout":    func(s *Settings) { s.WriteTimeout = "x" },
		"bad history age":      func(s *Settings) { s.HistoryAge = "1 day" },
		"bad replay window":    func(s *Settings) { s.ReplayWindow = "?" },
		"bad shutdown":         func(s *Settings) { s.ShutdownTimeout = "y" },
		"bad cluster key":      func(s *Settings) { s.ClusterBind = "127.0.0.1:0"; s.ClusterKey = "short" },
		"bad origin":           func(s *Settings) { s.CORSOrigins = []string{"example.com"} },
		"bad algorithm":        func(s *Settings) { s.PublisherAlg = "HS999" },
		"bad protocol":         func(s *Settings) { s.Protocol = "v9" },
		"bad lifetime":         func(s *Settings) { s.MaxLifetime = "forever" },
		"bad hub url":          func(s *Settings) { s.HubURL = "https://hub.example/elsewhere" },
	} {
		t.Run(name, func(t *testing.T) {
			s := settings()
			mod(&s)
			if srv, err := New(s, nil); err == nil {
				srv.Close(context.Background())
				t.Fatal("no error")
			}
		})
	}
}

func TestHeartbeatZeroDisables(t *testing.T) {
	s := settings()
	s.Heartbeat = "0s"
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
}

func TestSplitList(t *testing.T) {
	got := splitList([]string{"a,b", " c  d ", "", "e"})
	if strings.Join(got, "|") != "a|b|c|d|e" {
		t.Fatalf("got %q", got)
	}
}

func TestCluster(t *testing.T) {
	keyB64 := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes
	bindA, bindB := freePort(t, "both"), freePort(t, "both")
	sa := settings()
	sa.ClusterBind, sa.ClusterKey, sa.ClusterPeers = bindA, keyB64, []string{bindB}
	sb := settings()
	sb.ClusterBind, sb.ClusterKey, sb.ClusterPeers = bindB, keyB64, []string{bindA}
	a, baseA := start(t, sa)
	b, baseB := start(t, sb)

	deadline := time.Now().Add(10 * time.Second)
	for a.gossip.NumAliveNodes() < 2 || b.gossip.NumAliveNodes() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("nodes did not see each other")
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := subscribe(t, ctx, baseB, "https://example.com/x")
	time.Sleep(50 * time.Millisecond)
	// The group membership travels in gossip metadata: retry until B is in A's group.
	for i := 0; ; i++ {
		publish(t, baseA, "https://example.com/x", fmt.Sprint("m", i))
		select {
		case got := <-ch:
			if !strings.HasPrefix(got, "m") {
				t.Fatalf("got %q", got)
			}
			code, body := get(t, baseA+"/metrics")
			if code != 200 || !strings.Contains(body, "gossiper_cluster_nodes 2\n") {
				t.Fatalf("metrics: %s", body)
			}
			return
		case <-time.After(200 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("update did not reach the other node")
			}
		}
	}
}

func TestProtectedResourceMetadataRoute(t *testing.T) {
	_, base := start(t, settings())
	code, body := get(t, base+"/.well-known/oauth-protected-resource/.well-known/mercure")
	if code != 200 || !strings.Contains(body, `"resource":"`+base+`/.well-known/mercure"`) {
		t.Fatalf("metadata: %d %s", code, body)
	}
	s := settings()
	s.Protocol = "legacy"
	_, legacy := start(t, s)
	if code, _ := get(t, legacy+"/.well-known/oauth-protected-resource/.well-known/mercure"); code != 404 {
		t.Fatalf("legacy hub serves metadata: %d", code)
	}
}

func TestModernPublish(t *testing.T) {
	s := settings()
	s.Protocol = "modern"
	s.TrustedIssuers = []string{"https://app.example"}
	s.ResourceID = "https://hub.example/.well-known/mercure"
	_, base := start(t, s)
	claims := jwt.MapClaims{
		"iss": "https://app.example", "aud": s.ResourceID, "sub": "s", "client_id": "c",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "j",
		"authorization_details": []any{map[string]any{
			"type": "https://mercure.rocks/authorization-detail", "actions": []string{"publish"},
			"topics": []any{map[string]any{"match": "*"}},
		}},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["typ"] = "at+jwt"
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/.well-known/mercure", strings.NewReader("topic=x&data=y"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+signed)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("modern publish: %d", resp.StatusCode)
	}
}

// The history ages out after an hour by default; "0s" keeps updates however old.
func TestHistoryAgeSetting(t *testing.T) {
	for in, want := range map[string]time.Duration{"1h": time.Hour, "10m": 10 * time.Minute, "0s": -1, "0": -1} {
		s := settings()
		s.HistoryAge = in
		srv, err := New(s, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := srv.baseConfig.HistoryAge; got != want {
			t.Errorf("history age %q: %v, want %v", in, got, want)
		}
		srv.Close(context.Background())
	}
	if Defaults().Protocol != "modern" {
		t.Errorf("default protocol %q: Mercure 1.0 only, as the reference hub", Defaults().Protocol)
	}
	if Defaults().HistoryAge != "1h" {
		t.Errorf("default history age %q", Defaults().HistoryAge)
	}
}

// FrankenPHP's MERCURE_EXTRA_DIRECTIVES carry over where the settings were not given otherwise.
func TestExtraDirectives(t *testing.T) {
	s := Defaults()
	s.CookieName = "mine"
	log := &recLog{}
	applyExtraDirectives(&s, "anonymous\n  cors_origins \"https://a.example\" https://b.example\nsubscriptions\ncookie_name theirs\nheartbeat 15s\nui\n", log)
	if !s.Anonymous || !s.Subscriptions || strings.Join(s.CORSOrigins, ",") != "https://a.example,https://b.example" ||
		s.CookieName != "mine" || s.Heartbeat != "15s" {
		t.Errorf("settings %+v", s)
	}
	if len(log.warns) != 1 || !strings.Contains(log.warns[0], "not supported") {
		t.Errorf("warnings %q", log.warns)
	}
	if s.Protocol != "modern" {
		t.Errorf("protocol %q without protocol_version_compatibility", s.Protocol)
	}
	applyExtraDirectives(&s, "protocol_version_compatibility 8\n", log)
	if s.Protocol != "both" {
		t.Errorf("protocol %q with protocol_version_compatibility", s.Protocol)
	}
	s.Protocol = "legacy"
	applyExtraDirectives(&s, "protocol_version_compatibility 7\n", log)
	if s.Protocol != "legacy" {
		t.Errorf("protocol %q: --protocol given, the directive changed it", s.Protocol)
	}
}

type recLog struct {
	logger.Logger
	warns []string
}

func (r *recLog) Warn(msg string, _ ...any) { r.warns = append(r.warns, msg) }
