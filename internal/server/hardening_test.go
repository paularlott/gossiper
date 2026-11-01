package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/internal/configstore"
	"golang.org/x/crypto/bcrypt"
)

// With only a JWK Set URL, no algorithm is assumed: an RS256 Mercure 1.0 access token (and a draft-07 token) of its
// keys is accepted.
func TestJWKSOnlyAcceptsRS256(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	set, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "k1", "use": "sig",
		"n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}}})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(set)
	}))
	defer jwks.Close()

	s := Defaults()
	s.PublisherJWKS, s.InsecureKeyURLs = jwks.URL, true
	s.TrustedIssuers = []string{"https://idp.example"}
	s.ResourceID = "https://hub.example/.well-known/mercure"
	srv, base := start(t, s)
	if alg := srv.baseConfig.PublisherKey.Algorithm; alg != "" {
		t.Fatalf("algorithm %q assumed for a JWK Set", alg)
	}
	sign := func(claims jwt.MapClaims, typ string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		if typ != "" {
			tok.Header["typ"] = typ
		}
		signed, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	post := func(tok string) int {
		req, _ := http.NewRequest(http.MethodPost, base+"/.well-known/mercure", strings.NewReader("topic=x&data=y"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	at := sign(jwt.MapClaims{
		"iss": "https://idp.example", "aud": s.ResourceID, "sub": "s", "client_id": "c",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "j",
		"authorization_details": []any{map[string]any{
			"type": "https://mercure.rocks/authorization-detail", "actions": []string{"publish"},
			"topics": []any{map[string]any{"match": "*"}},
		}},
	}, "at+jwt")
	if code := post(at); code != 200 {
		t.Errorf("RS256 at+jwt: %d", code)
	}
	if code := post(sign(jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}, "")); code != 200 {
		t.Errorf("RS256 draft-07: %d", code)
	}
	// HS256 stays the default of a secret.
	s = settings()
	srv2, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close(context.Background())
	if alg := srv2.baseConfig.PublisherKey.Algorithm; alg != "HS256" {
		t.Errorf("secret's algorithm %q", alg)
	}
}

// Profiling is served on the admin listener only.
func TestPprofNeedsAdminListener(t *testing.T) {
	s := settings()
	s.Pprof = true
	if _, err := New(s, nil); err == nil || !strings.Contains(err.Error(), "admin-listen") {
		t.Fatalf("pprof without admin-listen: %v", err)
	}
	s.AdminListen = "127.0.0.1:0"
	n := startNode(t, s)
	if got := status(t, n.base+"/debug/pprof/cmdline"); got != http.StatusNotFound {
		t.Errorf("main listener /debug/pprof/cmdline: %d", got)
	}
	if got := status(t, n.admin+"/debug/pprof/"); got != http.StatusOK {
		t.Errorf("admin listener /debug/pprof/: %d", got)
	}
}

// A single hub taking Mercure 1.0 tokens of an authorization server (or a trusted issuer of its own choosing) needs
// its resource identifier; the default setup does not.
func TestHostAudienceNeedsResource(t *testing.T) {
	for name, c := range map[string]struct {
		mod  func(*Settings)
		fail bool
	}{
		"default":                   {func(*Settings) {}, false},
		"anonymous only":            {func(s *Settings) { s.PublisherKey = "" }, false},
		"authorization server":      {func(s *Settings) { s.AuthServers = []string{"https://as.example"} }, true},
		"authorization server, rid": {func(s *Settings) { s.AuthServers = []string{"https://as.example"}; s.ResourceID = "urn:hub" }, false},
		"authorization server, hub-url": {func(s *Settings) {
			s.AuthServers = []string{"https://as.example"}
			s.HubURL = "https://hub.example/.well-known/mercure"
		}, false},
		"authorization server, relative hub-url": {func(s *Settings) {
			s.AuthServers = []string{"https://as.example"}
			s.HubURL = "/.well-known/mercure"
		}, true},
		"authorization server, legacy": {func(s *Settings) { s.AuthServers = []string{"https://as.example"}; s.Protocol = "legacy" }, false},
		"trusted issuer":               {func(s *Settings) { s.TrustedIssuers = []string{"https://app.example"} }, true},
		"trusted issuer, no key":       {func(s *Settings) { s.TrustedIssuers = []string{"https://app.example"}; s.PublisherKey = "" }, false},
		"trusted issuer, modern":       {func(s *Settings) { s.TrustedIssuers = []string{"https://app.example"}; s.Protocol = "modern" }, true},
	} {
		s := settings()
		c.mod(&s)
		p, err := gossiper.ParseProtocol(s.Protocol)
		if err != nil {
			t.Fatal(err)
		}
		if err := hostAudience(s, p); (err != nil) != c.fail {
			t.Errorf("%s: %v", name, err)
		}
	}
	s := settings()
	s.AuthServers = []string{"https://as.example"}
	if _, err := New(s, nil); err == nil || !strings.Contains(err.Error(), "resource-identifier") {
		t.Errorf("New with an authorization server and no resource identifier: %v", err)
	}
	srv, err := New(settings(), nil) // the default setup starts
	if err != nil {
		t.Fatal(err)
	}
	srv.Close(context.Background())
}

func TestStreamLimitsCount(t *testing.T) {
	l := newStreamLimits(3, 2)
	for i, c := range []struct {
		ip   string
		want int
	}{{"a", 0}, {"a", 0}, {"a", 429}, {"b", 0}, {"c", 503}} {
		if got := l.acquire(c.ip); got != c.want {
			t.Fatalf("%d (%s): %d, want %d", i, c.ip, got, c.want)
		}
	}
	l.release("a")
	if got := l.acquire("c"); got != 0 {
		t.Fatalf("after a release: %d", got)
	}
	for _, ip := range []string{"a", "b", "c"} {
		l.release(ip)
	}
	if l.open.Load() != 0 || len(l.byIP) != 0 {
		t.Fatalf("left over: %d open, %v", l.open.Load(), l.byIP)
	}
}

// The node's stream limits: per client address (429), then all together (503); other requests are not counted, and a
// stream's slot is free once it ends.
func TestStreamLimits(t *testing.T) {
	s := settings()
	s.MaxSubscribers, s.MaxPerIP = 3, 2
	s.TrustedProxies = []string{"127.0.0.1"}
	_, base := start(t, s)
	open := func(ctx context.Context, xff string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/mercure?topic=x", nil)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return http.DefaultClient.Do(req)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var held []context.CancelFunc
	hold := func(xff string) {
		t.Helper()
		c, stop := context.WithCancel(ctx)
		resp, err := open(c, xff)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("stream from %q: %d", xff, resp.StatusCode)
		}
		held = append(held, func() { stop(); resp.Body.Close() })
	}
	refused := func(xff string, want int) {
		t.Helper()
		resp, err := open(ctx, xff)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("stream from %q: %d (Retry-After %q), want %d", xff, resp.StatusCode, resp.Header.Get("Retry-After"), want)
		}
	}
	hold("")
	hold("")
	refused("", http.StatusTooManyRequests)
	hold("198.51.100.1")
	refused("198.51.100.2", http.StatusServiceUnavailable)
	publish(t, base, "x", "not a stream") // publishing is not counted
	for _, m := range []string{http.MethodHead, http.MethodOptions} {
		req, _ := http.NewRequest(m, base+"/.well-known/mercure?topic=x", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
			t.Errorf("%s counted: %d", m, resp.StatusCode)
		}
	}
	held[0]()
	var resp *http.Response
	eventually(t, 5*time.Second, "the slot freed", func() bool {
		r, err := open(ctx, "198.51.100.2")
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 200 {
			r.Body.Close()
			return false
		}
		resp = r
		return true
	})
	resp.Body.Close()
	for _, h := range held[1:] {
		h()
	}
}

// With a shutdown delay, /readyz answers 503 while the server still serves, before the listeners close.
func TestShutdownDelay(t *testing.T) {
	s := settings()
	s.ShutdownDelay = "1s"
	n := startNode(t, s)
	done := make(chan error, 1)
	go func() { done <- n.stop() }()
	eventually(t, 900*time.Millisecond, "readyz 503", func() bool { return status(t, n.base+"/readyz") == http.StatusServiceUnavailable })
	if got := status(t, n.base+"/healthz"); got != http.StatusOK {
		t.Errorf("healthz while draining: %d", got)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("did not stop")
	}
	s.ShutdownDelay = "soon"
	if _, err := New(s, nil); err == nil {
		t.Error("bad shutdown delay accepted")
	}
}

// The admin API reads records as stored: with many tenants, listing and reading checks no hub's settings, and a
// write checks only the record written.
func TestAdminAPIManyTenants(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	const count = 500
	err := n.store.Update(context.Background(), func(tx *configstore.Tx) error {
		for i := range count {
			name := fmt.Sprintf("t%03d", i)
			tx.Put(tenantKey(name), specJSON(storedTenant{Created: int64(i + 1), Spec: tenantSpec{Name: name,
				Hosts:   []string{name + ".test"},
				Mercure: &tenantMercure{PublisherKey: fmt.Sprintf("secret-of-%s-0123456789abcdef0123456789", name)}}}))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "the tenants applied", func() bool { return len(n.Tenants.Names()) == count })
	eventually(t, 5*time.Second, "each record checked", func() bool { return n.validated.Load() >= count })
	before := n.validated.Load()
	if before != count {
		t.Errorf("%d checks for %d records", before, count)
	}
	start := time.Now()
	for range 3 {
		if l := api(t, n.base, "GET", "/api/tenants", nil, 200)["tenants"].([]any); len(l) != count {
			t.Fatalf("list: %d tenants", len(l))
		}
		api(t, n.base, "GET", "/api/tenants/t250", nil, 200)
		api(t, n.base, "GET", "/api/status", nil, 200)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("reads took %v", d)
	}
	if got := n.validated.Load(); got != before {
		t.Errorf("reads checked %d records", got-before)
	}
	// A write checks the record written, not the others: once each, applying included.
	api(t, n.base, "POST", "/api/tenants", tenantSpec{Name: "extra", Hosts: []string{"extra.test"},
		Mercure: &tenantMercure{PublisherKey: "secret-of-extra-0123456789abcdef0123456789"}}, 201)
	api(t, n.base, "POST", "/api/tenants", tenantSpec{Name: "clash", Hosts: []string{"t001.test"},
		Mercure: &tenantMercure{PublisherKey: "secret-of-clash-0123456789abcdef0123456789"}}, 409)
	eventually(t, 10*time.Second, "the new tenant applied", func() bool { return n.Tenants.Hub("extra") != nil })
	if got := n.validated.Load() - before; got != 2 {
		t.Errorf("two writes checked %d records", got)
	}
}

// Past its entries, the failure limiter counts the other addresses together.
func TestFailLimiterBounded(t *testing.T) {
	l := newFailLimiter(2, time.Minute, 2)
	l.fail("a")
	l.fail("b")
	for _, ip := range []string{"c", "d", "e"} { // over the table: one count for them all
		l.fail(ip)
	}
	if len(l.counts) != 3 {
		t.Fatalf("%d entries", len(l.counts))
	}
	if l.blocked("a") != 0 || l.blocked("b") != 0 {
		t.Error("an address with one failure is blocked")
	}
	if l.blocked("f") == 0 {
		t.Error("the shared count is not limited")
	}
}

// Bcrypt comparisons are bounded: over the bound a request is answered 429 unchecked, and not counted as a failure.
func TestAdminBcryptBounded(t *testing.T) {
	s := adminSettings(t, "")
	h, _ := bcrypt.GenerateFromPassword([]byte("hashed-token"), bcrypt.MinCost)
	s.APIToken = string(h)
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	a := &adminAPI{s: srv, token: s.APIToken, limiter: newFailLimiter(60, time.Minute, maxFailEntries),
		bcrypts: make(chan struct{}, 1)}
	handler := a.auth(func(w http.ResponseWriter, _ *http.Request) error { w.WriteHeader(204); return nil })
	try := func(tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/status", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	a.bcrypts <- struct{}{} // a comparison under way
	if w := try("wrong"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("busy: %d", w.Code)
	}
	if len(a.limiter.counts) != 0 {
		t.Error("an unchecked request counted as a failure")
	}
	<-a.bcrypts
	if w := try("wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", w.Code)
	}
	if w := try("hashed-token"); w.Code != 204 {
		t.Errorf("right token: %d", w.Code)
	}
	a.bcrypts <- struct{}{}
	if w := try("hashed-token"); w.Code != 204 { // accepted before: no comparison needed
		t.Errorf("known token while busy: %d", w.Code)
	}
}
