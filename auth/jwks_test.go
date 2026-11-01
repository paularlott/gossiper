package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer serves a switchable JWK Set and counts requests.
type jwksServer struct {
	*httptest.Server
	hits   atomic.Int64
	mu     sync.Mutex
	body   []byte
	status int
	delay  time.Duration
	hang   bool
}

func newJWKSServer(t testing.TB, body []byte) *jwksServer {
	s := &jwksServer{body: body, status: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		body, status, delay, hang := s.body, s.status, s.delay, s.hang
		s.mu.Unlock()
		if hang {
			<-r.Context().Done()
			return
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) set(body []byte, status int) {
	s.mu.Lock()
	s.body, s.status = body, status
	s.mu.Unlock()
}
func (s *jwksServer) setDelay(d time.Duration) { s.mu.Lock(); s.delay = d; s.mu.Unlock() }
func (s *jwksServer) setHang(h bool)           { s.mu.Lock(); s.hang = h; s.mu.Unlock() }
func (s *jwksServer) count() int64             { return s.hits.Load() }

func newJWKSVerifier(t testing.TB, srv *jwksServer, cfg KeyConfig, o internalOpts) *Verifier {
	t.Helper()
	cfg.JWKSURL, cfg.AllowInsecureHTTP = srv.URL, true
	v, err := newVerifier(cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}

func tk(alg string, priv any) testKey {
	return testKey{alg: alg, method: jwt.GetSigningMethod(alg), priv: priv}
}

func TestJWKSKidSelection(t *testing.T) {
	rs, es, ed, hs := keyFor(t, "RS256"), keyFor(t, "ES384"), keyFor(t, "EdDSA"), keyFor(t, "HS512")
	encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, jwksJSON(t,
		jwkMap(t, rs.pub, "r1", "", "sig"),
		jwkMap(t, es.pub, "e1", "ES384", ""),
		jwkMap(t, ed.pub, "o1", "", ""),
		jwkMap(t, hs.pub, "h1", "", ""),
		jwkMap(t, &encKey.PublicKey, "enc1", "", "enc"),
	))
	v := newJWKSVerifier(t, srv, KeyConfig{}, internalOpts{})
	if !v.Ready() {
		t.Fatal("not ready")
	}

	for _, tt := range []struct {
		kid string
		key testKey
	}{{"r1", rs}, {"e1", es}, {"o1", ed}} {
		if _, err := v.Verify(ctx(), sign(t, tt.key, mercureClaims(nil), map[string]any{"kid": tt.kid})); err != nil {
			t.Errorf("kid %s: %v", tt.kid, err)
		}
	}
	// A remote "oct" key is used only when the algorithm is named, and then only that algorithm.
	hsTok := sign(t, hs, mercureClaims(nil), map[string]any{"kid": "h1"})
	wantErr(t, func() error { _, err := v.Verify(ctx(), hsTok); return err }(), ErrInvalid)
	hv := newJWKSVerifier(t, srv, KeyConfig{Algorithm: "HS512"}, internalOpts{})
	if _, err := hv.Verify(ctx(), hsTok); err != nil {
		t.Errorf("HS512 named: %v", err)
	}
	if _, err := hv.Verify(ctx(), sign(t, rs, mercureClaims(nil), map[string]any{"kid": "r1"})); !errors.Is(err, ErrInvalid) {
		t.Errorf("RS256 with HS512 named: %v", err)
	}
	if _, err := NewVerifier(KeyConfig{JWKSURL: srv.URL, AllowInsecureHTTP: true, Algorithm: "HS999"}); err == nil {
		t.Error("unknown algorithm accepted with a JWK Set")
	}
	// PS256 is acceptable for an RSA key without alg.
	ps := keyFor(t, "PS256")
	if _, err := v.Verify(ctx(), sign(t, ps, mercureClaims(nil), map[string]any{"kid": "r1"})); err != nil {
		t.Errorf("PS256: %v", err)
	}

	bad := map[string]string{
		"kid with other key's signature": sign(t, rs, mercureClaims(nil), map[string]any{"kid": "e1"}),
		"unknown kid":                    sign(t, rs, mercureClaims(nil), map[string]any{"kid": "nope"}),
		"enc key ignored":                sign(t, tk("RS256", encKey), mercureClaims(nil), map[string]any{"kid": "enc1"}),
		"kid not a string":               sign(t, rs, mercureClaims(nil), map[string]any{"kid": 5}),
		"hs256 against rsa kid":          sign(t, tk("HS256", []byte("x")), mercureClaims(nil), map[string]any{"kid": "r1"}),
		"ES256 header, ES384 jwk alg":    sign(t, keyFor(t, "ES256"), mercureClaims(nil), map[string]any{"kid": "e1"}),
		"crit":                           sign(t, rs, mercureClaims(nil), map[string]any{"kid": "r1", "crit": []string{"x"}}),
		"none":                           rawToken(`{"alg":"none","kid":"r1"}`, `{"mercure":{}}`, ""),
	}
	for name, tok := range bad {
		_, err := v.Verify(ctx(), tok)
		if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestJWKSNoKidTriesEveryKey(t *testing.T) {
	rs, es := keyFor(t, "RS256"), keyFor(t, "ES256")
	rs2 := tk("RS256", extraRSA)
	srv := newJWKSServer(t, jwksJSON(t,
		jwkMap(t, rs.pub, "a", "", ""),
		jwkMap(t, &extraRSA.PublicKey, "", "", ""), // no kid at all
		jwkMap(t, es.pub, "", "", ""),
	))
	v := newJWKSVerifier(t, srv, KeyConfig{}, internalOpts{})
	for name, k := range map[string]testKey{"first rsa": rs, "second rsa": rs2, "ec": es} {
		if _, err := v.Verify(ctx(), sign(t, k, mercureClaims(nil), nil)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A key not in the set.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := v.Verify(ctx(), sign(t, tk("RS256", other), mercureClaims(nil), nil))
	wantErr(t, err, ErrInvalid)
	// Algorithm with no compatible key.
	_, err = v.Verify(ctx(), sign(t, keyFor(t, "EdDSA"), mercureClaims(nil), nil))
	wantErr(t, err, ErrInvalid)
	// Alg confusion: HS256 with the RSA public PEM as secret.
	forged := sign(t, tk("HS256", []byte(rs.pem)), mercureClaims(nil), nil)
	_, err = v.Verify(ctx(), forged)
	wantErr(t, err, ErrInvalid)
}

func TestJWKSAlgRestrictions(t *testing.T) {
	rs := keyFor(t, "RS256")
	p256, p384 := keyFor(t, "ES256"), keyFor(t, "ES384")
	srv := newJWKSServer(t, jwksJSON(t,
		jwkMap(t, rs.pub, "pinned", "RS256", ""),
		jwkMap(t, p256.pub, "p256", "", ""),
	))
	v := newJWKSVerifier(t, srv, KeyConfig{}, internalOpts{})

	// JWK alg RS256 rejects PS256 even though the key could verify it.
	_, err := v.Verify(ctx(), sign(t, keyFor(t, "PS256"), mercureClaims(nil), map[string]any{"kid": "pinned"}))
	wantErr(t, err, ErrInvalid)
	if _, err := v.Verify(ctx(), sign(t, rs, mercureClaims(nil), map[string]any{"kid": "pinned"})); err != nil {
		t.Error(err)
	}
	// P-256 key must not verify ES384 / ES512 tokens.
	for _, alg := range []string{"ES384", "ES512"} {
		_, err = v.Verify(ctx(), sign(t, keyFor(t, alg), mercureClaims(nil), map[string]any{"kid": "p256"}))
		wantErr(t, err, ErrInvalid)
	}
	_ = p384
}

func TestJWKSParsing(t *testing.T) {
	rs := keyFor(t, "RS256")
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	off := jwkMap(t, &p256.PublicKey, "off", "", "")
	off["x"] = "AAAA" // not on curve

	good := jwkMap(t, rs.pub, "good", "", "")
	keys := []map[string]any{
		{"kty": "RSA", "kid": "no-n"},
		{"kty": "FOO", "kid": "weird"},
		{"kty": "EC", "crv": "P-224", "x": "AA", "y": "AA"},
		{"kty": "OKP", "crv": "Ed448", "x": "AA"},
		{"kty": "OKP", "crv": "Ed25519", "x": "AA"},
		{"kty": "oct", "k": ""},
		jwkMap(t, rs.pub, "bad-alg", "ES256", ""), // alg does not fit key type
		jwkMap(t, rs.pub, "unk-alg", "XX999", ""),
		off,
		good,
	}
	set, err := parseJWKS(jwksJSON(t, keys...))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.all) != 1 || len(set.byKid["good"]) != 1 {
		t.Fatalf("unexpected set: %d keys", len(set.all))
	}

	for name, body := range map[string]string{
		"not json":   "nope",
		"no keys":    `{}`,
		"empty keys": `{"keys":[]}`,
		"all bad":    `{"keys":[{"kty":"FOO"}]}`,
		"keys wrong": `{"keys":"x"}`,
		"too many":   `{"keys":[` + strings.Repeat(`{},`, maxJWKSEntries) + `{}]}`,
	} {
		if _, err := parseJWKS([]byte(body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	// base64 with padding is tolerated; EC coordinates are left-padded.
	m := jwkMap(t, rs.pub, "p", "", "")
	m["n"] = m["n"].(string) + "="
	if _, err := parseJWKS(jwksJSON(t, m)); err != nil {
		t.Errorf("padded n: %v", err)
	}
	for i := 0; i < 50; i++ { // short coordinates occur ~1/128 of the time per key
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jm := jwkMap(t, &k.PublicKey, "x", "", "")
		jm["x"] = b64uBytes(k.X.Bytes()) // strip leading zeros
		jm["y"] = b64uBytes(k.Y.Bytes())
		if _, err := parseJWKS(jwksJSON(t, jm)); err != nil {
			t.Fatalf("stripped coordinates: %v", err)
		}
	}
}

func TestJWKSRotationAndRateLimit(t *testing.T) {
	a, b := keyFor(t, "RS256"), tk("RS256", extraRSA)
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	clk := newFakeClock()
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: time.Hour}, internalOpts{now: clk.Now})
	if srv.count() != 1 {
		t.Fatalf("initial fetches = %d", srv.count())
	}
	tokA := sign(t, a, mercureClaims(nil), map[string]any{"kid": "a"})
	tokB := sign(t, b, mercureClaims(nil), map[string]any{"kid": "b"})
	if _, err := v.Verify(ctx(), tokA); err != nil {
		t.Fatal(err)
	}

	// The issuer rotates, but we fetched moments ago: no refetch yet.
	srv.set(jwksJSON(t, jwkMap(t, &extraRSA.PublicKey, "b", "", "")), 200)
	_, err := v.Verify(ctx(), tokB)
	wantErr(t, err, ErrInvalid)
	if srv.count() != 1 {
		t.Fatalf("rate limit violated: %d fetches", srv.count())
	}

	// After the minimum interval an unknown kid triggers exactly one refetch.
	clk.Advance(31 * time.Second)
	if _, err := v.Verify(ctx(), tokB); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if srv.count() != 2 {
		t.Fatalf("fetches = %d", srv.count())
	}
	// Old key is gone with the old set.
	_, err = v.Verify(ctx(), tokA)
	wantErr(t, err, ErrInvalid)
	if srv.count() != 2 { // kid a unknown, but rate limited again
		t.Fatalf("fetches = %d", srv.count())
	}
	clk.Advance(29 * time.Second)
	for i := 0; i < 5; i++ {
		v.Verify(ctx(), sign(t, a, mercureClaims(nil), map[string]any{"kid": "zzz"}))
	}
	if srv.count() != 2 {
		t.Fatalf("fetches = %d within 30s", srv.count())
	}
	clk.Advance(2 * time.Second)
	v.Verify(ctx(), sign(t, a, mercureClaims(nil), map[string]any{"kid": "zzz"}))
	if srv.count() != 3 {
		t.Fatalf("fetches = %d after 30s", srv.count())
	}
}

func TestJWKSRateLimitRealClock(t *testing.T) {
	a := keyFor(t, "RS256")
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	v := newJWKSVerifier(t, srv, KeyConfig{}, internalOpts{})
	for i := 0; i < 20; i++ {
		v.Verify(ctx(), sign(t, a, mercureClaims(nil), map[string]any{"kid": "unknown"}))
	}
	if srv.count() != 1 {
		t.Fatalf("fetches = %d, want 1", srv.count())
	}
}

func TestJWKSSingleflight(t *testing.T) {
	a, b := keyFor(t, "RS256"), tk("RS256", extraRSA)
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	clk := newFakeClock()
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: time.Hour}, internalOpts{now: clk.Now})

	srv.set(jwksJSON(t, jwkMap(t, a.pub, "a", "", ""), jwkMap(t, &extraRSA.PublicKey, "b", "", "")), 200)
	srv.setDelay(150 * time.Millisecond)
	clk.Advance(time.Minute)

	tok := sign(t, b, mercureClaims(nil), map[string]any{"kid": "b"})
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(ctx(), tok); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
	}
	wg.Wait()
	if srv.count() != 2 {
		t.Fatalf("fetches = %d, want 2 (concurrent misses must share one)", srv.count())
	}
}

func TestJWKSContextRespected(t *testing.T) {
	a, b := keyFor(t, "RS256"), tk("RS256", extraRSA)
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	clk := newFakeClock()
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: time.Hour}, internalOpts{now: clk.Now})
	srv.setDelay(2 * time.Second)
	clk.Advance(time.Minute)

	c, cancel := context.WithTimeout(ctx(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := v.Verify(c, sign(t, b, mercureClaims(nil), map[string]any{"kid": "b"}))
	wantErr(t, err, ErrInvalid)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want deadline exceeded in chain, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("Verify ignored its context (%v)", time.Since(start))
	}
}

func TestJWKSFailedRefreshKeepsKeys(t *testing.T) {
	a := keyFor(t, "RS256")
	good := jwksJSON(t, jwkMap(t, a.pub, "a", "", ""))
	srv := newJWKSServer(t, good)
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: 15 * time.Millisecond}, internalOpts{})
	tok := sign(t, a, mercureClaims(nil), map[string]any{"kid": "a"})
	if v.JWKSError() != nil {
		t.Fatal(v.JWKSError())
	}

	huge := append(append([]byte(`{"keys":[`), good[len(`{"keys":[`):len(good)-2]...), []byte(`],"pad":"`+strings.Repeat("a", maxJWKSSize)+`"}`)...)
	cases := map[string]struct {
		body   []byte
		status int
	}{
		"500":       {[]byte("boom"), 500},
		"garbage":   {[]byte("<html>"), 200},
		"empty set": {[]byte(`{"keys":[]}`), 200},
		"oversized": {huge, 200},
	}
	for name, c := range cases {
		srv.set(c.body, c.status)
		before := srv.count()
		eventually(t, 3*time.Second, name+" refetch", func() bool { return srv.count() >= before+2 })
		if _, err := v.Verify(ctx(), tok); err != nil {
			t.Fatalf("%s: old keys lost: %v", name, err)
		}
		if !v.Ready() {
			t.Fatalf("%s: lost readiness", name)
		}
		eventually(t, time.Second, name+" error recorded", func() bool { return v.JWKSError() != nil })
	}

	// Recovery with a new set is picked up by the background refresh.
	b := tk("RS256", extraRSA)
	srv.set(jwksJSON(t, jwkMap(t, &extraRSA.PublicKey, "b", "", "")), 200)
	tokB := sign(t, b, mercureClaims(nil), map[string]any{"kid": "b"})
	eventually(t, 3*time.Second, "new keys", func() bool {
		_, err := v.Verify(ctx(), tokB)
		return err == nil
	})
	eventually(t, time.Second, "error cleared", func() bool { return v.JWKSError() == nil })
}

func TestJWKSNotReadyUntilFetched(t *testing.T) {
	a := keyFor(t, "RS256")
	srv := newJWKSServer(t, []byte("down"))
	srv.set([]byte("down"), 503)
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: 15 * time.Millisecond}, internalOpts{})
	if v.Ready() {
		t.Fatal("ready with no key set")
	}
	tok := sign(t, a, mercureClaims(nil), map[string]any{"kid": "a"})
	for _, tok := range []string{tok, sign(t, a, mercureClaims(nil), nil)} {
		_, err := v.Verify(ctx(), tok)
		wantErr(t, err, ErrInvalid)
	}
	if v.JWKSError() == nil {
		t.Error("expected a recorded fetch error")
	}
	srv.set(jwksJSON(t, jwkMap(t, a.pub, "a", "", "")), 200)
	eventually(t, 3*time.Second, "ready", v.Ready)
	if _, err := v.Verify(ctx(), tok); err != nil {
		t.Fatal(err)
	}
}

func TestJWKSNotReadyRetriesOnVerify(t *testing.T) {
	a := keyFor(t, "RS256")
	srv := newJWKSServer(t, nil)
	srv.set([]byte("down"), 503)
	clk := newFakeClock()
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: time.Hour}, internalOpts{now: clk.Now})
	tok := sign(t, a, mercureClaims(nil), nil)
	_, err := v.Verify(ctx(), tok)
	wantErr(t, err, ErrInvalid)
	if srv.count() != 1 {
		t.Fatalf("fetches = %d (retry must be rate limited)", srv.count())
	}
	srv.set(jwksJSON(t, jwkMap(t, a.pub, "", "", "")), 200)
	clk.Advance(time.Minute)
	if _, err := v.Verify(ctx(), tok); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestJWKSOversizedInitial(t *testing.T) {
	a := keyFor(t, "RS256")
	good := jwksJSON(t, jwkMap(t, a.pub, "a", "", ""))
	body := append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"pad":"`+strings.Repeat("a", maxJWKSSize)+`"}`)...)
	srv := newJWKSServer(t, body)
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: time.Hour}, internalOpts{})
	if v.Ready() {
		t.Fatal("oversized set must not be accepted")
	}
	// Just under the limit is fine.
	small := append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"pad":"`+strings.Repeat("a", maxJWKSSize-len(good)-20)+`"}`)...)
	if len(small) > maxJWKSSize {
		t.Fatalf("test bug: %d", len(small))
	}
	srv2 := newJWKSServer(t, small)
	if v2 := newJWKSVerifier(t, srv2, KeyConfig{}, internalOpts{}); !v2.Ready() {
		t.Fatalf("set below limit rejected: %v", v2.JWKSError())
	}
}

func TestJWKSCustomClientAndRedirect(t *testing.T) {
	a := keyFor(t, "RS256")
	target := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	redir := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redir.Close()
	var used atomic.Bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used.Store(true)
		return http.DefaultTransport.RoundTrip(r)
	})}
	v, err := NewVerifier(KeyConfig{JWKSURL: redir.URL, HTTPClient: client, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if !used.Load() || !v.Ready() {
		t.Fatalf("custom client used=%v ready=%v", used.Load(), v.Ready())
	}
}

func TestJWKSRedirectOffHTTPSRefused(t *testing.T) {
	a := keyFor(t, "RS256")
	plain := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	tlsSrv := httptest.NewTLSServer(http.RedirectHandler(plain.URL, http.StatusFound))
	defer tlsSrv.Close()
	v, err := NewVerifier(KeyConfig{JWKSURL: tlsSrv.URL, HTTPClient: tlsSrv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.Ready() || plain.count() != 0 {
		t.Fatalf("followed a redirect to http (ready=%v hits=%d)", v.Ready(), plain.count())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJWKSWeakIsFalse(t *testing.T) {
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, []byte("x"), "h", "", "")))
	if newJWKSVerifier(t, srv, KeyConfig{}, internalOpts{}).Weak() {
		t.Error("JWKS verifier reports Weak")
	}
}

func TestJWKSExpiryStillChecked(t *testing.T) {
	a := keyFor(t, "RS256")
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	v := newJWKSVerifier(t, srv, KeyConfig{}, internalOpts{})
	tok := sign(t, a, mercureClaims(jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}), map[string]any{"kid": "a"})
	_, err := v.Verify(ctx(), tok)
	wantErr(t, err, ErrInvalid)
	_, err = v.Verify(ctx(), "garbage")
	wantErr(t, err, ErrMalformed)
}

func TestCloseStopsGoroutines(t *testing.T) {
	a := keyFor(t, "RS256")
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: transport}

	runtime.GC()
	base := runtime.NumGoroutine()
	v, err := NewVerifier(KeyConfig{JWKSURL: srv.URL, JWKSRefresh: 5 * time.Millisecond, HTTPClient: client, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, "refreshes", func() bool { return srv.count() >= 4 })
	if runtime.NumGoroutine() <= base {
		t.Fatal("expected a refresh goroutine to be running")
	}

	done := make(chan struct{})
	go func() { v.Close(); v.Close(); close(done) }() // idempotent
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return")
	}
	n := srv.count()
	time.Sleep(50 * time.Millisecond)
	if srv.count() != n {
		t.Error("fetches continued after Close")
	}
	transport.CloseIdleConnections()
	eventually(t, 2*time.Second, "goroutines to exit", func() bool { return runtime.NumGoroutine() <= base })

	// The last key set keeps working; no refetch is attempted.
	tok := sign(t, a, mercureClaims(nil), map[string]any{"kid": "a"})
	if _, err := v.Verify(ctx(), tok); err != nil {
		t.Fatalf("verify after Close: %v", err)
	}
	_, err = v.Verify(ctx(), sign(t, a, mercureClaims(nil), map[string]any{"kid": "other"}))
	wantErr(t, err, ErrInvalid)
}

func TestCloseAbortsInflightFetch(t *testing.T) {
	a := keyFor(t, "RS256")
	srv := newJWKSServer(t, jwksJSON(t, jwkMap(t, a.pub, "a", "", "")))
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: 10 * time.Millisecond}, internalOpts{})
	srv.setHang(true)
	before := srv.count()
	eventually(t, 2*time.Second, "hanging fetch", func() bool { return srv.count() > before })
	done := make(chan struct{})
	go func() { v.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked on an in-flight fetch")
	}
}

func TestCloseStaticIsNoop(t *testing.T) {
	v, _ := hs256Verifier(t)
	v.Close()
	v.Close()
	if v.JWKSError() != nil {
		t.Error("static verifier has no JWKS error")
	}
}

func TestJWKSConcurrentRace(t *testing.T) {
	a, es := keyFor(t, "RS256"), keyFor(t, "ES256")
	set := jwksJSON(t, jwkMap(t, a.pub, "a", "", ""), jwkMap(t, es.pub, "e", "", ""))
	srv := newJWKSServer(t, set)
	clk := newFakeClock()
	v := newJWKSVerifier(t, srv, KeyConfig{JWKSRefresh: 2 * time.Millisecond}, internalOpts{now: clk.Now, minRefetch: time.Nanosecond})
	toks := []string{
		sign(t, a, mercureClaims(nil), map[string]any{"kid": "a"}),
		sign(t, es, mercureClaims(nil), nil),
		sign(t, a, mercureClaims(nil), map[string]any{"kid": "missing"}),
	}
	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				clk.Advance(time.Millisecond)
				_, err := v.Verify(ctx(), toks[(g+i)%len(toks)])
				if (g+i)%len(toks) == 2 {
					if !errors.Is(err, ErrInvalid) {
						t.Errorf("missing kid: %v", err)
						return
					}
				} else if err != nil {
					t.Errorf("verify: %v", err)
					return
				}
				if i%25 == 0 {
					srv.set(set, 200) // concurrent server-side changes
				}
			}
		}(g)
	}
	wg.Wait()
}
