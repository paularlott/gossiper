package auth

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccessJWKSPerIssuerWithKid(t *testing.T) {
	a1, a2, b1 := atEC(t), atEC(t), atEC(t)
	srvA := newJWKSServer(t, atJWKS(t, jwkMap(t, a1.pub, "k1", "", ""), jwkMap(t, a2.pub, "k2", "", "")))
	// B reuses the kid "k1" with a different key.
	srvB := newJWKSServer(t, atJWKS(t, jwkMap(t, b1.pub, "k1", "", "")))
	v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{
		{Issuer: "https://a.example", JWKSURL: srvA.URL},
		{Issuer: "https://b.example", JWKSURL: srvB.URL},
	}})
	if !v.Ready() {
		t.Fatal("not ready")
	}
	mint := func(k testKey, iss, kid string) string {
		hdr := map[string]any{}
		if kid != "" {
			hdr["kid"] = kid
		}
		return atMint(t, k, atClaims(clock, iss, nil), hdr)
	}
	atOK(t, v, mint(a1, "https://a.example", "k1"))
	atOK(t, v, mint(a2, "https://a.example", "k2"))
	atOK(t, v, mint(a2, "https://a.example", "")) // no kid: every key of the issuer is tried
	atOK(t, v, mint(b1, "https://b.example", "k1"))
	// Never a pooled set.
	atInvalid(t, v, mint(a1, "https://b.example", "k1"))
	atInvalid(t, v, mint(a1, "https://b.example", ""))
	atInvalid(t, v, mint(b1, "https://a.example", "k1"))
	atInvalid(t, v, mint(b1, "https://a.example", ""))
	// kid selects within the issuer: k1 names a1, not a2.
	atInvalid(t, v, mint(a2, "https://a.example", "k1"))
	atInvalid(t, v, mint(a1, "https://a.example", "unknown"))
	// Untrusted issuer never reaches a key set.
	hits := srvA.count() + srvB.count()
	atInvalid(t, v, mint(a1, "https://evil.example", "k1"))
	if srvA.count()+srvB.count() != hits {
		t.Fatal("untrusted issuer triggered a fetch")
	}
}

func TestAccessJWKSRotation(t *testing.T) {
	a1, a2 := atEC(t), atEC(t)
	srv := newJWKSServer(t, atJWKS(t, jwkMap(t, a1.pub, "k1", "", "")))
	v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{{Issuer: atIss, JWKSURL: srv.URL}}})
	tok := func() string { return atMint(t, a2, atClaims(clock, atIss, nil), map[string]any{"kid": "k2"}) }
	atInvalid(t, v, tok()) // unknown kid, refetch rate limited
	srv.set(atJWKS(t, jwkMap(t, a1.pub, "k1", "", ""), jwkMap(t, a2.pub, "k2", "", "")), 200)
	atInvalid(t, v, tok())
	clock.Advance(time.Minute)
	atOK(t, v, tok())
}

func TestAccessJWKSAlgorithms(t *testing.T) {
	ec, rs, hs := keyFor(t, "ES256"), keyFor(t, "RS256"), keyFor(t, "HS256")
	secret := hs.pub
	srv := newJWKSServer(t, atJWKS(t,
		jwkMap(t, ec.pub, "ec", "", ""), jwkMap(t, rs.pub, "rs", "", ""), jwkMap(t, secret, "hs", "", "")))
	t.Run("default excludes symmetric", func(t *testing.T) {
		v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{{Issuer: atIss, JWKSURL: srv.URL}}})
		atOK(t, v, atMint(t, ec, atClaims(clock, atIss, nil), map[string]any{"kid": "ec"}))
		atOK(t, v, atMint(t, rs, atClaims(clock, atIss, nil), map[string]any{"kid": "rs"}))
		atInvalid(t, v, atMint(t, hs, atClaims(clock, atIss, nil), map[string]any{"kid": "hs"}))
	})
	t.Run("explicit symmetric", func(t *testing.T) {
		v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{{Issuer: atIss, JWKSURL: srv.URL, Algorithms: []string{"HS256"}}}})
		atOK(t, v, atMint(t, hs, atClaims(clock, atIss, nil), map[string]any{"kid": "hs"}))
		atInvalid(t, v, atMint(t, ec, atClaims(clock, atIss, nil), map[string]any{"kid": "ec"}))
	})
	t.Run("allowlist and key type together", func(t *testing.T) {
		v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{{Issuer: atIss, JWKSURL: srv.URL, Algorithms: []string{"RS256", "ES256"}}}})
		atOK(t, v, atMint(t, rs, atClaims(clock, atIss, nil), map[string]any{"kid": "rs"}))
		atInvalid(t, v, atMint(t, keyFor(t, "PS256"), atClaims(clock, atIss, nil), map[string]any{"kid": "rs"}))
		// ES256 token against the RSA key's kid: confusion is refused.
		atInvalid(t, v, atMint(t, ec, atClaims(clock, atIss, nil), map[string]any{"kid": "rs"}))
	})
}

func TestAccessJWKSNotReady(t *testing.T) {
	k := atEC(t)
	srv := newJWKSServer(t, nil)
	srv.set(nil, 500)
	v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{
		{Issuer: atIss, JWKSURL: srv.URL}, {Issuer: "https://static", Key: keyFor(t, "HS256").pem},
	}})
	if v.Ready() {
		t.Fatal("ready with a failing key set")
	}
	atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, nil), nil))
	// The static issuer works regardless.
	atOK(t, v, atMint(t, keyFor(t, "HS256"), atClaims(clock, "https://static", nil), nil))

	srv.set(atJWKS(t, jwkMap(t, k.pub, "", "", "")), 200)
	clock.Advance(time.Minute)
	atOK(t, v, atMint(t, k, atClaims(clock, atIss, nil), nil))
	if !v.Ready() {
		t.Fatal("not ready after recovery")
	}
}

func TestAccessJWKSTLS(t *testing.T) {
	k := atEC(t)
	body := atJWKS(t, jwkMap(t, k.pub, "k", "", ""))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the untrusted-certificate handshake errors are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Without the test client the server certificate is untrusted.
	v, _ := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, JWKSURL: srv.URL}}})
	if v.Ready() {
		t.Fatal("untrusted certificate accepted")
	}
	v, clock := atNew(t, AccessConfig{HTTPClient: srv.Client(), Issuers: []Issuer{{Issuer: atIss, JWKSURL: srv.URL}}})
	if !v.Ready() {
		t.Fatal("not ready")
	}
	atOK(t, v, atMint(t, k, atClaims(clock, atIss, nil), nil))
}

func TestAccessRedirectsOffHTTPSRefused(t *testing.T) {
	k := atEC(t)
	plain := newJWKSServer(t, atJWKS(t, jwkMap(t, k.pub, "k", "", "")))
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	t.Cleanup(tlsSrv.Close)

	v, _ := atNew(t, AccessConfig{HTTPClient: tlsSrv.Client(), Issuers: []Issuer{{Issuer: atIss, JWKSURL: tlsSrv.URL}}})
	if v.Ready() || plain.count() != 0 {
		t.Fatalf("followed a redirect to http (ready=%v hits=%d)", v.Ready(), plain.count())
	}
	// Allowed when http is explicitly permitted.
	v, _ = atNew(t, AccessConfig{HTTPClient: tlsSrv.Client(), AllowInsecureHTTP: true, Issuers: []Issuer{{Issuer: atIss, JWKSURL: tlsSrv.URL}}})
	if !v.Ready() {
		t.Fatal("redirect refused with AllowInsecureHTTP")
	}
}

func TestAccessCallerClientNotMutated(t *testing.T) {
	c := &http.Client{}
	v, _ := atNew(t, AccessConfig{HTTPClient: c, Issuers: []Issuer{{Issuer: atIss, Key: "s"}}})
	_ = v
	if c.CheckRedirect != nil {
		t.Fatal("caller's client was modified")
	}
}

// --- discovery ---

const (
	atOAuthPath = "/.well-known/oauth-authorization-server"
	atOIDCPath  = "/.well-known/openid-configuration"
)

func TestAccessDiscovery(t *testing.T) {
	k := atEC(t)
	keys := atJWKS(t, jwkMap(t, k.pub, "k1", "", ""))
	cases := []struct {
		name   string
		prefix string
		paths  []string
		fetch  string // path expected to have been served
	}{
		{"RFC 8414", "", []string{atOAuthPath}, atOAuthPath},
		{"OIDC fallback", "", []string{atOIDCPath}, atOIDCPath},
		{"RFC 8414 preferred over OIDC", "", []string{atOAuthPath, atOIDCPath}, atOAuthPath},
		{"issuer with path, RFC 8414 insertion", "/tenant1", []string{atOAuthPath + "/tenant1"}, atOAuthPath + "/tenant1"},
		{"issuer with path, appended", "/tenant1", []string{"/tenant1" + atOAuthPath}, "/tenant1" + atOAuthPath},
		{"issuer with path, OIDC", "/tenant1", []string{"/tenant1" + atOIDCPath}, "/tenant1" + atOIDCPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newATMeta(t, tc.prefix, keys, tc.paths...)
			v, clock := atNew(t, atDiscoverCfg(m))
			if !v.Ready() {
				t.Fatal("not ready")
			}
			atOK(t, v, atMint(t, k, atClaims(clock, m.issuerID(), nil), map[string]any{"kid": "k1"}))
			if m.hit(tc.fetch) == 0 || m.hit("/jwks") == 0 {
				t.Fatalf("hits %v", m.hits)
			}
			atInvalid(t, v, atMint(t, k, atClaims(clock, "https://other.example", nil), nil))
		})
	}
}

func TestAccessDiscoveryTrailingSlashIssuer(t *testing.T) {
	k := atEC(t)
	m := newATMeta(t, "/t/", atJWKS(t, jwkMap(t, k.pub, "k1", "", "")), atOAuthPath+"/t")
	v, clock := atNew(t, atDiscoverCfg(m))
	atOK(t, v, atMint(t, k, atClaims(clock, m.issuerID(), nil), nil))
}

func TestAccessDiscoveryRejects(t *testing.T) {
	k := atEC(t)
	keys := atJWKS(t, jwkMap(t, k.pub, "k1", "", ""))

	t.Run("metadata issuer mismatch", func(t *testing.T) {
		m := newATMeta(t, "", keys, atOAuthPath, atOIDCPath)
		m.issuer = "https://someone-else.example"
		v, clock := atNew(t, atDiscoverCfg(m))
		if v.Ready() {
			t.Fatal("accepted metadata for another issuer")
		}
		atInvalid(t, v, atMint(t, k, atClaims(clock, m.issuerID(), nil), nil))
		if m.hit("/jwks") != 0 {
			t.Fatal("fetched keys named by mismatching metadata")
		}
	})
	t.Run("no metadata", func(t *testing.T) {
		m := newATMeta(t, "", keys)
		v, _ := atNew(t, atDiscoverCfg(m))
		if v.Ready() {
			t.Fatal("ready without metadata")
		}
	})
	t.Run("insecure jwks_uri", func(t *testing.T) {
		plain := newJWKSServer(t, keys)
		m := newATMeta(t, "", keys, atOAuthPath)
		m.jwksURI = plain.URL
		v, _ := atNew(t, atDiscoverCfg(m))
		if v.Ready() || plain.count() != 0 {
			t.Fatalf("followed an http jwks_uri (hits=%d)", plain.count())
		}
	})
	t.Run("missing jwks_uri", func(t *testing.T) {
		srv := httptest.NewTLSServer(nil)
		t.Cleanup(srv.Close)
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"issuer":%q}`, srv.URL)
		})
		v, _ := atNew(t, AccessConfig{HTTPClient: srv.Client(), Issuers: []Issuer{{Issuer: srv.URL, Discover: true}}})
		if v.Ready() {
			t.Fatal("ready without jwks_uri")
		}
	})
	t.Run("garbage metadata", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }))
		t.Cleanup(srv.Close)
		v, _ := atNew(t, AccessConfig{HTTPClient: srv.Client(), Issuers: []Issuer{{Issuer: srv.URL, Discover: true}}})
		if v.Ready() {
			t.Fatal("ready")
		}
	})
	t.Run("oversized metadata", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"issuer":"x","pad":"` + strings.Repeat("a", maxJWKSSize+10) + `"}`))
		}))
		t.Cleanup(srv.Close)
		v, _ := atNew(t, AccessConfig{HTTPClient: srv.Client(), Issuers: []Issuer{{Issuer: srv.URL, Discover: true}}})
		if v.Ready() {
			t.Fatal("ready")
		}
	})
}

func TestAccessDiscoveryAllowInsecureHTTP(t *testing.T) {
	k := atEC(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case atOAuthPath:
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srv.URL, srv.URL+"/jwks")
		case "/jwks":
			w.Write(atJWKS(t, jwkMap(t, k.pub, "", "", "")))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	v, clock := atNew(t, AccessConfig{AllowInsecureHTTP: true, Issuers: []Issuer{{Issuer: srv.URL, Discover: true}}})
	atOK(t, v, atMint(t, k, atClaims(clock, srv.URL, nil), nil))
}

func TestAccessDiscoveryRecoversAndRediscovers(t *testing.T) {
	k1, k2 := atEC(t), atEC(t)
	m := newATMeta(t, "", atJWKS(t, jwkMap(t, k1.pub, "", "", "")))
	v, clock := atNew(t, atDiscoverCfg(m))
	if v.Ready() {
		t.Fatal("ready before the metadata exists")
	}
	m.mu.Lock()
	m.paths[atOAuthPath] = true
	m.mu.Unlock()
	clock.Advance(time.Minute)
	atOK(t, v, atMint(t, k1, atClaims(clock, m.issuerID(), nil), nil))

	// The jwks_uri moves while the old one starts failing: the next refetch
	// consults the metadata again.
	m.mu.Lock()
	m.jwksCode = 500
	m.mu.Unlock()
	clock.Advance(time.Minute)
	atInvalid(t, v, atMint(t, k2, atClaims(clock, m.issuerID(), map[string]any{}), map[string]any{"kid": "unknown"}))
	before := m.hit(atOAuthPath)
	m.mu.Lock()
	m.jwksCode = 200
	m.jwks = atJWKS(t, jwkMap(t, k2.pub, "k2", "", ""))
	m.mu.Unlock()
	clock.Advance(time.Minute)
	atOK(t, v, atMint(t, k2, atClaims(clock, m.issuerID(), nil), map[string]any{"kid": "k2"}))
	if m.hit(atOAuthPath) <= before {
		t.Fatal("metadata not consulted again after a failed fetch")
	}
}

func TestAccessMixedIssuers(t *testing.T) {
	ka, kb := atEC(t), atRSA(t)
	m := newATMeta(t, "", atJWKS(t, jwkMap(t, ka.pub, "d", "", "")), atOAuthPath)
	srv := newJWKSServer(t, atJWKS(t, jwkMap(t, kb.pub, "j", "", "")))
	hs := keyFor(t, "HS512")
	v, clock := atNew(t, AccessConfig{HTTPClient: m.Client(), AllowInsecureHTTP: true, Issuers: []Issuer{
		{Issuer: m.issuerID(), Discover: true},
		{Issuer: "https://jwks.example", JWKSURL: srv.URL},
		{Issuer: "https://static.example", Key: hs.pem},
	}})
	atOK(t, v, atMint(t, ka, atClaims(clock, m.issuerID(), nil), nil))
	atOK(t, v, atMint(t, kb, atClaims(clock, "https://jwks.example", nil), nil))
	atOK(t, v, atMint(t, hs, atClaims(clock, "https://static.example", nil), nil))
	atInvalid(t, v, atMint(t, ka, atClaims(clock, "https://jwks.example", nil), nil))
	atInvalid(t, v, atMint(t, kb, atClaims(clock, m.issuerID(), nil), nil))
	atInvalid(t, v, atMint(t, hs, atClaims(clock, m.issuerID(), nil), nil))
}

func TestAccessParallelInitialFetch(t *testing.T) {
	var started atomic.Int32
	release := make(chan struct{})
	k := atEC(t)
	body := atJWKS(t, jwkMap(t, k.pub, "", "", ""))
	mk := func() *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started.Add(1)
			<-release
			w.Write(body)
		}))
		t.Cleanup(s.Close)
		return s
	}
	s1, s2 := mk(), mk()
	done := make(chan *AccessVerifier)
	go func() {
		v, err := NewAccessVerifier(AccessConfig{Audience: atAud, AllowInsecureHTTP: true, Issuers: []Issuer{
			{Issuer: "https://1", JWKSURL: s1.URL}, {Issuer: "https://2", JWKSURL: s2.URL},
		}})
		if err != nil {
			t.Error(err)
		}
		done <- v
	}()
	eventually(t, 5*time.Second, "both fetches to start concurrently", func() bool { return started.Load() == 2 })
	close(release)
	v := <-done
	if v != nil {
		v.Close()
	}
}

// --- IsAccessToken ---

func TestIsAccessToken(t *testing.T) {
	k := keyFor(t, "HS256")
	clock := newFakeClock()
	details := atClaims(clock, atIss, nil)
	noDetails := atClaims(clock, atIss, map[string]any{"authorization_details": atDel})
	classic := jwtClassic(clock)
	for name, tc := range map[string]struct {
		tok  string
		want bool
	}{
		"at+jwt with details":      {atMint(t, k, details, nil), true},
		"at+jwt without details":   {atMint(t, k, noDetails, nil), true},
		"application/at+jwt":       {atMint(t, k, noDetails, map[string]any{"typ": "Application/AT+JWT"}), true},
		"JWT typ with details":     {atMint(t, k, details, map[string]any{"typ": "JWT"}), true},
		"no typ with details":      {atMint(t, k, details, map[string]any{"typ": atDel}), true},
		"empty details claim":      {atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": []any{}}), map[string]any{"typ": "JWT"}), true},
		"classic":                  {atMint(t, k, classic, map[string]any{"typ": "JWT"}), false},
		"classic without typ":      {atMint(t, k, classic, map[string]any{"typ": atDel}), false},
		"id token typ":             {atMint(t, k, classic, map[string]any{"typ": "id+jwt"}), false},
		"numeric typ":              {atMint(t, k, classic, map[string]any{"typ": 5}), false},
		"empty":                    {"", false},
		"garbage":                  {"abc", false},
		"two segments":             {"a.b", false},
		"four segments":            {"a.b.c.d", false},
		"bad header":               {"!!.e30.AA", false},
		"header not object":        {rawToken(`[]`, `{}`, "AA"), false},
		"payload not object":       {rawToken(`{"typ":"JWT"}`, `[]`, "AA"), false},
		"payload not json":         {rawToken(`{"typ":"JWT"}`, `x`, "AA"), false},
		"unsigned at+jwt":          {rawToken(`{"alg":"none","typ":"at+jwt"}`, `{}`, ""), true},
		"unsigned details":         {rawToken(`{"alg":"none"}`, `{"authorization_details":[]}`, ""), true},
		"case sensitive claim":     {rawToken(`{}`, `{"Authorization_Details":[]}`, ""), false},
		"too long":                 {strings.Repeat("a", 2<<20), false},
		"mercure claim only":       {rawToken(`{"alg":"HS256"}`, `{"mercure":{}}`, "AA"), false},
		"typ with at+jwt in claim": {rawToken(`{"alg":"HS256"}`, `{"typ":"at+jwt"}`, "AA"), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := IsAccessToken(tc.tok); got != tc.want {
				t.Fatalf("IsAccessToken = %v", got)
			}
		})
	}
}

// --- concurrency ---

func TestAccessConcurrent(t *testing.T) {
	ka := atEC(t)
	srv := newJWKSServer(t, atJWKS(t, jwkMap(t, ka.pub, "k", "", "")))
	hs := keyFor(t, "HS256")
	v, err := NewAccessVerifier(AccessConfig{Audience: atAud, AllowInsecureHTTP: true, Issuers: []Issuer{
		{Issuer: "https://jwks", JWKSURL: srv.URL}, {Issuer: "https://static", Key: hs.pem},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	now := &fakeClock{t: time.Now()}
	good1 := atMint(t, ka, atClaims(now, "https://jwks", nil), map[string]any{"kid": "k"})
	good2 := atMint(t, hs, atClaims(now, "https://static", nil), nil)
	bad := atMint(t, ka, atClaims(now, "https://static", nil), nil)
	unknown := atMint(t, ka, atClaims(now, "https://jwks", nil), map[string]any{"kid": "zzz"})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := v.Verify(context.Background(), good1); err != nil {
					t.Error(err)
					return
				}
				if c, err := v.Verify(context.Background(), good2); err != nil || len(c.Details) != 1 {
					t.Error(err)
					return
				}
				if _, err := v.Verify(context.Background(), bad); err == nil {
					t.Error("bad token accepted")
					return
				}
				v.Verify(context.Background(), unknown)
				v.Ready()
			}
		}()
	}
	wg.Wait()
}
