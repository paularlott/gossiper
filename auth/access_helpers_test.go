package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	atAud = "https://hub.example/.well-known/mercure"
	atIss = "https://issuer.example"
)

// atDel, as a claim or header value, removes that key.
type atDelT struct{}

var atDel = atDelT{}

func atMint(t testing.TB, k testKey, claims jwt.MapClaims, hdr map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(k.method, claims)
	tok.Header["typ"] = "at+jwt"
	for h, v := range hdr {
		if v == atDel {
			delete(tok.Header, h)
		} else {
			tok.Header[h] = v
		}
	}
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func atTopic(match, matchType string) map[string]any {
	m := map[string]any{"match": match}
	if matchType != "" {
		m["match_type"] = matchType
	}
	return m
}

func atDetail(actions []any, topics ...any) map[string]any {
	return map[string]any{"type": DetailType, "actions": actions, "topics": topics}
}

func atDefaultDetail() map[string]any {
	return atDetail([]any{"subscribe"}, atTopic("https://example.com/a", ""))
}

// atClaims returns a complete valid claim set for iss, valid at clock's time.
func atClaims(c *fakeClock, iss string, over map[string]any) jwt.MapClaims {
	m := jwt.MapClaims{
		"iss":                   iss,
		"aud":                   atAud,
		"sub":                   "urn:sub:1",
		"client_id":             "client-1",
		"jti":                   "jti-1",
		"iat":                   c.Now().Unix(),
		"exp":                   c.Now().Add(time.Hour).Unix(),
		"authorization_details": []any{atDefaultDetail()},
	}
	for k, v := range over {
		if v == atDel {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func atNew(t testing.TB, cfg AccessConfig) (*AccessVerifier, *fakeClock) {
	t.Helper()
	if cfg.Audience == "" {
		cfg.Audience = atAud
	}
	clock := newFakeClock()
	v, err := newAccessVerifier(cfg, internalOpts{now: clock.Now})
	if err != nil {
		t.Fatalf("newAccessVerifier: %v", err)
	}
	t.Cleanup(v.Close)
	return v, clock
}

// atStatic returns a verifier trusting atIss with the HS256 test key.
func atStatic(t testing.TB, mod func(*AccessConfig)) (*AccessVerifier, *fakeClock, testKey) {
	t.Helper()
	k := keyFor(t, "HS256")
	cfg := AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: k.pem}}}
	if mod != nil {
		mod(&cfg)
	}
	v, c := atNew(t, cfg)
	return v, c, k
}

func atInvalid(t testing.TB, v *AccessVerifier, token string) {
	t.Helper()
	_, err := v.Verify(ctx(), token)
	if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrInvalid only, got %v", err)
	}
}

func atMalformed(t testing.TB, v *AccessVerifier, token string) {
	t.Helper()
	_, err := v.Verify(ctx(), token)
	if !errors.Is(err, ErrMalformed) || errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrMalformed only, got %v", err)
	}
}

func atOK(t testing.TB, v *AccessVerifier, token string) *AccessClaims {
	t.Helper()
	c, err := v.Verify(ctx(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return c
}

func atEC(t testing.TB) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{alg: "ES256", method: jwt.SigningMethodES256, priv: priv, pub: &priv.PublicKey, pem: pubPEM(t, &priv.PublicKey)}
}

func atRSA(t testing.TB) testKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{alg: "RS256", method: jwt.SigningMethodRS256, priv: priv, pub: &priv.PublicKey, pem: pubPEM(t, &priv.PublicKey)}
}

// atMeta is a TLS server acting as an authorization server: it serves
// metadata at the paths in meta (path -> issuer reported, "" for none) and a
// JWK Set at /jwks.
type atMeta struct {
	*httptest.Server
	mu       sync.Mutex
	jwks     []byte
	jwksURI  string // default: <server>/jwks
	issuer   string // issuer reported in metadata; default: server URL + prefix
	prefix   string // issuer path component
	paths    map[string]bool
	hits     map[string]int
	jwksCode int
}

func newATMeta(t testing.TB, prefix string, jwks []byte, paths ...string) *atMeta {
	m := &atMeta{jwks: jwks, prefix: prefix, paths: map[string]bool{}, hits: map[string]int{}, jwksCode: 200}
	for _, p := range paths {
		m.paths[p] = true
	}
	m.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.hits[r.URL.Path]++
		switch {
		case r.URL.Path == "/jwks":
			if m.jwksCode != 200 {
				http.Error(w, "no", m.jwksCode)
				return
			}
			w.Write(m.jwks)
		case m.paths[r.URL.Path]:
			iss := m.issuer
			if iss == "" {
				iss = m.URL + m.prefix
			}
			uri := m.jwksURI
			if uri == "" {
				uri = m.URL + "/jwks"
			}
			json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": uri})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *atMeta) issuerID() string { return m.URL + m.prefix }

func (m *atMeta) hit(p string) int { m.mu.Lock(); defer m.mu.Unlock(); return m.hits[p] }

// atTLSVerifier trusts one discovered issuer, using m's client.
func atDiscoverCfg(m *atMeta, algs ...string) AccessConfig {
	return AccessConfig{
		HTTPClient: m.Client(),
		Issuers:    []Issuer{{Issuer: m.issuerID(), Discover: true, Algorithms: algs}},
	}
}

func atJWKS(t testing.TB, keys ...map[string]any) []byte { return jwksJSON(t, keys...) }

func atBigDetails(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = atDefaultDetail()
	}
	return out
}

func atTopics(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = atTopic("https://example.com/"+strconv.Itoa(i), "")
	}
	return out
}

func jwtClassic(c *fakeClock) map[string]any {
	return map[string]any{
		"mercure": map[string]any{"subscribe": []string{"*"}},
		"exp":     c.Now().Add(time.Hour).Unix(),
	}
}
