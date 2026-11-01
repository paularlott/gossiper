package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type testKey struct {
	alg    string
	method jwt.SigningMethod
	priv   any // signing key
	pub    any // verification key (the secret for HMAC)
	pem    string
}

var (
	keysOnce sync.Once
	keyList  []testKey
	extraRSA *rsa.PrivateKey // a second RSA key
)

func pubPEM(t testing.TB, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// testKeys returns one key per supported algorithm.
func testKeys(t testing.TB) []testKey {
	t.Helper()
	keysOnce.Do(func() {
		must := func(err error) {
			if err != nil {
				panic(err)
			}
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		extraRSA, err = rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		must(err)
		p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		must(err)
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		must(err)

		add := func(alg string, priv, pub any, pemStr string) {
			keyList = append(keyList, testKey{alg, jwt.GetSigningMethod(alg), priv, pub, pemStr})
		}
		secret := strings.Repeat("s3cr3t-", 12)
		for _, a := range []string{"HS256", "HS384", "HS512"} {
			add(a, []byte(secret), []byte(secret), secret)
		}
		rsaPEM := mustPEM(&rsaKey.PublicKey)
		for _, a := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
			add(a, rsaKey, &rsaKey.PublicKey, rsaPEM)
		}
		add("ES256", p256, &p256.PublicKey, mustPEM(&p256.PublicKey))
		add("ES384", p384, &p384.PublicKey, mustPEM(&p384.PublicKey))
		add("ES512", p521, &p521.PublicKey, mustPEM(&p521.PublicKey))
		add("EdDSA", edPriv, edPub, mustPEM(edPub))
	})
	return keyList
}

func mustPEM(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func keyFor(t testing.TB, alg string) testKey {
	t.Helper()
	for _, k := range testKeys(t) {
		if k.alg == alg {
			return k
		}
	}
	t.Fatalf("no test key for %s", alg)
	return testKey{}
}

func mercureClaims(extra jwt.MapClaims) jwt.MapClaims {
	c := jwt.MapClaims{"mercure": map[string]any{
		"publish":   []string{"https://example.com/a", "*"},
		"subscribe": []string{"https://example.com/{x}"},
	}}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// sign signs claims with k, with optional extra header fields.
func sign(t testing.TB, k testKey, claims jwt.MapClaims, hdr map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(k.method, claims)
	for h, v := range hdr {
		tok.Header[h] = v
	}
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// rawToken builds a token from raw JSON header and payload strings.
func rawToken(header, payload, sig string) string {
	return b64u(header) + "." + b64u(payload) + "." + sig
}

func newStatic(t testing.TB, cfg KeyConfig) *Verifier {
	t.Helper()
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	t.Cleanup(v.Close)
	return v
}

func hs256Verifier(t testing.TB) (*Verifier, testKey) {
	k := keyFor(t, "HS256")
	return newStatic(t, KeyConfig{Key: k.pem}), k
}

func ctx() context.Context { return context.Background() }

// ---- JWK helpers ----

func jwkMap(t testing.TB, pub any, kid, alg, use string) map[string]any {
	t.Helper()
	m := map[string]any{}
	if kid != "" {
		m["kid"] = kid
	}
	if alg != "" {
		m["alg"] = alg
	}
	if use != "" {
		m["use"] = use
	}
	enc := base64.RawURLEncoding.EncodeToString
	switch k := pub.(type) {
	case *rsa.PublicKey:
		m["kty"] = "RSA"
		m["n"] = enc(k.N.Bytes())
		m["e"] = enc(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PublicKey:
		pt, err := k.Bytes() // 0x04, then X and Y
		if err != nil {
			panic(err)
		}
		size := (len(pt) - 1) / 2
		m["kty"] = "EC"
		m["crv"] = k.Curve.Params().Name
		m["x"] = enc(pt[1 : 1+size])
		m["y"] = enc(pt[1+size:])
	case ed25519.PublicKey:
		m["kty"] = "OKP"
		m["crv"] = "Ed25519"
		m["x"] = enc(k)
	case []byte:
		m["kty"] = "oct"
		m["k"] = enc(k)
	default:
		t.Fatalf("unsupported key %T", pub)
	}
	return m
}

func jwksJSON(t testing.TB, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func selfSignedCert(t testing.TB, pub, priv any) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gossiper-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func eventually(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func b64uBytes(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
