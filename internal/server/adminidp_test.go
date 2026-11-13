package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const adminAudience = "https://admin.test/api"

// fakeIDP is an OAuth authorization server: RFC 8414 metadata and a JWK Set, and access tokens (RFC 9068) it signs.
type fakeIDP struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
}

func newFakeIDP(t *testing.T) *fakeIDP { return newFakeIDPOver(t, false) }

// newFakeIDPOver is newFakeIDP, over https with a certificate of its own with useTLS.
func newFakeIDPOver(t *testing.T, useTLS bool) *fakeIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIDP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pt, err := key.PublicKey.Bytes() // 0x04, then X and Y
		if err != nil {
			t.Error(err)
		}
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1",
			"alg": "ES256", "use": "sig", "x": enc(pt[1:33]), "y": enc(pt[33:])}}})
	})
	if useTLS {
		p.srv = httptest.NewTLSServer(mux)
	} else {
		p.srv = httptest.NewServer(mux)
	}
	t.Cleanup(p.srv.Close)
	return p
}

// token signs an access token for the admin API with claims added to (or replacing) the usual ones.
func (p *fakeIDP) token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	c := jwt.MapClaims{"iss": p.srv.URL, "aud": []string{"c_admin", adminAudience}, "sub": "user-1", "client_id": "c_admin",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	for k, v := range claims {
		c[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["typ"], tok.Header["kid"] = "at+jwt", "k1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// details is the authorization_details claim of the given admin details.
func details(ds ...map[string]any) jwt.MapClaims {
	out := []any{map[string]any{"type": "https://mercure.rocks/authorization-detail", "actions": []string{"publish"}}} // another type: ignored
	for _, d := range ds {
		d["type"] = DefaultAdminDetailType
		out = append(out, d)
	}
	return jwt.MapClaims{"authorization_details": out}
}

func idpSettings(t *testing.T, p *fakeIDP) Settings {
	s := adminSettings(t, "")
	s.AdminIssuer, s.AdminAudience, s.InsecureKeyURLs = p.srv.URL, adminAudience, true
	return s
}

// The admin API takes the IdP's tokens beside the static one: what a token may do (read, write, which tenants)
// comes from its admin authorization details, each a rule of its own.
func TestAdminAPIIdPTokens(t *testing.T) {
	p := newFakeIDP(t)
	n := startNode(t, idpSettings(t, p))
	alpha, bravo := newTN(t, "alpha", false, false), newTN(t, "bravo", false, false)
	expect := func(tok, method, path string, body any, want int) {
		t.Helper()
		if code, out := call(t, n.base, method, path, tok, body); code != want {
			t.Fatalf("%s %s: %d (want %d) %v", method, path, code, want, out)
		}
	}

	admin := p.token(t, details(map[string]any{"actions": []string{"write"}}))
	expect(admin, "POST", "/api/tenants", alpha.spec(t), 201)
	expect(admin, "PUT", "/api/tenants/bravo", bravo.spec(t), 201)
	expect(admin, "GET", "/api/status", nil, 200)

	reader := p.token(t, details(map[string]any{"actions": []string{"read"}}))
	expect(reader, "GET", "/api/tenants/bravo", nil, 200)
	expect(reader, "PUT", "/api/tenants/bravo", bravo.spec(t), 403)
	expect(reader, "DELETE", "/api/tenants/bravo", nil, 403)

	// Reading every tenant and writing alpha is not writing bravo; the list shows what the token may read.
	alphaAdmin := p.token(t, details(map[string]any{"actions": []string{"read"}}, map[string]any{"actions": []string{"write"}, "tenants": []string{"alpha"}}))
	expect(alphaAdmin, "PUT", "/api/tenants/alpha", alpha.spec(t), 200)
	expect(alphaAdmin, "PUT", "/api/tenants/bravo", bravo.spec(t), 403)
	expect(alphaAdmin, "GET", "/api/tenants/bravo", nil, 200)

	alphaOnly := p.token(t, details(map[string]any{"actions": []string{"write"}, "tenants": []string{"alpha"}}))
	expect(alphaOnly, "GET", "/api/tenants/bravo", nil, 403)
	expect(alphaOnly, "POST", "/api/tenants", newTN(t, "charlie", false, false).spec(t), 403)
	if _, out := call(t, n.base, "GET", "/api/tenants", alphaOnly, nil); len(out["tenants"].([]any)) != 1 {
		t.Fatalf("a token for alpha lists %v", out["tenants"])
	}
	expect(alphaOnly, "DELETE", "/api/tenants/alpha", nil, 204)

	// A valid token without admin rights is forbidden; a token that is not valid is not authenticated.
	expect(p.token(t, details()), "GET", "/api/tenants", nil, 403)
	expect(p.token(t, details(map[string]any{"actions": []string{"delete"}})), "GET", "/api/tenants", nil, 403)
	expect(p.token(t, jwt.MapClaims{"aud": []string{"https://other.test/api"}}), "GET", "/api/tenants", nil, 401)
	expect(p.token(t, jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}), "GET", "/api/tenants", nil, 401)
	expect(newFakeIDP(t).token(t, details(map[string]any{"actions": []string{"write"}})), "GET", "/api/tenants", nil, 401) // another key

	// The static token still does anything.
	expect(apiToken, "DELETE", "/api/tenants/bravo", nil, 204)
}

// Without a static token, only the IdP's tokens are taken; --admin-scope gives full access to a token with it.
func TestAdminAPIIdPOnlyAndScope(t *testing.T) {
	p := newFakeIDP(t)
	s := idpSettings(t, p)
	s.APIToken, s.AdminScope = "", "gossiper:admin"
	n := startNode(t, s)
	if code, _ := call(t, n.base, "GET", "/api/tenants", apiToken, nil); code != 401 {
		t.Errorf("a static token with none configured: %d", code)
	}
	if code, _ := call(t, n.base, "POST", "/api/tenants", p.token(t, jwt.MapClaims{"scope": "openid gossiper:admin"}), newTN(t, "alpha", false, false).spec(t)); code != 201 {
		t.Errorf("a token with the admin scope: %d", code)
	}
	if code, _ := call(t, n.base, "GET", "/api/tenants", p.token(t, jwt.MapClaims{"scope": "openid"}), nil); code != 403 {
		t.Errorf("a token without the admin scope: %d", code)
	}
}

// The IdP settings go together, and need the database.
func TestAdminIdPSettings(t *testing.T) {
	for name, mod := range map[string]func(*Settings){
		"issuer without audience":  func(s *Settings) { s.AdminIssuer, s.AdminAudience = "https://idp.test", "" },
		"audience without issuer":  func(s *Settings) { s.AdminIssuer, s.AdminAudience = "", adminAudience },
		"scope without issuer":     func(s *Settings) { s.AdminIssuer, s.AdminScope = "", "x" },
		"insecure issuer by https": func(s *Settings) { s.InsecureKeyURLs = false; s.AdminIssuer = "http://idp.test" },
	} {
		t.Run(name, func(t *testing.T) {
			s := adminSettings(t, "")
			s.AdminIssuer, s.AdminAudience = "https://idp.test", adminAudience
			mod(&s)
			if srv, err := New(s, nil); err == nil {
				srv.Close(t.Context())
				t.Fatal("accepted")
			} else if !strings.Contains(strings.ToLower(err.Error()), "admin") {
				t.Logf("refused: %v", err)
			}
		})
	}
}

// An identity provider over https with a certificate the system does not trust: refused, but taken with its
// certificate in --key-urls-ca-file, or with --allow-insecure-key-urls.
func TestAdminIdPCertificate(t *testing.T) {
	p := newFakeIDPOver(t, true)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := p.token(t, details(map[string]any{"actions": []string{"read"}}))
	for _, tc := range []struct {
		name     string
		ca       string
		insecure bool
		want     int
	}{{"untrusted", "", false, 401}, {"ca file", caFile, false, 200}, {"insecure", "", true, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			s := adminSettings(t, "")
			s.AdminIssuer, s.AdminAudience, s.KeyURLsCAFile, s.InsecureKeyURLs = p.srv.URL, adminAudience, tc.ca, tc.insecure
			n := startNode(t, s)
			if code, out := call(t, n.base, "GET", "/api/tenants", tok, nil); code != tc.want {
				t.Fatalf("%d (want %d) %v", code, tc.want, out)
			}
		})
	}
	s := adminSettings(t, "")
	s.KeyURLsCAFile = filepath.Join(t.TempDir(), "none.pem")
	_ = os.WriteFile(s.KeyURLsCAFile, []byte("not a certificate"), 0o600)
	if srv, err := New(s, nil); err == nil {
		srv.Close(t.Context())
		t.Fatal("a CA file without a certificate was accepted")
	}
}
