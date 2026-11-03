package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// rsaPublisher is an RSA key pair: the PEM public key a hub is given, and the private key its publisher signs with.
func rsaPublisher(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), k
}

// publishTokens are a draft-07 token granting everything, signed properly with priv (RS256) and forged with the
// public key's PEM text as an HS256 secret.
func publishTokens(t *testing.T, pubPEM string, priv *rsa.PrivateKey) (signed, forged string) {
	t.Helper()
	claims := jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}, "subscribe": []string{"*"}},
		"exp": time.Now().Add(time.Hour).Unix()}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	if forged, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(pubPEM)); err != nil {
		t.Fatal(err)
	}
	return signed, forged
}

// A PEM public key without an algorithm verifies with its own (RS256), not as an HS256 secret: a token "signed"
// with the public key's text, which anyone may have, is refused. On a single hub and on a tenant's.
func TestPEMKeyIsNotAnHMACSecret(t *testing.T) {
	pubPEM, priv := rsaPublisher(t)
	signed, forged := publishTokens(t, pubPEM, priv)
	form := url.Values{"topic": {"https://victim.test/all"}, "data": {"x"}}

	s := settings()
	s.PublisherKey, s.Anonymous = pubPEM, false
	single := startNode(t, s)

	file := writeTenants(t, tenantSpec{Name: "rsa", Hosts: []string{"rsa.test"}, Mercure: &tenantMercure{PublisherKey: pubPEM}})
	tenants := startNode(t, tenantSettings(t, file))

	for _, tc := range []struct{ name, base, host string }{{"single hub", single.base, ""}, {"tenant", tenants.base, "rsa.test"}} {
		if code, body := postForm(t, tc.base, tc.host, forged, form); code != 401 {
			t.Errorf("%s: a token forged with the public key: %d %s", tc.name, code, body)
		}
		if code, body := postForm(t, tc.base, tc.host, signed, form); code != 200 {
			t.Errorf("%s: an RS256 token: %d %s", tc.name, code, body)
		}
	}
}

// An HMAC algorithm named with a PEM public key is refused at start, for the server's keys and a tenant's.
func TestHMACAlgorithmWithPEMKeyRefused(t *testing.T) {
	pubPEM, _ := rsaPublisher(t)
	s := settings()
	s.PublisherKey, s.PublisherAlg = pubPEM, "HS256"
	if srv, err := New(s, nil); err == nil {
		srv.Close(t.Context())
		t.Error("HS256 with a PEM publisher key accepted")
	} else if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("refused, but not for the PEM key: %v", err)
	}

	file := writeTenants(t, tenantSpec{Name: "rsa", Hosts: []string{"rsa.test"}, Mercure: &tenantMercure{PublisherKey: pubPEM, PublisherAlg: "HS512"}})
	if srv, err := New(tenantSettings(t, file), nil); err == nil {
		srv.Close(t.Context())
		t.Error("HS512 with a tenant's PEM publisher key accepted")
	}
}
