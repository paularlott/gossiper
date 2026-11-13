package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// hmacKey is an HS256 test key for secret.
func hmacKey(secret string) testKey {
	return testKey{alg: "HS256", method: jwt.SigningMethodHS256, priv: []byte(secret), pub: []byte(secret), pem: secret}
}

// A draft-07 verifier with a previous key accepts tokens signed with either key until PreviousUntil, then only the
// current key's.
func TestVerifierPreviousKey(t *testing.T) {
	cur, prev, other := hmacKey("current-secret-0123456789abcdef0123456789"), hmacKey("previous-secret-0123456789abcdef012345678"),
		hmacKey("other-secret-0123456789abcdef0123456789abc")
	clock := newFakeClock()
	v, err := newVerifier(KeyConfig{Key: cur.pem, PreviousKey: prev.pem, PreviousUntil: clock.Now().Add(time.Hour)}, internalOpts{now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	verify := func(k testKey) error { _, err := v.Verify(ctx(), sign(t, k, mercureClaims(nil), nil)); return err }

	if err := verify(cur); err != nil {
		t.Errorf("current key: %v", err)
	}
	if err := verify(prev); err != nil {
		t.Errorf("previous key within its time: %v", err)
	}
	if err := verify(other); !errors.Is(err, ErrInvalid) {
		t.Errorf("another key: %v, want ErrInvalid", err)
	}
	clock.Advance(time.Hour)
	if err := verify(prev); !errors.Is(err, ErrInvalid) {
		t.Errorf("previous key after PreviousUntil: %v, want ErrInvalid", err)
	}
	if err := verify(cur); err != nil {
		t.Errorf("current key after PreviousUntil: %v", err)
	}
}

// A previous key needs a current one, and must itself be a valid key.
func TestVerifierPreviousKeyChecked(t *testing.T) {
	ec := keyFor(t, "ES256")
	for name, cfg := range map[string]KeyConfig{
		"without Key":         {JWKSURL: "https://idp.example/jwks", PreviousKey: "previous-secret-0123456789abcdef012345678"},
		"PEM as HMAC secret":  {Key: "current-secret-0123456789abcdef0123456789", Algorithm: "HS256", PreviousKey: ec.pem},
		"unparseable PEM key": {Key: ec.pem, PreviousKey: "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----"},
	} {
		if _, err := NewVerifier(cfg); err == nil {
			t.Errorf("%s: NewVerifier accepted it", name)
		}
		if _, err := CheckKey(cfg); err == nil {
			t.Errorf("%s: CheckKey accepted it", name)
		}
	}
}

// A Mercure 1.0 issuer with a previous key accepts tokens signed with either until PreviousUntil.
func TestAccessIssuerPreviousKey(t *testing.T) {
	cur, prev, other := hmacKey("current-secret-0123456789abcdef0123456789"), hmacKey("previous-secret-0123456789abcdef012345678"),
		hmacKey("other-secret-0123456789abcdef0123456789abc")
	clock := newFakeClock()
	v, err := newAccessVerifier(AccessConfig{Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: cur.pem, PreviousKey: prev.pem,
		PreviousUntil: clock.Now().Add(time.Hour)}}}, internalOpts{now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	tok := func(k testKey) string { return atMint(t, k, atClaims(clock, atIss, nil), nil) }

	atOK(t, v, tok(cur))
	atOK(t, v, tok(prev))
	atInvalid(t, v, tok(other))
	clock.Advance(time.Hour)
	atInvalid(t, v, tok(prev))
	atOK(t, v, tok(cur))
}

// A previous key moving from a secret to a public key: both algorithms verify during the overlap.
func TestAccessIssuerPreviousKeyOtherAlgorithm(t *testing.T) {
	ec := keyFor(t, "ES256")
	prev := hmacKey("previous-secret-0123456789abcdef012345678")
	clock := newFakeClock()
	v, err := newAccessVerifier(AccessConfig{Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: ec.pem, PreviousKey: prev.pem,
		PreviousUntil: clock.Now().Add(time.Hour)}}}, internalOpts{now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	atOK(t, v, atMint(t, ec, atClaims(clock, atIss, nil), nil))
	atOK(t, v, atMint(t, prev, atClaims(clock, atIss, nil), nil))
	clock.Advance(2 * time.Hour)
	atInvalid(t, v, atMint(t, prev, atClaims(clock, atIss, nil), nil))
}

func TestAccessIssuerPreviousKeyNeedsKey(t *testing.T) {
	_, err := NewAccessVerifier(AccessConfig{Audience: atAud, Issuers: []Issuer{{Issuer: "https://idp.example", Discover: true,
		PreviousKey: "previous-secret-0123456789abcdef012345678"}}})
	if err == nil {
		t.Fatal("an issuer with a previous key and no Key was accepted")
	}
}
