package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func wantErr(t *testing.T, err, kind error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %v, got success", kind)
	}
	other := ErrInvalid
	if kind == ErrInvalid {
		other = ErrMalformed
	}
	if !errors.Is(err, kind) || errors.Is(err, other) {
		t.Fatalf("expected exactly %v, got %v", kind, err)
	}
}

func TestVerifyAllAlgorithms(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	for _, k := range testKeys(t) {
		t.Run(k.alg, func(t *testing.T) {
			v := newStatic(t, KeyConfig{Key: k.pem, Algorithm: k.alg})
			tok := sign(t, k, mercureClaims(jwt.MapClaims{"exp": exp.Unix(), "sub": "alice"}), nil)
			c, err := v.Verify(ctx(), tok)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.Publish, []string{"https://example.com/a", "*"}) || !c.HasPublish {
				t.Errorf("publish = %v (%v)", c.Publish, c.HasPublish)
			}
			if !reflect.DeepEqual(c.Subscribe, []string{"https://example.com/{x}"}) || !c.HasSubscribe {
				t.Errorf("subscribe = %v (%v)", c.Subscribe, c.HasSubscribe)
			}
			if c.Subject != "alice" || !c.Expiry.Equal(exp) || c.Payload != nil {
				t.Errorf("claims = %+v", c)
			}
			if !v.Ready() {
				t.Error("static verifier must be ready")
			}
		})
	}
}

func TestWrongKeyAndTamper(t *testing.T) {
	for _, k := range testKeys(t) {
		t.Run(k.alg, func(t *testing.T) {
			v := newStatic(t, KeyConfig{Key: k.pem, Algorithm: k.alg})
			tok := sign(t, k, mercureClaims(nil), nil)

			// Tamper with the payload, keeping the signature.
			parts := strings.Split(tok, ".")
			parts[1] = b64u(`{"mercure":{"publish":["*"]},"x":1}`)
			_, err := v.Verify(ctx(), strings.Join(parts, "."))
			wantErr(t, err, ErrInvalid)

			// Signature from a different key of the same type.
			var other testKey
			switch k.pub.(type) {
			case []byte:
				other = testKey{k.alg, k.method, []byte("another secret"), nil, ""}
			case *rsa.PublicKey:
				other = testKey{k.alg, k.method, extraRSA, nil, ""}
			case *ecdsa.PublicKey:
				pk, _ := ecdsa.GenerateKey(k.priv.(*ecdsa.PrivateKey).Curve, rand.Reader)
				other = testKey{k.alg, k.method, pk, nil, ""}
			case ed25519.PublicKey:
				_, pk, _ := ed25519.GenerateKey(rand.Reader)
				other = testKey{k.alg, k.method, pk, nil, ""}
			}
			_, err = v.Verify(ctx(), sign(t, other, mercureClaims(nil), nil))
			wantErr(t, err, ErrInvalid)
		})
	}
}

func TestOnlyConfiguredAlgorithm(t *testing.T) {
	hs256 := keyFor(t, "HS256")
	hs512 := keyFor(t, "HS512")
	v := newStatic(t, KeyConfig{Key: hs256.pem, Algorithm: "HS256"})
	_, err := v.Verify(ctx(), sign(t, hs512, mercureClaims(nil), nil))
	wantErr(t, err, ErrInvalid)

	// RS256 token against PS256 verifier and vice versa.
	rs := keyFor(t, "RS256")
	ps := keyFor(t, "PS256")
	vps := newStatic(t, KeyConfig{Key: ps.pem, Algorithm: "PS256"})
	_, err = vps.Verify(ctx(), sign(t, rs, mercureClaims(nil), nil))
	wantErr(t, err, ErrInvalid)
}

func TestAlgConfusion(t *testing.T) {
	// HS256 token "signed" with the RSA public key PEM as the HMAC secret.
	rs := keyFor(t, "RS256")
	forged := sign(t, testKey{"HS256", jwt.SigningMethodHS256, []byte(rs.pem), nil, ""}, mercureClaims(nil), nil)
	v := newStatic(t, KeyConfig{Key: rs.pem, Algorithm: "RS256"})
	_, err := v.Verify(ctx(), forged)
	wantErr(t, err, ErrInvalid)

	// Same against an EC verifier and an Ed25519 verifier.
	for _, alg := range []string{"ES256", "EdDSA"} {
		k := keyFor(t, alg)
		forged := sign(t, testKey{"HS256", jwt.SigningMethodHS256, []byte(k.pem), nil, ""}, mercureClaims(nil), nil)
		v := newStatic(t, KeyConfig{Key: k.pem, Algorithm: alg})
		_, err := v.Verify(ctx(), forged)
		wantErr(t, err, ErrInvalid)
	}
}

func TestAlgNone(t *testing.T) {
	payload := `{"mercure":{"publish":["*"]}}`
	toks := []string{
		rawToken(`{"alg":"none"}`, payload, ""),
		rawToken(`{"alg":"none"}`, payload, "c2ln"),
		rawToken(`{"alg":"None"}`, payload, ""),
		rawToken(`{"alg":"NONE","typ":"JWT"}`, payload, ""),
		rawToken(`{"alg":""}`, payload, ""),
		rawToken(`{"typ":"JWT"}`, payload, ""),
		rawToken(`{"alg":5}`, payload, ""),
		rawToken(`{"alg":"FOO"}`, payload, "c2ln"),
	}
	hv, _ := hs256Verifier(t)
	verifiers := []*Verifier{hv, newStatic(t, KeyConfig{Key: keyFor(t, "RS256").pem, Algorithm: "RS256"})}
	for _, v := range verifiers {
		for _, tok := range toks {
			_, err := v.Verify(ctx(), tok)
			wantErr(t, err, ErrInvalid)
		}
	}
}

func TestCritHeaderRejected(t *testing.T) {
	v, k := hs256Verifier(t)
	tok := sign(t, k, mercureClaims(nil), map[string]any{"crit": []string{"exp"}})
	_, err := v.Verify(ctx(), tok)
	wantErr(t, err, ErrInvalid)
}

func TestExpiryAndNotBefore(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		claims jwt.MapClaims
		leeway time.Duration
		want   error // nil = success
	}{
		{"no exp", nil, 0, nil},
		{"future exp", jwt.MapClaims{"exp": now.Add(time.Hour).Unix()}, 0, nil},
		{"expired", jwt.MapClaims{"exp": now.Add(-time.Minute).Unix()}, 0, ErrInvalid},
		{"expired within leeway", jwt.MapClaims{"exp": now.Add(-time.Minute).Unix()}, 2 * time.Minute, nil},
		{"expired beyond leeway", jwt.MapClaims{"exp": now.Add(-time.Minute).Unix()}, 30 * time.Second, ErrInvalid},
		{"nbf past", jwt.MapClaims{"nbf": now.Add(-time.Minute).Unix()}, 0, nil},
		{"nbf future", jwt.MapClaims{"nbf": now.Add(time.Minute).Unix()}, 0, ErrInvalid},
		{"nbf future within leeway", jwt.MapClaims{"nbf": now.Add(time.Minute).Unix()}, 2 * time.Minute, nil},
		{"nbf future beyond leeway", jwt.MapClaims{"nbf": now.Add(time.Minute).Unix()}, 10 * time.Second, ErrInvalid},
		{"iat in the future ignored", jwt.MapClaims{"iat": now.Add(time.Hour).Unix()}, 0, nil},
		{"fractional exp", jwt.MapClaims{"exp": float64(now.Add(time.Hour).UnixNano()) / 1e9}, 0, nil},
	}
	k := keyFor(t, "HS256")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newStatic(t, KeyConfig{Key: k.pem, Leeway: tt.leeway})
			_, err := v.Verify(ctx(), sign(t, k, mercureClaims(tt.claims), nil))
			if tt.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantErr(t, err, tt.want)
		})
	}
	t.Run("no exp means zero expiry", func(t *testing.T) {
		v, k := hs256Verifier(t)
		c, err := v.Verify(ctx(), sign(t, k, mercureClaims(nil), nil))
		if err != nil || !c.Expiry.IsZero() {
			t.Fatalf("%v %v", c, err)
		}
	})
}

func TestMalformed(t *testing.T) {
	v, k := hs256Verifier(t)
	good := sign(t, k, mercureClaims(nil), nil)
	parts := strings.Split(good, ".")
	hdr, pl := parts[0], parts[1]

	tests := map[string]string{
		"empty":              "",
		"no dots":            "abcdef",
		"one dot":            "a.b",
		"four segments":      good + ".x",
		"bad header base64":  "!!!." + pl + "." + parts[2],
		"header not json":    b64u("notjson") + "." + pl + "." + parts[2],
		"header json array":  b64u(`[]`) + "." + pl + "." + parts[2],
		"payload bad base64": hdr + ".@@@." + parts[2],
		"payload not json":   hdr + "." + b64u("notjson") + "." + parts[2],
		"payload array":      hdr + "." + b64u(`[1]`) + "." + parts[2],
		"signature base64":   hdr + "." + pl + ".***",
		"exp wrong type":     rawToken(`{"alg":"HS256"}`, `{"exp":"soon","mercure":{}}`, "c2ln"),
		"too long":           strings.Repeat("a", MaxTokenSize+1),
		"only dots":          "..",
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(ctx(), tok)
			wantErr(t, err, ErrMalformed)
		})
	}
}

func TestTokenSizeLimit(t *testing.T) {
	v, k := hs256Verifier(t)
	// Largest accepted: pad a claim until the token is exactly MaxTokenSize.
	build := func(n int) string {
		return sign(t, k, mercureClaims(jwt.MapClaims{"pad": strings.Repeat("x", n)}), nil)
	}
	n := (MaxTokenSize - len(build(0))) * 3 / 4
	for len(build(n)) > MaxTokenSize {
		n--
	}
	tok := build(n)
	if len(tok) > MaxTokenSize || len(tok) < MaxTokenSize-4 {
		t.Fatalf("could not build near-limit token: %d", len(tok))
	}
	if _, err := v.Verify(ctx(), tok); err != nil {
		t.Fatalf("token of %d bytes: %v", len(tok), err)
	}
	_, err := v.Verify(ctx(), build(n+8))
	wantErr(t, err, ErrMalformed)
}

func TestMercureClaim(t *testing.T) {
	v, k := hs256Verifier(t)
	signRaw := func(payload string) string {
		// Sign arbitrary JSON payload via a raw token and real HMAC.
		h := b64u(`{"alg":"HS256","typ":"JWT"}`)
		signing := h + "." + b64u(payload)
		sig, err := jwt.SigningMethodHS256.Sign(signing, k.priv)
		if err != nil {
			t.Fatal(err)
		}
		return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	invalid := map[string]string{
		"missing":             `{"sub":"x"}`,
		"null":                `{"mercure":null}`,
		"string":              `{"mercure":"x"}`,
		"number":              `{"mercure":1}`,
		"array":               `{"mercure":[]}`,
		"bool":                `{"mercure":true}`,
		"publish string":      `{"mercure":{"publish":"*"}}`,
		"publish object":      `{"mercure":{"publish":{}}}`,
		"publish number":      `{"mercure":{"publish":1}}`,
		"publish bool":        `{"mercure":{"publish":true}}`,
		"publish mixed":       `{"mercure":{"publish":["a",1]}}`,
		"publish null elem":   `{"mercure":{"publish":["a",null]}}`,
		"publish nested":      `{"mercure":{"publish":[["a"]]}}`,
		"subscribe string":    `{"mercure":{"subscribe":"*"}}`,
		"subscribe mixed":     `{"mercure":{"subscribe":[true]}}`,
		"subscribe object":    `{"mercure":{"subscribe":{"a":1}}}`,
		"publish ok subs bad": `{"mercure":{"publish":["*"],"subscribe":5}}`,
	}
	for name, p := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			_, err := v.Verify(ctx(), signRaw(p))
			wantErr(t, err, ErrInvalid)
		})
	}

	valid := []struct {
		name         string
		payload      string
		pub, sub     []string
		hasP, hasS   bool
		wantPayload  string
		wantSubject  string
		expectNilPub bool
	}{
		{name: "empty object", payload: `{"mercure":{}}`},
		{name: "empty arrays", payload: `{"mercure":{"publish":[],"subscribe":[]}}`, pub: []string{}, sub: []string{}, hasP: true, hasS: true},
		{name: "null arrays are absent", payload: `{"mercure":{"publish":null,"subscribe":null}}`},
		{name: "publish only", payload: `{"mercure":{"publish":["a","b"]}}`, pub: []string{"a", "b"}, hasP: true},
		{name: "subscribe only", payload: `{"mercure":{"subscribe":["x"]}}`, sub: []string{"x"}, hasS: true},
		{name: "payload object", payload: `{"mercure":{"payload":{"user":"kevin","n":[1,2]}}}`, wantPayload: `{"user":"kevin","n":[1,2]}`},
		{name: "payload string", payload: `{"mercure":{"payload":"hi"}}`, wantPayload: `"hi"`},
		{name: "payload number", payload: `{"mercure":{"payload":42}}`, wantPayload: `42`},
		{name: "payload null", payload: `{"mercure":{"payload":null}}`, wantPayload: `null`},
		{name: "payload array", payload: `{"mercure":{"payload":[1,"a"]}}`, wantPayload: `[1,"a"]`},
		{name: "sub", payload: `{"sub":"bob","mercure":{}}`, wantSubject: "bob"},
		{name: "sub wrong type ignored", payload: `{"sub":5,"mercure":{}}`},
		{name: "unknown claims ignored", payload: `{"iss":"x","aud":["a"],"jti":"1","mercure":{"foo":1}}`},
		{name: "whitespace", payload: `{"mercure" :  { "publish" : [ "a" ] } }`, pub: []string{"a"}, hasP: true},
	}
	for _, tt := range valid {
		t.Run("valid "+tt.name, func(t *testing.T) {
			c, err := v.Verify(ctx(), signRaw(tt.payload))
			if err != nil {
				t.Fatal(err)
			}
			if c.HasPublish != tt.hasP || c.HasSubscribe != tt.hasS {
				t.Errorf("has flags = %v %v", c.HasPublish, c.HasSubscribe)
			}
			if !reflect.DeepEqual(c.Publish, tt.pub) || !reflect.DeepEqual(c.Subscribe, tt.sub) {
				t.Errorf("selectors = %#v %#v", c.Publish, c.Subscribe)
			}
			if string(c.Payload) != tt.wantPayload {
				t.Errorf("payload = %q want %q", c.Payload, tt.wantPayload)
			}
			if tt.wantPayload == "" && c.Payload != nil {
				t.Error("payload must be nil when absent")
			}
			if c.Subject != tt.wantSubject {
				t.Errorf("subject = %q", c.Subject)
			}
		})
	}
}

// RSA keys under 2048 bits are refused as they are loaded, from PEM and from a JWK Set.
func TestRSAMinimumBits(t *testing.T) {
	full := keyFor(t, "RS256").pub.(*rsa.PublicKey)
	short := &rsa.PublicKey{N: new(big.Int).Rsh(full.N, 1024), E: full.E}
	der, err := x509.MarshalPKIXPublicKey(short)
	if err != nil {
		t.Fatal(err)
	}
	p := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := NewVerifier(KeyConfig{Key: p, Algorithm: "RS256"}); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("short RSA PEM: %v", err)
	}
	if _, err := parseJWKS(jwksJSON(t, jwkMap(t, short, "s", "", ""))); err == nil {
		t.Fatal("short RSA JWK accepted")
	}
}

func TestPEMParsing(t *testing.T) {
	rsaK := keyFor(t, "RS256")
	rsaPub := rsaK.pub.(*rsa.PublicKey)
	ecK := keyFor(t, "ES256")
	edK := keyFor(t, "EdDSA")

	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))
	rsaPriv := rsaK.priv.(*rsa.PrivateKey)
	rsaCert := selfSignedCert(t, rsaPub, rsaPriv)
	ecCert := selfSignedCert(t, ecK.pub, ecK.priv)
	edCert := selfSignedCert(t, edK.pub, edK.priv)
	privDER, _ := x509.MarshalPKCS8PrivateKey(rsaPriv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	junk := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}))
	p384K := keyFor(t, "ES384")

	tests := []struct {
		name    string
		key     string
		alg     string
		sign    testKey
		wantErr bool
	}{
		{"pkix rsa", rsaK.pem, "RS256", rsaK, false},
		{"pkcs1 rsa", pkcs1, "RS256", rsaK, false},
		{"pkcs1 rsa PS384", pkcs1, "PS384", keyFor(t, "PS384"), false},
		{"cert rsa", rsaCert, "RS256", rsaK, false},
		{"cert ec", ecCert, "ES256", ecK, false},
		{"cert ed25519", edCert, "EdDSA", edK, false},
		{"pkix ec", ecK.pem, "ES256", ecK, false},
		{"pkix ed", edK.pem, "EdDSA", edK, false},
		{"leading text and multiple blocks", "# my key\n" + junk + rsaK.pem, "RS256", rsaK, false},
		{"private key rejected", privPEM, "RS256", rsaK, true},
		{"not pem", "not a pem", "RS256", rsaK, true},
		{"only junk block", junk, "RS256", rsaK, true},
		{"rsa key for ES256", rsaK.pem, "ES256", ecK, true},
		{"ec key for RS256", ecK.pem, "RS256", rsaK, true},
		{"ed key for ES256", edK.pem, "ES256", ecK, true},
		{"P-256 key for ES384", ecK.pem, "ES384", p384K, true},
		{"P-384 key for ES256", p384K.pem, "ES256", ecK, true},
		{"rsa key for EdDSA", rsaK.pem, "EdDSA", edK, true},
		{"unknown algorithm", rsaK.pem, "RS999", rsaK, true},
		{"none algorithm", rsaK.pem, "none", rsaK, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(KeyConfig{Key: tt.key, Algorithm: tt.alg})
			if tt.wantErr {
				if err == nil {
					v.Close()
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if _, err := v.Verify(ctx(), sign(t, tt.sign, mercureClaims(nil), nil)); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("P-256 and P-384 keys mismatch", func(t *testing.T) {
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if _, err := NewVerifier(KeyConfig{Key: pubPEM(t, &p256.PublicKey), Algorithm: "ES512"}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestConfigValidation(t *testing.T) {
	hs := keyFor(t, "HS256").pem
	bad := []KeyConfig{
		{},
		{Key: hs, JWKSURL: "https://example.com/jwks"},
		{Key: hs, Algorithm: "nope"},
		{JWKSURL: "not a url"},
		{JWKSURL: "ftp://example.com/jwks"},
		{JWKSURL: "https:///jwks"},
		{Key: hs, Leeway: -time.Second},
	}
	for i, cfg := range bad {
		if v, err := NewVerifier(cfg); err == nil {
			v.Close()
			t.Errorf("config %d: expected error", i)
		}
	}
}

func TestWeak(t *testing.T) {
	tests := []struct {
		alg  string
		n    int
		weak bool
	}{
		{"HS256", 31, true}, {"HS256", 32, false}, {"", 8, true}, {"", 40, false},
		{"HS384", 47, true}, {"HS384", 48, false},
		{"HS512", 63, true}, {"HS512", 64, false},
	}
	for _, tt := range tests {
		v := newStatic(t, KeyConfig{Key: strings.Repeat("k", tt.n), Algorithm: tt.alg})
		if v.Weak() != tt.weak {
			t.Errorf("%s/%d: Weak = %v", tt.alg, tt.n, v.Weak())
		}
	}
	if newStatic(t, KeyConfig{Key: keyFor(t, "RS256").pem, Algorithm: "RS256"}).Weak() {
		t.Error("asymmetric verifier must not be weak")
	}
}

func TestShortSecretStillWorks(t *testing.T) {
	k := testKey{"HS256", jwt.SigningMethodHS256, []byte("short"), nil, ""}
	v := newStatic(t, KeyConfig{Key: "short"})
	if _, err := v.Verify(ctx(), sign(t, k, mercureClaims(nil), nil)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyContextIgnoredForStatic(t *testing.T) {
	v, k := hs256Verifier(t)
	c, cancel := contextCancelled()
	defer cancel()
	if _, err := v.Verify(c, sign(t, k, mercureClaims(nil), nil)); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsCarryReason(t *testing.T) {
	v, _ := hs256Verifier(t)
	_, err := v.Verify(ctx(), "a.b")
	if err == nil || !strings.Contains(err.Error(), "malformed") || len(err.Error()) < len(ErrMalformed.Error())+3 {
		t.Fatalf("no reason in %v", err)
	}
}

func TestConcurrentVerify(t *testing.T) {
	rs := keyFor(t, "RS256")
	hs := keyFor(t, "HS256")
	vr := newStatic(t, KeyConfig{Key: rs.pem, Algorithm: "RS256"})
	vh := newStatic(t, KeyConfig{Key: hs.pem})
	goodR := sign(t, rs, mercureClaims(nil), nil)
	goodH := sign(t, hs, mercureClaims(nil), nil)
	expired := sign(t, hs, mercureClaims(jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}), nil)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if c, err := vr.Verify(ctx(), goodR); err != nil || len(c.Publish) != 2 {
					t.Errorf("rs: %v", err)
					return
				}
				if _, err := vh.Verify(ctx(), goodH); err != nil {
					t.Errorf("hs: %v", err)
					return
				}
				if _, err := vh.Verify(ctx(), expired); !errors.Is(err, ErrInvalid) {
					t.Errorf("expired: %v", err)
					return
				}
				if _, err := vh.Verify(ctx(), "x.y"); !errors.Is(err, ErrMalformed) {
					t.Errorf("malformed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzVerify(f *testing.F) {
	rs := keyFor(f, "RS256")
	hs := keyFor(f, "HS256")
	ed := keyFor(f, "EdDSA")
	verifiers := []*Verifier{
		newStatic(f, KeyConfig{Key: hs.pem}),
		newStatic(f, KeyConfig{Key: rs.pem, Algorithm: "RS256"}),
		newStatic(f, KeyConfig{Key: ed.pem, Algorithm: "EdDSA"}),
	}
	seeds := []string{
		sign(f, hs, mercureClaims(nil), nil),
		sign(f, hs, mercureClaims(jwt.MapClaims{"exp": 1, "sub": "x"}), map[string]any{"kid": "k"}),
		sign(f, rs, mercureClaims(nil), nil),
		sign(f, ed, mercureClaims(jwt.MapClaims{"mercure": map[string]any{"payload": []int{1}}}), nil),
		rawToken(`{"alg":"none"}`, `{"mercure":{}}`, ""),
		rawToken(`{"alg":"HS256"}`, `{"mercure":{"publish":[null]}}`, "AAAA"),
		"", ".", "..", "a.b.c", "....",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		for _, v := range verifiers {
			c, err := v.Verify(ctx(), tok)
			if err == nil {
				if c == nil {
					t.Fatal("nil claims without error")
				}
				continue
			}
			m, i := errors.Is(err, ErrMalformed), errors.Is(err, ErrInvalid)
			if m == i {
				t.Fatalf("error must wrap exactly one sentinel: %v", err)
			}
		}
	})
}

func BenchmarkVerifyHS256(b *testing.B) {
	k := keyFor(b, "HS256")
	v := newStatic(b, KeyConfig{Key: k.pem})
	tok := sign(b, k, mercureClaims(jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), nil)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Verify(ctx(), tok); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyRS256(b *testing.B) {
	k := keyFor(b, "RS256")
	v := newStatic(b, KeyConfig{Key: k.pem, Algorithm: "RS256"})
	tok := sign(b, k, mercureClaims(jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), nil)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Verify(ctx(), tok); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyES256(b *testing.B) {
	k := keyFor(b, "ES256")
	v := newStatic(b, KeyConfig{Key: k.pem, Algorithm: "ES256"})
	tok := sign(b, k, mercureClaims(nil), nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(ctx(), tok); err != nil {
			b.Fatal(err)
		}
	}
}

func TestWeakSecretAndInsecureJWKS(t *testing.T) {
	for k, want := range map[KeyConfig]bool{
		{Key: "short"}:                                     true,
		{Key: strings.Repeat("x", 32)}:                     false,
		{Key: strings.Repeat("x", 32), Algorithm: "HS512"}: true,
		{JWKSURL: "https://idp.example/jwks"}:              false,
	} {
		if got := WeakSecret(k); got != want {
			t.Errorf("WeakSecret(%+v) = %v, want %v", k, got, want)
		}
	}
	if _, err := NewVerifier(KeyConfig{JWKSURL: "http://idp.example/jwks"}); err == nil {
		t.Error("a plain-HTTP JWK Set URL was accepted")
	}
	v, err := NewVerifier(KeyConfig{JWKSURL: "http://127.0.0.1:1/jwks", AllowInsecureHTTP: true, HTTPClient: &http.Client{Timeout: 100 * time.Millisecond}})
	if err != nil {
		t.Fatalf("allowed plain HTTP: %v", err)
	}
	v.Close()
}

// Without an algorithm a PEM public key verifies with its own, and an HMAC algorithm with it is refused: the public
// key is never an HMAC secret.
func TestDefaultAlgorithm(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256", "ES384", "ES512", "EdDSA", "HS256"} {
		k := keyFor(t, alg)
		if got, err := DefaultAlgorithm(k.pem); err != nil || got != alg {
			t.Errorf("%s key: %q %v", alg, got, err)
		}
		v, err := NewVerifier(KeyConfig{Key: k.pem})
		if err != nil {
			t.Fatalf("%s key without an algorithm: %v", alg, err)
		}
		if _, err := v.Verify(ctx(), sign(t, k, mercureClaims(nil), nil)); err != nil {
			t.Errorf("%s key without an algorithm: its token refused: %v", alg, err)
		}
	}
	rs := keyFor(t, "RS256")
	v, _ := NewVerifier(KeyConfig{Key: rs.pem})
	forged := testKey{alg: "HS256", method: jwt.SigningMethodHS256, priv: []byte(rs.pem)}
	if _, err := v.Verify(ctx(), sign(t, forged, mercureClaims(nil), nil)); err == nil {
		t.Error("a token signed with the public key's text as an HS256 secret verified")
	}
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		if _, err := NewVerifier(KeyConfig{Key: rs.pem, Algorithm: alg}); err == nil || !strings.Contains(err.Error(), "PEM") {
			t.Errorf("%s with a PEM key: %v", alg, err)
		}
	}
	if WeakSecret(KeyConfig{Key: rs.pem}) {
		t.Error("a PEM key reported as a weak secret")
	}
	if _, err := DefaultAlgorithm("-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----\n"); err == nil {
		t.Error("a PEM block that does not parse got an algorithm")
	}
}
