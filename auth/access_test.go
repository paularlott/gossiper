package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAccessHappyPath(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	if !v.Ready() {
		t.Fatal("static verifier not ready")
	}
	c := atOK(t, v, atMint(t, k, atClaims(clock, atIss, nil), nil))
	want := &AccessClaims{
		Issuer: atIss, Subject: "urn:sub:1", ClientID: "client-1", JTI: "jti-1",
		Audience: []string{atAud},
		IssuedAt: time.Unix(clock.Now().Unix(), 0),
		Expiry:   time.Unix(clock.Now().Add(time.Hour).Unix(), 0),
		Details: []Detail{{
			Actions: []string{"subscribe"},
			Topics:  []TopicMatcher{{Match: "https://example.com/a", MatchType: "exact"}},
		}},
		RawDetails: json.RawMessage(`[{"actions":["subscribe"],"topics":[{"match":"https://example.com/a"}],"type":"https://mercure.rocks/authorization-detail"}]`),
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("claims\n got %+v\nwant %+v", c, want)
	}
}

func TestAccessAllAlgorithms(t *testing.T) {
	for _, k := range testKeys(t) {
		t.Run(k.alg, func(t *testing.T) {
			v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: k.pem}}})
			atOK(t, v, atMint(t, k, atClaims(clock, atIss, nil), nil))
		})
	}
}

func TestAccessOptionalClaims(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	tok := atMint(t, k, atClaims(clock, atIss, map[string]any{
		"sub": atDel, "client_id": atDel, "jti": atDel, "iat": atDel, "authorization_details": atDel,
	}), nil)
	c := atOK(t, v, tok)
	if c.Subject != "" || c.ClientID != "" || c.JTI != "" || !c.IssuedAt.IsZero() || len(c.Details) != 0 || c.Expiry.IsZero() {
		t.Fatalf("unexpected %+v", c)
	}
	// Present claims of the wrong type are rejected.
	for _, over := range []map[string]any{
		{"sub": 5}, {"client_id": []string{"a"}}, {"jti": true}, {"iat": "now"}, {"iat": -1},
	} {
		atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, over), nil))
	}
}

func TestAccessTyp(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	claims := atClaims(clock, atIss, nil)
	for _, typ := range []string{"at+jwt", "AT+JWT", "At+Jwt", "application/at+jwt", "Application/AT+JWT", "APPLICATION/at+jwt"} {
		atOK(t, v, atMint(t, k, claims, map[string]any{"typ": typ}))
	}
	for _, typ := range []any{
		"JWT", "jwt", "", "application/jwt", "at+jwt ", " at+jwt", "at+jwtx", "xat+jwt", "application/",
		"application/application/at+jwt", "application/at+jwt/", "id+jwt", 123, nil, []string{"at+jwt"}, atDel,
	} {
		t.Run(fmt.Sprintf("%v", typ), func(t *testing.T) {
			atInvalid(t, v, atMint(t, k, claims, map[string]any{"typ": typ}))
		})
	}
}

func TestAccessAlgorithmAllowlist(t *testing.T) {
	rs := keyFor(t, "RS256")
	t.Run("default allows RS and PS but not HS for a public key", func(t *testing.T) {
		v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: rs.pem}}})
		for _, a := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
			atOK(t, v, atMint(t, keyFor(t, a), atClaims(clock, atIss, nil), nil))
		}
	})
	t.Run("explicit list restricts", func(t *testing.T) {
		v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: rs.pem, Algorithms: []string{"RS256"}}}})
		atOK(t, v, atMint(t, rs, atClaims(clock, atIss, nil), nil))
		atInvalid(t, v, atMint(t, keyFor(t, "RS384"), atClaims(clock, atIss, nil), nil))
		atInvalid(t, v, atMint(t, keyFor(t, "PS256"), atClaims(clock, atIss, nil), nil))
	})
	t.Run("EC curve selects the algorithm", func(t *testing.T) {
		es := keyFor(t, "ES384")
		v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: es.pem}}})
		atOK(t, v, atMint(t, es, atClaims(clock, atIss, nil), nil))
		atInvalid(t, v, atMint(t, keyFor(t, "ES256"), atClaims(clock, atIss, nil), nil))
	})
	t.Run("alg none", func(t *testing.T) {
		v, clock, _ := atStatic(t, nil)
		payload, _ := json.Marshal(atClaims(clock, atIss, nil))
		for _, alg := range []string{"none", "None", "NONE", ""} {
			atInvalid(t, v, rawToken(`{"alg":"`+alg+`","typ":"at+jwt"}`, string(payload), ""))
		}
		_, err := v.Verify(ctx(), rawToken(`{"typ":"at+jwt"}`, string(payload), "AAAA"))
		if err == nil {
			t.Fatal("token without alg accepted")
		}
	})
	t.Run("RSA public key used as HMAC secret", func(t *testing.T) {
		v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: rs.pem}}})
		forged := testKey{alg: "HS256", method: jwt.SigningMethodHS256, priv: []byte(rs.pem)}
		atInvalid(t, v, atMint(t, forged, atClaims(clock, atIss, nil), nil))
	})
	t.Run("HMAC issuer refuses asymmetric algorithms", func(t *testing.T) {
		v, clock, _ := atStatic(t, nil)
		atInvalid(t, v, atMint(t, rs, atClaims(clock, atIss, nil), nil))
		atInvalid(t, v, atMint(t, keyFor(t, "EdDSA"), atClaims(clock, atIss, nil), nil))
	})
	t.Run("HMAC algorithm list", func(t *testing.T) {
		hs := keyFor(t, "HS384")
		v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: hs.pem, Algorithms: []string{"HS384"}}}})
		atOK(t, v, atMint(t, hs, atClaims(clock, atIss, nil), nil))
		atInvalid(t, v, atMint(t, keyFor(t, "HS256"), atClaims(clock, atIss, nil), nil))
	})
	t.Run("another issuer's algorithms do not leak", func(t *testing.T) {
		es := atEC(t)
		v, clock := atNew(t, AccessConfig{Issuers: []Issuer{
			{Issuer: "https://a", Key: es.pem},
			{Issuer: "https://b", Key: rs.pem, Algorithms: []string{"RS256"}},
		}})
		atOK(t, v, atMint(t, es, atClaims(clock, "https://a", nil), nil))
		atInvalid(t, v, atMint(t, es, atClaims(clock, "https://b", nil), nil))
	})
}

func TestAccessIssuerIsolation(t *testing.T) {
	a, b := atEC(t), atEC(t)
	hs := keyFor(t, "HS256")
	v, clock := atNew(t, AccessConfig{Issuers: []Issuer{
		{Issuer: "https://a.example", Key: a.pem},
		{Issuer: "https://b.example", Key: b.pem},
		{Issuer: "https://c.example", Key: hs.pem},
	}})
	atOK(t, v, atMint(t, a, atClaims(clock, "https://a.example", nil), nil))
	atOK(t, v, atMint(t, b, atClaims(clock, "https://b.example", nil), nil))
	atOK(t, v, atMint(t, hs, atClaims(clock, "https://c.example", nil), nil))
	// A token signed with A's key but claiming B (or C) is rejected.
	atInvalid(t, v, atMint(t, a, atClaims(clock, "https://b.example", nil), nil))
	atInvalid(t, v, atMint(t, b, atClaims(clock, "https://a.example", nil), nil))
	atInvalid(t, v, atMint(t, a, atClaims(clock, "https://c.example", nil), nil))
	atInvalid(t, v, atMint(t, hs, atClaims(clock, "https://a.example", nil), nil))
}

func TestAccessIssuerClaim(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	for name, iss := range map[string]any{
		"missing": atDel, "untrusted": "https://evil.example", "empty": "", "number": 7, "null": nil,
		"case": strings.ToUpper(atIss), "trailing slash": atIss + "/", "prefix": atIss + ".evil", "array": []string{atIss},
	} {
		t.Run(name, func(t *testing.T) {
			atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"iss": iss}), nil))
		})
	}
}

func TestAccessAudience(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	ok := map[string]any{
		"string":      atAud,
		"array":       []string{atAud},
		"array first": []string{"https://other", atAud},
		"array last":  []string{atAud, "https://other"},
	}
	for name, aud := range ok {
		t.Run("ok "+name, func(t *testing.T) {
			c := atOK(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"aud": aud}), nil))
			found := false
			for _, a := range c.Audience {
				found = found || a == atAud
			}
			if !found {
				t.Fatalf("audience %v", c.Audience)
			}
		})
	}
	bad := map[string]any{
		"missing": atDel, "null": nil, "wrong": "https://other", "empty string": "", "empty array": []string{},
		"wrong array": []string{"https://a", "https://b"}, "prefix": atAud + "/x", "suffix": "x" + atAud,
		"case": strings.ToUpper(atAud), "number": 5, "object": map[string]any{"a": atAud},
		"non-string member": []any{atAud, 5}, "nested": []any{[]string{atAud}},
	}
	for name, aud := range bad {
		t.Run("bad "+name, func(t *testing.T) {
			atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"aud": aud}), nil))
		})
	}
}

func TestAccessVerifyAudience(t *testing.T) {
	// No configured identifier: the caller gives one with each token.
	k := keyFor(t, "HS256")
	clock := newFakeClock()
	v, err := newAccessVerifier(AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: k.pem}}}, internalOpts{now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	tok := atMint(t, k, atClaims(clock, atIss, nil), nil)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify without any audience: %v", err)
	}
	if _, err := v.VerifyAudience(context.Background(), tok, atAud); err != nil {
		t.Fatalf("VerifyAudience: %v", err)
	}
	if _, err := v.VerifyAudience(context.Background(), tok, "https://other.example"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("VerifyAudience with another identifier: %v", err)
	}
	// A configured identifier is the fallback for "".
	v2, clock2, k2 := atStatic(t, nil)
	if _, err := v2.VerifyAudience(context.Background(), atMint(t, k2, atClaims(clock2, atIss, nil), nil), ""); err != nil {
		t.Fatalf("VerifyAudience falling back: %v", err)
	}
}

func TestAccessAudienceConfigured(t *testing.T) {
	v, clock, k := atStatic(t, func(c *AccessConfig) { c.Audience = "https://hub2.example" })
	atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, nil), nil))
	atOK(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"aud": []string{atAud, "https://hub2.example"}}), nil))
}

func TestAccessExpAndNbf(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	now := clock.Now()
	mint := func(over map[string]any) string { return atMint(t, k, atClaims(clock, atIss, over), nil) }

	atOK(t, v, mint(map[string]any{"exp": now.Add(time.Second).Unix()}))
	atOK(t, v, mint(map[string]any{"exp": float64(now.Unix()) + 1.5}))
	for name, over := range map[string]map[string]any{
		"missing exp":  {"exp": atDel},
		"null exp":     {"exp": nil},
		"past":         {"exp": now.Add(-time.Second).Unix()},
		"exactly now":  {"exp": now.Unix()},
		"string exp":   {"exp": fmt.Sprint(now.Add(time.Hour).Unix())},
		"object exp":   {"exp": map[string]any{}},
		"negative exp": {"exp": -1},
		"huge exp":     {"exp": 1e15},
		"nbf future":   {"nbf": now.Add(time.Minute).Unix()},
		"nbf string":   {"nbf": "0"},
		"nbf negative": {"nbf": -5},
	} {
		t.Run(name, func(t *testing.T) { atInvalid(t, v, mint(over)) })
	}
	atOK(t, v, mint(map[string]any{"nbf": now.Unix()}))
	atOK(t, v, mint(map[string]any{"nbf": now.Add(-time.Hour).Unix()}))

	// The first request with a token is checked, and so is a later one.
	tok := mint(map[string]any{"exp": now.Add(10 * time.Second).Unix()})
	atOK(t, v, tok)
	clock.Advance(10 * time.Second)
	atInvalid(t, v, tok)
}

func TestAccessLeeway(t *testing.T) {
	v, clock, k := atStatic(t, func(c *AccessConfig) { c.Leeway = 30 * time.Second })
	now := clock.Now()
	mint := func(over map[string]any) string { return atMint(t, k, atClaims(clock, atIss, over), nil) }
	atOK(t, v, mint(map[string]any{"exp": now.Add(-29 * time.Second).Unix()}))
	atInvalid(t, v, mint(map[string]any{"exp": now.Add(-30 * time.Second).Unix()}))
	atOK(t, v, mint(map[string]any{"nbf": now.Add(30 * time.Second).Unix()}))
	atInvalid(t, v, mint(map[string]any{"nbf": now.Add(31 * time.Second).Unix()}))
	// iat is not validated.
	atOK(t, v, mint(map[string]any{"iat": now.Add(time.Hour).Unix()}))
	// exp is still required with a leeway.
	atInvalid(t, v, mint(map[string]any{"exp": atDel}))
}

func TestAccessSignature(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	tok := atMint(t, k, atClaims(clock, atIss, nil), nil)
	parts := strings.Split(tok, ".")

	atInvalid(t, v, atMint(t, keyFor(t, "HS256"), atClaims(clock, atIss, nil), nil)[:len(tok)-2]+"AA")
	// Payload swapped for another validly signed token's payload.
	other := strings.Split(atMint(t, k, atClaims(clock, atIss, map[string]any{"sub": "admin"}), nil), ".")
	atInvalid(t, v, parts[0]+"."+other[1]+"."+parts[2])
	// A different secret.
	bad := testKey{alg: "HS256", method: jwt.SigningMethodHS256, priv: []byte("some other secret entirely, 32+ b")}
	atInvalid(t, v, atMint(t, bad, atClaims(clock, atIss, nil), nil))
	// Empty signature.
	atInvalid(t, v, parts[0]+"."+parts[1]+".")
}

func TestAccessKeyMaterialInTokenIgnored(t *testing.T) {
	trusted, attacker := atEC(t), atEC(t)
	v, clock := atNew(t, AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: trusted.pem}}})
	jwkHdr := jwkMap(t, attacker.pub, "", "ES256", "")

	// Signed by the attacker, advertising the attacker's key in every way.
	for name, hdr := range map[string]map[string]any{
		"jwk": {"jwk": jwkHdr},
		"jku": {"jku": "https://evil.example/jwks"},
		"x5u": {"x5u": "https://evil.example/cert"},
		"x5c": {"x5c": []string{"AAAA"}},
		"kid": {"kid": "attacker"},
	} {
		t.Run(name, func(t *testing.T) {
			atInvalid(t, v, atMint(t, attacker, atClaims(clock, atIss, nil), hdr))
			// The same headers on a token the trusted key signed are harmless.
			atOK(t, v, atMint(t, trusted, atClaims(clock, atIss, nil), hdr))
		})
	}
	atInvalid(t, v, atMint(t, trusted, atClaims(clock, atIss, nil), map[string]any{"crit": []string{"exp"}}))
}

func TestAccessMalformedVersusInvalid(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	good := atMint(t, k, atClaims(clock, atIss, nil), nil)
	parts := strings.Split(good, ".")
	payload, _ := json.Marshal(atClaims(clock, atIss, nil))

	for name, tok := range map[string]string{
		"empty":         "",
		"one segment":   "abc",
		"two segments":  parts[0] + "." + parts[1],
		"four segments": good + ".AAAA",
		"jwe":           good + ".AAAA.BBBB",
		"bad b64 hdr":   "!!!." + parts[1] + "." + parts[2],
		"bad b64 pay":   parts[0] + ".!!!." + parts[2],
		"hdr not json":  rawToken("not json", string(payload), "AAAA"),
		"hdr array":     rawToken("[]", string(payload), "AAAA"),
		"pay not json":  rawToken(`{"alg":"HS256","typ":"at+jwt"}`, "nope", "AAAA"),
		"pay array":     rawToken(`{"alg":"HS256","typ":"at+jwt"}`, "[]", "AAAA"),
		"pay string":    rawToken(`{"alg":"HS256","typ":"at+jwt"}`, `"x"`, "AAAA"),
		"too long":      strings.Repeat("a", MaxTokenSize+1),
		"bad b64 sig":   parts[0] + "." + parts[1] + ".!!!",
	} {
		t.Run(name, func(t *testing.T) { atMalformed(t, v, tok) })
	}

	// Well-formed tokens that fail any other check are invalid_token.
	atInvalid(t, v, atMint(t, k, atClaims(clock, "https://evil", nil), nil))
	atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"exp": 1}), nil))
	atInvalid(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"aud": "x"}), nil))
	atInvalid(t, v, rawToken(`{"alg":"HS256","typ":"at+jwt"}`, `null`, "AAAA"))
}

func TestAccessMaxTokenSize(t *testing.T) {
	v, clock, k := atStatic(t, func(c *AccessConfig) { c.MaxTokenSize = 400 })
	atOK(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": atDel}), nil))
	atMalformed(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"sub": strings.Repeat("x", 400)}), nil))
}

func TestAccessClassicTokenRejected(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	classic := jwt.MapClaims{"mercure": map[string]any{"subscribe": []string{"*"}}, "exp": clock.Now().Add(time.Hour).Unix()}
	atInvalid(t, v, atMint(t, k, classic, map[string]any{"typ": "JWT"}))
	atInvalid(t, v, atMint(t, k, classic, nil))
}

// --- authorization_details ---

func TestAccessDetails(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	mercure := func(m map[string]any) map[string]any {
		out := map[string]any{"type": DetailType, "actions": []any{"publish"}, "topics": []any{atTopic("*", "")}}
		for key, val := range m {
			if val == atDel {
				delete(out, key)
			} else {
				out[key] = val
			}
		}
		return out
	}
	foreign := map[string]any{"type": "https://other.example/detail", "actions": 5, "topics": "garbage", "locations": []string{"x"}}

	type tc struct {
		name    string
		details any // the authorization_details claim; atDel removes the claim
		want    []Detail
		bad     bool
	}
	pub := func(topics ...TopicMatcher) Detail { return Detail{Actions: []string{"publish"}, Topics: topics} }
	star := TopicMatcher{"*", "exact"}
	tests := []tc{
		{name: "absent", details: atDel},
		{name: "null", details: nil},
		{name: "empty array", details: []any{}},
		{name: "foreign only is ignored", details: []any{foreign}},
		{name: "non-object entries are not Mercure", details: []any{5, "x", nil, []any{}}},
		{name: "missing or odd type is not Mercure", details: []any{map[string]any{"actions": 1}, map[string]any{"type": 5}, map[string]any{"type": nil}}},
		{name: "type compared exactly", details: []any{
			map[string]any{"type": strings.ToUpper(DetailType)}, map[string]any{"type": DetailType + "/"}, map[string]any{"type": " " + DetailType},
		}},
		{name: "simple", details: []any{mercure(nil)}, want: []Detail{pub(star)}},
		{name: "foreign around Mercure", details: []any{foreign, mercure(nil), foreign}, want: []Detail{pub(star)}},
		{name: "order kept", details: []any{
			mercure(map[string]any{"topics": []any{atTopic("https://a", "")}}),
			mercure(map[string]any{"topics": []any{atTopic("https://b/:id", "urlpattern")}, "actions": []any{"subscribe", "publish"}}),
		}, want: []Detail{
			pub(TopicMatcher{"https://a", "exact"}),
			{Actions: []string{"subscribe", "publish"}, Topics: []TopicMatcher{{"https://b/:id", "urlpattern"}}},
		}},
		{name: "explicit exact", details: []any{mercure(map[string]any{"topics": []any{atTopic("https://a", "exact")}})},
			want: []Detail{pub(TopicMatcher{"https://a", "exact"})}},
		{name: "several topics", details: []any{mercure(map[string]any{"topics": []any{atTopic("https://a", ""), atTopic("https://b/*", "urlpattern")}})},
			want: []Detail{pub(TopicMatcher{"https://a", "exact"}, TopicMatcher{"https://b/*", "urlpattern"})}},
		{name: "unknown action ignored but kept", details: []any{mercure(map[string]any{"actions": []any{"frobnicate", "publish"}})},
			want: []Detail{{Actions: []string{"frobnicate", "publish"}, Topics: []TopicMatcher{star}}}},
		{name: "only unknown action is valid", details: []any{mercure(map[string]any{"actions": []any{"frobnicate"}})},
			want: []Detail{{Actions: []string{"frobnicate"}, Topics: []TopicMatcher{star}}}},
		{name: "wildcard with urlpattern type", details: []any{mercure(map[string]any{"topics": []any{atTopic("*", "urlpattern")}})},
			want: []Detail{pub(TopicMatcher{"*", "urlpattern"})}},
		{name: "extra properties ignored", details: []any{mercure(map[string]any{"locations": []any{"x"}, "extra": 1})}, want: []Detail{pub(star)}},
		{name: "payload object", details: []any{mercure(map[string]any{"payload": map[string]any{"a": 1}})},
			want: []Detail{{Actions: []string{"publish"}, Topics: []TopicMatcher{star}, Payload: json.RawMessage(`{"a":1}`)}}},
		{name: "empty payload object", details: []any{mercure(map[string]any{"payload": map[string]any{}})},
			want: []Detail{{Actions: []string{"publish"}, Topics: []TopicMatcher{star}, Payload: json.RawMessage(`{}`)}}},

		{name: "claim is an object", details: mercure(nil), bad: true},
		{name: "claim is a string", details: "x", bad: true},
		{name: "claim is a number", details: 1, bad: true},
		{name: "missing actions", details: []any{mercure(map[string]any{"actions": atDel})}, bad: true},
		{name: "null actions", details: []any{mercure(map[string]any{"actions": nil})}, bad: true},
		{name: "empty actions", details: []any{mercure(map[string]any{"actions": []any{}})}, bad: true},
		{name: "actions is a string", details: []any{mercure(map[string]any{"actions": "publish"})}, bad: true},
		{name: "actions is an object", details: []any{mercure(map[string]any{"actions": map[string]any{}})}, bad: true},
		{name: "non-string action", details: []any{mercure(map[string]any{"actions": []any{"publish", 5}})}, bad: true},
		{name: "null action", details: []any{mercure(map[string]any{"actions": []any{nil}})}, bad: true},
		{name: "missing topics", details: []any{mercure(map[string]any{"topics": atDel})}, bad: true},
		{name: "null topics", details: []any{mercure(map[string]any{"topics": nil})}, bad: true},
		{name: "empty topics", details: []any{mercure(map[string]any{"topics": []any{}})}, bad: true},
		{name: "topics is a string", details: []any{mercure(map[string]any{"topics": "*"})}, bad: true},
		{name: "topic is a string", details: []any{mercure(map[string]any{"topics": []any{"*"}})}, bad: true},
		{name: "topic is null", details: []any{mercure(map[string]any{"topics": []any{nil}})}, bad: true},
		{name: "topic is an array", details: []any{mercure(map[string]any{"topics": []any{[]any{}}})}, bad: true},
		{name: "match missing", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"match_type": "exact"}}})}, bad: true},
		{name: "match empty", details: []any{mercure(map[string]any{"topics": []any{atTopic("", "")}})}, bad: true},
		{name: "match not a string", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"match": 5}}})}, bad: true},
		{name: "match null", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"match": nil}}})}, bad: true},
		{name: "match key is case sensitive", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"Match": "*"}}})}, bad: true},
		{name: "unknown match_type", details: []any{mercure(map[string]any{"topics": []any{atTopic("*", "regex")}})}, bad: true},
		{name: "match_type is case sensitive", details: []any{mercure(map[string]any{"topics": []any{atTopic("https://a", "Exact")}})}, bad: true},
		{name: "match_type urlpattern case", details: []any{mercure(map[string]any{"topics": []any{atTopic("https://a", "URLPattern")}})}, bad: true},
		{name: "empty match_type", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"match": "https://a", "match_type": ""}}})}, bad: true},
		{name: "match_type null", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"match": "https://a", "match_type": nil}}})}, bad: true},
		{name: "match_type number", details: []any{mercure(map[string]any{"topics": []any{map[string]any{"match": "https://a", "match_type": 1}}})}, bad: true},
		{name: "one bad topic among good", details: []any{mercure(map[string]any{"topics": []any{atTopic("https://a", ""), atTopic("https://b", "nope")}})}, bad: true},
		{name: "payload string", details: []any{mercure(map[string]any{"payload": "x"})}, bad: true},
		{name: "payload array", details: []any{mercure(map[string]any{"payload": []any{}})}, bad: true},
		{name: "payload null", details: []any{mercure(map[string]any{"payload": nil})}, bad: true},
		{name: "payload number", details: []any{mercure(map[string]any{"payload": 1})}, bad: true},
		{name: "no partial acceptance: good then bad", details: []any{mercure(nil), mercure(map[string]any{"actions": []any{}})}, bad: true},
		{name: "no partial acceptance: bad then good", details: []any{mercure(map[string]any{"payload": 1}), mercure(nil)}, bad: true},
		{name: "bad among foreign", details: []any{foreign, mercure(map[string]any{"topics": []any{}}), foreign}, bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": tt.details}), nil)
			if tt.bad {
				atInvalid(t, v, tok)
				return
			}
			c := atOK(t, v, tok)
			if len(c.Details) != len(tt.want) || (len(tt.want) > 0 && !reflect.DeepEqual(c.Details, tt.want)) {
				t.Fatalf("details\n got %+v\nwant %+v", c.Details, tt.want)
			}
		})
	}
}

func TestAccessDetailKeysAreCaseSensitive(t *testing.T) {
	v, clock, k := atStatic(t, nil)
	// A claim named differently is not authorization_details.
	tok := atMint(t, k, atClaims(clock, atIss, map[string]any{
		"authorization_details": atDel, "Authorization_Details": []any{atDefaultDetail()},
	}), nil)
	if c := atOK(t, v, tok); len(c.Details) != 0 {
		t.Fatalf("details %+v", c.Details)
	}
	// "TYPE" is not "type": the entry is not a Mercure detail.
	d := atDefaultDetail()
	d["TYPE"] = d["type"]
	delete(d, "type")
	tok = atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": []any{d}}), nil)
	if c := atOK(t, v, tok); len(c.Details) != 0 {
		t.Fatalf("details %+v", c.Details)
	}
}

func TestAccessDetailLimits(t *testing.T) {
	detailsTok := func(t *testing.T, v *AccessVerifier, clock *fakeClock, k testKey, details any) string {
		return atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": details}), nil)
	}
	t.Run("MaxDetails counts Mercure details only", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MaxDetails = 2 })
		foreign := map[string]any{"type": "other"}
		atOK(t, v, detailsTok(t, v, clock, k, []any{foreign, atDefaultDetail(), foreign, foreign, atDefaultDetail(), foreign}))
		atInvalid(t, v, detailsTok(t, v, clock, k, atBigDetails(3)))
	})
	t.Run("MaxTopics", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MaxTopics = 3 })
		atOK(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopics(3)...)}))
		atInvalid(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopics(4)...)}))
		// The limit is per detail.
		atOK(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopics(3)...), atDetail([]any{"publish"}, atTopics(3)...)}))
	})
	t.Run("MaxPatternLength", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MaxPatternLength = 20 })
		atOK(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopic(strings.Repeat("a", 20), ""))}))
		atInvalid(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopic(strings.Repeat("a", 21), ""))}))
	})
	t.Run("defaults", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MaxTokenSize = 4 << 20 })
		atOK(t, v, detailsTok(t, v, clock, k, atBigDetails(DefaultMaxDetails)))
		atInvalid(t, v, detailsTok(t, v, clock, k, atBigDetails(DefaultMaxDetails+1)))
		atOK(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopics(DefaultMaxTopics)...)}))
		atInvalid(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopics(DefaultMaxTopics+1)...)}))
		atOK(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopic(strings.Repeat("a", DefaultMaxPatternLength), ""))}))
		atInvalid(t, v, detailsTok(t, v, clock, k, []any{atDetail([]any{"publish"}, atTopic(strings.Repeat("a", DefaultMaxPatternLength+1), ""))}))
	})
}

func TestAccessMatcherTypes(t *testing.T) {
	mint := func(t *testing.T, v *AccessVerifier, clock *fakeClock, k testKey, topics ...any) string {
		return atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": []any{atDetail([]any{"subscribe"}, topics...)}}), nil)
	}
	t.Run("custom set", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MatcherTypes = []string{"exact", "regex"} })
		atOK(t, v, mint(t, v, clock, k, atTopic("a", "regex"), atTopic("b", "")))
		atInvalid(t, v, mint(t, v, clock, k, atTopic("a", "urlpattern")))
	})
	t.Run("exact only", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MatcherTypes = []string{"exact"} })
		atOK(t, v, mint(t, v, clock, k, atTopic("a", "exact")))
		atInvalid(t, v, mint(t, v, clock, k, atTopic("a", "urlpattern")))
	})
	t.Run("without exact, a missing match_type is unsupported", func(t *testing.T) {
		v, clock, k := atStatic(t, func(c *AccessConfig) { c.MatcherTypes = []string{"urlpattern"} })
		atInvalid(t, v, mint(t, v, clock, k, atTopic("a", "")))
		atOK(t, v, mint(t, v, clock, k, atTopic("a", "urlpattern")))
	})
	t.Run("ValidateMatcher", func(t *testing.T) {
		var calls []string
		v, clock, k := atStatic(t, func(c *AccessConfig) {
			c.ValidateMatcher = func(mt, p string) error {
				calls = append(calls, mt+"|"+p)
				if strings.Contains(p, "(") {
					return errors.New("bad pattern")
				}
				return nil
			}
		})
		atOK(t, v, mint(t, v, clock, k, atTopic("https://a", ""), atTopic("https://b/:id", "urlpattern"), atTopic("*", "urlpattern")))
		want := []string{"exact|https://a", "urlpattern|https://b/:id"} // the wildcard is not passed
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls %v, want %v", calls, want)
		}
		atInvalid(t, v, mint(t, v, clock, k, atTopic("https://a", ""), atTopic("https://b/(", "urlpattern")))
		atInvalid(t, v, mint(t, v, clock, k, atTopic("(", "")))
	})
}

// --- configuration ---

func TestAccessConfigErrors(t *testing.T) {
	hs := keyFor(t, "HS256").pem
	rs := keyFor(t, "RS256")
	es := keyFor(t, "ES256")
	ok := Issuer{Issuer: atIss, Key: hs}
	for name, cfg := range map[string]AccessConfig{
		"no issuers":        {Audience: atAud},
		"negative leeway":   {Audience: atAud, Issuers: []Issuer{ok}, Leeway: -1},
		"negative limit":    {Audience: atAud, Issuers: []Issuer{ok}, MaxTopics: -1},
		"negative size":     {Audience: atAud, Issuers: []Issuer{ok}, MaxTokenSize: -1},
		"empty matcher":     {Audience: atAud, Issuers: []Issuer{ok}, MatcherTypes: []string{""}},
		"empty issuer id":   {Audience: atAud, Issuers: []Issuer{{Key: hs}}},
		"duplicate issuer":  {Audience: atAud, Issuers: []Issuer{ok, ok}},
		"no key source":     {Audience: atAud, Issuers: []Issuer{{Issuer: atIss}}},
		"key and jwks":      {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: hs, JWKSURL: "https://x/jwks"}}},
		"key and discover":  {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: hs, Discover: true}}},
		"jwks and discover": {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, JWKSURL: "https://x/jwks", Discover: true}}},
		"alg none":          {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: hs, Algorithms: []string{"none"}}}},
		"alg unknown":       {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: hs, Algorithms: []string{"HS999"}}}},
		"alg mixed":         {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: hs, Algorithms: []string{"HS256", "ES256"}}}},
		"alg vs key kind":   {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: rs.pem, Algorithms: []string{"ES256"}}}},
		"alg vs curve":      {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: es.pem, Algorithms: []string{"ES384"}}}},
		"bad PEM":           {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"}}},
		"private key":       {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, Key: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}}},
		"http jwks":         {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, JWKSURL: "http://x/jwks"}}},
		"ftp jwks":          {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, JWKSURL: "ftp://x/jwks"}}},
		"relative jwks":     {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, JWKSURL: "/jwks"}}},
		"jwks fragment":     {Audience: atAud, Issuers: []Issuer{{Issuer: atIss, JWKSURL: "https://x/jwks#f"}}},
		"http discover":     {Audience: atAud, Issuers: []Issuer{{Issuer: "http://issuer.example", Discover: true}}},
		"discover non-url":  {Audience: atAud, Issuers: []Issuer{{Issuer: "urn:issuer", Discover: true}}},
		"discover query":    {Audience: atAud, Issuers: []Issuer{{Issuer: "https://issuer.example?x=1", Discover: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := NewAccessVerifier(cfg)
			if err == nil {
				v.Close()
				t.Fatal("expected an error")
			}
		})
	}
}

func TestAccessCloseAndReady(t *testing.T) {
	k := atEC(t)
	srv := newJWKSServer(t, atJWKS(t, jwkMap(t, k.pub, "k", "", "")))
	cfg := AccessConfig{Audience: atAud, AllowInsecureHTTP: true, Issuers: []Issuer{
		{Issuer: atIss, JWKSURL: srv.URL}, {Issuer: "https://static", Key: keyFor(t, "HS256").pem},
	}}
	v, err := NewAccessVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Ready() {
		t.Fatal("not ready")
	}
	v.Close()
	v.Close()
	// The verifier uses the real clock here.
	tok := atMint(t, k, atClaims(&fakeClock{t: time.Now()}, atIss, nil), map[string]any{"kid": "k"})
	if _, err := v.Verify(ctx(), tok); err != nil {
		t.Fatalf("Verify after Close: %v", err)
	}
}

// A PEM public key is never an HMAC secret, even with an HMAC algorithm named: anyone with the key could sign.
func TestAccessExplicitHMACRefusesPEM(t *testing.T) {
	es := keyFor(t, "ES256")
	_, err := NewAccessVerifier(AccessConfig{Issuers: []Issuer{{Issuer: atIss, Key: es.pem, Algorithms: []string{"HS256"}}}})
	if err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("a PEM key taken as an HMAC secret: %v", err)
	}
}

// An API that is not a hub skips the Mercure details (a malformed one does not refuse the token) and reads its own
// from RawDetails, with the scope.
func TestAccessSkipMercureDetails(t *testing.T) {
	v, clock, k := atStatic(t, func(c *AccessConfig) { c.SkipMercureDetails = true })
	raw := []any{map[string]any{"type": DetailType, "actions": []string{"publish"}}, // no topics: a hub would refuse it
		map[string]any{"type": "urn:example:admin", "actions": []string{"read"}}}
	c := atOK(t, v, atMint(t, k, atClaims(clock, atIss, map[string]any{"authorization_details": raw, "scope": "openid admin"}), nil))
	if c.Details != nil || c.Scope != "openid admin" || !strings.Contains(string(c.RawDetails), "urn:example:admin") {
		t.Fatalf("details %v, scope %q, raw %s", c.Details, c.Scope, c.RawDetails)
	}
}
