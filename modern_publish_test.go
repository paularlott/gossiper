package gossiper

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
)

const (
	bookTopic = "https://example.com/books/1"
	userTopic = "https://example.com/users/42/books/1"
)

// pubCase is one publish attempt: a token's details and the form sent with it.
type pubCase struct {
	name    string
	details []any
	form    url.Values
	code    int
	errCode string // the WWW-Authenticate error of a refusal
}

func bookForm() url.Values { return form("topic", bookTopic, "data", "x") }

// TestPublishGrants: a token publishes on a topic when a detail with the publish action has a matcher for it.
func TestPublishGrants(t *testing.T) {
	both := url.Values{"topic": {bookTopic, userTopic}, "data": {"x"}}
	rel := form("topic", "/books/1", "data", "x")
	tests := []pubCase{
		{"exact with match_type", []any{mDetail(pubOnly, mExact(bookTopic))}, bookForm(), 200, ""},
		{"exact without match_type", []any{mDetail(pubOnly, mBare(bookTopic))}, bookForm(), 200, ""},
		{"exact for another topic", []any{mDetail(pubOnly, mExact("https://example.com/books/2"))}, bookForm(), 403, "insufficient_scope"},
		{"exact is not a pattern", []any{mDetail(pubOnly, mExact("https://example.com/books/:id"))}, bookForm(), 403, "insufficient_scope"},
		{"exact is not a prefix", []any{mDetail(pubOnly, mExact("https://example.com/books/"))}, bookForm(), 403, "insufficient_scope"},
		{"exact is byte for byte", []any{mDetail(pubOnly, mExact("https://EXAMPLE.com/books/1"))}, bookForm(), 403, "insufficient_scope"},
		{"exact is case-sensitive", []any{mDetail(pubOnly, mExact("https://example.com/Books/1"))}, bookForm(), 403, "insufficient_scope"},
		{"exact is not resolved", []any{mDetail(pubOnly, mExact("/books/1"))}, bookForm(), 403, "insufficient_scope"},
		{"urlpattern", []any{mDetail(pubOnly, mPattern("https://example.com/books/:id"))}, bookForm(), 200, ""},
		{"urlpattern, other segment", []any{mDetail(pubOnly, mPattern("https://example.com/authors/:id"))}, bookForm(), 403, "insufficient_scope"},
		{"urlpattern needs a whole segment", []any{mDetail(pubOnly, mPattern("https://example.com/books"))}, bookForm(), 403, "insufficient_scope"},
		{"urlpattern wildcard", []any{mDetail(pubOnly, mPattern("https://example.com/*"))}, bookForm(), 200, ""},
		{"urlpattern, other host", []any{mDetail(pubOnly, mPattern("https://other.example/*"))}, bookForm(), 403, "insufficient_scope"},
		{"urlpattern, other scheme", []any{mDetail(pubOnly, mPattern("http://example.com/*"))}, bookForm(), 403, "insufficient_scope"},
		{"urlpattern path is case-sensitive", []any{mDetail(pubOnly, mPattern("https://example.com/Books/:id"))}, bookForm(), 403, "insufficient_scope"},
		{"urlpattern host in the pattern is case-insensitive", []any{mDetail(pubOnly, mPattern("https://EXAMPLE.com/books/:id"))}, bookForm(), 200, ""},
		{"urlpattern host in the topic is case-insensitive", []any{mDetail(pubOnly, mPattern("https://example.com/books/:id"))},
			form("topic", "https://EXAMPLE.COM/books/1"), 200, ""},
		{"urlpattern regexp group", []any{mDetail(pubOnly, mPattern(`https://example.com/books/:id(\d+)`))}, bookForm(), 200, ""},
		{"urlpattern regexp group mismatch", []any{mDetail(pubOnly, mPattern(`https://example.com/books/:id([a-z]+)`))}, bookForm(), 403, "insufficient_scope"},
		{"relative urlpattern, relative topic", []any{mDetail(pubOnly, mPattern("/books/:id"))}, rel, 200, ""},
		{"relative urlpattern, other path", []any{mDetail(pubOnly, mPattern("/authors/:id"))}, rel, 403, "insufficient_scope"},
		{"relative urlpattern resolves against the hub", []any{mDetail(pubOnly, mPattern("/books/:id"))}, bookForm(), 403, "insufficient_scope"},
		{"relative topic, absolute pattern", []any{mDetail(pubOnly, mPattern("https://example.com/*"))}, rel, 403, "insufficient_scope"},
		{"wildcard without match_type", []any{mDetail(pubOnly, mBare("*"))}, bookForm(), 200, ""},
		{"wildcard exact", []any{mDetail(pubOnly, mExact("*"))}, bookForm(), 200, ""},
		{"wildcard urlpattern", []any{mDetail(pubOnly, mPattern("*"))}, bookForm(), 200, ""},
		{"wildcard grants relative topics", []any{mDetail(pubOnly, mBare("*"))}, rel, 200, ""},
		{"subscribe action only", []any{mDetail(subOnly, mBare("*"))}, bookForm(), 403, "insufficient_scope"},
		{"subscribe grant does not publish", []any{mDetail(subOnly, mExact(bookTopic)), mDetail(pubOnly, mExact("other"))}, bookForm(), 403, "insufficient_scope"},
		{"publish and subscribe", []any{mDetail(pubAndSb, mExact(bookTopic))}, bookForm(), 200, ""},
		{"unknown action beside publish", []any{mDetail([]string{"frobnicate", "publish"}, mBare("*"))}, bookForm(), 200, ""},
		{"unknown action alone", []any{mDetail([]string{"frobnicate"}, mBare("*"))}, bookForm(), 403, "insufficient_scope"},
		{"actions are case-sensitive", []any{mDetail([]string{"Publish", "PUBLISH"}, mBare("*"))}, bookForm(), 403, "insufficient_scope"},
		{"detail of another type", []any{map[string]any{"type": "https://example.com/other", "actions": pubOnly, "topics": []any{mBare("*")}}}, bookForm(), 403, "insufficient_scope"},
		{"detail of another type beside a Mercure one", []any{
			map[string]any{"type": "https://example.com/other", "actions": pubOnly, "topics": []any{mBare("*")}},
			mDetail(pubOnly, mExact(bookTopic)),
		}, bookForm(), 200, ""},
		{"empty authorization_details", []any{}, bookForm(), 403, "insufficient_scope"},
		{"second detail grants", []any{mDetail(pubOnly, mExact("nope")), mDetail(pubOnly, mExact(bookTopic))}, bookForm(), 200, ""},
		{"one of several topics in a detail", []any{mDetail(pubOnly, mExact("nope"), mExact(bookTopic), mExact("nope2"))}, bookForm(), 200, ""},
		// Every topic, canonical and alternate, must be granted.
		{"both topics, one detail", []any{mDetail(pubOnly, mExact(bookTopic), mExact(userTopic))}, both, 200, ""},
		{"both topics, two details", []any{mDetail(pubOnly, mExact(bookTopic)), mDetail(pubOnly, mExact(userTopic))}, both, 200, ""},
		{"both topics, one pattern", []any{mDetail(pubOnly, mPattern("https://example.com/*"))}, both, 200, ""},
		{"canonical granted, alternate not", []any{mDetail(pubOnly, mExact(bookTopic))}, both, 403, "insufficient_scope"},
		{"alternate granted, canonical not", []any{mDetail(pubOnly, mExact(userTopic))}, both, 403, "insufficient_scope"},
		{"alternate granted only for subscribe", []any{mDetail(pubOnly, mExact(bookTopic)), mDetail(subOnly, mExact(userTopic))}, both, 403, "insufficient_scope"},
		{"three topics, last not granted", []any{mDetail(pubOnly, mPattern("https://example.com/books/*"), mExact(userTopic))},
			url.Values{"topic": {bookTopic, userTopic, "https://other.example/x"}}, 403, "insufficient_scope"},
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := e.post(t, e.access(t, tc.details...), tc.form)
				if r.code != tc.code {
					t.Fatalf("%d %q, want %d", r.code, r.body, tc.code)
				}
				if tc.code == 200 {
					if r.body == "" || r.header.Get("Content-Type") != "text/plain; charset=utf-8" {
						t.Fatalf("response %q (%s)", r.body, r.header.Get("Content-Type"))
					}
					return
				}
				wantChallenge(t, r.header, tc.errCode, e.metadataURL())
			})
		}
	})
}

// TestPublishWithoutGrantsDispatchesNothing: a refused publish reaches no subscriber, even for the topics the
// token does grant.
func TestPublishWithoutGrantsDispatchesNothing(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		c := e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match_urlpattern", "*")
		tok := e.access(t, mDetail(pubOnly, mExact(bookTopic)))
		if r := e.post(t, tok, url.Values{"topic": {bookTopic, userTopic}, "data": {"refused"}}); r.code != 403 {
			t.Fatalf("%d", r.code)
		}
		if r := e.post(t, tok, url.Values{"topic": {bookTopic}, "data": {"sentinel"}}); r.code != 200 {
			t.Fatalf("%d", r.code)
		}
		if got := c.drain("sentinel"); len(got) != 0 {
			t.Fatalf("subscriber received %v", got)
		}
		if e.hub.Stats().PublishRejected == 0 {
			t.Fatal("the refusal was not counted")
		}
	})
}

// TestPublishTokenValidation: a token that does not validate is refused with invalid_token, a malformed one with
// invalid_request.
func TestPublishTokenValidation(t *testing.T) {
	good := []any{mDetail(pubOnly, mBare("*"))}
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		aud := e.hubURL()
		mod := func(f func(c jwt.MapClaims)) string {
			c := accessClaims(aud, time.Hour, good...)
			f(c)
			return signAccess(t, c)
		}
		noneSigned := func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodNone, accessClaims(aud, time.Hour, good...))
			tok.Header["typ"] = "at+jwt"
			s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		tests := []struct {
			name    string
			tok     string
			code    int
			errCode string
		}{
			{"valid", signAccess(t, accessClaims(aud, time.Hour, good...)), 200, ""},
			{"aud as a list holding the resource", mod(func(c jwt.MapClaims) { c["aud"] = []string{"https://x.example", aud} }), 200, ""},
			{"typ application/at+jwt", signAccessTyp(t, testSecret, "application/at+jwt", accessClaims(aud, time.Hour, good...)), 200, ""},
			{"typ AT+JWT", signAccessTyp(t, testSecret, "AT+JWT", accessClaims(aud, time.Hour, good...)), 200, ""},
			{"typ Application/At+Jwt", signAccessTyp(t, testSecret, "Application/At+Jwt", accessClaims(aud, time.Hour, good...)), 200, ""},
			{"wrong audience", signAccess(t, accessClaims("https://other.example/.well-known/mercure", time.Hour, good...)), 401, "invalid_token"},
			{"audience without the path", signAccess(t, accessClaims(e.srv.URL, time.Hour, good...)), 401, "invalid_token"},
			{"audience with a trailing slash", signAccess(t, accessClaims(aud+"/", time.Hour, good...)), 401, "invalid_token"},
			{"aud as a list without the resource", mod(func(c jwt.MapClaims) { c["aud"] = []string{"a", "b"} }), 401, "invalid_token"},
			{"empty aud list", mod(func(c jwt.MapClaims) { c["aud"] = []string{} }), 401, "invalid_token"},
			{"no aud", mod(func(c jwt.MapClaims) { delete(c, "aud") }), 401, "invalid_token"},
			{"aud of the wrong type", mod(func(c jwt.MapClaims) { c["aud"] = 7 }), 401, "invalid_token"},
			{"wrong issuer", mod(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }), 401, "invalid_token"},
			{"issuer with a trailing slash", mod(func(c jwt.MapClaims) { c["iss"] = testIssuer + "/" }), 401, "invalid_token"},
			{"no issuer", mod(func(c jwt.MapClaims) { delete(c, "iss") }), 401, "invalid_token"},
			{"empty issuer", mod(func(c jwt.MapClaims) { c["iss"] = "" }), 401, "invalid_token"},
			{"expired", mod(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }), 401, "invalid_token"},
			{"no exp", mod(func(c jwt.MapClaims) { delete(c, "exp") }), 401, "invalid_token"},
			{"exp of the wrong type", mod(func(c jwt.MapClaims) { c["exp"] = "tomorrow" }), 401, "invalid_token"},
			{"not yet valid", mod(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }), 401, "invalid_token"},
			{"nbf in the past", mod(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(-time.Hour).Unix() }), 200, ""},
			{"bad signature", signAccessTyp(t, "another-secret-another-secret-12345", "at+jwt", accessClaims(aud, time.Hour, good...)), 401, "invalid_token"},
			{"alg none", noneSigned(), 401, "invalid_token"},
			{"typ missing, with authorization_details", signAccessTyp(t, testSecret, "", accessClaims(aud, time.Hour, good...)), 401, "invalid_token"},
			{"typ JWT, with authorization_details", signAccessTyp(t, testSecret, "JWT", accessClaims(aud, time.Hour, good...)), 401, "invalid_token"},
			{"typ at+jwt in a longer name", signAccessTyp(t, testSecret, "x-at+jwt", accessClaims(aud, time.Hour, good...)), 401, "invalid_token"},
			// Without typ and without authorization_details the token is not recognised as a Mercure 1.0 access
			// token: it is a draft-07 token, which has no mercure claim.
			{"typ missing, no authorization_details", func() string {
				c := accessClaims(aud, time.Hour)
				delete(c, "authorization_details")
				return signAccessTyp(t, testSecret, "", c)
			}(), 401, "invalid_token"},
			{"authorization_details not an array", mod(func(c jwt.MapClaims) { c["authorization_details"] = map[string]any{} }), 401, "invalid_token"},
			{"detail without actions", mod(func(c jwt.MapClaims) {
				c["authorization_details"] = []any{map[string]any{"type": auth.DetailType, "topics": []any{mBare("*")}}}
			}), 401, "invalid_token"},
			{"detail without topics", mod(func(c jwt.MapClaims) {
				c["authorization_details"] = []any{map[string]any{"type": auth.DetailType, "actions": pubOnly}}
			}), 401, "invalid_token"},
			{"topic matcher of an unknown type", mod(func(c jwt.MapClaims) {
				c["authorization_details"] = []any{mDetail(pubOnly, map[string]any{"match": "*", "match_type": "regex"})}
			}), 401, "invalid_token"},
			{"invalid url pattern in a grant", mod(func(c jwt.MapClaims) {
				c["authorization_details"] = []any{mDetail(pubOnly, mPattern("https://example.com/("))}
			}), 401, "invalid_token"},
			{"one bad detail spoils the token", mod(func(c jwt.MapClaims) {
				c["authorization_details"] = []any{mDetail(pubOnly, mBare("*")), mDetail(pubOnly, map[string]any{"match": "x", "match_type": "nope"})}
			}), 401, "invalid_token"},
			{"non-string action", mod(func(c jwt.MapClaims) {
				c["authorization_details"] = []any{mDetail([]string{"publish"}, mBare("*")), map[string]any{
					"type": auth.DetailType, "actions": []any{"publish", 7}, "topics": []any{mBare("*")}}}
			}), 401, "invalid_token"},
			// Malformed: the presentation or the token is not a JWS.
			{"payload is not base64", seg(`{"alg":"HS256","typ":"at+jwt"}`) + ".!!!." + seg("sig"), 400, "invalid_request"},
			{"payload is not JSON", seg(`{"alg":"HS256","typ":"at+jwt"}`) + "." + seg("not json") + "." + seg("sig"), 400, "invalid_request"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := e.post(t, tc.tok, form("topic", "t"))
				if r.code != tc.code {
					t.Fatalf("%d %q, want %d", r.code, r.body, tc.code)
				}
				if tc.code != 200 {
					wantChallenge(t, r.header, tc.errCode, e.metadataURL())
				}
			})
		}
		// Limits on the details are limits of the token: it is refused as a whole.
		manyDetails := make([]any, auth.DefaultMaxDetails+1)
		for i := range manyDetails {
			manyDetails[i] = mDetail(pubOnly, mExact("t"))
		}
		manyTopics := make([]map[string]any, auth.DefaultMaxTopics+1)
		for i := range manyTopics {
			manyTopics[i] = mExact("t")
		}
		atLimit := make([]any, auth.DefaultMaxDetails)
		for i := range atLimit {
			atLimit[i] = mDetail(pubOnly, mExact("t"))
		}
		for _, tc := range []struct {
			name string
			tok  string
			code int
		}{
			{"details at the limit", signAccess(t, accessClaims(aud, time.Hour, atLimit...)), 200},
			{"too many details", signAccess(t, accessClaims(aud, time.Hour, manyDetails...)), 401},
			{"too many topics in a detail", signAccess(t, accessClaims(aud, time.Hour, mDetail(pubOnly, manyTopics...))), 401},
			{"matcher over the length limit", signAccess(t, accessClaims(aud, time.Hour, mDetail(pubOnly, mExact(strings.Repeat("a", auth.DefaultMaxPatternLength+1))))), 401},
			{"token over the size limit", mod(func(c jwt.MapClaims) { c["jti"] = strings.Repeat("j", auth.MaxTokenSize) }), 400},
			// RFC 9068 asks issuers for these claims; the hub enforces iss, exp and aud and uses the rest when it relies on them.
			{"no sub, client_id, jti or iat", mod(func(c jwt.MapClaims) {
				delete(c, "sub")
				delete(c, "client_id")
				delete(c, "jti")
				delete(c, "iat")
			}), 200},
			{"sub of the wrong type", mod(func(c jwt.MapClaims) { c["sub"] = 7 }), 401},
			{"iat of the wrong type", mod(func(c jwt.MapClaims) { c["iat"] = "now" }), 401},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := e.post(t, tc.tok, form("topic", "t"))
				if r.code != tc.code {
					t.Fatalf("%d %q, want %d", r.code, r.body, tc.code)
				}
			})
		}
		for _, name := range []string{"not-a-jwt", "a.b", "a.b.c.d", "....", seg("x")} {
			t.Run("garbage "+name, func(t *testing.T) {
				r := e.post(t, name, form("topic", "t"))
				if r.code != 400 && r.code != 401 {
					t.Fatalf("%d", r.code)
				}
			})
		}
	})
}

// TestPublishMalformedToken: a token that is not a JWT is a malformed presentation: 400 invalid_request, on any
// hub that takes Mercure 1.0 tokens.
func TestPublishMalformedToken(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		for _, tok := range []string{"not-a-jwt", "a.b.c", "x.y"} {
			t.Run(tok, func(t *testing.T) {
				r := e.post(t, tok, form("topic", "t"))
				if r.code != 400 {
					t.Fatalf("a token that is not a JWT (%q): %d, want 400 invalid_request", tok, r.code)
				}
				wantChallenge(t, r.header, "invalid_request", e.metadataURL())
			})
		}
	})
}

// TestPublishAuthorizationHeader: the presentation of a bearer token.
func TestPublishAuthorizationHeader(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		tok := e.access(t, mDetail(pubOnly, mBare("*")))
		for _, tc := range []struct {
			name string
			hdr  http.Header
			code int
			err  string
		}{
			{"bearer", http.Header{"Authorization": {"Bearer " + tok}}, 200, ""},
			{"lowercase scheme", http.Header{"Authorization": {"bearer " + tok}}, 200, ""},
			{"uppercase scheme", http.Header{"Authorization": {"BEARER " + tok}}, 200, ""},
			{"no token", nil, 401, ""},
			{"basic", http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}}, 400, "invalid_request"},
			{"bearer without token", http.Header{"Authorization": {"Bearer"}}, 400, "invalid_request"},
			{"bearer with blank token", http.Header{"Authorization": {"Bearer    "}}, 400, "invalid_request"},
			{"token only", http.Header{"Authorization": {tok}}, 400, "invalid_request"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := e.do(t, http.MethodPost, e.hubURL(), tc.hdr, form("topic", "t").Encode())
				if r.code != tc.code {
					t.Fatalf("%d %s, want %d", r.code, r.body, tc.code)
				}
				if tc.code != 200 {
					wantChallenge(t, r.header, tc.err, e.metadataURL())
				}
			})
		}
		t.Run("access_token query parameter is not accepted", func(t *testing.T) {
			r := e.do(t, http.MethodPost, e.hubURL()+"?access_token="+url.QueryEscape(tok), nil, form("topic", "t").Encode())
			if r.code != 401 {
				t.Fatalf("%d", r.code)
			}
		})
	})
}

// TestPublishPerRequestAudience: without a configured resource identifier, a token's audience is the hub URL as the
// client contacted it.
func TestPublishPerRequestAudience(t *testing.T) {
	grant := mDetail(pubOnly, mBare("*"))
	f := form("topic", "t")
	post := func(t *testing.T, h *Hub, tok string, hdr http.Header) int {
		t.Helper()
		if hdr == nil {
			hdr = http.Header{}
		}
		hdr.Set("Authorization", "Bearer "+tok)
		return hubDo(t, h, http.MethodPost, hubPath, hdr, f.Encode()).Code
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		t.Run("host header", func(t *testing.T) {
			h := newModernHub(t, mcfg(p))
			if c := post(t, h, accessFor(t, hubAud, grant), nil); c != 200 {
				t.Fatalf("default host: %d", c)
			}
			alt := http.Header{"Host": {"alt.test:8080"}}
			if c := post(t, h, accessFor(t, "http://alt.test:8080"+hubPath, grant), alt); c != 200 {
				t.Fatalf("alternate host: %d", c)
			}
			if c := post(t, h, accessFor(t, hubAud, grant), http.Header{"Host": {"alt.test:8080"}}); c != 401 {
				t.Fatalf("a token for another host: %d", c)
			}
			if c := post(t, h, accessFor(t, "http://alt.test:8080"+hubPath, grant), nil); c != 401 {
				t.Fatalf("a token for another host, request for example.com: %d", c)
			}
			if c := post(t, h, accessFor(t, "http://EXAMPLE.com"+hubPath, grant), nil); c != 401 {
				t.Fatalf("audience compares byte for byte, got %d", c)
			}
		})
		t.Run("forwarded protocol is ignored by default", func(t *testing.T) {
			h := newModernHub(t, mcfg(p))
			if c := post(t, h, accessFor(t, hubAud, grant), http.Header{"X-Forwarded-Proto": {"https"}}); c != 200 {
				t.Fatalf("the http audience with X-Forwarded-Proto ignored: %d", c)
			}
			if c := post(t, h, accessFor(t, "https://example.com"+hubPath, grant), http.Header{"X-Forwarded-Proto": {"https"}}); c != 401 {
				t.Fatalf("the https audience from an untrusted X-Forwarded-Proto: %d", c)
			}
		})
		t.Run("forwarded protocol, trusted", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.TrustForwardedProto = true
			h := newModernHub(t, cfg)
			https := http.Header{"X-Forwarded-Proto": {"https"}}
			if c := post(t, h, accessFor(t, "https://example.com"+hubPath, grant), https); c != 200 {
				t.Fatalf("https audience behind a proxy: %d", c)
			}
			if c := post(t, h, accessFor(t, hubAud, grant), http.Header{"X-Forwarded-Proto": {"https"}}); c != 401 {
				t.Fatalf("http audience behind a proxy that terminates TLS: %d", c)
			}
			if c := post(t, h, accessFor(t, hubAud, grant), http.Header{"X-Forwarded-Proto": {"http"}}); c != 200 {
				t.Fatalf("http forwarded: %d", c)
			}
			for _, v := range []string{"gopher", "HTTPS", "", "https, http", "ftp"} {
				if c := post(t, h, accessFor(t, hubAud, grant), http.Header{"X-Forwarded-Proto": {v}}); c != 200 {
					t.Fatalf("a forwarded protocol of %q is ignored: %d", v, c)
				}
			}
			if c := post(t, h, accessFor(t, hubAud, grant), nil); c != 200 {
				t.Fatalf("no header: %d", c)
			}
		})
		t.Run("configured resource identifier", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.ResourceIdentifier = "https://hub.example.com/.well-known/mercure"
			h := newModernHub(t, cfg)
			if c := post(t, h, accessFor(t, cfg.ResourceIdentifier, grant), nil); c != 200 {
				t.Fatalf("configured identifier: %d", c)
			}
			if c := post(t, h, accessFor(t, cfg.ResourceIdentifier, grant), http.Header{"Host": {"elsewhere.test"}}); c != 200 {
				t.Fatalf("configured identifier, other host: %d", c)
			}
			if c := post(t, h, accessFor(t, hubAud, grant), nil); c != 401 {
				t.Fatalf("the request's own URL must not match once an identifier is configured: %d", c)
			}
		})
		t.Run("absolute hub URL", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.HubURL = "https://hub.example.com/.well-known/mercure"
			h := newModernHub(t, cfg)
			if c := post(t, h, accessFor(t, cfg.HubURL, grant), nil); c != 200 {
				t.Fatalf("hub URL: %d", c)
			}
			if c := post(t, h, accessFor(t, hubAud, grant), nil); c != 401 {
				t.Fatalf("request URL with an absolute hub URL: %d", c)
			}
		})
		t.Run("resource identifier beats the hub URL", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.HubURL = "https://hub.example.com/.well-known/mercure"
			cfg.ResourceIdentifier = "urn:example:hub"
			h := newModernHub(t, cfg)
			if c := post(t, h, accessFor(t, "urn:example:hub", grant), nil); c != 200 {
				t.Fatalf("identifier: %d", c)
			}
			if c := post(t, h, accessFor(t, cfg.HubURL, grant), nil); c != 401 {
				t.Fatalf("hub URL: %d", c)
			}
		})
		t.Run("resource_metadata names the hub the client contacted", func(t *testing.T) {
			h := newModernHub(t, mcfg(p))
			w := hubDo(t, h, http.MethodPost, hubPath, http.Header{"Host": {"alt.test:8080"}}, f.Encode())
			wantChallenge(t, w.Header(), "", "http://alt.test:8080"+metadataPath)
			w = hubDo(t, h, http.MethodPost, hubPath, http.Header{"X-Forwarded-Proto": {"https"}}, f.Encode())
			wantChallenge(t, w.Header(), "", "http://example.com"+metadataPath) // untrusted: ignored
			trusted := mcfg(p)
			trusted.TrustForwardedProto = true
			th := newModernHub(t, trusted)
			w = hubDo(t, th, http.MethodPost, hubPath, http.Header{"X-Forwarded-Proto": {"https"}}, f.Encode())
			wantChallenge(t, w.Header(), "", "https://example.com"+metadataPath)
			w = hubDo(t, th, http.MethodPost, hubPath, http.Header{"X-Forwarded-Proto": {"gopher"}}, f.Encode())
			wantChallenge(t, w.Header(), "", "http://example.com"+metadataPath)

			cfg := mcfg(p)
			cfg.HubURL = "https://hub.example.com/.well-known/mercure"
			h = newModernHub(t, cfg)
			w = hubDo(t, h, http.MethodPost, hubPath, http.Header{"Host": {"alt.test"}}, f.Encode())
			wantChallenge(t, w.Header(), "", "https://hub.example.com"+metadataPath)
		})
	})
}

// TestChallengeResourceMetadata: the 401 and 403 challenges of a hub that speaks Mercure 1.0 point at its protected
// resource metadata; a draft-07 hub's do not.
func TestChallengeResourceMetadata(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		md := e.metadataURL()
		r := e.post(t, "", form("topic", "t"))
		if r.code != 401 {
			t.Fatal(r.code)
		}
		wantChallenge(t, r.header, "", md)
		if got := r.header.Get("WWW-Authenticate"); got != `Bearer resource_metadata="`+md+`"` {
			t.Fatalf("challenge %q", got)
		}
		r = e.post(t, e.access(t, mDetail(subOnly, mBare("*"))), form("topic", "t"))
		wantChallenge(t, r.header, "insufficient_scope", md)
		r = e.post(t, "x.y.z", form("topic", "t"))
		if r.code == 401 {
			wantChallenge(t, r.header, "invalid_token", md)
		}
		// A subscriber refused for lack of a token.
		r = e.get(t, e.hubURL()+"?match=t", nil)
		if r.code != 401 {
			t.Fatalf("anonymous subscribe: %d", r.code)
		}
		wantChallenge(t, r.header, "", md)
	})
	t.Run("legacy", func(t *testing.T) {
		e := newEnv(t, Config{Protocol: ProtocolLegacy})
		r := e.post(t, "", form("topic", "t"))
		wantChallenge(t, r.header, "", "")
		r = e.post(t, tokenFor(t, nil, all), form("topic", "t"))
		wantChallenge(t, r.header, "insufficient_scope", "")
		r = e.post(t, signJWT(t, "another-secret-another-secret-12345", mercureClaims(all, nil)), form("topic", "t"))
		wantChallenge(t, r.header, "invalid_token", "")
		r = e.post(t, "garbage", form("topic", "t"))
		wantChallenge(t, r.header, "invalid_request", "")
	})
	t.Run("both, draft-07 token", func(t *testing.T) {
		e := newEnv(t, mcfg(ProtocolBoth))
		r := e.post(t, tokenFor(t, nil, all), form("topic", "t"))
		wantChallenge(t, r.header, "insufficient_scope", e.metadataURL())
	})
}

// TestModernPublishValidation: §5 of the draft, for every protocol setting; the checks do not depend on the token.
func TestModernPublishValidation(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	topics := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "t" + long(i%7) + string(rune('A'+i%26)) + strings.Repeat("x", i/26)
		}
		return out
	}
	tests := []struct {
		name string
		form url.Values
		code int
		msg  string // part of the response body of a refusal
	}{
		{"ok", form("topic", "https://example.com/a"), 200, ""},
		{"missing topic", form("data", "x"), 400, `Missing "topic" parameter`},
		{"empty topic", form("topic", ""), 400, `Invalid "topic"`},
		{"wildcard topic", form("topic", "*"), 400, `Invalid "topic"`},
		{"wildcard alternate topic", form("topic", "a", "topic", "*"), 400, `Invalid "topic"`},
		{"topic holding a wildcard", form("topic", "a*"), 200, ""},
		{"double wildcard topic", form("topic", "**"), 200, ""},
		{"control in topic", form("topic", "a\x01b"), 400, ""},
		{"NUL in topic", form("topic", "a\x00b"), 400, ""},
		{"newline in topic", form("topic", "a\nb"), 400, ""},
		{"DEL in topic", form("topic", "a\x7fb"), 400, ""},
		{"C1 in topic", form("topic", "a\u0085b"), 400, ""},
		{"C1 in alternate topic", form("topic", "a", "topic", "b\u009fb"), 400, ""},
		{"Cf in topic", form("topic", "a\u200bb"), 400, ""},
		{"bidi override in topic", form("topic", "a\u202eb"), 400, ""},
		{"invalid UTF-8 in topic", form("topic", "a\xffb"), 400, ""},
		{"non-ASCII topic", form("topic", "https://example.com/é/日本"), 200, ""},
		{"control in id", form("topic", "t", "id", "a\x01b"), 400, `Invalid "id"`},
		{"C1 in id", form("topic", "t", "id", "a\u0085b"), 400, `Invalid "id"`},
		{"Cf in id", form("topic", "t", "id", "a\u200bb"), 400, `Invalid "id"`},
		{"id starting with #", form("topic", "t", "id", "#1"), 400, `Invalid "id"`},
		{"id with a # inside", form("topic", "t", "id", "a#1"), 200, ""},
		{"id earliest", form("topic", "t", "id", "earliest"), 400, `Invalid "id"`},
		{"id Earliest", form("topic", "t", "id", "Earliest"), 200, ""},
		{"id is an IRI", form("topic", "t", "id", "urn:uuid:60a76c80-d399-11d9-b93c-0003939e0af6"), 200, ""},
		{"control in type", form("topic", "t", "type", "a\x01b"), 400, `Invalid "type"`},
		{"C1 in type", form("topic", "t", "type", "a\u0085b"), 400, `Invalid "type"`},
		{"Cf in type", form("topic", "t", "type", "a\u2060b"), 400, `Invalid "type"`},
		{"newline in type", form("topic", "t", "type", "a\nretry: 1"), 400, `Invalid "type"`},
		{"type mercure", form("topic", "t", "type", "mercure"), 400, `Invalid "type"`},
		{"type holding mercure", form("topic", "t", "type", "mercure2"), 200, ""},
		{"ordinary type", form("topic", "t", "type", "book-updated"), 200, ""},
		{"retry digits", form("topic", "t", "retry", "3000"), 200, ""},
		{"retry zero", form("topic", "t", "retry", "0"), 200, ""},
		{"retry empty", form("topic", "t", "retry", ""), 400, `Invalid "retry"`},
		{"retry negative", form("topic", "t", "retry", "-1"), 400, `Invalid "retry"`},
		{"retry plus", form("topic", "t", "retry", "+1"), 400, `Invalid "retry"`},
		{"retry spaces", form("topic", "t", "retry", " 1"), 400, `Invalid "retry"`},
		{"retry letters", form("topic", "t", "retry", "12a"), 400, `Invalid "retry"`},
		{"retry decimal", form("topic", "t", "retry", "1.5"), 400, `Invalid "retry"`},
		{"retry hex", form("topic", "t", "retry", "0x10"), 400, `Invalid "retry"`},
		{"retry fullwidth digits", form("topic", "t", "retry", "\uff11\uff12"), 400, `Invalid "retry"`},
		{"retry arabic-indic digits", form("topic", "t", "retry", "\u0661\u0662"), 400, `Invalid "retry"`},
		{"retry too long", form("topic", "t", "retry", strings.Repeat("9", 25)), 400, `Invalid "retry"`},
		{"retry overflows", form("topic", "t", "retry", "99999999999999999999"), 400, `Invalid "retry"`},
		{"invalid UTF-8 data", form("topic", "t", "data", "\xff\xfe"), 400, `Invalid "data"`},
		{"unknown fields are ignored", form("topic", "t", "frob", "x", "match", "y", "data", "d"), 200, ""},
		{"topic at the limit", form("topic", long(MaxTopicLength)), 200, ""},
		{"topic over the limit", form("topic", long(MaxTopicLength+1)), 413, ""},
		{"alternate topic over the limit", form("topic", "a", "topic", long(MaxTopicLength+1)), 413, ""},
		{"topics at the limit", url.Values{"topic": topics(MaxTopics)}, 200, ""},
		{"topics over the limit", url.Values{"topic": topics(MaxTopics + 1)}, 413, ""},
		{"id at the limit", form("topic", "t", "id", long(MaxIDLength)), 200, ""},
		{"id over the limit", form("topic", "t", "id", long(MaxIDLength+1)), 413, ""},
		{"type at the limit", form("topic", "t", "type", long(MaxTypeLength)), 200, ""},
		{"type over the limit", form("topic", "t", "type", long(MaxTypeLength+1)), 413, ""},
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		tok := e.access(t, mDetail(pubOnly, mBare("*")))
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := e.post(t, tok, tc.form)
				if r.code != tc.code {
					t.Fatalf("%d %q, want %d", r.code, r.body, tc.code)
				}
				if tc.msg != "" && !strings.Contains(r.body, tc.msg) {
					t.Fatalf("body %q does not hold %q", r.body, tc.msg)
				}
			})
		}
	})
}

// TestPublishReservedNamespace: no topic may address the hub's own namespace, whatever its spelling.
func TestPublishReservedNamespace(t *testing.T) {
	reserved := []string{
		"/.well-known/mercure",
		"/.well-known/mercure/",
		"/.well-known/mercure/subscriptions",
		"/.well-known/mercure/subscriptions/exact/a/b",
		"/.well-known/mercure/subscriptions/https%3A%2F%2Fexample.com%2Fa/urn%3Auuid%3Ax",
		"https://hub.example.com/.well-known/mercure/subscriptions/exact/a/b",
		"https://anything.example/.well-known/mercure",
		"http://localhost:8080/.well-known/mercure/x",
		"//other.example/.well-known/mercure/subscriptions/x",
		"https://HUB.EXAMPLE.COM/.well-known/mercure/x",
		"/.well-known/%6Dercure/subscriptions/x",
		"/.well-known/%6dercure",
		"/.well-known/mercur%65/x",
		"/%2E%77ell-known/mercure",
		"/.well-known/mercure/../mercure/x",
		"/.well-known/mercure/./x",
		"/./.well-known/mercure",
		"/x/../.well-known/mercure/subscriptions/y",
		"/a/b/../../.well-known/mercure",
		"/.well-known/./mercure",
		"/.well-known/%2e/mercure",
		"/.well-known/x/%2E%2E/mercure",
		"https://example.com/foo/../.well-known/mercure/x",
		`\.well-known\mercure`,
		`/.well-known\mercure\subscriptions`,
		`https://example.com\.well-known\mercure\x`,
		"/.well-known/mercure?x=1",
		"/.well-known/mercure#frag",
		"/.well-known/mercure/subscriptions/x?y=/z#f",
		"../.well-known/mercure",
		"mercure", // a relative reference resolves against the hub URL: to the hub's own path
		"./mercure",
		"mercure/subscriptions/x",
		"../../.well-known/mercure/x",
		" /.well-known/mercure/subscriptions/exact/a/b", // spaces around it, which URL parsers (URL Pattern too) trim
		"/.well-known/mercure/subscriptions/x ",
		"  https://localhost/.well-known/mercure/subscriptions/x",
		" mercure",
	}
	notReserved := []string{
		"/.well-known/mercurex",
		"/.well-known/mercure-other",
		"/.well-known/mercur",
		"/.well-known/",
		"/.well-known/other",
		"/well-known/mercure",
		"/x/.well-known/mercure",
		"https://example.com/x/.well-known/mercure",
		"https://example.com/mercure",
		"urn:uuid:60a76c80-d399-11d9-b93c-0003939e0af6",
		"%zz",
		"http://[::1",
		"tag:example.com,2026:.well-known/mercure",
		"https://example.com/.well-known/mercure.json",
		" general",
		"hello world",
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		for _, hubURL := range []string{"", "https://hub.example.com/.well-known/mercure"} {
			cfg := mcfg(p)
			cfg.HubURL = hubURL
			e := newEnv(t, cfg)
			aud := e.hubURL()
			if hubURL != "" {
				aud = hubURL
			}
			narrow := accessFor(t, aud, mDetail(pubOnly, mPattern("https://example.com/*")))
			wide := accessFor(t, aud, mDetail(pubOnly, mBare("*")))
			for _, tp := range reserved {
				t.Run("reserved "+hubURL+" "+tp, func(t *testing.T) {
					for _, tok := range []string{wide, narrow} {
						if r := e.post(t, tok, form("topic", tp)); r.code != 400 || !strings.Contains(r.body, "reserved") {
							t.Fatalf("canonical: %d %q", r.code, r.body)
						}
					}
					// As an alternate topic too.
					if r := e.post(t, wide, form("topic", "https://example.com/ok", "topic", tp)); r.code != 400 {
						t.Fatalf("alternate: %d %q", r.code, r.body)
					}
				})
			}
			for _, tp := range notReserved {
				t.Run("free "+hubURL+" "+tp, func(t *testing.T) {
					if r := e.post(t, wide, form("topic", tp)); r.code != 200 {
						t.Fatalf("%d %q", r.code, r.body)
					}
				})
			}
		}
	})
	t.Run("the Go API", func(t *testing.T) {
		h := newModernHub(t, mcfg(ProtocolBoth))
		for _, tp := range reserved {
			if _, err := h.Publish(t.Context(), &Update{Topics: []string{tp}}); err != ErrReservedTopic {
				t.Errorf("Publish(%q): %v", tp, err)
			}
		}
		if _, err := h.Publish(t.Context(), &Update{Topics: []string{"a", "*"}}); err != ErrInvalidTopic {
			t.Errorf("wildcard topic: %v", err)
		}
		if _, err := h.Publish(t.Context(), &Update{Topics: []string{"a"}, Type: "mercure"}); err != ErrInvalidType {
			t.Errorf("type mercure: %v", err)
		}
	})
}

// TestPublishValidationPrecedesAuthorization: a request that breaks §5 is refused with 400 whatever the token
// grants, but only when the token is valid.
func TestPublishValidationPrecedesAuthorization(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		subscribeOnly := e.access(t, mDetail(subOnly, mBare("*")))
		narrow := e.access(t, mDetail(pubOnly, mExact("granted")))
		for _, f := range []url.Values{
			form("topic", "/.well-known/mercure/subscriptions/x"),
			form("topic", "*"),
			form("topic", "granted", "type", "mercure"),
			form("topic", "granted", "retry", "x"),
			form("topic", "granted", "id", "#x"),
			form("topic", "granted", "topic", "a\u200bb"),
		} {
			for _, tok := range []string{subscribeOnly, narrow} {
				if r := e.post(t, tok, f); r.code != 400 {
					t.Errorf("%v: %d %q", f, r.code, r.body)
				}
			}
		}
		// The token is checked first.
		if r := e.post(t, "", form("topic", "*")); r.code != 401 {
			t.Errorf("no token: %d", r.code)
		}
		bad := signAccess(t, accessClaims("https://other.example", time.Hour, mDetail(pubOnly, mBare("*"))))
		if r := e.post(t, bad, form("topic", "*")); r.code != 401 {
			t.Errorf("bad token: %d", r.code)
		}
	})
}

func TestPublishBodyLimit(t *testing.T) {
	cfg := mcfg(ProtocolBoth)
	cfg.MaxPublishBytes = 512
	e := newEnv(t, cfg)
	tok := e.access(t, mDetail(pubOnly, mBare("*")))
	if r := e.post(t, tok, form("topic", "t", "data", strings.Repeat("x", 200))); r.code != 200 {
		t.Fatalf("%d", r.code)
	}
	r := e.post(t, tok, form("topic", "t", "data", strings.Repeat("x", 2000)))
	if r.code != 413 {
		t.Fatalf("%d %q", r.code, r.body)
	}
}

// TestPublishPrivacyAndFields: the private flag marks an update by its presence; type and retry reach subscribers.
func TestPublishPrivacyAndFields(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Anonymous = true
		e := newEnv(t, cfg)
		anon := e.matchStream(t, "", "match", "p")
		granted := e.matchStream(t, e.access(t, mDetail(subOnly, mExact("p"))), "match", "p")
		other := e.matchStream(t, e.access(t, mDetail(subOnly, mExact("other"))), "match", "p")
		pub := e.access(t, mDetail(pubOnly, mBare("*")))
		for _, tc := range []struct {
			data string
			form url.Values
		}{
			{"public", form("topic", "p")},
			{"private=on", form("topic", "p", "private", "on")},
			{"private-empty", form("topic", "p", "private", "")},
			{"private=false", form("topic", "p", "private", "false")},
			{"private=0", form("topic", "p", "private", "0")},
			{"private-twice", form("topic", "p", "private", "", "private", "")},
		} {
			tc.form.Set("data", tc.data)
			if r := e.post(t, pub, tc.form); r.code != 200 {
				t.Fatalf("%s: %d %s", tc.data, r.code, r.body)
			}
		}
		if r := e.post(t, pub, form("topic", "p", "data", "end")); r.code != 200 {
			t.Fatal(r.code)
		}
		if got := anon.drain("end"); len(got) != 1 || got[0] != "public" {
			t.Errorf("anonymous subscriber got %v, want only the public update", got)
		}
		if got := other.drain("end"); len(got) != 1 || got[0] != "public" {
			t.Errorf("subscriber with another grant got %v, want only the public update", got)
		}
		want := []string{"public", "private=on", "private-empty", "private=false", "private=0", "private-twice"}
		if got := granted.drain("end"); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("authorized subscriber got %v, want %v", got, want)
		}
	})
}

// TestModernPublishResponse: the hub answers 200 with the id as text/plain.
func TestModernPublishResponse(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		tok := e.access(t, mDetail(pubAndSb, mBare("*")))
		c := e.matchStream(t, tok, "match", "t")
		r := e.post(t, tok, form("topic", "t", "data", "hello\r\nworld", "type", "greeting", "retry", "1500", "id", "custom-1"))
		if r.code != 200 || r.body != "custom-1" || r.header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("%d %q %q", r.code, r.body, r.header.Get("Content-Type"))
		}
		ev := c.mustNext()
		if ev.ID != "custom-1" || ev.Type != "greeting" || ev.Data != "hello\nworld" || !ev.HasRetry || ev.Retry != "1500" {
			t.Fatalf("event %+v", ev)
		}
		r = e.post(t, tok, form("topic", "t"))
		if r.code != 200 || !uuidV7.MatchString(r.body) {
			t.Fatalf("generated id %q (%d)", r.body, r.code)
		}
		if ev = c.mustNext(); ev.ID != r.body || ev.Data != "" {
			t.Fatalf("event %+v", ev)
		}
		// The hub-wide security headers.
		if r.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("headers %v", r.header)
		}
	})
}

func TestModernPublishMethodsAndPaths(t *testing.T) {
	e := newEnv(t, mcfg(ProtocolBoth))
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := e.do(t, m, e.hubURL(), nil, "")
		if r.code != 405 || !strings.Contains(r.header.Get("Allow"), "QUERY") {
			t.Errorf("%s: %d %v", m, r.code, r.header)
		}
	}
	if r := e.get(t, e.srv.URL+hubPath+"/other", nil); r.code != 404 {
		t.Errorf("unknown path %d", r.code)
	}
	if r := e.get(t, e.srv.URL+"/", nil); r.code != 404 {
		t.Errorf("root %d", r.code)
	}
}
