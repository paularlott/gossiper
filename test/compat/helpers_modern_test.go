//go:build compat

package compat

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Mercure 1.0 (draft-08): RFC 9068 access tokens, "match" parameters, QUERY, last_event_id.

var (
	hubV1        = hub{"gossiper-v1", envOr("COMPAT_V1_URL", "http://localhost:13004")}
	hubRefModern = hub{"reference-modern", envOr("COMPAT_REFERENCE_MODERN_URL", "http://localhost:13005")}
	appV1        = envOr("COMPAT_APP_V1_URL", "http://localhost:13006")
	appRefModern = hubRefModern.base
)

const (
	modernCookie = "__Secure-mercure_access_token"
	trustedIss   = "https://localhost"
	detailType   = "https://mercure.rocks/authorization-detail"
	prmPath      = "/.well-known/oauth-protected-resource" + hubPath
)

// modernHubs are the Gossiper instances compared with the Mercure 1.0 reference: the default (both protocols) and
// --protocol modern.
var modernHubs = []hub{hubSC, hubV1}

// resource is the identifier of h: the hub URL the client contacted.
func (h hub) resource() string { return h.base + hubPath }

// match is one entry of an authorization_details "topics" array.
type match map[string]any

func ex(s string) match { return match{"match": s} }
func up(s string) match { return match{"match": s, "match_type": "urlpattern"} }

func pubDetail(topics ...match) map[string]any {
	return map[string]any{"type": detailType, "actions": []string{"publish"}, "topics": topics}
}

func subDetail(payload any, topics ...match) map[string]any {
	d := map[string]any{"type": detailType, "actions": []string{"subscribe"}, "topics": topics}
	if payload != nil {
		d["payload"] = payload
	}
	return d
}

func bothDetail(topics ...match) map[string]any {
	return map[string]any{"type": detailType, "actions": []string{"publish", "subscribe"}, "topics": topics}
}

// at is an access token under construction.
type at struct {
	Header map[string]any
	Claims jwt.MapClaims
	Key    string
	Method jwt.SigningMethod
}

// newAT returns a valid access token for h carrying the given authorization_details entries.
func newAT(h hub, details ...map[string]any) *at {
	c := jwt.MapClaims{
		"iss":       trustedIss,
		"aud":       h.resource(),
		"sub":       "compat-user",
		"client_id": "compat-client",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       randHex(8),
	}
	if len(details) > 0 {
		c["authorization_details"] = details
	}
	return &at{Header: map[string]any{"typ": "at+jwt"}, Claims: c, Key: secret, Method: jwt.SigningMethodHS256}
}

func (a *at) with(f func(*at)) *at { f(a); return a }

func (a *at) claim(k string, v any) *at {
	if v == nil {
		delete(a.Claims, k)
	} else {
		a.Claims[k] = v
	}
	return a
}

func (a *at) typ(v any) *at {
	if v == nil {
		delete(a.Header, "typ")
	} else {
		a.Header["typ"] = v
	}
	return a
}

func (a *at) String() string {
	t := jwt.NewWithClaims(a.Method, a.Claims)
	for k, v := range a.Header {
		t.Header[k] = v
	}
	if a.Header["typ"] == nil {
		delete(t.Header, "typ")
	}
	var k any = []byte(a.Key)
	if a.Method == jwt.SigningMethodNone {
		k = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := t.SignedString(k)
	if err != nil {
		panic(err)
	}
	return s
}

// mcase is a raw request built per hub (tokens carry the hub's own resource identifier).
type mcase struct {
	name      string
	req       func(h hub) req
	known     known
	knownBoth known // additionally known for the default (protocol "both") Gossiper, which also speaks draft-07
}

// runModernRaw sends every case to each Gossiper and to the Mercure 1.0 reference and compares the responses.
func runModernRaw(t *testing.T, cases []mcase) {
	for _, h := range modernHubs {
		h := h
		t.Run(h.name, func(t *testing.T) {
			for _, c := range cases {
				c := c
				t.Run(c.name, func(t *testing.T) {
					got, ref := h.do(c.req(h)), hubRefModern.do(c.req(hubRefModern))
					t.Logf("%s %s -> reference %d, %s %d", c.req(h).Method, c.req(h).Path, ref.Status, h.name, got.Status)
					k := c.known
					if h == hubSC && c.knownBoth != nil {
						k = mergeKnown(c.known, c.knownBoth)
					}
					(&cmp{t: t, hubName: h.name, known: k, modern: true, gotBase: h.base, refBase: hubRefModern.base}).resp(got, ref, true)
				})
			}
		})
	}
}

func authz(tok string) map[string]string { return map[string]string{"Authorization": bearer(tok)} }

func hdrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

var _ = http.MethodGet

func mergeKnown(a, b known) known {
	m := known{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}
