//go:build compat

package compat

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------------------------------------
// Mercure 1.0 differential tests: the default Gossiper (--protocol both) and --protocol modern against the
// FrankenPHP built-in hub in its default (Mercure 1.0) mode.

var (
	knMalformed = kn("classification of an undecodable token: the two hubs split 400 invalid_request / 401 invalid_token differently (garbage and 2-segment tokens vs. bad base64/JSON payloads); both refuse it", "status", "header:WWW-Authenticate")
	knSlash     = kn("Gossiper normalizes a trailing slash in the Origin header before checking publish_origins; the reference rejects it (browsers never send it)", "status", "header:WWW-Authenticate", "header:Access-Control-Allow-Origin", "header:Access-Control-Allow-Credentials")
	knLimit     = kn("Gossiper answers 413 for a field over its size limit (id 1 KiB, type 256 B, topic 4 KiB); the reference answers 400 for ids/topics and accepts any type length", "status")
	knAllow     = kn("Gossiper adds an Allow header (get, head, options, post, query) to its 405", "header:Allow")
)

var knLegacyAccepted = kn("the default Gossiper (--protocol both) also accepts draft-07 tokens/parameters; --protocol modern and the reference refuse them", "*")

func TestModernPublishAuth(t *testing.T) {
	topic := ns("m/auth")
	body := pubForm(topic)
	post := func(tok func(h hub) string, extra map[string]string) func(h hub) req {
		return func(h hub) req {
			a := ""
			if tok != nil {
				a = bearer(tok(h))
			}
			return publishReq(body, a, extra)
		}
	}
	pub := func(topics ...match) func(h hub) string {
		return func(h hub) string { return newAT(h, pubDetail(topics...)).String() }
	}
	mod := func(d func(h hub) *at) func(h hub) string { return func(h hub) string { return d(h).String() } }
	base := func(h hub, topics ...match) *at {
		if len(topics) == 0 {
			topics = []match{up("*")}
		}
		return newAT(h, pubDetail(topics...))
	}
	cookie := func(name string, hdr map[string]string, tok func(h hub) string) func(h hub) req {
		return func(h hub) req {
			r := publishReq(body, "", hdr)
			r.Header["Cookie"] = name + "=" + tok(h)
			return r
		}
	}
	now := time.Now()
	allowed := hdrs("Origin", allowedOrigin)
	runModernRaw(t, []mcase{
		{name: "no-token", req: post(nil, nil)},
		{name: "urlpattern-star", req: post(pub(up("*")), nil)},
		{name: "exact-topic", req: post(pub(ex(topic)), nil)},
		{name: "exact-other-topic", req: post(pub(ex(topic+"/other")), nil)},
		{name: "exact-star-literal", req: post(pub(ex("*")), nil)},
		{name: "urlpattern-prefix-star", req: post(pub(up(ns("m/")+"*")), nil)},
		{name: "urlpattern-named-group", req: post(pub(up(ns("m/")+":name")), nil)},
		{name: "urlpattern-named-group-too-short", req: post(pub(up(ns("m/")+"auth/:name")), nil)},
		{name: "urlpattern-regexp-group-match", req: post(pub(up(ns("m/")+"(au.*)")), nil)},
		{name: "urlpattern-regexp-group-no-match", req: post(pub(up(ns("m/")+"(x.*)")), nil)},
		{name: "urlpattern-optional-modifier", req: post(pub(up(ns("m/")+"auth{/other}?")), nil)},
		{name: "urlpattern-other-origin", req: post(pub(up("https://other.test/*")), nil)},
		{name: "urlpattern-scheme-wildcard", req: post(pub(up("*://compat.test/*")), nil)},
		{name: "urlpattern-relative", req: post(pub(up("/m/*")), nil)},
		{name: "urlpattern-invalid-syntax", req: post(pub(up("https://compat.test/(unclosed")), nil)},
		{name: "match-type-unknown", req: post(pub(match{"match": topic, "match_type": "regexp"}), nil)},
		{name: "match-type-exact-explicit", req: post(pub(match{"match": topic, "match_type": "exact"}), nil)},
		{name: "topic-object-without-match", req: post(pub(match{"match_type": "exact"}), nil)},
		{name: "topic-object-empty-match", req: post(pub(ex("")), nil)},
		{name: "empty-topics-array", req: post(func(h hub) string { return newAT(h, pubDetail()).String() }, nil)},
		{name: "no-authorization-details", req: post(mod(func(h hub) *at { return newAT(h) }), nil)},
		{name: "empty-authorization-details", req: post(mod(func(h hub) *at { return newAT(h).claim("authorization_details", []any{}) }), nil)},
		{name: "authorization-details-not-an-array", req: post(mod(func(h hub) *at { return newAT(h).claim("authorization_details", pubDetail(up("*"))) }), nil)},
		{name: "subscribe-only-grant", req: post(func(h hub) string { return newAT(h, subDetail(nil, up("*"))).String() }, nil)},
		{name: "publish-and-subscribe-grant", req: post(func(h hub) string { return newAT(h, bothDetail(up("*"))).String() }, nil)},
		{name: "detail-wrong-type", req: post(mod(func(h hub) *at {
			d := pubDetail(up("*"))
			d["type"] = "https://example.com/other"
			return newAT(h, d)
		}), nil)},
		{name: "detail-missing-type", req: post(mod(func(h hub) *at {
			d := pubDetail(up("*"))
			delete(d, "type")
			return newAT(h, d)
		}), nil)},
		{name: "detail-unknown-action", req: post(mod(func(h hub) *at {
			d := pubDetail(up("*"))
			d["actions"] = []string{"delete"}
			return newAT(h, d)
		}), nil)},
		{name: "detail-publish-plus-unknown-action", req: post(mod(func(h hub) *at {
			d := pubDetail(up("*"))
			d["actions"] = []string{"publish", "delete"}
			return newAT(h, d)
		}), nil)},
		{name: "detail-empty-actions", req: post(mod(func(h hub) *at {
			d := pubDetail(up("*"))
			d["actions"] = []string{}
			return newAT(h, d)
		}), nil)},
		{name: "two-details-second-covers", req: post(func(h hub) string {
			return newAT(h, pubDetail(ex("https://other.test/x")), pubDetail(ex(topic))).String()
		}, nil)},
		{name: "two-details-neither-covers-both-topics", req: func(h hub) req {
			v := url.Values{"topic": {topic, topic + "/2"}, "data": {"d"}}
			return publishReq(v, bearer(newAT(h, pubDetail(ex(topic)), pubDetail(ex("https://other.test/x"))).String()), nil)
		}},
		{name: "two-details-cover-both-topics", req: func(h hub) req {
			v := url.Values{"topic": {topic, topic + "/2"}, "data": {"d"}}
			return publishReq(v, bearer(newAT(h, pubDetail(ex(topic)), pubDetail(ex(topic+"/2"))).String()), nil)
		}},
		{name: "multi-topic-one-unauthorized", req: func(h hub) req {
			v := url.Values{"topic": {topic, "https://other.test/x"}, "data": {"d"}}
			return publishReq(v, bearer(newAT(h, pubDetail(ex(topic))).String()), nil)
		}},
		{name: "private-update", req: func(h hub) req {
			return publishReq(pubForm(topic, "private", "on"), bearer(base(h).String()), nil)
		}},
		// iss
		{name: "iss-untrusted", req: post(mod(func(h hub) *at { return base(h).claim("iss", "https://evil.example") }), nil)},
		{name: "iss-missing", req: post(mod(func(h hub) *at { return base(h).claim("iss", nil) }), nil)},
		{name: "iss-trailing-slash", req: post(mod(func(h hub) *at { return base(h).claim("iss", trustedIss+"/") }), nil)},
		{name: "iss-not-a-string", req: post(mod(func(h hub) *at { return base(h).claim("iss", 42) }), nil)},
		// aud
		{name: "aud-wrong", req: post(mod(func(h hub) *at { return base(h).claim("aud", "https://other.test/.well-known/mercure") }), nil)},
		{name: "aud-missing", req: post(mod(func(h hub) *at { return base(h).claim("aud", nil) }), nil)},
		{name: "aud-array-containing-hub", req: post(mod(func(h hub) *at { return base(h).claim("aud", []string{"https://other.test/x", h.resource()}) }), nil)},
		{name: "aud-array-without-hub", req: post(mod(func(h hub) *at { return base(h).claim("aud", []string{"https://other.test/x"}) }), nil)},
		{name: "aud-hub-origin-only", req: post(mod(func(h hub) *at { return base(h).claim("aud", h.base) }), nil)},
		{name: "aud-trailing-slash", req: post(mod(func(h hub) *at { return base(h).claim("aud", h.resource()+"/") }), nil)},
		{name: "aud-empty-array", req: post(mod(func(h hub) *at { return base(h).claim("aud", []string{}) }), nil)},
		// typ
		{name: "typ-missing", req: post(mod(func(h hub) *at { return base(h).typ(nil) }), nil)},
		{name: "typ-JWT", req: post(mod(func(h hub) *at { return base(h).typ("JWT") }), nil)},
		{name: "typ-uppercase", req: post(mod(func(h hub) *at { return base(h).typ("AT+JWT") }), nil)},
		{name: "typ-application-at-jwt", req: post(mod(func(h hub) *at { return base(h).typ("application/at+jwt") }), nil)},
		// exp / nbf / other claims
		{name: "expired", req: post(mod(func(h hub) *at { return base(h).claim("exp", now.Add(-time.Hour).Unix()) }), nil)},
		{name: "exp-missing", req: post(mod(func(h hub) *at { return base(h).claim("exp", nil) }), nil)},
		{name: "exp-float", req: post(mod(func(h hub) *at { return base(h).claim("exp", float64(now.Add(time.Hour).UnixNano())/1e9) }), nil)},
		{name: "exp-string", req: post(mod(func(h hub) *at { return base(h).claim("exp", "tomorrow") }), nil)},
		{name: "nbf-future", req: post(mod(func(h hub) *at { return base(h).claim("nbf", now.Add(time.Hour).Unix()) }), nil)},
		{name: "iat-future", req: post(mod(func(h hub) *at { return base(h).claim("iat", now.Add(time.Hour).Unix()) }), nil)},
		{name: "sub-missing", req: post(mod(func(h hub) *at { return base(h).claim("sub", nil) }), nil)},
		{name: "client_id-missing", req: post(mod(func(h hub) *at { return base(h).claim("client_id", nil) }), nil)},
		{name: "jti-missing", req: post(mod(func(h hub) *at { return base(h).claim("jti", nil) }), nil)},
		{name: "scope-claim-extra", req: post(mod(func(h hub) *at { return base(h).claim("scope", "mercure:publish") }), nil)},
		// algorithms and malformed tokens
		{name: "alg-HS512", req: post(mod(func(h hub) *at { return base(h).with(func(a *at) { a.Method = jwt.SigningMethodHS512 }) }), nil)},
		{name: "alg-none", req: post(mod(func(h hub) *at {
			return base(h).with(func(a *at) { a.Method = jwt.SigningMethodNone; a.Key = "" })
		}), nil)},
		{name: "wrong-key", req: post(mod(func(h hub) *at { return base(h).with(func(a *at) { a.Key = "another-secret-another-secret-123456" }) }), nil)},
		{name: "malformed-garbage", known: knMalformed, req: post(func(h hub) string { return "not-a-jwt" }, nil)},
		{name: "malformed-two-segments", known: knMalformed, req: post(func(h hub) string { return "aaa.bbb" }, nil)},
		{name: "malformed-bad-base64-payload", known: knMalformed, req: post(func(h hub) string {
			p := strings.Split(base(h).String(), ".")
			return p[0] + ".%%%." + p[2]
		}, nil)},
		{name: "malformed-payload-not-json", known: knMalformed, req: post(func(h hub) string {
			p := strings.Split(base(h).String(), ".")
			return p[0] + ".bm90LWpzb24." + p[2]
		}, nil)},
		{name: "legacy-token-mercure-claim", known: nil, knownBoth: knLegacyAccepted, req: post(func(h hub) string { return pubToken("*") }, nil)},
		{name: "authorization-basic", req: func(h hub) req { return publishReq(body, "Basic dXNlcjpwYXNz", nil) }},
		{name: "authorization-bare-token", req: func(h hub) req { return publishReq(body, base(h).String(), nil) }},
		{name: "authorization-lowercase-bearer", req: func(h hub) req { return publishReq(body, "bearer "+base(h).String(), nil) }},
		{name: "authorization-dpop-scheme", req: func(h hub) req { return publishReq(body, "DPoP "+base(h).String(), nil) }},
		// cookie (the Secure-prefixed cookie; raw HTTP clients can send it on http)
		{name: "cookie-no-origin", req: cookie(modernCookie, nil, func(h hub) string { return base(h).String() })},
		{name: "cookie-allowed-origin", req: cookie(modernCookie, allowed, func(h hub) string { return base(h).String() })},
		{name: "cookie-allowed-origin-trailing-slash", known: knSlash, req: cookie(modernCookie, hdrs("Origin", allowedOrigin+"/"), func(h hub) string { return base(h).String() })},
		{name: "cookie-bad-origin", req: cookie(modernCookie, hdrs("Origin", badOrigin), func(h hub) string { return base(h).String() })},
		{name: "cookie-null-origin", req: cookie(modernCookie, hdrs("Origin", "null"), func(h hub) string { return base(h).String() })},
		{name: "cookie-referer-allowed", req: cookie(modernCookie, hdrs("Referer", allowedOrigin+"/page"), func(h hub) string { return base(h).String() })},
		{name: "cookie-referer-bad", req: cookie(modernCookie, hdrs("Referer", badOrigin+"/page"), func(h hub) string { return base(h).String() })},
		{name: "cookie-allowed-origin-bad-token", known: knMalformed, req: cookie(modernCookie, allowed, func(h hub) string { return "garbage" })},
		{name: "cookie-allowed-origin-wrong-aud", req: cookie(modernCookie, allowed, func(h hub) string { return base(h).claim("aud", "https://other.test/x").String() })},
		{name: "cookie-allowed-origin-no-publish-grant", req: cookie(modernCookie, allowed, func(h hub) string { return newAT(h, subDetail(nil, up("*"))).String() })},
		{name: "cookie-legacy-name-with-modern-token", knownBoth: knLegacyAccepted, req: cookie("mercureAuthorization", allowed, func(h hub) string { return base(h).String() })},
		{name: "cookie-host-prefix-name", req: cookie("__Host-mercure_access_token", allowed, func(h hub) string { return base(h).String() })},
		{name: "cookie-unprefixed-name", req: cookie("mercure_access_token", allowed, func(h hub) string { return base(h).String() })},
		{name: "cookie-legacy-token-in-modern-cookie", knownBoth: knLegacyAccepted, req: cookie(modernCookie, allowed, func(h hub) string { return pubToken("*") })},
		{name: "bearer-with-bad-origin", req: func(h hub) req { return publishReq(body, bearer(base(h).String()), hdrs("Origin", badOrigin)) }},
		// query-parameter token (bearer_methods_supported is only "header")
		{name: "query-authorization-valid", knownBoth: knLegacyAccepted, req: func(h hub) req {
			r := publishReq(body, "", nil)
			r.Path += "?authorization=" + url.QueryEscape(base(h).String())
			return r
		}},
		{name: "query-access_token-valid", req: func(h hub) req {
			r := publishReq(body, "", nil)
			r.Path += "?access_token=" + url.QueryEscape(base(h).String())
			return r
		}},
		{name: "form-body-access_token", req: func(h hub) req {
			v := pubForm(topic)
			v.Set("access_token", base(h).String())
			return publishReq(v, "", nil)
		}},
		// precedence
		{name: "header-bad-cookie-good", known: knMalformed, req: func(h hub) req {
			r := publishReq(body, bearer("garbage"), allowed)
			r.Header["Cookie"] = modernCookie + "=" + base(h).String()
			return r
		}},
		{name: "header-good-cookie-bad", req: func(h hub) req {
			r := publishReq(body, bearer(base(h).String()), allowed)
			r.Header["Cookie"] = modernCookie + "=garbage"
			return r
		}},
		{name: "cookie-and-valid-header-bad-origin", req: func(h hub) req {
			r := publishReq(body, bearer(base(h).String()), hdrs("Origin", badOrigin))
			r.Header["Cookie"] = modernCookie + "=" + base(h).String()
			return r
		}},
	})
}

func TestModernPublishValidation(t *testing.T) {
	topic := ns("m/valid")
	tok := func(h hub) string { return bearer(newAT(h, pubDetail(up("*"))).String()) }
	p := func(v url.Values) func(h hub) req {
		return func(h hub) req { return publishReq(v, tok(h), nil) }
	}
	pf := func(f func(h hub) url.Values) func(h hub) req {
		return func(h hub) req { return publishReq(f(h), tok(h), nil) }
	}
	raw := func(contentType, body string) func(h hub) req {
		return func(h hub) req {
			hd := map[string]string{"Authorization": tok(h)}
			if contentType != "" {
				hd["Content-Type"] = contentType
			}
			return req{Method: http.MethodPost, Path: hubPath, Header: hd, Body: body}
		}
	}
	method := func(m string) func(h hub) req {
		return func(h hub) req {
			return req{Method: m, Path: hubPath, Header: map[string]string{"Authorization": tok(h), "Content-Type": "application/x-www-form-urlencoded"}, Body: pubForm(topic).Encode()}
		}
	}
	both := func(reason string) known { return kn(reason, "*") }
	runModernRaw(t, []mcase{
		{name: "ok-minimal", req: p(url.Values{"topic": {topic}})},
		{name: "ok-all-fields", req: p(pubForm(topic, "id", "id-"+runID+"-1", "type", "t", "retry", "100", "private", "on"))},
		{name: "ok-private-empty-value", req: p(pubForm(topic, "private", ""))},
		{name: "ok-private-false-value", req: p(pubForm(topic, "private", "false"))},
		{name: "ok-empty-data", req: p(url.Values{"topic": {topic}, "data": {""}})},
		{name: "ok-id-with-spaces-and-unicode", req: p(pubForm(topic, "id", "id é "+runID))},
		{name: "ok-relative-topic", req: p(pubForm("relative-topic"))},
		{name: "ok-topic-with-query-and-fragment", req: p(pubForm(topic + "/é?a=b&c=d#frag"))},
		{name: "ok-many-alternate-topics", req: p(url.Values{"topic": {topic, topic + "/2", topic + "/3"}, "data": {"x"}})},
		{name: "ok-data-with-newlines", req: p(pubForm(topic, "data", "a\nb\r\nc"))},
		{name: "ok-type-custom", req: p(pubForm(topic, "type", "custom.event"))},
		{name: "missing-topic", req: p(url.Values{"data": {"x"}})},
		{name: "empty-topic", req: p(url.Values{"topic": {""}, "data": {"x"}})},
		{name: "topic-star", req: p(pubForm("*"))},
		{name: "topic-star-with-exact-star-grant", req: func(h hub) req {
			return publishReq(pubForm("*"), bearer(newAT(h, pubDetail(ex("*"))).String()), nil)
		}},
		{name: "empty-body", req: raw("application/x-www-form-urlencoded", "")},
		{name: "id-earliest", req: p(pubForm(topic, "id", "earliest"))},
		{name: "id-with-newline", req: p(pubForm(topic, "id", "a\nb"))},
		{name: "id-with-cr", req: p(pubForm(topic, "id", "a\rb"))},
		{name: "id-with-nul", req: p(pubForm(topic, "id", "a\x00b"))},
		{name: "id-starting-with-hash", req: p(pubForm(topic, "id", "#abc"))},
		{name: "id-too-long", known: knLimit, req: p(pubForm(topic, "id", strings.Repeat("x", 3000)))},
		{name: "id-cf-zero-width-space", req: p(pubForm(topic, "id", "a\u200bb"))},
		{name: "id-cf-rlo", req: p(pubForm(topic, "id", "a\u202eb"))},
		{name: "id-cf-bom", req: p(pubForm(topic, "id", "\ufeffab"))},
		{name: "id-cf-soft-hyphen", req: p(pubForm(topic, "id", "a\u00adb"))},
		{name: "id-unicode-line-separator", req: p(pubForm(topic, "id", "a\u2028b"))},
		{name: "id-c1-control", req: p(pubForm(topic, "id", "a\u0085b"))},
		{name: "id-del", req: p(pubForm(topic, "id", "a\x7fb"))},
		{name: "retry-not-a-number", req: p(pubForm(topic, "retry", "abc"))},
		{name: "retry-negative", req: p(pubForm(topic, "retry", "-1"))},
		{name: "retry-float", req: p(pubForm(topic, "retry", "1.5"))},
		{name: "retry-empty", known: kn("an empty retry= is ignored by the reference and rejected (400) by Gossiper", "status"), req: p(pubForm(topic, "retry", ""))},
		{name: "retry-zero", req: p(pubForm(topic, "retry", "0"))},
		{name: "retry-huge", req: p(pubForm(topic, "retry", "99999999999999999999999"))},
		{name: "type-mercure", req: p(pubForm(topic, "type", "mercure"))},
		{name: "type-mercure-uppercase", req: p(pubForm(topic, "type", "Mercure"))},
		{name: "type-mercure-trailing-space", req: p(pubForm(topic, "type", "mercure "))},
		{name: "type-with-newline", req: p(pubForm(topic, "type", "a\nb"))},
		{name: "type-too-long", known: knLimit, req: p(pubForm(topic, "type", strings.Repeat("t", 2000)))},
		{name: "type-cf-zero-width", req: p(pubForm(topic, "type", "mer\u200bcure"))},
		{name: "type-cf-in-custom", req: p(pubForm(topic, "type", "a\u200eb"))},
		{name: "topic-cf-zero-width", req: p(pubForm(topic + "/a\u200bb"))},
		{name: "topic-cf-rlo", req: p(pubForm(topic + "/\u202e"))},
		{name: "topic-cf-bom", req: p(pubForm("\ufeff" + topic))},
		{name: "topic-with-newline", req: p(pubForm(topic + "\nx"))},
		{name: "topic-too-long", known: knLimit, req: p(pubForm(topic + "/" + strings.Repeat("x", 5000)))},
		{name: "data-cf-allowed", req: p(pubForm(topic, "data", "a\u200bb\u202ec\ufeff"))},
		{name: "data-not-utf8", req: raw("application/x-www-form-urlencoded", "topic=x&data=%ff%fe")},
		// reserved namespace variants
		{name: "reserved-subscriptions", req: p(pubForm("/.well-known/mercure/subscriptions/a/b"))},
		{name: "reserved-modern-subscription-path", req: p(pubForm("/.well-known/mercure/subscriptions/exact/a/b"))},
		{name: "reserved-exact", req: p(pubForm("/.well-known/mercure"))},
		{name: "reserved-trailing-slash", req: p(pubForm("/.well-known/mercure/"))},
		{name: "reserved-absolute-hub-url", req: pf(func(h hub) url.Values { return pubForm(h.base + "/.well-known/mercure/subscriptions/a/b") })},
		{name: "reserved-absolute-hub-url-exact", req: pf(func(h hub) url.Values { return pubForm(h.resource()) })},
		{name: "reserved-absolute-other-host", req: p(pubForm("http://example.com/.well-known/mercure/subscriptions/a"))},
		{name: "reserved-scheme-relative", req: pf(func(h hub) url.Values {
			return pubForm("//" + strings.TrimPrefix(h.base, "http://") + "/.well-known/mercure/subscriptions/a")
		})},
		{name: "reserved-percent-encoded-dot", req: p(pubForm("/%2Ewell-known/mercure/subscriptions/a"))},
		{name: "reserved-percent-encoded-segment", req: p(pubForm("/.well-known/%6Dercure/subscriptions/a"))},
		{name: "reserved-percent-encoded-slash", known: kn("topic /.well-known%2Fmercure/...: an encoded slash is data, the reference accepts it (it is a different topic); Gossiper refuses it as a possible spoof of the reserved namespace (400)", "status"), req: p(pubForm("/.well-known%2Fmercure/subscriptions/a"))},
		{name: "reserved-dot-segment", req: p(pubForm("/foo/../.well-known/mercure/subscriptions/a"))},
		{name: "reserved-dot-segment-current", req: p(pubForm("/./.well-known/./mercure/subscriptions/a"))},
		{name: "reserved-dot-segment-absolute", req: pf(func(h hub) url.Values { return pubForm(h.base + "/x/../.well-known/mercure/subscriptions/a") })},
		{name: "reserved-double-slash", known: kn("topic /.well-known//mercure/...: a different URL, accepted by the reference; Gossiper refuses it (400) as a possible spoof of the reserved namespace", "status"), req: p(pubForm("/.well-known//mercure/subscriptions/a"))},
		{name: "reserved-uppercase", req: p(pubForm("/.WELL-KNOWN/MERCURE/subscriptions/a"))},
		{name: "reserved-with-query", req: p(pubForm("/.well-known/mercure/subscriptions/a?x=1"))},
		{name: "reserved-with-fragment", req: p(pubForm("/.well-known/mercure/subscriptions/a#f"))},
		{name: "reserved-as-alternate-topic", req: p(url.Values{"topic": {topic, "/.well-known/mercure/subscriptions/a"}, "data": {"x"}})},
		{name: "reserved-prefix-lookalike", req: p(pubForm("/.well-known/mercure-other/x"))},
		{name: "reserved-with-star-grant-token", req: p(pubForm("/.well-known/mercure/subscriptions/a/b"))},
		// framing
		{name: "content-type-json", req: raw("application/json", `{"topic":"x","data":"y"}`)},
		{name: "content-type-text-plain", req: raw("text/plain", "topic=x&data=y")},
		{name: "content-type-missing", req: raw("", "topic=x&data=y")},
		{name: "content-type-multipart", req: raw("multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"topic\"\r\n\r\nx\r\n--XX\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\ny\r\n--XX--\r\n")},
		{name: "body-1.5MB", known: both("Gossiper limits the publish body to 1 MiB (--max-publish-size)"), req: p(pubForm(topic, "data", strings.Repeat("x", 1_500_000)))},
		{name: "method-get-no-match", req: method(http.MethodGet)},
		{name: "method-put", known: knAllow, req: method(http.MethodPut)},
		{name: "method-patch", known: knAllow, req: method(http.MethodPatch)},
		{name: "method-delete", known: knAllow, req: method(http.MethodDelete)},
		{name: "method-head", req: method(http.MethodHead)},
		{name: "method-query-with-publish-body", knownBoth: knLegacyAccepted, req: method("QUERY")},
		{name: "unknown-path", req: func(h hub) req { r := publishReq(pubForm(topic), tok(h), nil); r.Path = hubPath + "/nope"; return r }},
		{name: "trailing-slash", req: func(h hub) req { r := publishReq(pubForm(topic), tok(h), nil); r.Path = hubPath + "/"; return r }},
	})
}

var (
	knEmptyMatch = kn("an empty match value opens a stream on the reference; Gossiper refuses it (400)", "status", "header:Content-Type")
	knQueryCT    = kn("a QUERY without a Content-Type: the reference answers 400, Gossiper 415 (it checks the media type first); both refuse it, and both answer 415 for another media type", "status", "header:Content-Type")
	knLEIDHeader = kn("the response header Last-Event-ID (draft-07 name) is sent by the default Gossiper next to Mercure-Last-Event-ID; the reference and --protocol modern send only Mercure-Last-Event-ID", "header:Last-Event-ID")
)

func TestModernSubscribeRequests(t *testing.T) {
	topic := ns("m/subreq")
	q := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Add(kv[i], kv[i+1])
		}
		return hubPath + "?" + v.Encode()
	}
	get := func(path string, hd map[string]string) func(h hub) req {
		return func(h hub) req { return req{Path: path, Header: hd} }
	}
	getTok := func(path string, tok func(h hub) string) func(h hub) req {
		return func(h hub) req { return req{Path: path, Header: authz(tok(h))} }
	}
	query := func(path, body, ct string, hd map[string]string) func(h hub) req {
		return func(h hub) req {
			m := map[string]string{}
			if ct != "" {
				m["Content-Type"] = ct
			}
			for k, v := range hd {
				m[k] = v
			}
			return req{Method: "QUERY", Path: path, Header: m, Body: body}
		}
	}
	form := "application/x-www-form-urlencoded"
	subTok := func(h hub) string { return newAT(h, subDetail(nil, up("*"))).String() }
	runModernRaw(t, []mcase{
		{name: "no-match", req: get(hubPath, nil)},
		{name: "empty-match", known: knEmptyMatch, req: get(hubPath+"?match=", nil)},
		{name: "legacy-topic-param", knownBoth: knLegacyAccepted, req: get(q("topic", topic), nil)},
		{name: "match", req: get(q("match", topic), nil)},
		{name: "match-exact", req: get(q("match_exact", topic), nil)},
		{name: "match-urlpattern", req: get(q("match_urlpattern", topic+"/:id"), nil)},
		{name: "match-all-three", req: get(q("match", topic, "match_exact", topic+"/e", "match_urlpattern", topic+"/*"), nil)},
		{name: "match-many", req: get(q("match", "a", "match", "b", "match", "c"), nil)},
		{name: "match-star", req: get(q("match", "*"), nil)},
		{name: "match-urlpattern-star", req: get(q("match_urlpattern", "*"), nil)},
		{name: "match-urlpattern-regexp", req: get(q("match_urlpattern", topic+"/(\\d+)"), nil)},
		{name: "match-urlpattern-relative", req: get(q("match_urlpattern", "/books/:id"), nil)},
		{name: "match-urlpattern-invalid", req: get(q("match_urlpattern", "https://x.test/(unclosed"), nil)},
		{name: "match-urlpattern-empty", known: knEmptyMatch, req: get(q("match_urlpattern", ""), nil)},
		{name: "match-exact-empty", known: knEmptyMatch, req: get(q("match_exact", ""), nil)},
		{name: "match-with-legacy-template", req: get(q("match", topic+"/{id}"), nil)},
		{name: "match-unknown-type", req: get(q("match_regexp", ".*"), nil)},
		{name: "match-unknown-type-with-valid-match", req: get(q("match", topic, "match_foo", "x"), nil)},
		{name: "match-type-camelcase", req: get(q("matchUrlpattern", "*"), nil)},
		{name: "match-with-unknown-other-param", req: get(q("match", topic, "foo", "bar"), nil)},
		{name: "match-invalid-utf8", req: get(hubPath+"?match=%ff%fe", nil)},
		{name: "match-with-newline", req: get(q("match", topic+"\nx"), nil)},
		{name: "match-cf-zero-width", req: get(q("match", topic+"/a\u200bb"), nil)},
		{name: "match-too-long", req: get(q("match", topic+"/"+strings.Repeat("x", 5000)), nil)},
		{name: "head", req: func(h hub) req { return req{Method: http.MethodHead, Path: q("match", topic)} }},
		{name: "post-without-token", req: func(h hub) req { return req{Method: http.MethodPost, Path: hubPath} }},
		// QUERY
		{name: "query-body-match", req: query(hubPath, "match="+url.QueryEscape(topic), form, nil)},
		{name: "query-body-match-exact", req: query(hubPath, "match_exact="+url.QueryEscape(topic), form, nil)},
		{name: "query-body-match-urlpattern", req: query(hubPath, "match_urlpattern="+url.QueryEscape(topic+"/:id"), form, nil)},
		{name: "query-body-and-query-string", req: query(q("match", topic), "match_exact="+url.QueryEscape(topic+"/2"), form, nil)},
		{name: "query-body-unknown-match-type", req: query(hubPath, "match_foo=x", form, nil)},
		{name: "query-empty-body", req: query(hubPath, "", form, nil)},
		{name: "query-no-body-with-query-string", known: knQueryCT, req: query(q("match", topic), "", "", nil)},
		{name: "query-wrong-content-type", req: query(hubPath, "match="+url.QueryEscape(topic), "text/plain", nil)},
		{name: "query-json-content-type", req: query(hubPath, `{"match":"x"}`, "application/json", nil)},
		{name: "query-no-content-type", known: knQueryCT, req: query(hubPath, "match=x", "", nil)},
		{name: "query-with-charset", req: query(hubPath, "match=x", form+"; charset=utf-8", nil)},
		{name: "query-invalid-body-escape", req: query(hubPath, "match=%zz", form, nil)},
		{name: "query-with-token", req: func(h hub) req { return query(hubPath, "match="+url.QueryEscape(topic), form, authz(subTok(h)))(h) }},
		{name: "query-with-bad-token", known: knMalformed, req: query(hubPath, "match="+url.QueryEscape(topic), form, authz("garbage"))},
		{name: "query-last-event-id-in-body", knownBoth: knLEIDHeader, req: query(hubPath, "match="+url.QueryEscape(topic)+"&last_event_id=earliest", form, nil)},
		{name: "query-allowed-origin", req: query(hubPath, "match="+url.QueryEscape(topic), form, hdrs("Origin", allowedOrigin))},
		// tokens
		{name: "token-header", req: getTok(q("match", topic), subTok)},
		{name: "token-wrong-aud", req: getTok(q("match", topic), func(h hub) string {
			return newAT(h, subDetail(nil, up("*"))).claim("aud", "https://other.test/x").String()
		})},
		{name: "token-wrong-iss", req: getTok(q("match", topic), func(h hub) string {
			return newAT(h, subDetail(nil, up("*"))).claim("iss", "https://evil.example").String()
		})},
		{name: "token-expired", req: getTok(q("match", topic), func(h hub) string {
			return newAT(h, subDetail(nil, up("*"))).claim("exp", time.Now().Add(-time.Hour).Unix()).String()
		})},
		{name: "token-no-typ", req: getTok(q("match", topic), func(h hub) string { return newAT(h, subDetail(nil, up("*"))).typ(nil).String() })},
		{name: "token-publish-only-grant", req: getTok(q("match", topic), func(h hub) string { return newAT(h, pubDetail(up("*"))).String() })},
		{name: "token-no-details", req: getTok(q("match", topic), func(h hub) string { return newAT(h).String() })},
		{name: "token-legacy-claim", knownBoth: knLegacyAccepted, req: getTok(q("match", topic), func(h hub) string { return subToken("*") })},
		{name: "token-garbage", known: knMalformed, req: getTok(q("match", topic), func(h hub) string { return "garbage" })},
		{name: "token-basic-scheme", req: get(q("match", topic), hdrs("Authorization", "Basic dXNlcjpwYXNz"))},
		{name: "cookie-valid", req: func(h hub) req {
			return req{Path: q("match", topic), Header: hdrs("Cookie", modernCookie+"="+subTok(h))}
		}},
		{name: "cookie-bad", known: knMalformed, req: get(q("match", topic), hdrs("Cookie", modernCookie+"=garbage"))},
		{name: "cookie-legacy-name", knownBoth: knLegacyAccepted, req: func(h hub) req {
			return req{Path: q("match", topic), Header: hdrs("Cookie", "mercureAuthorization="+subTok(h))}
		}},
		{name: "cookie-valid-bad-origin", req: func(h hub) req {
			return req{Path: q("match", topic), Header: hdrs("Cookie", modernCookie+"="+subTok(h), "Origin", badOrigin)}
		}},
		{name: "query-authorization", knownBoth: knLegacyAccepted, req: func(h hub) req { return req{Path: q("match", topic, "authorization", subTok(h))} }},
		{name: "query-authorization-garbage", knownBoth: knLegacyAccepted, req: get(q("match", topic, "authorization", "garbage"), nil)},
		{name: "query-access-token", req: func(h hub) req { return req{Path: q("match", topic, "access_token", subTok(h))} }},
		// replay parameters
		{name: "last-event-id-header-unknown", knownBoth: knLEIDHeader, req: get(q("match", topic), hdrs("Last-Event-ID", "urn:uuid:00000000-0000-7000-8000-000000000000"))},
		{name: "last_event_id-query-unknown", knownBoth: knLEIDHeader, req: get(q("match", topic, "last_event_id", "unknown"), nil)},
		{name: "last_event_id-query-earliest", knownBoth: knLEIDHeader, req: get(q("match", topic, "last_event_id", "earliest"), nil)},
		{name: "last-event-id-header-earliest", knownBoth: knLEIDHeader, req: get(q("match", topic), hdrs("Last-Event-ID", "earliest"))},
		{name: "lastEventID-query-legacy-name", known: kn("the draft-07 query name lastEventID is ignored by the reference; Gossiper honours it", "header:Last-Event-ID", "header:Mercure-Last-Event-ID"), req: get(q("match", topic, "lastEventID", "earliest"), nil)},
		{name: "last_event_id-empty", known: kn("an empty last_event_id= parameter: the reference replays from the start and says so (Mercure-Last-Event-ID: earliest); Gossiper treats it as absent", "header:Mercure-Last-Event-ID", "header:Last-Event-ID"), req: get(q("match", topic, "last_event_id", ""), nil)},
		{name: "unknown-path", req: get("/.well-known/mercure/x?match=a", nil)},
		{name: "accept-json", known: kn("the reference answers 406 when Accept excludes text/event-stream; Gossiper streams regardless", "status", "header:Content-Type"), req: get(q("match", topic), hdrs("Accept", "application/json"))},
	})
}

func TestModernCORSAndMetadata(t *testing.T) {
	topic := ns("m/cors")
	subPath := hubPath + "?match=" + url.QueryEscape(topic)
	opt := func(path string, h map[string]string) func(hub) req {
		return func(hub) req { return req{Method: http.MethodOptions, Path: path, Header: h} }
	}
	knPre := kn("Gossiper answers CORS preflights for POST/QUERY and echoes valid request headers; the reference only grants some", "header:Access-Control-Allow-Origin", "header:Access-Control-Allow-Credentials", "header:Access-Control-Allow-Methods", "header:Access-Control-Allow-Headers")
	runModernRaw(t, []mcase{
		{name: "subscribe-allowed-origin", req: func(hub) req { return req{Path: subPath, Header: hdrs("Origin", allowedOrigin)} }},
		{name: "subscribe-bad-origin", req: func(hub) req { return req{Path: subPath, Header: hdrs("Origin", badOrigin)} }},
		{name: "subscribe-error-allowed-origin", req: func(hub) req { return req{Path: hubPath, Header: hdrs("Origin", allowedOrigin)} }},
		{name: "preflight-get-authorization-last-event-id", req: opt(hubPath, hdrs("Origin", allowedOrigin, "Access-Control-Request-Method", "GET", "Access-Control-Request-Headers", "authorization,last-event-id"))},
		{name: "preflight-query-content-type", known: knPre, req: opt(hubPath, hdrs("Origin", allowedOrigin, "Access-Control-Request-Method", "QUERY", "Access-Control-Request-Headers", "content-type,authorization"))},
		{name: "preflight-post-authorization", known: knPre, req: opt(hubPath, hdrs("Origin", allowedOrigin, "Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "authorization,content-type"))},
		{name: "preflight-bad-origin", req: opt(hubPath, hdrs("Origin", badOrigin, "Access-Control-Request-Method", "GET"))},
		{name: "preflight-no-method", known: kn("plain OPTIONS: reference 405, Gossiper 204", "status"), req: opt(hubPath, hdrs("Origin", allowedOrigin))},
		// protected resource metadata (RFC 9728)
		{name: "prm-get", req: func(hub) req { return req{Path: prmPath} }},
		{name: "prm-head", req: func(hub) req { return req{Method: http.MethodHead, Path: prmPath} }},
		{name: "prm-post", known: knAllow, req: func(hub) req { return req{Method: http.MethodPost, Path: prmPath} }},
		{name: "prm-options", req: opt(prmPath, hdrs("Origin", allowedOrigin, "Access-Control-Request-Method", "GET"))},
		{name: "prm-with-allowed-origin", req: func(hub) req { return req{Path: prmPath, Header: hdrs("Origin", allowedOrigin)} }},
		{name: "prm-with-bad-origin", req: func(hub) req { return req{Path: prmPath, Header: hdrs("Origin", badOrigin)} }},
		{name: "prm-trailing-slash", req: func(hub) req { return req{Path: prmPath + "/"} }},
		{name: "prm-bare-well-known", req: func(hub) req { return req{Path: "/.well-known/oauth-protected-resource"} }},
		{name: "prm-other-resource-path", req: func(hub) req { return req{Path: "/.well-known/oauth-protected-resource/other"} }},
		{name: "prm-host-header", req: func(hub) req { return req{Path: prmPath, Header: hdrs("Host", "hub.example.org")} }},
		{name: "prm-forwarded-headers", req: func(hub) req {
			return req{Path: prmPath, Header: hdrs("X-Forwarded-Proto", "https", "X-Forwarded-Host", "hub.example.org")}
		}},
		{name: "prm-forwarded-standard-header", req: func(hub) req {
			return req{Path: prmPath, Header: hdrs("Forwarded", "proto=https;host=hub.example.org")}
		}},
		{name: "401-resource-metadata-with-host-header", known: knMalformed, req: func(hub) req {
			return req{Path: hubPath + "?match=x", Header: hdrs("Host", "hub.example.org", "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x")}
		}},
		{name: "401-resource-metadata-forwarded", req: func(hub) req { // forwarding headers are ignored by both (Gossiper trusts them only with --trust-forwarded-proto)
			return publishReq(pubForm(topic), "", hdrs("X-Forwarded-Proto", "https", "X-Forwarded-Host", "hub.example.org"))
		}},
	})
}

// canonJSONMap parses a JSON object body (hub base replaced) for a structural comparison.
func jsonObject(h hub, body string) map[string]any {
	var m map[string]any
	_ = json.Unmarshal([]byte(strings.ReplaceAll(body, h.base, "<hub>")), &m)
	return m
}

// The protected resource metadata document: the same members with the same values (the order of arrays aside).
func TestModernProtectedResourceMetadata(t *testing.T) {
	ref := hubRefModern.do(req{Path: prmPath})
	refDoc := jsonObject(hubRefModern, ref.Body)
	t.Logf("reference: %s", ref.Body)
	if refDoc == nil {
		t.Fatalf("the reference sent no JSON document: %d %q", ref.Status, ref.Body)
	}
	for _, h := range modernHubs {
		h := h
		t.Run(h.name, func(t *testing.T) {
			got := h.do(req{Path: prmPath})
			t.Logf("%s: %s", h.name, got.Body)
			eq(t, "status", http.StatusText(got.Status), http.StatusText(ref.Status))
			eq(t, "Content-Type", got.Header.Get("Content-Type"), ref.Header.Get("Content-Type"))
			doc := jsonObject(h, got.Body)
			if doc == nil {
				t.Fatalf("not JSON: %q", got.Body)
			}
			c := &cmp{t: t, hubName: h.name, known: knPRM}
			keys := map[string]bool{}
			for k := range refDoc {
				keys[k] = true
			}
			for k := range doc {
				keys[k] = true
			}
			var names []string
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				g, r := doc[k], refDoc[k]
				norm := func(v any) any {
					if a, ok := v.([]any); ok {
						s := make([]string, len(a))
						for i, x := range a {
							s[i], _ = x.(string)
						}
						sort.Strings(s)
						return s
					}
					return v
				}
				if !reflect.DeepEqual(norm(g), norm(r)) {
					gb, _ := json.Marshal(g)
					rb, _ := json.Marshal(r)
					c.add("prm:"+k, "metadata member "+k, string(rb), string(gb), false)
				}
			}
		})
	}
}

var knPRM = kn("Gossiper adds mercure_matcher_types_supported (the matcher types it supports); the reference does not list them", "prm:mercure_matcher_types_supported")

// ---------------------------------------------------------------------------------------------------------
// Mercure 1.0 scenarios: frames compared with the Mercure 1.0 reference.

func TestModernScenarios(t *testing.T) {
	T := "{{ns}}/a"
	M := func(s scenario) scenario { s.Modern = true; return s }
	ctx := func(s scenario) scenario { return s }
	_ = ctx
	var all []scenario
	add := func(ss ...scenario) {
		for _, s := range ss {
			all = append(all, M(s))
		}
	}
	pubs := func(topic string, datas ...string) []pub {
		var p []pub
		for _, d := range datas {
			p = append(p, pub{Topics: []string{topic}, Data: d})
		}
		return p
	}
	add(
		scenario{Name: "public-match", Topics: []string{T}, Post: pubs(T, "hello"), WantData: []string{"hello"}},
		scenario{Name: "public-match-exact", Topics: []string{T}, Param: "match_exact", Post: pubs(T, "hello", "again"), WantData: []string{"hello", "again"}},
		scenario{Name: "match-exact-is-not-a-pattern", Topics: []string{"{{ns}}/books/:id"}, Param: "match_exact", Sentinel: "{{ns}}/books/:id",
			Post: []pub{{Topics: []string{"{{ns}}/books/1"}, Data: "no"}, {Topics: []string{"{{ns}}/books/:id"}, Data: "literal"}}, WantData: []string{"literal"}},
		scenario{Name: "match-is-exact-not-pattern", Topics: []string{"{{ns}}/books/:id"}, Sentinel: "{{ns}}/books/:id",
			Post: []pub{{Topics: []string{"{{ns}}/books/1"}, Data: "no"}, {Topics: []string{"{{ns}}/books/:id"}, Data: "literal"}}, WantData: []string{"literal"}},
		scenario{Name: "match-legacy-template-is-literal", Topics: []string{"{{ns}}/books/{id}"}, Sentinel: "{{ns}}/books/{id}",
			Post: []pub{{Topics: []string{"{{ns}}/books/1"}, Data: "no"}, {Topics: []string{"{{ns}}/books/{id}"}, Data: "literal"}}, WantData: []string{"literal"}},
		scenario{Name: "urlpattern-named-group", Params: []string{"match_urlpattern={{ns}}/books/:id"}, Sentinel: "{{ns}}/books/end",
			Post: []pub{
				{Topics: []string{"{{ns}}/books/1"}, Data: "match"},
				{Topics: []string{"{{ns}}/books/1/chapters"}, Data: "no-nested"},
				{Topics: []string{"{{ns}}/books"}, Data: "no-parent"},
				{Topics: []string{"{{ns}}/other/1"}, Data: "no-other"},
				{Topics: []string{"{{ns}}/books/a%20b"}, Data: "encoded"},
			}, WantData: []string{"match", "encoded"}},
		scenario{Name: "urlpattern-wildcard", Params: []string{"match_urlpattern={{ns}}/files/*"}, Sentinel: "{{ns}}/files/end",
			Post: []pub{
				{Topics: []string{"{{ns}}/files/a"}, Data: "a"},
				{Topics: []string{"{{ns}}/files/a/b/c.txt"}, Data: "deep"},
				{Topics: []string{"{{ns}}/files"}, Data: "no-bare"},
				{Topics: []string{"{{ns}}/other"}, Data: "no"},
			}, WantData: []string{"a", "deep"}},
		scenario{Name: "urlpattern-regexp-group", Params: []string{"match_urlpattern={{ns}}/n/(\\d+)"}, Sentinel: "{{ns}}/n/0",
			Post: []pub{
				{Topics: []string{"{{ns}}/n/42"}, Data: "num"},
				{Topics: []string{"{{ns}}/n/abc"}, Data: "no-alpha"},
				{Topics: []string{"{{ns}}/n/4/2"}, Data: "no-two-segments"},
			}, WantData: []string{"num"}},
		scenario{Name: "urlpattern-optional-and-modifiers", Params: []string{"match_urlpattern={{ns}}/opt/:a{/:b}?"}, Sentinel: "{{ns}}/opt/end",
			Post: []pub{
				{Topics: []string{"{{ns}}/opt/x"}, Data: "one"},
				{Topics: []string{"{{ns}}/opt/x/y"}, Data: "two"},
				{Topics: []string{"{{ns}}/opt/x/y/z"}, Data: "no-three"},
			}, WantData: []string{"one", "two"}},
		scenario{Name: "urlpattern-star-everything", Params: []string{"match_urlpattern=*"}, Sentinel: "{{ns}}/z",
			Post: []pub{
				{Topics: []string{"{{ns}}/x"}, Data: "x"},
				{Topics: []string{"https://other.test/y"}, Data: "y"},
				{Topics: []string{"{{ns}}/x"}, Data: "priv", Private: true},
			}, WantData: []string{"x", "y"}},
		scenario{Name: "urlpattern-scheme-and-host-wildcards", Params: []string{"match_urlpattern=*://compat.test/*"}, Sentinel: "{{ns}}/z",
			Post: []pub{{Topics: []string{"{{ns}}/x"}, Data: "x"}, {Topics: []string{"https://other.test/y"}, Data: "no"}}, WantData: []string{"x"}},
		scenario{Name: "match-star-is-the-wildcard", Topics: []string{"*"}, Sentinel: "{{ns}}/z",
			Post: []pub{{Topics: []string{"{{ns}}/x"}, Data: "x"}, {Topics: []string{"https://other.test/y"}, Data: "y"}, {Topics: []string{"{{ns}}/x"}, Data: "priv", Private: true}}, WantData: []string{"x", "y"}},
		scenario{Name: "mixed-matchers-one-subscription", Topics: []string{"{{ns}}/exact"}, Params: []string{"match_exact={{ns}}/exact2", "match_urlpattern={{ns}}/p/:x"}, Sentinel: "{{ns}}/exact",
			Post: []pub{
				{Topics: []string{"{{ns}}/exact2"}, Data: "e2"},
				{Topics: []string{"{{ns}}/p/1"}, Data: "p1"},
				{Topics: []string{"{{ns}}/nothing"}, Data: "no"},
			}, WantData: []string{"e2", "p1"}},
		scenario{Name: "update-matching-two-selectors-delivered-once", Topics: []string{"{{ns}}/a"}, Params: []string{"match_urlpattern={{ns}}/*"}, Sentinel: "{{ns}}/zz",
			Post: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "once"}}, WantData: []string{"once"}},
		scenario{Name: "duplicate-matches", Topics: []string{T, T}, Post: pubs(T, "once"), WantData: []string{"once"}},
		// fields
		scenario{Name: "id-type-retry", Topics: []string{T}, Known: kn("retry=0: Gossiper sends \"retry: 0\", the reference drops it (zero value = unset)", "frame.retry"),
			Post: []pub{
				{Topics: []string{T}, Data: "typed", ID: "my-id-{{rid}}", Type: "custom", Retry: "2500"},
				{Topics: []string{T}, Data: "only-retry", Retry: "0"},
				{Topics: []string{T}, Data: "only-type", Type: "message"},
			}},
		scenario{Name: "multiline-and-unicode", Topics: []string{T},
			Post: []pub{
				{Topics: []string{T}, Data: "one\ntwo\r\nthree"},
				{Topics: []string{T}, Data: "lone-cr\rline"},
				{Topics: []string{T}, Data: ""},
				{Topics: []string{T}, NoData: true},
				{Topics: []string{T}, Data: "héllo 世界 \U0001F389 \u2028\u2029 \u0085 end", Type: "événement"},
				{Topics: []string{T}, Data: "zero\u200bwidth \u202e rlo \ufeff bom"},
			}},
		// private updates
		scenario{Name: "private-anonymous-filtered", Topics: []string{T},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}}, WantData: []string{"public"}},
		scenario{Name: "private-exact-grant", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}}, WantData: []string{"secret", "public"}},
		scenario{Name: "private-urlpattern-grant", Topics: []string{T}, Auth: &auth{Patterns: []string{"{{ns}}/*"}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}}, WantData: []string{"secret"}},
		scenario{Name: "private-urlpattern-grant-not-matching", Topics: []string{T}, Auth: &auth{Patterns: []string{"{{ns}}/other/*"}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}}, WantData: []string{"public"}},
		scenario{Name: "private-exact-grant-other-topic", Topics: []string{T}, Auth: &auth{Subscribe: []string{"{{ns}}/other"}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}}, WantData: []string{"public"}},
		scenario{Name: "private-grant-star-pattern", Topics: []string{T}, Auth: &auth{Patterns: []string{"*"}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}}, WantData: []string{"secret"}},
		scenario{Name: "private-grant-exact-star-literal", Topics: []string{T}, Auth: &auth{Subscribe: []string{"*"}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}}},
		scenario{Name: "private-grant-via-cookie", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}, Via: "cookie"},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}}, WantData: []string{"secret"}},
		scenario{Name: "private-grant-with-payload", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}, Payload: map[string]any{"user": "alice"}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}}, WantData: []string{"secret"}},
		// alternate topics: an update's canonical and alternate topics and the grant
		scenario{Name: "alt-topics-grant-for-alternate-only", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/b"}},
			Post: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi", Private: true}}, WantData: []string{"multi"}},
		scenario{Name: "alt-topics-grant-for-canonical-only", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/a"}},
			Post: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi", Private: true}, {Topics: []string{"{{ns}}/b"}, Data: "pub"}}, WantData: []string{"multi", "pub"}},
		scenario{Name: "alt-topics-grant-for-neither", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/c"}},
			Post: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi", Private: true}, {Topics: []string{"{{ns}}/b"}, Data: "pub"}}, WantData: []string{"pub"}},
		scenario{Name: "alt-topics-pattern-grant-covers-alternate", Params: []string{"match_urlpattern={{ns}}/x/*"}, Auth: &auth{Patterns: []string{"{{ns}}/alt/*"}}, Sentinel: "{{ns}}/x/end",
			Post: []pub{{Topics: []string{"{{ns}}/x/1", "{{ns}}/alt/1"}, Data: "multi", Private: true}, {Topics: []string{"{{ns}}/x/2"}, Data: "priv-no-alt", Private: true}}, WantData: []string{"multi"}},
		scenario{Name: "alt-topics-subscribe-to-alternate-grant-on-canonical-pattern", Topics: []string{"{{ns}}/alt/1"}, Auth: &auth{Patterns: []string{"{{ns}}/x/*"}},
			Post: []pub{{Topics: []string{"{{ns}}/x/1", "{{ns}}/alt/1"}, Data: "multi", Private: true}, {Topics: []string{"{{ns}}/alt/1"}, Data: "pub"}}, WantData: []string{"multi", "pub"}},
		scenario{Name: "alt-topics-two-grants-each-one-topic", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/a", "{{ns}}/c"}},
			Post: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b", "{{ns}}/c"}, Data: "multi", Private: true}}, WantData: []string{"multi"}},
		scenario{Name: "multi-topic-update-subscriber-on-alternate", Topics: []string{"{{ns}}/b"},
			Post: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi"}}, WantData: []string{"multi"}},
		// QUERY
		scenario{Name: "query-method-public", QueryM: true, Topics: []string{T}, Post: pubs(T, "via QUERY"), WantData: []string{"via QUERY"}},
		scenario{Name: "query-method-urlpattern", QueryM: true, Params: []string{"match_urlpattern={{ns}}/q/:id"}, Sentinel: "{{ns}}/q/end",
			Post: []pub{{Topics: []string{"{{ns}}/q/1"}, Data: "one"}, {Topics: []string{"{{ns}}/q/1/x"}, Data: "no"}}, WantData: []string{"one"}},
		scenario{Name: "query-method-private-with-token", QueryM: true, Topics: []string{T}, Auth: &auth{Subscribe: []string{T}},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}}, WantData: []string{"secret"}},
		scenario{Name: "query-method-private-anonymous", QueryM: true, Topics: []string{T},
			Post: []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}}, WantData: []string{"public"}},
		scenario{Name: "query-method-replay", QueryM: true, Topics: []string{T}, Query: "last_event_id={{id:0}}",
			Pre: pubs(T, "p0", "p1", "p2"), Post: pubs(T, "live"), WantData: []string{"p1", "p2", "live"}},
	)
	// replay
	pre := pubs(T, "p0", "p1", "p2")
	live := pubs(T, "live")
	add(
		scenario{Name: "replay-last_event_id-query", Pre: pre, Topics: []string{T}, Query: "last_event_id={{id:0}}", Post: live, WantData: []string{"p1", "p2", "live"}},
		scenario{Name: "replay-Last-Event-ID-header", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "{{id:0}}"}, Post: live, WantData: []string{"p1", "p2", "live"}},
		scenario{Name: "replay-from-last-event", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "{{id:2}}"}, Post: live, WantData: []string{"live"}},
		scenario{Name: "replay-earliest-query", Pre: pre, Topics: []string{T}, Query: "last_event_id=earliest", Post: live, WantData: []string{"p0", "p1", "p2", "live"}},
		scenario{Name: "replay-earliest-header", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "earliest"}, Post: live, WantData: []string{"p0", "p1", "p2", "live"}},
		scenario{Name: "replay-unknown-id-header", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "urn:uuid:00000000-0000-7000-8000-000000000000"}, Post: live},
		scenario{Name: "replay-unknown-id-query", Pre: pre, Topics: []string{T}, Query: "last_event_id=does-not-exist", Post: live},
		scenario{Name: "replay-header-and-query-both", Pre: pre, Topics: []string{T}, Query: "last_event_id={{id:1}}", Header: map[string]string{"Last-Event-ID": "{{id:0}}"}, Post: live},
		scenario{Name: "replay-private-filtered-anonymous", Topics: []string{T}, Query: "last_event_id={{id:0}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"p2", "live"}},
		scenario{Name: "replay-private-with-grant", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}}, Query: "last_event_id={{id:0}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"secret", "p2", "live"}},
		scenario{Name: "replay-private-alternate-topic-grant", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/a"}}, Query: "last_event_id=earliest",
			Pre: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi", Private: true}, {Topics: []string{"{{ns}}/b"}, Data: "own", Private: true}}, Post: pubs("{{ns}}/b", "live"), WantData: []string{"multi", "live"}},
		scenario{Name: "replay-other-topics-excluded", Topics: []string{T}, Query: "last_event_id={{id:0}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{"{{ns}}/other"}, Data: "other"}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"p2", "live"}},
		scenario{Name: "replay-with-urlpattern", Params: []string{"match_urlpattern={{ns}}/books/:id"}, Query: "last_event_id={{id:0}}", Sentinel: "{{ns}}/books/end",
			Pre:  []pub{{Topics: []string{"{{ns}}/books/1"}, Data: "p0"}, {Topics: []string{"{{ns}}/books/2"}, Data: "p1"}, {Topics: []string{"{{ns}}/other"}, Data: "x"}},
			Post: []pub{{Topics: []string{"{{ns}}/books/3"}, Data: "live"}}, WantData: []string{"p1", "live"}},
		scenario{Name: "replay-custom-ids", Topics: []string{T}, Query: "last_event_id=first-{{rid}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0", ID: "first-{{rid}}"}, {Topics: []string{T}, Data: "p1", ID: "second-{{rid}}"}}, WantData: []string{"p1", "live"}},
		scenario{Name: "replay-preserves-fields", Topics: []string{T}, Query: "last_event_id=earliest", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "m\nn", Type: "t1", Retry: "100", ID: "id1-{{rid}}"}}, WantData: []string{"m\nn", "live"}},
		scenario{Name: "replay-multi-topic-update-once", Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Query: "last_event_id=earliest", Post: live,
			Pre: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi"}}, WantData: []string{"multi", "live"}},
		scenario{Name: "replay-legacy-query-name", Known: kn("the draft-07 query name lastEventID: the reference ignores it, Gossiper honours it", "header:Mercure-Last-Event-ID", "header:Last-Event-ID", "frames.count", "frame.id", "frame.data"),
			Pre: pre, Topics: []string{T}, Query: "lastEventID={{id:0}}", Post: live},
	)
	for _, h := range modernHubs {
		h := h
		t.Run(h.name, func(t *testing.T) {
			for _, sc := range all {
				sc := sc
				if h == hubSC {
					sc.Known = mergeKnown(sc.Known, kn("the default Gossiper also sends the draft-07 response header Last-Event-ID", "header:Last-Event-ID"))
				}
				t.Run(sc.Name, func(t *testing.T) { runDifferential(t, h, sc) })
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------------------
// Mercure 1.0 subscription events and API.

func openModernSubscribers(t *testing.T, h hub, base string) (anon, withPayload *sseStream) {
	t.Helper()
	var err error
	anon, err = h.stream(hubPath+"?match="+url.QueryEscape(base+"/x")+"&match_urlpattern="+url.QueryEscape(base+"/:id"), nil)
	if err != nil || anon.Status != 200 {
		t.Fatalf("%s: anonymous subscriber: %v %+v", h.name, err, anon)
	}
	tok := newAT(h, subDetail(map[string]any{"user": "carol", "n": 3}, ex(base+"/z"))).String()
	withPayload, err = h.stream(hubPath+"?match_exact="+url.QueryEscape(base+"/z"), authz(tok))
	if err != nil || withPayload.Status != 200 {
		t.Fatalf("%s: token subscriber: %v %+v", h.name, err, withPayload)
	}
	time.Sleep(400 * time.Millisecond)
	return
}

func TestModernSubscriptionsAPI(t *testing.T) {
	base := ns("m/subsapi")
	admin := func(h hub) string {
		return newAT(h, subDetail(nil, up("/.well-known/mercure/subscriptions*"))).String()
	}
	for _, h := range modernHubs {
		h := h
		t.Run(h.name, func(t *testing.T) {
			a1, b1 := openModernSubscribers(t, h, base)
			defer a1.Close()
			defer b1.Close()
			a2, b2 := openModernSubscribers(t, hubRefModern, base)
			defer a2.Close()
			defer b2.Close()

			enc := func(s string) string { return url.PathEscape(s) }
			ids := func(h hub) (anon, tok string) {
				find := func(path string) string {
					r := h.do(req{Path: path, Header: authz(admin(h))})
					var doc struct {
						Subscriptions []struct{ Subscriber string }
					}
					_ = json.Unmarshal([]byte(r.Body), &doc)
					if len(doc.Subscriptions) == 1 {
						return doc.Subscriptions[0].Subscriber
					}
					return ""
				}
				return find(subsPath + "/exact/" + enc(base+"/x")), find(subsPath + "/exact/" + enc(base+"/z"))
			}
			gotAnon, gotTok := ids(h)
			refAnon, refTok := ids(hubRefModern)
			if gotAnon == "" || gotTok == "" || refAnon == "" || refTok == "" {
				t.Fatalf("subscriber ids not found: %q %q %q %q", gotAnon, gotTok, refAnon, refTok)
			}
			type c struct {
				name string
				req  func(h hub, anon, tok string) req
			}
			a := func(h hub) map[string]string { return authz(admin(h)) }
			cases := []c{
				{"no-token", func(h hub, an, tk string) req { return req{Path: subsPath} }},
				{"garbage-token", func(h hub, an, tk string) req { return req{Path: subsPath, Header: authz("garbage")} }},
				{"wrong-aud", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: authz(newAT(h, subDetail(nil, up("*"))).claim("aud", "https://other.test/x").String())}
				}},
				{"other-grant", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: authz(newAT(h, subDetail(nil, up("https://other.test/*"))).String())}
				}},
				{"publish-only-grant", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: authz(newAT(h, pubDetail(up("*"))).String())}
				}},
				{"legacy-token", func(h hub, an, tk string) req { return req{Path: subsPath, Header: authz(subToken("*"))} }},
				{"exact-collection-grant", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: authz(newAT(h, subDetail(nil, ex(subsPath))).String())}
				}},
				{"star-grant", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: authz(newAT(h, subDetail(nil, up("*"))).String())}
				}},
				{"collection", func(h hub, an, tk string) req { return req{Path: subsPath, Header: a(h)} }},
				{"collection-cookie", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: hdrs("Cookie", modernCookie+"="+admin(h))}
				}},
				{"collection-query-authorization", func(h hub, an, tk string) req {
					return req{Path: subsPath + "?authorization=" + url.QueryEscape(admin(h))}
				}},
				{"collection-head", func(h hub, an, tk string) req { return req{Method: http.MethodHead, Path: subsPath, Header: a(h)} }},
				{"collection-post", func(h hub, an, tk string) req { return req{Method: http.MethodPost, Path: subsPath, Header: a(h)} }},
				{"collection-trailing-slash", func(h hub, an, tk string) req { return req{Path: subsPath + "/", Header: a(h)} }},
				{"collection-allowed-origin", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: hdrs("Authorization", bearer(admin(h)), "Origin", allowedOrigin)}
				}},
				{"collection-if-none-match", func(h hub, an, tk string) req {
					return req{Path: subsPath, Header: hdrs("Authorization", bearer(admin(h)), "If-None-Match", `"x"`)}
				}},
				{"by-type-exact", func(h hub, an, tk string) req { return req{Path: subsPath + "/exact", Header: a(h)} }},
				{"by-type-urlpattern", func(h hub, an, tk string) req { return req{Path: subsPath + "/urlpattern", Header: a(h)} }},
				{"by-type-unknown", func(h hub, an, tk string) req { return req{Path: subsPath + "/regexp", Header: a(h)} }},
				{"by-match-exact", func(h hub, an, tk string) req { return req{Path: subsPath + "/exact/" + enc(base+"/x"), Header: a(h)} }},
				{"by-match-urlpattern", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/urlpattern/" + enc(base+"/:id"), Header: a(h)}
				}},
				{"by-match-payload", func(h hub, an, tk string) req { return req{Path: subsPath + "/exact/" + enc(base+"/z"), Header: a(h)} }},
				{"by-match-unknown", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/exact/" + enc(base+"/none"), Header: a(h)}
				}},
				{"by-match-wrong-type", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/urlpattern/" + enc(base+"/x"), Header: a(h)}
				}},
				{"by-match-unknown-type", func(h hub, an, tk string) req { return req{Path: subsPath + "/regexp/" + enc(base+"/x"), Header: a(h)} }},
				{"subscription", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/exact/" + enc(base+"/x") + "/" + enc(an), Header: a(h)}
				}},
				{"subscription-urlpattern", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/urlpattern/" + enc(base+"/:id") + "/" + enc(an), Header: a(h)}
				}},
				{"subscription-with-payload", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/exact/" + enc(base+"/z") + "/" + enc(tk), Header: a(h)}
				}},
				{"subscription-unknown", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/exact/" + enc(base+"/x") + "/urn:uuid:00000000-0000-4000-8000-000000000000", Header: a(h)}
				}},
				{"subscription-narrow-grant", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/exact/" + enc(base+"/x") + "/" + enc(an), Header: authz(newAT(h, subDetail(nil, up(subsPath+"/exact/*"))).String())}
				}},
				{"subscription-narrow-grant-insufficient", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/exact/" + enc(base+"/x") + "/" + enc(an), Header: authz(newAT(h, subDetail(nil, up(subsPath+"/urlpattern/*"))).String())}
				}},
				{"legacy-two-segment-path", func(h hub, an, tk string) req {
					return req{Path: subsPath + "/" + enc(base+"/x") + "/" + enc(an), Header: a(h)}
				}},
				{"too-many-segments", func(h hub, an, tk string) req { return req{Path: subsPath + "/exact/a/b/c", Header: a(h)} }},
			}
			caseKnown := map[string]known{
				"collection-head":                kn("HEAD on the subscriptions API: reference 405, Gossiper answers like GET without a body", "*"),
				"collection-post":                knAllow,
				"collection-query-authorization": knLegacyAccepted,
				"legacy-token":                   knLegacyAccepted,
				"garbage-token":                  knMalformed,
				"by-type-unknown":                kn("/subscriptions/{unknown type}: the reference answers 404, Gossiper an empty collection", "status", "header:Content-Type", "header:Link", "body"),
				"by-match-unknown-type":          kn("/subscriptions/{unknown type}/{match}: the reference answers 400 (unsupported topic matcher type), Gossiper 404", "status", "header:Link", "body"),
				"legacy-two-segment-path":        kn("/subscriptions/{topic}/{subscriber} (draft-07 shape) with a Mercure 1.0 token: the reference answers 400 (unsupported topic matcher type), Gossiper 404", "status", "header:Link", "body"),
			}
			for _, cs := range cases {
				cs := cs
				t.Run(cs.name, func(t *testing.T) {
					got := h.do(cs.req(h, gotAnon, gotTok))
					ref := hubRefModern.do(cs.req(hubRefModern, refAnon, refTok))
					t.Logf("reference %d, %s %d", ref.Status, h.name, got.Status)
					k := known{}
					if kk, ok := caseKnown[cs.name]; ok {
						if kk == nil || (h != hubSC && len(kk) == 1 && kk["*"] != "" && strings.Contains(kk["*"], "default Gossiper")) {
						} else {
							k = kk
						}
					}
					c := &cmp{t: t, hubName: h.name, known: k, modern: true, gotBase: h.base, refBase: hubRefModern.base}
					c.resp(got, ref, false)
					if g, r := canonSubBody(got.Body), canonSubBody(ref.Body); g != r {
						c.add("body", "body", r, g, !(isJSONObject(got.Body) && isJSONObject(ref.Body)))
					}
					t.Logf("body: %s", canonSubBody(got.Body))
				})
			}
		})
	}
}

func isJSONObject(s string) bool {
	var m map[string]any
	return json.Unmarshal([]byte(s), &m) == nil
}

// modernSubscriptionEvents: A watches the subscription topics, B connects (two matchers, payload) and leaves.
func modernSubscriptionEvents(t *testing.T, h hub) ([]frame, *sseStream) {
	t.Helper()
	base := ns("m/subev")
	watch := up("/.well-known/mercure/subscriptions/*")
	a, err := h.stream(hubPath+"?match_urlpattern="+url.QueryEscape(subsPath+"/*")+"&match="+url.QueryEscape(base+"/end"),
		authz(newAT(h, subDetail(nil, watch)).String()))
	if err != nil || a.Status != 200 {
		t.Fatalf("%s: watcher: %v %+v", h.name, err, a)
	}
	time.Sleep(400 * time.Millisecond)
	tok := newAT(h, subDetail(map[string]any{"user": "bob"}, ex(base+"/x"))).String()
	b, err := h.stream(hubPath+"?match_exact="+url.QueryEscape(base+"/x")+"&match_urlpattern="+url.QueryEscape(base+"/:id"), authz(tok))
	if err != nil || b.Status != 200 {
		t.Fatalf("%s: subscriber: %v %+v", h.name, err, b)
	}
	time.Sleep(400 * time.Millisecond)
	b.Close()
	time.Sleep(600 * time.Millisecond)
	pt := newAT(h, pubDetail(up("*"))).String()
	if r := h.do(publishReq(url.Values{"topic": {base + "/end"}, "data": {"END"}}, bearer(pt), nil)); r.Status != 200 {
		t.Fatalf("%s: END publish: %d", h.name, r.Status)
	}
	fs, ok := a.collect(8 * time.Second)
	if !ok {
		t.Fatalf("%s: END not received; frames %s", h.name, framesString(fs))
	}
	return fs, a
}

func normModernSubFrames(fs []frame) []frame {
	var out []frame
	for _, f := range fs {
		if !strings.Contains(f.Data, "subev") {
			continue
		}
		f.ID = normText(f.ID)
		f.Data = canonSubBody(f.Data)
		f.Raw = ""
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Data < out[j].Data })
	return out
}

func TestModernSubscriptionEvents(t *testing.T) {
	time.Sleep(time.Second)
	refFrames, refStream := modernSubscriptionEvents(t, hubRefModern)
	refStream.Close()
	if len(normModernSubFrames(refFrames)) == 0 {
		t.Fatal("the reference sent no subscription events")
	}
	t.Logf("reference: %s", framesString(normModernSubFrames(refFrames)))
	for _, h := range modernHubs {
		h := h
		t.Run(h.name, func(t *testing.T) {
			fs, s := modernSubscriptionEvents(t, h)
			defer s.Close()
			t.Logf("%s: %s", h.name, framesString(normModernSubFrames(fs)))
			(&cmp{t: t, hubName: h.name, known: known{}}).frames(normModernSubFrames(fs), normModernSubFrames(refFrames))
			for _, f := range fs {
				if strings.Contains(f.Data, "subev") {
					eq(t, "event type", f.Event, "mercure")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------------------
// The Symfony client for Mercure 1.0 (symfony/mercure 0.9): publishes with RFC 9068 access tokens.

type v1Stack struct {
	name string
	hub  hub
	app  string
}

var v1Stacks = []v1Stack{
	{"gossiper-both-symfony09", hubSC, appSC},
	{"gossiper-modern-symfony09", hubV1, appV1},
	{"reference-modern-symfony09", hubRefModern, appRefModern},
}

func phpPublishPath(t *testing.T, app, path string, q url.Values) (int, string) {
	t.Helper()
	res, err := client.Get(app + path + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b := make([]byte, 4096)
	n, _ := res.Body.Read(b)
	return res.StatusCode, strings.TrimSpace(string(b[:n]))
}

func TestSymfonyV1Client(t *testing.T) {
	type pc struct {
		name    string
		sub     func(h hub, ns string) (path string, hdr map[string]string)
		publish func(ns string) url.Values
		none    bool // the subscriber must not receive it
		check   func(t *testing.T, id string, f frame)
	}
	matchPath := func(h hub, topics ...string) string {
		q := url.Values{}
		for _, tp := range topics {
			q.Add("match", tp)
		}
		return hubPath + "?" + q.Encode()
	}
	cases := []pc{
		{name: "public", sub: func(h hub, ns string) (string, map[string]string) { return matchPath(h, ns+"/pub"), nil },
			publish: func(ns string) url.Values { return url.Values{"topic": {ns + "/pub"}, "data": {"hello"}} },
			check:   func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "hello"); eq(t, "id", f.ID, id) }},
		{name: "private-anonymous-must-not-receive", none: true,
			sub: func(h hub, ns string) (string, map[string]string) { return matchPath(h, ns+"/priv"), nil },
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/priv"}, "data": {"secret"}, "private": {"1"}}
			}},
		{name: "private-with-urlpattern-grant",
			sub: func(h hub, ns string) (string, map[string]string) {
				return matchPath(h, ns+"/priv"), authz(newAT(h, subDetail(nil, up(ns+"/*"))).String())
			},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/priv"}, "data": {"secret"}, "private": {"1"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "secret"); eq(t, "id", f.ID, id) }},
		{name: "private-grant-for-other-topic", none: true,
			sub: func(h hub, ns string) (string, map[string]string) {
				return matchPath(h, ns+"/priv"), authz(newAT(h, subDetail(nil, ex(ns+"/other"))).String())
			},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/priv"}, "data": {"secret"}, "private": {"1"}}
			}},
		{name: "multi-topic-private-grant-on-alternate",
			sub: func(h hub, ns string) (string, map[string]string) {
				return matchPath(h, ns+"/b"), authz(newAT(h, subDetail(nil, ex(ns+"/a"))).String())
			},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/a", ns + "/b"}, "data": {"both"}, "private": {"1"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "both") }},
		{name: "urlpattern-subscription",
			sub: func(h hub, ns string) (string, map[string]string) {
				return hubPath + "?match_urlpattern=" + url.QueryEscape(ns+"/books/:id"), nil
			},
			publish: func(ns string) url.Values { return url.Values{"topic": {ns + "/books/7"}, "data": {"pattern"}} },
			check:   func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "pattern") }},
		{name: "type-retry-id",
			sub: func(h hub, ns string) (string, map[string]string) { return matchPath(h, ns+"/t"), nil },
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/t"}, "data": {"typed"}, "id": {"my-id-" + runID}, "type": {"custom-type"}, "retry": {"4321"}}
			},
			check: func(t *testing.T, id string, f frame) {
				eq(t, "returned id", id, "my-id-"+runID)
				eq(t, "id", f.ID, "my-id-"+runID)
				eq(t, "event", f.Event, "custom-type")
				eq(t, "retry", f.Retry, "4321")
			}},
		{name: "multi-line-and-unicode",
			sub: func(h hub, ns string) (string, map[string]string) { return matchPath(h, ns+"/m"), nil },
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/m"}, "data": {"ligne un\nligne deux 世界 \U0001F389\n\nfin"}, "type": {"événement"}}
			},
			check: func(t *testing.T, id string, f frame) {
				eq(t, "data", f.Data, "ligne un\nligne deux 世界 \U0001F389\n\nfin")
				eq(t, "event", f.Event, "événement")
			}},
		{name: "empty-data",
			sub:     func(h hub, ns string) (string, map[string]string) { return matchPath(h, ns+"/e"), nil },
			publish: func(ns string) url.Values { return url.Values{"topic": {ns + "/e"}} },
			check:   func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, ""); eq(t, "id", f.ID, id) }},
	}
	got := map[string]map[string]frame{}
	for _, st := range v1Stacks {
		st := st
		got[st.name] = map[string]frame{}
		t.Run(st.name, func(t *testing.T) {
			for _, c := range cases {
				c := c
				t.Run(c.name, func(t *testing.T) {
					ns := "https://compat.test/" + runID + "/phpv1/" + st.name + "/" + c.name
					path, hdr := c.sub(st.hub, ns)
					s, err := st.hub.stream(path, hdr)
					if err != nil || s.Status != 200 {
						t.Fatalf("subscribe: %v %+v", err, s)
					}
					defer s.Close()
					time.Sleep(250 * time.Millisecond)
					code, id := phpPublishPath(t, st.app, "/v1/publish", c.publish(ns))
					if code != 200 || id == "" {
						t.Fatalf("PHP publish failed: %d %s", code, id)
					}
					if c.none {
						phpPublishPath(t, st.app, "/v1/publish", url.Values{"topic": {ns + "/" + path[strings.LastIndex(path, "/")+1:]}, "data": {"END"}})
						// the sentinel goes to the subscription's own topic
						return
					}
					f, ok := s.next(5 * time.Second)
					if !ok {
						t.Fatal("no event received")
					}
					t.Logf("frame: %s raw=%q", f, f.Raw)
					c.check(t, id, f)
					f.Raw = strings.ReplaceAll(f.Raw, id, "<id>")
					got[st.name][c.name] = f
				})
			}
		})
	}
	t.Run("same-frames-as-reference", func(t *testing.T) {
		for _, c := range cases {
			ref := got["reference-modern-symfony09"][c.name]
			for _, st := range v1Stacks[:2] {
				if g := got[st.name][c.name]; g.Raw != ref.Raw {
					t.Errorf("%s: %s wire frame %q, reference %q", c.name, st.name, g.Raw, ref.Raw)
				}
			}
		}
	})
}

// "none" cases: the subscriber must not get the private update. The sentinel needs the subscribed topic, so those
// cases are checked here separately.
func TestSymfonyV1PrivateNotDelivered(t *testing.T) {
	for _, st := range v1Stacks {
		st := st
		t.Run(st.name, func(t *testing.T) {
			ns := "https://compat.test/" + runID + "/phpv1/none/" + st.name
			for _, tc := range []struct {
				name string
				hdr  func(h hub) map[string]string
			}{
				{"anonymous", func(h hub) map[string]string { return nil }},
				{"grant-for-other-topic", func(h hub) map[string]string { return authz(newAT(h, subDetail(nil, ex(ns+"/other"))).String()) }},
				{"publish-only-grant", func(h hub) map[string]string { return authz(newAT(h, pubDetail(up("*"))).String()) }},
			} {
				s, err := st.hub.stream(hubPath+"?match="+url.QueryEscape(ns+"/"+tc.name), tc.hdr(st.hub))
				if err != nil || s.Status != 200 {
					t.Fatalf("%s: subscribe: %v %+v", tc.name, err, s)
				}
				time.Sleep(250 * time.Millisecond)
				phpPublishPath(t, st.app, "/v1/publish", url.Values{"topic": {ns + "/" + tc.name}, "data": {"secret"}, "private": {"1"}})
				phpPublishPath(t, st.app, "/v1/publish", url.Values{"topic": {ns + "/" + tc.name}, "data": {"END"}})
				fs, ok := s.collect(5 * time.Second)
				s.Close()
				if !ok || len(fs) != 0 {
					t.Errorf("%s: received %s (END seen: %v)", tc.name, framesString(fs), ok)
				}
			}
		})
	}
}

// The publisher's own grant is enforced: a Symfony token limited to one topic cannot publish to another.
func TestSymfonyV1PublisherGrants(t *testing.T) {
	for _, st := range v1Stacks {
		st := st
		t.Run(st.name, func(t *testing.T) {
			ns := "https://compat.test/" + runID + "/phpv1/grants/" + st.name
			for _, tc := range []struct {
				grant string
				topic string
				ok    bool
			}{
				{"exact:" + ns + "/a", ns + "/a", true},
				{"exact:" + ns + "/a", ns + "/b", false},
				{"urlpattern:" + ns + "/*", ns + "/zzz", true},
				{"urlpattern:" + ns + "/x/*", ns + "/y/1", false},
				{"urlpattern:https://other.test/*", ns + "/a", false},
			} {
				code, body := phpPublishPath(t, st.app, "/v1/publish", url.Values{"topic": {tc.topic}, "data": {"d"}, "grant": {tc.grant}})
				if (code == 200) != tc.ok {
					t.Errorf("grant %s topic %s: PHP answered %d %q, want ok=%v", tc.grant, tc.topic, code, body, tc.ok)
				}
			}
		})
	}
}

// /v1/discover: the Link header, and the access token that authorizes a private subscription as a cookie
// (__Secure-mercure_access_token; the library refuses to set it over plain HTTP, a raw client can still send it).
func TestSymfonyV1Discover(t *testing.T) {
	for _, st := range v1Stacks {
		st := st
		t.Run(st.name, func(t *testing.T) {
			ns := "https://compat.test/" + runID + "/phpv1/discover/" + st.name
			res, err := client.Get(st.app + "/v1/discover?subscribe=" + url.QueryEscape("urlpattern:"+ns+"/*"))
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var doc struct {
				Hub, CookieName, Token, CookieError string
			}
			b := make([]byte, 8192)
			n, _ := res.Body.Read(b)
			_ = json.Unmarshal(b[:n], &doc)
			if want := "<" + st.hub.resource() + ">; rel=\"mercure\""; res.Header.Get("Link") != want {
				t.Errorf("Link = %q, want %q", res.Header.Get("Link"), want)
			}
			eq(t, "cookie name", doc.CookieName, modernCookie)
			if doc.Token == "" {
				t.Fatalf("no token: %s", b[:n])
			}
			t.Logf("cookie error (expected on plain HTTP): %s", doc.CookieError)
			s, err := st.hub.stream(hubPath+"?match="+url.QueryEscape(ns+"/one"), map[string]string{"Cookie": modernCookie + "=" + doc.Token})
			if err != nil || s.Status != 200 {
				t.Fatalf("subscribe with the cookie: %v %+v", err, s)
			}
			defer s.Close()
			time.Sleep(250 * time.Millisecond)
			code, id := phpPublishPath(t, st.app, "/v1/publish", url.Values{"topic": {ns + "/one"}, "data": {"via cookie"}, "private": {"1"}})
			if code != 200 {
				t.Fatalf("publish: %d %s", code, id)
			}
			f, ok := s.next(5 * time.Second)
			if !ok {
				t.Fatal("the private update did not reach the cookie-authorized subscriber")
			}
			eq(t, "data", f.Data, "via cookie")
			eq(t, "id", f.ID, id)
		})
	}
}

// Browser-style checks (Node 24, `eventsource`, fetch) with the Mercure 1.0 protocol: ?match=, access tokens in the
// __Secure- cookie and as Bearer, QUERY, url patterns, last_event_id.
func TestJavaScriptModern(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	if _, err := os.Stat("js/node_modules/eventsource"); err != nil {
		cmd := exec.Command("npm", "install", "--no-audit", "--no-fund")
		cmd.Dir = "js"
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("npm install: %v\n%s", err, out)
		}
	}
	for _, st := range v1Stacks {
		st := st
		t.Run(st.name, func(t *testing.T) {
			cmd := exec.Command(node, "--test", "--test-timeout=20000", "check.mjs")
			cmd.Dir = "js"
			cmd.Env = append(os.Environ(), "MODERN=1", "HUB_URL="+st.hub.base, "APP_URL="+st.app)
			out, err := cmd.CombinedOutput()
			t.Logf("\n%s", out)
			if err != nil {
				t.Fatalf("node --test: %v", err)
			}
		})
	}
}
