//go:build compat

// Protocol-compatibility suite: Gossiper against the Mercure hub bundled in FrankenPHP (the reference).
//
// The stack must be up (see README.md):
//
//	docker compose -f test/compat/docker-compose.yml up -d --build
//	go test -tags compat -count=1 -v ./test/compat/
//
// Set COMPAT_UP=1 to have the test start the stack itself.
package compat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	if os.Getenv("COMPAT_UP") != "" {
		cmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "up", "-d", "--build", "--wait")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "docker compose up failed:", err)
			os.Exit(2)
		}
	}
	for _, h := range []hub{hubSC, hubModern, hubRef, hubV1, hubRefModern} {
		if !waitUp(h.base+hubPath, 90*time.Second) {
			fmt.Fprintf(os.Stderr, "%s is not up at %s; start the stack: docker compose -f test/compat/docker-compose.yml up -d --build\n", h.name, h.base)
			os.Exit(2)
		}
	}
	if !waitUp(appSC+"/info", 60*time.Second) {
		fmt.Fprintln(os.Stderr, "the PHP app is not up at", appSC)
		os.Exit(2)
	}
	code := m.Run()
	writeReport()
	os.Exit(code)
}

func waitUp(u string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		res, err := client.Get(u)
		if err == nil {
			res.Body.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// hubs compared with the reference in the raw and scenario tests; only the subscription events and API depend on the
// subscription format, those tests also run against the modern one.
var hubsUnderTest = []hub{hubSC}

// ---------------------------------------------------------------------------------------------------------
// (a) The Symfony Mercure client (PHP) publishing through the app, a Go SSE client receiving.

type stack struct {
	name string
	hub  hub
	app  string
}

var stacks = []stack{
	{"gossiper+symfony", hubSC, appSC},
	{"reference+symfony", hubRef, appRef},
}

func phpPublish(t *testing.T, app string, q url.Values) string {
	t.Helper()
	res, err := client.Get(app + "/publish?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b := make([]byte, 4096)
	n, _ := res.Body.Read(b)
	if res.StatusCode != 200 {
		t.Fatalf("PHP publish failed: %d %s", res.StatusCode, b[:n])
	}
	return strings.TrimSpace(string(b[:n]))
}

// phpCase publishes through Symfony and checks the frame a subscriber receives, on both stacks.
type phpCase struct {
	name      string
	subTopics []string
	sub       func(ns string) (query string, hdr map[string]string)
	publish   func(ns string) url.Values
	wantNone  bool // the subscriber must not receive it
	check     func(t *testing.T, id string, f frame)
}

func TestSymfonyClient(t *testing.T) {
	cases := []phpCase{
		{
			name: "public", subTopics: []string{"{ns}/pub"},
			publish: func(ns string) url.Values { return url.Values{"topic": {ns + "/pub"}, "data": {"hello"}} },
			check: func(t *testing.T, id string, f frame) {
				eq(t, "data", f.Data, "hello")
				eq(t, "id", f.ID, id)
				eq(t, "event", f.Event, "")
			},
		},
		{
			name: "private-anonymous-must-not-receive", subTopics: []string{"{ns}/priv"}, wantNone: true,
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/priv"}, "data": {"secret"}, "private": {"1"}}
			},
		},
		{
			name: "private-with-subscriber-token", subTopics: []string{"{ns}/priv"},
			sub: func(ns string) (string, map[string]string) {
				return "", map[string]string{"Authorization": bearer(subToken(ns + "/priv"))}
			},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/priv"}, "data": {"secret"}, "private": {"1"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "secret"); eq(t, "id", f.ID, id) },
		},
		{
			name: "private-token-for-other-topic", subTopics: []string{"{ns}/priv"}, wantNone: true,
			sub: func(ns string) (string, map[string]string) {
				return "", map[string]string{"Authorization": bearer(subToken(ns + "/other"))}
			},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/priv"}, "data": {"secret"}, "private": {"1"}}
			},
		},
		{
			name: "multi-topic", subTopics: []string{"{ns}/b"},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/a", ns + "/b"}, "data": {"both"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "both"); eq(t, "id", f.ID, id) },
		},
		{
			name: "type-retry-id", subTopics: []string{"{ns}/t"},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/t"}, "data": {"typed"}, "id": {"my-id-" + runID}, "type": {"custom-type"}, "retry": {"4321"}}
			},
			check: func(t *testing.T, id string, f frame) {
				eq(t, "returned id", id, "my-id-"+runID)
				eq(t, "id", f.ID, "my-id-"+runID)
				eq(t, "event", f.Event, "custom-type")
				eq(t, "retry", f.Retry, "4321")
				eq(t, "data", f.Data, "typed")
			},
		},
		{
			name: "multi-line-data", subTopics: []string{"{ns}/m"},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/m"}, "data": {"line one\nline two\n\nline four"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "line one\nline two\n\nline four") },
		},
		{
			name: "crlf-data", subTopics: []string{"{ns}/m"},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/m"}, "data": {"a\r\nb"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "a\nb") },
		},
		{
			name: "unicode", subTopics: []string{"{ns}/u"},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/u"}, "data": {"héllo wörld 世界 🎉   end"}, "type": {"événement"}}
			},
			check: func(t *testing.T, id string, f frame) {
				eq(t, "data", f.Data, "héllo wörld 世界 🎉   end")
				eq(t, "event", f.Event, "événement")
			},
		},
		{
			name: "unicode-topic-and-template", subTopics: []string{"{ns}/ü/{x}"},
			publish: func(ns string) url.Values {
				return url.Values{"topic": {ns + "/ü/abc"}, "data": {"ok"}}
			},
			check: func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, "ok") },
		},
		{
			name: "empty-data", subTopics: []string{"{ns}/e"},
			publish: func(ns string) url.Values { return url.Values{"topic": {ns + "/e"}} },
			check:   func(t *testing.T, id string, f frame) { eq(t, "data", f.Data, ""); eq(t, "id", f.ID, id) },
		},
	}
	got := map[string]map[string]frame{}
	for _, st := range stacks {
		st := st
		got[st.name] = map[string]frame{}
		t.Run(st.name, func(t *testing.T) {
			for _, c := range cases {
				c := c
				t.Run(c.name, func(t *testing.T) {
					ns := "https://compat.test/" + runID + "/php/" + st.name + "/" + c.name
					q := url.Values{}
					for _, tp := range c.subTopics {
						q.Add("topic", strings.ReplaceAll(tp, "{ns}", ns))
					}
					path := hubPath + "?" + q.Encode()
					var hdr map[string]string
					if c.sub != nil {
						extra, h := c.sub(ns)
						hdr = h
						if extra != "" {
							path += "&" + extra
						}
					}
					s, err := st.hub.stream(path, hdr)
					if err != nil || s.Status != 200 {
						t.Fatalf("subscribe: %v %+v", err, s)
					}
					defer s.Close()
					time.Sleep(250 * time.Millisecond)
					id := phpPublish(t, st.app, c.publish(ns))
					if id == "" {
						t.Fatal("PHP publish returned no id")
					}
					if c.wantNone {
						phpPublish(t, st.app, url.Values{"topic": {strings.ReplaceAll(c.subTopics[0], "{ns}", ns)}, "data": {"END"}})
						fs, _ := s.collect(5 * time.Second)
						if len(fs) != 0 {
							t.Fatalf("subscriber received what it must not: %s", framesString(fs))
						}
						return
					}
					f, ok := s.next(5 * time.Second)
					if !ok {
						t.Fatal("no event received")
					}
					t.Logf("frame: %s raw=%q", f, f.Raw)
					c.check(t, id, f)
					f.ID = "<id>"
					if c.name != "type-retry-id" {
						f.Raw = strings.ReplaceAll(f.Raw, id, "<id>")
					}
					got[st.name][c.name] = f
				})
			}
		})
	}
	// The frames Symfony's publishes produce must be identical on both hubs.
	t.Run("same-frames-as-reference", func(t *testing.T) {
		for _, c := range cases {
			a, b := got["gossiper+symfony"][c.name], got["reference+symfony"][c.name]
			if a.Raw != b.Raw {
				t.Errorf("%s: wire frames differ: gossiper=%q reference=%q", c.name, a.Raw, b.Raw)
			}
		}
	})
}

// kn builds a known-differences set: the fields all differ for the one reason.
func kn(reason string, fields ...string) known {
	k := known{}
	for _, f := range fields {
		k[f] = reason
	}
	return k
}

var knPreflight = kn("Gossiper answers CORS preflights for POST and echoes any (syntactically valid) request headers; the reference only grants GET preflights (publishing needs no preflight when it uses the cookie and a form body)",
	"header:Access-Control-Allow-Origin", "header:Access-Control-Allow-Credentials", "header:Access-Control-Allow-Methods", "header:Access-Control-Allow-Headers")

var (
	// An undecodable token: Gossiper classifies it as a malformed request (400 invalid_request, RFC 6750); the
	// reference answers 401 invalid_token for a token it can parse structurally but not decode, and for a bad cookie
	// or query token. Clients treat every 400/401 as "authentication failed".
	knBadTokenClass = kn("Gossiper: 400 invalid_request for a token that cannot be decoded; reference: 401 invalid_token", "status", "header:WWW-Authenticate")
	knBadTokenQuery = kn("Gossiper: 400 invalid_request for an undecodable token in the query; reference: 401 with a bare Bearer challenge", "status", "header:WWW-Authenticate")
)

func eq(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

// The /discover endpoint (Symfony Discovery + Authorization helpers): Link header and the authorization cookie.
func TestSymfonyDiscover(t *testing.T) {
	for _, st := range stacks {
		st := st
		t.Run(st.name, func(t *testing.T) {
			ns := "https://compat.test/" + runID + "/discover/" + st.name
			res, err := client.Get(st.app + "/discover?subscribe=" + url.QueryEscape(ns+"/{x}"))
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			link := res.Header.Get("Link")
			if want := "<" + st.hub.base + hubPath + ">; rel=\"mercure\""; link != want {
				t.Errorf("Link = %q, want %q", link, want)
			}
			var cookie string
			for _, c := range res.Cookies() {
				if c.Name == "mercureAuthorization" {
					cookie = c.Value
					if c.Path != hubPath || !c.HttpOnly {
						t.Errorf("cookie attributes: %+v", c)
					}
				}
			}
			if cookie == "" {
				t.Fatalf("no mercureAuthorization cookie: %v", res.Header)
			}
			// The cookie authorizes a private subscription at the hub (what a browser does).
			s, err := st.hub.stream(hubPath+"?topic="+url.QueryEscape(ns+"/{x}"), map[string]string{"Cookie": "mercureAuthorization=" + cookie})
			if err != nil || s.Status != 200 {
				t.Fatalf("subscribe with the cookie: %v %+v", err, s)
			}
			defer s.Close()
			time.Sleep(250 * time.Millisecond)
			id := phpPublish(t, st.app, url.Values{"topic": {ns + "/one"}, "data": {"via cookie"}, "private": {"1"}})
			f, ok := s.next(5 * time.Second)
			if !ok {
				t.Fatal("the private update did not reach the cookie-authorized subscriber")
			}
			eq(t, "data", f.Data, "via cookie")
			eq(t, "id", f.ID, id)
		})
	}
}

// ---------------------------------------------------------------------------------------------------------
// (b) Differential tests

type rawCase struct {
	name  string
	req   func() req
	known known
}

func ns(name string) string { return "https://compat.test/" + runID + "/" + name }

func pubForm(topic string, kv ...string) url.Values {
	v := url.Values{"topic": {topic}, "data": {"d"}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func runRaw(t *testing.T, cases []rawCase) {
	for _, h := range hubsUnderTest {
		h := h
		t.Run(h.name, func(t *testing.T) {
			for _, c := range cases {
				c := c
				t.Run(c.name, func(t *testing.T) { bothHubs(t, h, c.req(), c.known, true) })
			}
		})
	}
}

func TestPublishAuthMatrix(t *testing.T) {
	topic := ns("auth")
	other := ns("auth") + "/other"
	body := pubForm(topic)
	post := func(authz string, extra map[string]string) func() req {
		return func() req { return publishReq(body, authz, extra) }
	}
	now := time.Now()
	withExp := func(c jwt.MapClaims, exp time.Time) jwt.MapClaims { c["exp"] = exp.Unix(); return c }
	cookieReq := func(tok string, hdr map[string]string) func() req {
		return func() req {
			r := publishReq(body, "", hdr)
			r.Header["Cookie"] = "mercureAuthorization=" + tok
			return r
		}
	}
	good := pubToken("*")
	runRaw(t, []rawCase{
		{name: "no-token", req: post("", nil)},
		{name: "valid-publish-star", req: post(bearer(good), nil)},
		{name: "valid-publish-exact-topic", req: post(bearer(pubToken(topic)), nil)},
		{name: "valid-publish-template", req: post(bearer(pubToken(ns("auth")+"{/x}")), nil)},
		{name: "bad-signature-wrong-key", req: post(bearer(mintWith("another-secret-another-secret-123456", jwt.SigningMethodHS256, mercureClaims([]string{"*"}, nil))), nil)},
		{name: "malformed-garbage", req: post(bearer("not-a-jwt"), nil)},
		{name: "malformed-two-segments", req: post(bearer("aaa.bbb"), nil)},
		{name: "malformed-bad-base64-payload", known: knBadTokenClass, req: post(bearer(strings.Split(good, ".")[0]+".%%%."+strings.Split(good, ".")[2]), nil)},
		{name: "authorization-basic", req: post("Basic dXNlcjpwYXNz", nil)},
		{name: "authorization-token-without-bearer", known: kn("Gossiper accepts a bare JWT as the Authorization header value (no Bearer scheme); the reference answers 400 invalid_request", "status", "header:WWW-Authenticate"), req: post(good, nil)},
		{name: "authorization-lowercase-bearer", req: post("bearer "+good, nil)},
		{name: "expired", req: post(bearer(mint(withExp(mercureClaims([]string{"*"}, nil), now.Add(-time.Hour)))), nil)},
		{name: "not-expired", req: post(bearer(mint(withExp(mercureClaims([]string{"*"}, nil), now.Add(time.Hour)))), nil)},
		{name: "not-yet-valid-nbf", req: post(bearer(mint(func() jwt.MapClaims {
			c := mercureClaims([]string{"*"}, nil)
			c["nbf"] = now.Add(time.Hour).Unix()
			return c
		}())), nil)},
		{name: "alg-none", req: post(bearer(mintWith("", jwt.SigningMethodNone, mercureClaims([]string{"*"}, nil))), nil)},
		{name: "alg-HS512-with-the-key", req: post(bearer(mintWith(secret, jwt.SigningMethodHS512, mercureClaims([]string{"*"}, nil))), nil)},
		{name: "selector-for-other-topic", req: post(bearer(pubToken("https://other.test/{x}")), nil)},
		{name: "selector-exact-other-topic", req: post(bearer(pubToken(other)), nil)},
		{name: "empty-publish-array", req: post(bearer(pubToken()), nil)},
		{name: "no-publish-claim-subscribe-only", req: post(bearer(subToken("*")), nil)},
		{name: "no-mercure-claim", req: post(bearer(mint(jwt.MapClaims{"sub": "x"})), nil)},
		{name: "mercure-claim-empty-object", req: post(bearer(mint(jwt.MapClaims{"mercure": map[string]any{}})), nil)},
		{name: "publish-null", req: post(bearer(mint(jwt.MapClaims{"mercure": map[string]any{"publish": nil}})), nil)},
		{name: "publish-claim-is-string", req: post(bearer(mint(jwt.MapClaims{"mercure": map[string]any{"publish": "*"}})), nil)},
		{name: "publish-with-payload-and-subject", req: post(bearer(mint(jwt.MapClaims{"sub": "u1", "mercure": map[string]any{"publish": []string{"*"}, "payload": map[string]any{"a": 1}}})), nil)},
		{name: "multi-topic-one-unauthorized", req: func() req {
			v := url.Values{"topic": {topic, "https://other.test/x"}, "data": {"d"}}
			return publishReq(v, bearer(pubToken(topic)), nil)
		}},
		{name: "multi-topic-all-authorized", req: func() req {
			v := url.Values{"topic": {topic, other}, "data": {"d"}}
			return publishReq(v, bearer(pubToken(topic, other)), nil)
		}},
		{name: "private-update-with-publish-star", req: func() req {
			return publishReq(pubForm(topic, "private", "on"), bearer(good), nil)
		}},
		// cookie authorization (CSRF check)
		{name: "cookie-no-origin", req: cookieReq(good, nil)},
		{name: "cookie-allowed-origin", req: cookieReq(good, map[string]string{"Origin": allowedOrigin})},
		{name: "cookie-allowed-origin-trailing-slash", known: kn("Gossiper normalizes a trailing slash in the Origin header before checking publish_origins; the reference rejects it (such an Origin is not sent by browsers)", "status", "header:WWW-Authenticate", "header:Access-Control-Allow-Origin", "header:Access-Control-Allow-Credentials"), req: cookieReq(good, map[string]string{"Origin": allowedOrigin + "/"})},
		{name: "cookie-bad-origin", req: cookieReq(good, map[string]string{"Origin": badOrigin})},
		{name: "cookie-null-origin", req: cookieReq(good, map[string]string{"Origin": "null"})},
		{name: "cookie-referer-allowed", req: cookieReq(good, map[string]string{"Referer": allowedOrigin + "/page"})},
		{name: "cookie-referer-bad", req: cookieReq(good, map[string]string{"Referer": badOrigin + "/page"})},
		{name: "cookie-bad-origin-bad-token", req: cookieReq("garbage", map[string]string{"Origin": badOrigin})},
		{name: "cookie-allowed-origin-bad-token", known: knBadTokenClass, req: cookieReq("garbage", map[string]string{"Origin": allowedOrigin})},
		{name: "cookie-allowed-origin-wrong-key", req: cookieReq(mintWith("another-secret-another-secret-123456", jwt.SigningMethodHS256, mercureClaims([]string{"*"}, nil)), map[string]string{"Origin": allowedOrigin})},
		{name: "cookie-allowed-origin-no-publish-scope", req: cookieReq(pubToken(), map[string]string{"Origin": allowedOrigin})},
		{name: "cookie-allowed-origin-other-topic", req: cookieReq(pubToken("https://other.test/{x}"), map[string]string{"Origin": allowedOrigin})},
		{name: "bearer-with-bad-origin", req: post(bearer(good), map[string]string{"Origin": badOrigin})},
		{name: "bearer-with-allowed-origin", req: post(bearer(good), map[string]string{"Origin": allowedOrigin})},
		// authorization query parameter
		{name: "query-authorization-valid", req: func() req {
			r := publishReq(body, "", nil)
			r.Path += "?authorization=" + url.QueryEscape(good)
			return r
		}},
		{name: "query-authorization-bad", known: knBadTokenQuery, req: func() req {
			r := publishReq(body, "", nil)
			r.Path += "?authorization=garbage"
			return r
		}},
		{name: "query-authorization-no-publish", req: func() req {
			r := publishReq(body, "", nil)
			r.Path += "?authorization=" + url.QueryEscape(pubToken())
			return r
		}},
		// precedence between the sources
		{name: "header-bad-cookie-good", req: func() req {
			r := publishReq(body, bearer("garbage"), map[string]string{"Origin": allowedOrigin})
			r.Header["Cookie"] = "mercureAuthorization=" + good
			return r
		}},
		{name: "header-good-cookie-bad", req: func() req {
			r := publishReq(body, bearer(good), map[string]string{"Origin": allowedOrigin})
			r.Header["Cookie"] = "mercureAuthorization=garbage"
			return r
		}},
		{name: "query-good-header-bad", req: func() req {
			r := publishReq(body, bearer("garbage"), nil)
			r.Path += "?authorization=" + url.QueryEscape(good)
			return r
		}},
		{name: "cookie-and-valid-header-bad-origin", req: func() req {
			r := publishReq(body, bearer(good), map[string]string{"Origin": badOrigin})
			r.Header["Cookie"] = "mercureAuthorization=" + good
			return r
		}},
	})
}

func TestPublishValidation(t *testing.T) {
	topic := ns("valid")
	tok := bearer(pubToken("*"))
	p := func(v url.Values) func() req { return func() req { return publishReq(v, tok, nil) } }
	raw := func(contentType, body string) func() req {
		return func() req {
			h := map[string]string{"Authorization": tok}
			if contentType != "" {
				h["Content-Type"] = contentType
			}
			return req{Method: http.MethodPost, Path: hubPath, Header: h, Body: body}
		}
	}
	method := func(m string) func() req {
		return func() req {
			return req{Method: m, Path: hubPath, Header: map[string]string{"Authorization": tok, "Content-Type": "application/x-www-form-urlencoded"}, Body: pubForm(topic).Encode()}
		}
	}
	runRaw(t, []rawCase{
		{name: "ok-minimal", req: p(url.Values{"topic": {topic}})},
		{name: "ok-all-fields", req: p(pubForm(topic, "id", "id-"+runID+"-1", "type", "t", "retry", "100", "private", "on"))},
		{name: "ok-private-empty-value", req: p(pubForm(topic, "private", ""))},
		{name: "ok-private-false-value", req: p(pubForm(topic, "private", "false"))},
		{name: "ok-private-zero-value", req: p(pubForm(topic, "private", "0"))},
		{name: "ok-empty-data", req: p(url.Values{"topic": {topic}, "data": {""}})},
		{name: "ok-no-data-param", req: p(url.Values{"topic": {topic}})},
		{name: "ok-id-with-spaces-and-unicode", req: p(pubForm(topic, "id", "id é "+runID))},
		{name: "ok-id-numeric", req: p(pubForm(topic, "id", "12345"))},
		{name: "ok-retry-zero", req: p(pubForm(topic, "retry", "0"))},
		{name: "ok-topic-with-unicode-and-query", req: p(pubForm(topic + "/é?a=b&c=d#frag"))},
		{name: "ok-relative-topic", req: p(pubForm("relative-topic"))},
		{name: "ok-many-alternate-topics", req: p(url.Values{"topic": {topic, topic + "/2", topic + "/3"}, "data": {"x"}})},
		{name: "ok-data-with-newlines", req: p(pubForm(topic, "data", "a\nb\r\nc"))},
		{name: "ok-data-binary-ish", req: p(pubForm(topic, "data", "tab\there \"quotes\" <html> & 100%"))},
		{name: "missing-topic", req: p(url.Values{"data": {"x"}})},
		{name: "empty-topic", known: kn("topic= (empty) opens a stream on the reference; Gossiper refuses it (400)", "status", "header:Content-Type"), req: p(url.Values{"topic": {""}, "data": {"x"}})},
		{name: "empty-body", req: raw("application/x-www-form-urlencoded", "")},
		{name: "id-earliest", req: p(pubForm(topic, "id", "earliest"))},
		{name: "id-with-newline", req: p(pubForm(topic, "id", "a\nb"))},
		{name: "id-with-cr", req: p(pubForm(topic, "id", "a\rb"))},
		{name: "id-starting-with-hash", req: p(pubForm(topic, "id", "#abc"))},
		{name: "id-too-long", known: kn("an id over 1 KiB: Gossiper answers 413, the reference 400 (both refuse it)", "status"), req: p(pubForm(topic, "id", strings.Repeat("x", 3000)))},
		{name: "retry-not-a-number", req: p(pubForm(topic, "retry", "abc"))},
		{name: "retry-negative", req: p(pubForm(topic, "retry", "-1"))},
		{name: "retry-float", req: p(pubForm(topic, "retry", "1.5"))},
		{name: "retry-empty", known: kn("an empty retry= is ignored by the reference and rejected (400) by Gossiper; the Symfony client never sends it", "status"), req: p(pubForm(topic, "retry", ""))},
		{name: "retry-huge", req: p(pubForm(topic, "retry", "99999999999999999999999"))},
		{name: "retry-plus-sign", req: p(pubForm(topic, "retry", "+5"))},
		{name: "type-with-newline", req: p(pubForm(topic, "type", "a\nb"))},
		{name: "type-too-long", known: kn("Gossiper limits \"type\" to 256 bytes (413 or 400 depending on the version); the reference accepts any length", "status"), req: p(pubForm(topic, "type", strings.Repeat("t", 2000)))},
		{name: "topic-with-newline", req: p(pubForm(topic + "\nx"))},
		{name: "topic-in-reserved-subscriptions-namespace", req: p(pubForm("/.well-known/mercure/subscriptions/a/b"))},
		{name: "data-not-utf8", req: raw("application/x-www-form-urlencoded", "topic=x&data=%ff%fe")},
		{name: "body-1.5MB", req: p(pubForm(topic, "data", strings.Repeat("x", 1_500_000)))},
		{name: "content-type-json", req: raw("application/json", `{"topic":"x","data":"y"}`)},
		{name: "content-type-text-plain", req: raw("text/plain", "topic=x&data=y")},
		{name: "content-type-missing", req: raw("", "topic=x&data=y")},
		{name: "content-type-multipart", req: raw("multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"topic\"\r\n\r\nx\r\n--XX\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\ny\r\n--XX--\r\n")},
		{name: "topic-in-url-query-not-body", req: func() req {
			r := publishReq(url.Values{"data": {"y"}}, tok, nil)
			r.Path += "?topic=" + url.QueryEscape(topic)
			return r
		}},
		{name: "method-get-is-a-subscribe", req: method(http.MethodGet)},
		{name: "method-put", known: kn("Gossiper adds an Allow header to its 405", "header:Allow"), req: method(http.MethodPut)},
		{name: "method-patch", known: kn("Gossiper adds an Allow header to its 405", "header:Allow"), req: method(http.MethodPatch)},
		{name: "method-delete", known: kn("Gossiper adds an Allow header to its 405", "header:Allow"), req: method(http.MethodDelete)},
		{name: "method-head", req: method(http.MethodHead)},
		{name: "unknown-path", req: func() req { r := publishReq(pubForm(topic), tok, nil); r.Path = "/.well-known/mercure/nope"; return r }},
		{name: "path-without-well-known", req: func() req { r := publishReq(pubForm(topic), tok, nil); r.Path = "/"; return r }},
		{name: "trailing-slash", req: func() req { r := publishReq(pubForm(topic), tok, nil); r.Path = hubPath + "/"; return r }},
	})
}

func TestSubscribeRequests(t *testing.T) {
	topic := ns("subreq")
	q := func(extra ...string) string {
		v := url.Values{"topic": {topic}}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Add(extra[i], extra[i+1])
		}
		return hubPath + "?" + v.Encode()
	}
	get := func(path string, hdr map[string]string) func() req {
		return func() req { return req{Path: path, Header: hdr} }
	}
	sub := subToken("*")
	runRaw(t, []rawCase{
		{name: "no-topic", req: get(hubPath, nil)},
		{name: "empty-topic", known: kn("topic= (empty) opens a stream on the reference; Gossiper refuses it (400)", "status", "header:Content-Type"), req: get(hubPath+"?topic=", nil)},
		{name: "topic-param-other-name", req: get(hubPath+"?topics="+url.QueryEscape(topic), nil)},
		{name: "anonymous", req: get(q(), nil)},
		{name: "match-parameter-newer-protocol", known: kn("the reference also accepts the newer \"match\" subscription parameter (and its error message names it); Gossiper only knows \"topic\"", "status", "header:Content-Type"), req: get(hubPath+"?match="+url.QueryEscape(topic), nil)},
		{name: "anonymous-template-selector", req: get(hubPath+"?topic="+url.QueryEscape(topic+"/{id}"), nil)},
		{name: "anonymous-star", req: get(hubPath+"?topic=*", nil)},
		{name: "anonymous-many-topics", req: get(hubPath+"?topic=a&topic=b&topic=c", nil)},
		{name: "head", req: func() req { return req{Method: http.MethodHead, Path: q()} }},
		{name: "post-not-a-publish-no-token", req: func() req { return req{Method: http.MethodPost, Path: hubPath} }},
		{name: "valid-token-header", req: get(q(), map[string]string{"Authorization": bearer(sub)})},
		{name: "valid-token-publish-only-claims", req: get(q(), map[string]string{"Authorization": bearer(pubToken("*"))})},
		{name: "valid-token-no-mercure-claim", req: get(q(), map[string]string{"Authorization": bearer(mint(jwt.MapClaims{"sub": "x"}))})},
		{name: "bad-signature", req: get(q(), map[string]string{"Authorization": bearer(mintWith("another-secret-another-secret-123456", jwt.SigningMethodHS256, mercureClaims(nil, []string{"*"})))})},
		{name: "malformed", req: get(q(), map[string]string{"Authorization": bearer("garbage")})},
		{name: "authorization-basic", req: get(q(), map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})},
		{name: "expired", req: get(q(), map[string]string{"Authorization": bearer(mint(func() jwt.MapClaims {
			c := mercureClaims(nil, []string{"*"})
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return c
		}()))})},
		{name: "alg-none", req: get(q(), map[string]string{"Authorization": bearer(mintWith("", jwt.SigningMethodNone, mercureClaims(nil, []string{"*"})))})},
		{name: "cookie-valid", req: get(q(), map[string]string{"Cookie": "mercureAuthorization=" + sub})},
		{name: "cookie-bad", known: knBadTokenClass, req: get(q(), map[string]string{"Cookie": "mercureAuthorization=garbage"})},
		{name: "cookie-valid-with-allowed-origin", req: get(q(), map[string]string{"Cookie": "mercureAuthorization=" + sub, "Origin": allowedOrigin})},
		{name: "cookie-valid-with-bad-origin", req: get(q(), map[string]string{"Cookie": "mercureAuthorization=" + sub, "Origin": badOrigin})},
		{name: "query-authorization-valid", req: get(q("authorization", sub), nil)},
		{name: "query-authorization-bad", known: kn("an undecodable ?authorization= on a subscription: the reference ignores it and streams anonymously (200); Gossiper refuses it (400 invalid_request)", "status", "header:Content-Type", "header:WWW-Authenticate"), req: get(q("authorization", "garbage"), nil)},
		{name: "header-bad-query-good", req: get(q("authorization", sub), map[string]string{"Authorization": bearer("garbage")})},
		{name: "header-good-cookie-bad", req: get(q(), map[string]string{"Authorization": bearer(sub), "Cookie": "mercureAuthorization=garbage"})},
		{name: "last-event-id-header-unknown", req: get(q(), map[string]string{"Last-Event-ID": "urn:uuid:00000000-0000-7000-8000-000000000000"})},
		{name: "last-event-id-query-unknown", req: get(q("lastEventID", "unknown-id"), nil)},
		{name: "last-event-id-query-legacy-name", known: kn("Gossiper also reads the draft-07 query parameter Last-Event-ID; the reference ignores it", "header:Last-Event-ID", "header:Mercure-Last-Event-ID"), req: get(q("Last-Event-ID", "unknown-id"), nil)},
		{name: "last-event-id-earliest-header", req: get(q(), map[string]string{"Last-Event-ID": "earliest"})},
		{name: "last-event-id-earliest-query", req: get(q("lastEventID", "earliest"), nil)},
		{name: "accept-json", req: get(q(), map[string]string{"Accept": "application/json"})},
		{name: "unknown-path", req: get("/.well-known/mercure/x?topic=a", nil)},
		{name: "root", req: get("/", nil)},
	})
}

func TestCORS(t *testing.T) {
	topic := ns("cors")
	subPath := hubPath + "?topic=" + url.QueryEscape(topic)
	opt := func(h map[string]string) func() req {
		return func() req { return req{Method: http.MethodOptions, Path: hubPath, Header: h} }
	}
	runRaw(t, []rawCase{
		{name: "subscribe-allowed-origin", req: func() req { return req{Path: subPath, Header: map[string]string{"Origin": allowedOrigin}} }},
		{name: "subscribe-bad-origin", req: func() req { return req{Path: subPath, Header: map[string]string{"Origin": badOrigin}} }},
		{name: "subscribe-no-origin", req: func() req { return req{Path: subPath} }},
		{name: "subscribe-null-origin", req: func() req { return req{Path: subPath, Header: map[string]string{"Origin": "null"}} }},
		{name: "subscribe-origin-case", req: func() req { return req{Path: subPath, Header: map[string]string{"Origin": "http://EXAMPLE.com"}} }},
		{name: "subscribe-origin-https-variant", req: func() req { return req{Path: subPath, Header: map[string]string{"Origin": "https://example.com"}} }},
		{name: "subscribe-error-allowed-origin", req: func() req { return req{Path: hubPath, Header: map[string]string{"Origin": allowedOrigin}} }},
		{name: "publish-allowed-origin-error", req: func() req {
			r := publishReq(pubForm(topic), "", map[string]string{"Origin": allowedOrigin})
			return r
		}},
		{name: "publish-allowed-origin-ok", req: func() req {
			return publishReq(pubForm(topic), bearer(pubToken("*")), map[string]string{"Origin": allowedOrigin})
		}},
		{name: "publish-bad-origin-ok", req: func() req {
			return publishReq(pubForm(topic), bearer(pubToken("*")), map[string]string{"Origin": badOrigin})
		}},
		{name: "preflight-subscribe-allowed", req: opt(map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization,last-event-id"})},
		{name: "preflight-publish-allowed", known: knPreflight, req: opt(map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"})},
		{name: "preflight-bad-origin", req: opt(map[string]string{"Origin": badOrigin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization"})},
		{name: "preflight-no-request-method", known: kn("an OPTIONS without Access-Control-Request-Method: reference 405, Gossiper 204", "status"), req: opt(map[string]string{"Origin": allowedOrigin})},
		{name: "preflight-no-origin", req: opt(map[string]string{"Access-Control-Request-Method": "POST"})},
		{name: "preflight-method-put", known: knPreflight, req: opt(map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": "PUT"})},
		{name: "preflight-method-delete", known: knPreflight, req: opt(map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": "DELETE"})},
		{name: "preflight-custom-header", known: knPreflight, req: opt(map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-custom-header"})},
		{name: "options-without-cors-headers", known: kn("a plain OPTIONS: reference 405, Gossiper 204", "status"), req: opt(nil)},
		{name: "preflight-on-subscriptions-api", req: func() req {
			return req{Method: http.MethodOptions, Path: hubPath + "/subscriptions", Header: map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"}}
		}},
	})
}

// scenarios drive both hubs with the same publishes and subscribes and compare the frames.
func TestScenarios(t *testing.T) {
	T := "{{ns}}/a"
	all := []scenario{
		{Name: "public-live", Topics: []string{T}, Post: []pub{{Topics: []string{T}, Data: "hello"}}, WantData: []string{"hello"}},
		{Name: "id-type-retry", Topics: []string{T}, Known: kn("retry=0: Gossiper sends \"retry: 0\", the reference drops it (zero value = unset)", "frame.retry"),
			Post: []pub{
				{Topics: []string{T}, Data: "typed", ID: "my-id-{{rid}}", Type: "custom", Retry: "2500"},
				{Topics: []string{T}, Data: "only-retry", Retry: "0"},
				{Topics: []string{T}, Data: "only-type", Type: "message"},
				{Topics: []string{T}, Data: "uuid-id-{{rid}}", ID: "urn:uuid:11111111-2222-7333-8444-{{rid}}0000"},
			},
			WantData: []string{"typed", "only-retry", "only-type", "uuid-id-{{rid}}"}},
		{Name: "multiline-data", Topics: []string{T},
			Post: []pub{
				{Topics: []string{T}, Data: "one\ntwo\nthree"},
				{Topics: []string{T}, Data: "crlf\r\nline"},
				{Topics: []string{T}, Data: "trailing\n"},
				{Topics: []string{T}, Data: "\nleading"},
				{Topics: []string{T}, Data: "blank\n\nline"},
				{Topics: []string{T}, Data: "lone-cr\rline"},
				{Topics: []string{T}, Data: ""},
				{Topics: []string{T}, NoData: true},
				{Topics: []string{T}, Data: "  spaces  "},
				{Topics: []string{T}, Data: ": looks like a comment"},
				{Topics: []string{T}, Data: "data: nested field-like"},
			}},
		{Name: "unicode", Topics: []string{T},
			Post: []pub{
				{Topics: []string{T}, Data: "héllo wörld 世界 🎉    \u0085 end", Type: "événement"},
				{Topics: []string{T}, Data: `{"json":"with \"quotes\" and é","n":[1,2,3]}`, Type: "json"},
			}},
		{Name: "private-anonymous-filtered", Topics: []string{T},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}},
			WantData: []string{"public"}},
		{Name: "private-with-matching-token-header", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}},
			WantData: []string{"secret", "public"}},
		{Name: "private-with-matching-token-cookie", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}, Via: "cookie"},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}},
			WantData: []string{"secret"}},
		{Name: "private-with-matching-token-query", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}, Via: "query"},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}},
			WantData: []string{"secret"}},
		{Name: "private-token-other-topic", Topics: []string{T}, Auth: &auth{Subscribe: []string{"{{ns}}/other"}},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}},
			WantData: []string{"public"}},
		{Name: "private-token-star", Topics: []string{T}, Auth: &auth{Subscribe: []string{"*"}},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}},
			WantData: []string{"secret"}},
		{Name: "private-token-template", Topics: []string{T}, Auth: &auth{Subscribe: []string{"{{ns}}/{x}"}},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}},
			WantData: []string{"secret"}},
		{Name: "private-token-empty-subscribe", Topics: []string{T}, Auth: &auth{Subscribe: []string{}},
			Post:     []pub{{Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "public"}},
			WantData: []string{"public"}},
		{Name: "private-multi-topic-update-one-topic-authorized", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/b"}},
			Post:     []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi", Private: true}},
			WantData: []string{"multi"}},
		{Name: "private-multi-topic-sub-authorized-for-canonical-only", Topics: []string{"{{ns}}/b"}, Auth: &auth{Subscribe: []string{"{{ns}}/a"}},
			Post:     []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi", Private: true}, {Topics: []string{"{{ns}}/b"}, Data: "pub"}},
			WantData: []string{"multi", "pub"}},
		{Name: "multi-topic-update-subscriber-on-alternate", Topics: []string{"{{ns}}/b"},
			Post:     []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi"}},
			WantData: []string{"multi"}},
		{Name: "multi-topic-subscription-gets-update-once", Topics: []string{"{{ns}}/a", "{{ns}}/b", "{{ns}}/{x}"},
			Post:     []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "once"}},
			Sentinel: "{{ns}}/c", WantData: []string{"once"}},
		{Name: "duplicate-topic-selectors", Topics: []string{T, T},
			Post: []pub{{Topics: []string{T}, Data: "once"}}, WantData: []string{"once"}},
		{Name: "template-id", Topics: []string{"{{ns}}/books/{id}"},
			Post: []pub{
				{Topics: []string{"{{ns}}/books/1"}, Data: "match"},
				{Topics: []string{"{{ns}}/books/1/chapters"}, Data: "no-nested"},
				{Topics: []string{"{{ns}}/books"}, Data: "no-parent"},
				{Topics: []string{"{{ns}}/other/1"}, Data: "no-other"},
				{Topics: []string{"{{ns}}/books/a%20b"}, Data: "encoded"},
			},
			Sentinel: "{{ns}}/books/end", WantData: []string{"match", "encoded"}},
		{Name: "template-query-expansion", Topics: []string{"{{ns}}/search{?q,page}"},
			Post: []pub{
				{Topics: []string{"{{ns}}/search?q=go"}, Data: "q"},
				{Topics: []string{"{{ns}}/search?q=go&page=2"}, Data: "q+page"},
				{Topics: []string{"{{ns}}/search"}, Data: "bare"},
				{Topics: []string{"{{ns}}/other?q=go"}, Data: "other"},
			},
			Sentinel: "{{ns}}/search?q=end"},
		{Name: "template-path-segments", Topics: []string{"{{ns}}{/a}{/b}"},
			Post: []pub{
				{Topics: []string{"{{ns}}/x"}, Data: "one"},
				{Topics: []string{"{{ns}}/x/y"}, Data: "two"},
				{Topics: []string{"{{ns}}/x/y/z"}, Data: "three"},
				{Topics: []string{"{{ns}}"}, Data: "none"},
			},
			Sentinel: "{{ns}}/end"},
		{Name: "template-reserved-expansion", Topics: []string{"{{ns}}/files/{+path}"},
			Post: []pub{
				{Topics: []string{"{{ns}}/files/a/b/c.txt"}, Data: "deep"},
				{Topics: []string{"{{ns}}/files/x"}, Data: "shallow"},
				{Topics: []string{"{{ns}}/other"}, Data: "no"},
			},
			Sentinel: "{{ns}}/files/end"},
		{Name: "template-fragment-and-label", Topics: []string{"{{ns}}/u/{name}.json"},
			Post: []pub{
				{Topics: []string{"{{ns}}/u/bob.json"}, Data: "bob"},
				{Topics: []string{"{{ns}}/u/bob.xml"}, Data: "no"},
			},
			Sentinel: "{{ns}}/u/end.json"},
		{Name: "template-private-selector-in-token-vs-subscription-topic", Topics: []string{"{{ns}}/books/{id}"}, Auth: &auth{Subscribe: []string{"{{ns}}/books/{id}"}},
			Post: []pub{
				{Topics: []string{"{{ns}}/books/1"}, Data: "priv1", Private: true},
				{Topics: []string{"{{ns}}/books/1/x"}, Data: "no-nested", Private: true},
			},
			Sentinel: "{{ns}}/books/end", WantData: []string{"priv1"}},
		{Name: "template-sub-token-exact-selector", Topics: []string{"{{ns}}/books/{id}"}, Auth: &auth{Subscribe: []string{"{{ns}}/books/1"}},
			Post: []pub{
				{Topics: []string{"{{ns}}/books/1"}, Data: "priv1", Private: true},
				{Topics: []string{"{{ns}}/books/2"}, Data: "priv2", Private: true},
			},
			Sentinel: "{{ns}}/books/end", WantData: []string{"priv1"}},
		{Name: "star-anonymous", Topics: []string{"*"},
			Post: []pub{
				{Topics: []string{"{{ns}}/x"}, Data: "x"},
				{Topics: []string{"{{ns}}/y"}, Data: "y"},
				{Topics: []string{"{{ns}}/x"}, Data: "priv", Private: true},
			},
			Sentinel: "{{ns}}/z", WantData: []string{"x", "y"}},
		{Name: "star-with-private-token", Topics: []string{"*"}, Auth: &auth{Subscribe: []string{"{{ns}}/x"}},
			Post: []pub{
				{Topics: []string{"{{ns}}/x"}, Data: "x-priv", Private: true},
				{Topics: []string{"{{ns}}/y"}, Data: "y-priv", Private: true},
				{Topics: []string{"{{ns}}/y"}, Data: "y"},
			},
			Sentinel: "{{ns}}/z", WantData: []string{"x-priv", "y"}},
		{Name: "star-selector-in-token-template-selector-in-sub", Topics: []string{"{{ns}}/{x}"}, Auth: &auth{Subscribe: []string{"*"}},
			Post:     []pub{{Topics: []string{"{{ns}}/x"}, Data: "p", Private: true}},
			Sentinel: "{{ns}}/z", WantData: []string{"p"}},
		{Name: "percent-encoding-in-topics", Topics: []string{"{{ns}}/a b/é/%2F"},
			Post:     []pub{{Topics: []string{"{{ns}}/a b/é/%2F"}, Data: "exact"}, {Topics: []string{"{{ns}}/a%20b/é/%2F"}, Data: "different-encoding"}},
			Sentinel: "{{ns}}/a b/é/%2F", WantData: []string{"exact"}},
		{Name: "topic-case-sensitivity", Topics: []string{"{{ns}}/Case"},
			Post:     []pub{{Topics: []string{"{{ns}}/case"}, Data: "lower"}, {Topics: []string{"{{ns}}/Case"}, Data: "exact"}},
			Sentinel: "{{ns}}/Case", WantData: []string{"exact"}},
		{Name: "publish-order-preserved", Topics: []string{T},
			Post: func() []pub {
				var p []pub
				for i := 0; i < 30; i++ {
					p = append(p, pub{Topics: []string{T}, Data: fmt.Sprintf("n%02d", i)})
				}
				return p
			}()},
		{Name: "last-event-id-in-subscribe-response-without-replay", Topics: []string{T}, Post: []pub{{Topics: []string{T}, Data: "x"}}},
	}
	// replay
	pre := []pub{
		{Topics: []string{T}, Data: "p0"}, {Topics: []string{T}, Data: "p1"}, {Topics: []string{T}, Data: "p2"},
	}
	live := []pub{{Topics: []string{T}, Data: "live"}}
	all = append(all,
		scenario{Name: "replay-query-lastEventID", Pre: pre, Topics: []string{T}, Query: "lastEventID={{id:0}}", Post: live, WantData: []string{"p1", "p2", "live"}},
		scenario{Name: "replay-header-Last-Event-ID", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "{{id:0}}"}, Post: live, WantData: []string{"p1", "p2", "live"}},
		scenario{Name: "replay-from-last-event", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "{{id:2}}"}, Post: live, WantData: []string{"live"}},
		scenario{Name: "replay-earliest-query", Pre: pre, Topics: []string{T}, Query: "lastEventID=earliest", Post: live, WantData: []string{"p0", "p1", "p2", "live"}},
		scenario{Name: "replay-earliest-header", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "earliest"}, Post: live, WantData: []string{"p0", "p1", "p2", "live"}},
		scenario{Name: "replay-unknown-id-header", Pre: pre, Topics: []string{T}, Header: map[string]string{"Last-Event-ID": "urn:uuid:00000000-0000-7000-8000-000000000000"}, Post: live},
		scenario{Name: "replay-unknown-id-query", Pre: pre, Topics: []string{T}, Query: "lastEventID=does-not-exist", Post: live},
		scenario{Name: "replay-header-wins-over-query", Pre: pre, Topics: []string{T}, Query: "lastEventID={{id:1}}", Header: map[string]string{"Last-Event-ID": "{{id:0}}"}, Post: live},
		scenario{Name: "replay-legacy-query-name", Known: kn("Gossiper also honours the draft-07 query parameter Last-Event-ID (replays); the reference ignores it", "header:Last-Event-ID", "header:Mercure-Last-Event-ID", "frames.count", "frame.id", "frame.data"), Pre: pre, Topics: []string{T}, Query: "Last-Event-ID={{id:0}}", Post: live},
		scenario{Name: "replay-private-filtered-anonymous", Topics: []string{T}, Query: "lastEventID={{id:0}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"p2", "live"}},
		scenario{Name: "replay-private-with-token", Topics: []string{T}, Auth: &auth{Subscribe: []string{T}}, Query: "lastEventID={{id:0}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{T}, Data: "secret", Private: true}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"secret", "p2", "live"}},
		scenario{Name: "replay-other-topics-excluded", Topics: []string{T}, Query: "lastEventID={{id:0}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{"{{ns}}/other"}, Data: "other"}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"p2", "live"}},
		scenario{Name: "replay-id-of-other-topic-update", Topics: []string{T}, Query: "lastEventID={{id:1}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0"}, {Topics: []string{"{{ns}}/other"}, Data: "other"}, {Topics: []string{T}, Data: "p2"}}, WantData: []string{"p2", "live"}},
		scenario{Name: "replay-with-template-selector", Topics: []string{"{{ns}}/books/{id}"}, Query: "lastEventID={{id:0}}", Sentinel: "{{ns}}/books/end",
			Pre:  []pub{{Topics: []string{"{{ns}}/books/1"}, Data: "p0"}, {Topics: []string{"{{ns}}/books/2"}, Data: "p1"}, {Topics: []string{"{{ns}}/other"}, Data: "x"}},
			Post: []pub{{Topics: []string{"{{ns}}/books/3"}, Data: "live"}}, WantData: []string{"p1", "live"}},
		scenario{Name: "replay-custom-ids", Topics: []string{T}, Query: "lastEventID=first-{{rid}}", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "p0", ID: "first-{{rid}}"}, {Topics: []string{T}, Data: "p1", ID: "second-{{rid}}"}}, WantData: []string{"p1", "live"}},
		scenario{Name: "replay-preserves-fields", Topics: []string{T}, Query: "lastEventID=earliest", Post: live,
			Pre: []pub{{Topics: []string{T}, Data: "m\nn", Type: "t1", Retry: "100", ID: "id1-{{rid}}"}}, WantData: []string{"m\nn", "live"}},
		scenario{Name: "replay-multi-topic-update-once", Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Query: "lastEventID=earliest", Post: live,
			Pre: []pub{{Topics: []string{"{{ns}}/a", "{{ns}}/b"}, Data: "multi"}}, WantData: []string{"multi", "live"}},
	)
	for _, h := range hubsUnderTest {
		h := h
		t.Run(h.name, func(t *testing.T) {
			for _, sc := range all {
				sc := sc
				t.Run(sc.Name, func(t *testing.T) { runDifferential(t, h, sc) })
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------------------
// Subscriptions: the subscription events and the subscriptions API.
//
// Gossiper defaults to the draft-07 format ("@context", type "Subscription", no event type, application/ld+json);
// with --modern-subscription-format it must match the reference, which uses the current one.

const subsPath = hubPath + "/subscriptions"

// canonSubBody parses a subscriptions API body, normalizes the ids and sorts the subscriptions.
func canonSubBody(body string) string {
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return normText(strings.TrimSpace(body))
	}
	if subs, ok := v["subscriptions"].([]any); ok {
		sort.Slice(subs, func(i, j int) bool {
			a, _ := json.Marshal(subs[i])
			b, _ := json.Marshal(subs[j])
			return normText(string(a)) < normText(string(b))
		})
	}
	delete(v, "lastEventID") // the id of the last update: differs per hub
	b, _ := json.Marshal(v)
	return normText(string(b))
}

func subsAdminToken() string { return subToken(subsPath, subsPath+"/{+rest}") }

var knLegacySubs = kn("draft-07 subscription format (default mode): application/ld+json, \"@context\", capitalised types; use --modern-subscription-format for the current one", "body", "header:Content-Type", "header:Link", "frame.event", "frame.data", "frame.id")

// openSubscribers connects two subscribers (an anonymous one on two topics, and one with a token carrying a payload)
// and returns them; callers close them.
func openSubscribers(t *testing.T, h hub, base string) (anon, withPayload *sseStream) {
	t.Helper()
	var err error
	anon, err = h.stream(hubPath+"?topic="+url.QueryEscape(base+"/x")+"&topic="+url.QueryEscape(base+"/{y}"), nil)
	if err != nil || anon.Status != 200 {
		t.Fatalf("%s: anonymous subscriber: %v %+v", h.name, err, anon)
	}
	tok := mint(jwt.MapClaims{"mercure": map[string]any{"subscribe": []string{base + "/z"}, "payload": map[string]any{"user": "carol", "n": 3}}})
	withPayload, err = h.stream(hubPath+"?topic="+url.QueryEscape(base+"/z"), map[string]string{"Authorization": bearer(tok)})
	if err != nil || withPayload.Status != 200 {
		t.Fatalf("%s: token subscriber: %v %+v", h.name, err, withPayload)
	}
	time.Sleep(400 * time.Millisecond)
	return
}

func TestSubscriptionsAPI(t *testing.T) {
	base := ns("subsapi")
	for _, h := range []hub{hubModern, hubSC} {
		h := h
		k := known{}
		if h == hubSC {
			k = knLegacySubs
		}
		t.Run(h.name, func(t *testing.T) {
			a1, b1 := openSubscribers(t, h, base)
			defer a1.Close()
			defer b1.Close()
			a2, b2 := openSubscribers(t, hubRef, base)
			defer a2.Close()
			defer b2.Close()

			adminHdr := map[string]string{"Authorization": bearer(subsAdminToken())}
			encTopic := url.PathEscape(base + "/x")
			encTemplate := url.PathEscape(base + "/{y}")
			encZ := url.PathEscape(base + "/z")

			// the subscriber ids of the two hubs, for the per-subscriber URLs
			ids := func(h hub) (anon, tok string) {
				r := h.do(req{Path: subsPath + "/" + encTopic, Header: adminHdr})
				var doc struct {
					Subscriptions []struct{ Subscriber string }
				}
				_ = json.Unmarshal([]byte(r.Body), &doc)
				if len(doc.Subscriptions) == 1 {
					anon = doc.Subscriptions[0].Subscriber
				}
				r = h.do(req{Path: subsPath + "/" + encZ, Header: adminHdr})
				doc.Subscriptions = nil
				_ = json.Unmarshal([]byte(r.Body), &doc)
				if len(doc.Subscriptions) == 1 {
					tok = doc.Subscriptions[0].Subscriber
				}
				return
			}
			gotAnon, gotTok := ids(h)
			refAnon, refTok := ids(hubRef)
			if gotAnon == "" || gotTok == "" || refAnon == "" || refTok == "" {
				t.Fatalf("subscriber ids not found: %q %q %q %q", gotAnon, gotTok, refAnon, refTok)
			}

			type c struct {
				name string
				req  func(anon, tok string) req
			}
			caseKnown := map[string]known{
				"collection-head":        kn("HEAD on the subscriptions API: reference 405, Gossiper answers like GET without a body", "*"),
				"too-many-path-segments": kn("/subscriptions/a/b/c: the reference answers 400 (\"unsupported topic matcher type\"), Gossiper 404", "*"),
			}
			cases := []c{
				{"no-token", func(a, tk string) req { return req{Path: subsPath} }},
				{"bad-token", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Authorization": bearer("garbage")}}
				}},
				{"wrong-key", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Authorization": bearer(mintWith("another-secret-another-secret-123456", jwt.SigningMethodHS256, mercureClaims(nil, []string{"*"})))}}
				}},
				{"token-with-other-selectors", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Authorization": bearer(subToken("https://other.test/*"))}}
				}},
				{"token-publish-only", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Authorization": bearer(pubToken("*"))}}
				}},
				{"token-star", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Authorization": bearer(subToken("*"))}}
				}},
				{"token-exact-collection-only-for-topic-url", func(a, tk string) req {
					return req{Path: subsPath + "/" + encTopic, Header: map[string]string{"Authorization": bearer(subToken(subsPath))}}
				}},
				{"collection", func(a, tk string) req { return req{Path: subsPath, Header: adminHdr} }},
				{"collection-cookie", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Cookie": "mercureAuthorization=" + subsAdminToken()}}
				}},
				{"collection-query-authorization", func(a, tk string) req {
					return req{Path: subsPath + "?authorization=" + url.QueryEscape(subsAdminToken())}
				}},
				{"collection-head", func(a, tk string) req { return req{Method: http.MethodHead, Path: subsPath, Header: adminHdr} }},
				{"collection-trailing-slash", func(a, tk string) req { return req{Path: subsPath + "/", Header: adminHdr} }},
				{"collection-allowed-origin", func(a, tk string) req {
					return req{Path: subsPath, Header: map[string]string{"Authorization": adminHdr["Authorization"], "Origin": allowedOrigin}}
				}},
				{"topic-collection", func(a, tk string) req { return req{Path: subsPath + "/" + encTopic, Header: adminHdr} }},
				{"topic-collection-template-topic", func(a, tk string) req { return req{Path: subsPath + "/" + encTemplate, Header: adminHdr} }},
				{"topic-collection-payload", func(a, tk string) req { return req{Path: subsPath + "/" + encZ, Header: adminHdr} }},
				{"topic-collection-unknown", func(a, tk string) req {
					return req{Path: subsPath + "/" + url.PathEscape(base+"/none"), Header: adminHdr}
				}},
				{"subscription", func(a, tk string) req {
					return req{Path: subsPath + "/" + encTopic + "/" + url.PathEscape(a), Header: adminHdr}
				}},
				{"subscription-with-payload", func(a, tk string) req {
					return req{Path: subsPath + "/" + encZ + "/" + url.PathEscape(tk), Header: adminHdr}
				}},
				{"subscription-unknown", func(a, tk string) req {
					return req{Path: subsPath + "/" + encTopic + "/urn:uuid:00000000-0000-4000-8000-000000000000", Header: adminHdr}
				}},
				{"subscription-narrow-token", func(a, tk string) req {
					return req{Path: subsPath + "/" + encTopic + "/" + url.PathEscape(a), Header: map[string]string{"Authorization": bearer(subToken(subsPath + "/" + encTopic + "/{id}"))}}
				}},
				{"subscription-narrow-token-insufficient", func(a, tk string) req {
					return req{Path: subsPath + "/" + encTopic + "/" + url.PathEscape(a), Header: map[string]string{"Authorization": bearer(subToken(subsPath + "/" + encZ + "/{id}"))}}
				}},
				{"too-many-path-segments", func(a, tk string) req { return req{Path: subsPath + "/a/b/c", Header: adminHdr} }},
			}
			for _, cs := range cases {
				cs := cs
				t.Run(cs.name, func(t *testing.T) {
					got := h.do(cs.req(gotAnon, gotTok))
					ref := hubRef.do(cs.req(refAnon, refTok))
					t.Logf("reference %d, %s %d", ref.Status, h.name, got.Status)
					ck := k
					if kk, ok := caseKnown[cs.name]; ok {
						ck = kk
					}
					(&cmp{t: t, hubName: h.name, known: ck}).resp(got, ref, false)
					if g, r := canonSubBody(got.Body), canonSubBody(ref.Body); g != r {
						(&cmp{t: t, hubName: h.name, known: ck}).add("body", "body", r, g, h == hubSC)
					}
					t.Logf("body: %s", canonSubBody(got.Body))
				})
			}
		})
	}
}

// subscriptionEvents runs the scenario on h: A watches the subscription topics, B connects (two topics, payload)
// and disconnects; returns what A received.
func subscriptionEvents(t *testing.T, h hub) ([]frame, *sseStream) {
	t.Helper()
	base := ns("subev")
	tmpl := subsPath + "/{topic}/{subscriber}"
	a, err := h.stream(hubPath+"?topic="+url.QueryEscape(tmpl)+"&topic="+url.QueryEscape(base+"/end"), map[string]string{"Authorization": bearer(subToken(tmpl))})
	if err != nil || a.Status != 200 {
		t.Fatalf("%s: watcher: %v %+v", h.name, err, a)
	}
	time.Sleep(400 * time.Millisecond)
	tok := mint(jwt.MapClaims{"mercure": map[string]any{"subscribe": []string{base + "/x"}, "payload": map[string]any{"user": "bob"}}})
	b, err := h.stream(hubPath+"?topic="+url.QueryEscape(base+"/x")+"&topic="+url.QueryEscape(base+"/y"), map[string]string{"Authorization": bearer(tok)})
	if err != nil || b.Status != 200 {
		t.Fatalf("%s: subscriber: %v %+v", h.name, err, b)
	}
	time.Sleep(400 * time.Millisecond)
	b.Close()
	time.Sleep(600 * time.Millisecond)
	if r := h.do(publishReq(url.Values{"topic": {base + "/end"}, "data": {"END"}}, bearer(pubToken("*")), nil)); r.Status != 200 {
		t.Fatalf("%s: END publish: %d", h.name, r.Status)
	}
	fs, ok := a.collect(8 * time.Second)
	if !ok {
		t.Fatalf("%s: END not received; frames %s", h.name, framesString(fs))
	}
	return fs, a
}

func normSubFrames(fs []frame) []frame {
	var out []frame
	for _, f := range fs {
		if !strings.Contains(f.Data, "subev") { // events of other tests' subscribers going away
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

func TestSubscriptionEvents(t *testing.T) {
	time.Sleep(time.Second) // let the previous test's streams go away
	refFrames, refStream := subscriptionEvents(t, hubRef)
	refStream.Close()
	if len(refFrames) == 0 {
		t.Fatal("the reference sent no subscription events: is `subscriptions` enabled?")
	}
	t.Logf("reference: %s", framesString(normSubFrames(refFrames)))
	for _, h := range []hub{hubModern, hubSC} {
		h := h
		t.Run(h.name, func(t *testing.T) {
			k := known{}
			if h == hubSC {
				k = knLegacySubs
			}
			fs, s := subscriptionEvents(t, h)
			defer s.Close()
			t.Logf("%s: %s", h.name, framesString(normSubFrames(fs)))
			(&cmp{t: t, hubName: h.name, known: k}).frames(normSubFrames(fs), normSubFrames(refFrames))
			// What the reference sends: the event type "mercure" and a JSON "subscription" document.
			for _, f := range refFrames {
				eq(t, "reference event type", f.Event, "mercure")
			}
		})
	}
}

// The default (draft-07) format: JSON-LD, capitalised types, no "mercure" event type.
func TestSubscriptionDefaultFormatShape(t *testing.T) {
	fs, s := subscriptionEvents(t, hubSC)
	defer s.Close()
	if len(fs) == 0 {
		t.Fatal("no subscription events")
	}
	for _, f := range fs {
		var d map[string]any
		if err := json.Unmarshal([]byte(f.Data), &d); err != nil {
			t.Fatalf("data is not JSON: %q", f.Data)
		}
		if d["@context"] != "https://mercure.rocks/" || d["type"] != "Subscription" {
			t.Errorf("draft-07 shape expected, got %s", f.Data)
		}
		if f.Event != "" {
			t.Errorf("draft-07 events have no event type, got %q", f.Event)
		}
	}
	r := hubSC.do(req{Path: subsPath, Header: map[string]string{"Authorization": bearer(subsAdminToken())}})
	eq(t, "Content-Type", r.Header.Get("Content-Type"), "application/ld+json")
	var d map[string]any
	_ = json.Unmarshal([]byte(r.Body), &d)
	if d["@context"] != "https://mercure.rocks/" || d["type"] != "Subscriptions" {
		t.Errorf("draft-07 collection expected, got %s", r.Body)
	}
}

// ---------------------------------------------------------------------------------------------------------
// (c) Browser-style checks in Node (the `eventsource` package and fetch streaming), against both hubs.

func TestJavaScriptEventSource(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	if out, err := exec.Command(node, "-v").Output(); err == nil {
		t.Logf("node %s", strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat("js/node_modules/eventsource"); err != nil {
		cmd := exec.Command("npm", "install", "--no-audit", "--no-fund")
		cmd.Dir = "js"
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("npm install: %v\n%s", err, out)
		}
	}
	for _, st := range stacks {
		st := st
		t.Run(st.name, func(t *testing.T) {
			cmd := exec.Command(node, "--test", "check.mjs")
			cmd.Dir = "js"
			cmd.Env = append(os.Environ(), "HUB_URL="+st.hub.base, "APP_URL="+st.app)
			out, err := cmd.CombinedOutput()
			t.Logf("\n%s", out)
			if err != nil {
				t.Fatalf("node --test: %v", err)
			}
		})
	}
}
