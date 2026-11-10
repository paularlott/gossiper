package gossiper

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
)

// testIssuer is the issuer the test hubs trust for Mercure 1.0 access tokens signed with testSecret.
const testIssuer = "https://issuer.example"

// hubAud is the resource identifier of a hub served through hubDo: requests there are for Host example.com.
const hubAud = "http://example.com" + hubPath

var (
	pubOnly  = []string{"publish"}
	subOnly  = []string{"subscribe"}
	pubAndSb = []string{"publish", "subscribe"}
)

// mExact is an exact topic matcher with an explicit match_type.
func mExact(m string) map[string]any { return map[string]any{"match": m, "match_type": "exact"} }

// mBare is a topic matcher without a match_type (exact by default).
func mBare(m string) map[string]any { return map[string]any{"match": m} }

// mPattern is a URL pattern topic matcher.
func mPattern(m string) map[string]any { return map[string]any{"match": m, "match_type": "urlpattern"} }

// mDetail is a Mercure authorization detail.
func mDetail(actions []string, topics ...map[string]any) map[string]any {
	ts := make([]any, len(topics))
	for i, tp := range topics {
		ts[i] = tp
	}
	return map[string]any{"type": auth.DetailType, "actions": actions, "topics": ts}
}

// mPayload sets the payload of a detail.
func mPayload(d map[string]any, payload map[string]any) map[string]any {
	d["payload"] = payload
	return d
}

// accessClaims returns the claims RFC 9068 asks of an access token, with the given audience (a string or a list),
// lifetime and authorization details.
func accessClaims(aud any, ttl time.Duration, details ...any) jwt.MapClaims {
	now := time.Now()
	if details == nil {
		details = []any{}
	}
	return jwt.MapClaims{
		"iss": testIssuer, "aud": aud, "sub": "urn:uuid:5b2f1a64-37c2-4c3c-8d2e-0e4f4f3e5a11", "client_id": "client-1",
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": "urn:uuid:0d6f9f7e-6a53-4b9d-b0a8-2f2a9a7c0c01",
		"authorization_details": details,
	}
}

// signAccessTyp signs claims with the given typ header ("" leaves it out) and secret.
func signAccessTyp(t testing.TB, secret, typ string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if typ == "" {
		delete(tok.Header, "typ")
	} else {
		tok.Header["typ"] = typ
	}
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signAccess signs claims as a JWT access token (typ at+jwt) with the test secret.
func signAccess(t testing.TB, claims jwt.MapClaims) string {
	t.Helper()
	return signAccessTyp(t, testSecret, "at+jwt", claims)
}

// accessFor is a valid access token for audience aud, valid for an hour, with the details.
func accessFor(t testing.TB, aud string, details ...any) string {
	t.Helper()
	return signAccess(t, accessClaims(aud, time.Hour, details...))
}

// access is a valid access token for the hub of e.
func (e *env) access(t testing.TB, details ...any) string {
	t.Helper()
	return accessFor(t, e.hubURL(), details...)
}

// mcfg is the configuration of a hub that trusts testIssuer's tokens (signed with the test secret).
func mcfg(p Protocol) Config {
	return Config{Protocol: p, TrustedIssuers: []string{testIssuer}}
}

// protocols are the protocol settings that accept Mercure 1.0.
var protocols = []struct {
	name string
	p    Protocol
}{{"both", ProtocolBoth}, {"modern", ProtocolModern}}

// forProtocols runs fn as a subtest for Protocol Both and Modern.
func forProtocols(t *testing.T, fn func(t *testing.T, p Protocol)) {
	t.Helper()
	for _, pr := range protocols {
		t.Run(pr.name, func(t *testing.T) { fn(t, pr.p) })
	}
}

// hubDo sends one request straight to the hub's handler; the request is for Host example.com unless hdr names
// another with a "Host" entry.
func hubDo(t testing.TB, h *Hub, method, target string, hdr http.Header, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, vs := range hdr {
		if k == "Host" {
			r.Host = vs[0]
			continue
		}
		r.Header[k] = vs
	}
	if method == http.MethodPost && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// newModernHub is a hub for hubDo, closed at the end of the test.
func newModernHub(t testing.TB, cfg Config) *Hub {
	t.Helper()
	if cfg.Protocol == ProtocolDefault { // the tests speak draft-07 unless they choose a protocol
		cfg.Protocol = ProtocolBoth
	}
	if !hasKey(cfg.PublisherKey) {
		cfg.PublisherKey = auth.KeyConfig{Key: testSecret}
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	return h
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// parseChallenge parses a WWW-Authenticate: Bearer challenge into its auth-params. It fails the test for any
// other scheme.
func parseChallenge(t testing.TB, v string) map[string]string {
	t.Helper()
	if v != "Bearer" && !strings.HasPrefix(v, "Bearer ") {
		t.Fatalf("WWW-Authenticate %q is not a Bearer challenge", v)
	}
	out := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(v, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// wantChallenge checks a response's WWW-Authenticate error code ("" for none) and resource_metadata ("" for none).
func wantChallenge(t testing.TB, hd http.Header, code, metadataURL string) {
	t.Helper()
	got := hd.Get("WWW-Authenticate")
	p := parseChallenge(t, got)
	if p["error"] != code {
		t.Errorf("WWW-Authenticate %q: error %q, want %q", got, p["error"], code)
	}
	if p["resource_metadata"] != metadataURL {
		t.Errorf("WWW-Authenticate %q: resource_metadata %q, want %q", got, p["resource_metadata"], metadataURL)
	}
	if (code == "") != !strings.Contains(got, "error=") {
		t.Errorf("WWW-Authenticate %q: error parameter presence wrong for code %q", got, code)
	}
}

// metadataURLOf is the protected resource metadata URL of the test server.
func (e *env) metadataURL() string { return e.srv.URL + metadataPath }

// openStream opens a stream with any method and an optional form body, and waits for its first comment. The
// stream is closed when the test ends. It fails the test unless the hub answers 200.
func (e *env) openStream(t testing.TB, method string, query url.Values, hdr http.Header, body string) *sseClient {
	t.Helper()
	c, status, msg := e.tryOpenStream(t, method, query, hdr, body)
	if c == nil {
		t.Fatalf("%s %v: %d %s", method, query, status, msg)
	}
	return c
}

// tryOpenStream is openStream that reports a refusal (status and body) instead of failing; the stream is nil then.
func (e *env) tryOpenStream(t testing.TB, method string, query url.Values, hdr http.Header, body string) (*sseClient, int, string) {
	t.Helper()
	target := e.hubURL()
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	ctx, cancel := context.WithCancel(context.Background())
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		return nil, resp.StatusCode, string(b)
	}
	c := &sseClient{t: t, resp: resp, cancel: cancel, events: make(chan sseEvent, 1<<14), closed: make(chan struct{})}
	if method == http.MethodHead {
		close(c.closed)
		t.Cleanup(func() { cancel(); resp.Body.Close() })
		return c, 200, ""
	}
	go c.read()
	t.Cleanup(c.close)
	eventually(t, "the stream's first comment", func() bool { return c.comments.Load() > 0 })
	return c, 200, ""
}

// publishA publishes one public update with an access token and returns its id; it fails the test unless the hub
// accepts it.
func (e *env) publishA(t testing.TB, data string, topics ...string) string {
	t.Helper()
	r := e.post(t, e.access(t, mDetail(pubOnly, mBare("*"))), url.Values{"topic": topics, "data": {data}})
	if r.code != 200 {
		t.Fatalf("publish: %d %s", r.code, r.body)
	}
	return r.body
}

// matchStream opens a GET stream for the given match parameters (name, value pairs) with tok.
func (e *env) matchStream(t testing.TB, tok string, kv ...string) *sseClient {
	t.Helper()
	q := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		q.Add(kv[i], kv[i+1])
	}
	return e.openStream(t, http.MethodGet, q, bearer(tok), "")
}

// get is e.do for a GET.
func (e *env) get(t testing.TB, target string, hdr http.Header) result {
	t.Helper()
	return e.do(t, http.MethodGet, target, hdr, "")
}

// A hub's default protocol is Mercure 1.0 only, as the reference hub's: draft-07 tokens, topic parameters and the
// authorization query parameter are refused; Mercure 1.0 tokens and matchers are taken.
func TestDefaultProtocolIsModern(t *testing.T) {
	h, err := New(Config{PublisherKey: auth.KeyConfig{Key: testSecret}, TrustedIssuers: []string{testIssuer}, Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	bearer := func(tok string) http.Header { return http.Header{"Authorization": {"Bearer " + tok}} }
	f := form("topic", "https://example.com/a").Encode()
	if w := hubDo(t, h, http.MethodPost, hubPath, bearer(tokenFor(t, all, all)), f); w.Code != http.StatusUnauthorized {
		t.Errorf("draft-07 token: %d", w.Code)
	}
	if w := hubDo(t, h, http.MethodPost, hubPath+"?authorization="+tokenFor(t, all, all), nil, f); w.Code != http.StatusUnauthorized {
		t.Errorf("authorization query parameter: %d", w.Code)
	}
	modern := accessFor(t, "http://example.com"+hubPath, mDetail(pubOnly, mBare("*")))
	if w := hubDo(t, h, http.MethodPost, hubPath, bearer(modern), f); w.Code != http.StatusOK {
		t.Errorf("Mercure 1.0 token: %d %s", w.Code, w.Body)
	}
	if w := hubDo(t, h, http.MethodGet, hubPath+"?topic=https%3A%2F%2Fexample.com%2Fa", nil, ""); w.Code != http.StatusBadRequest {
		t.Errorf("topic parameter: %d", w.Code)
	}
}

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		in   string
		want Protocol
		ok   bool
	}{
		{"", ProtocolModern, true}, {"both", ProtocolBoth, true}, {"BOTH", ProtocolBoth, true},
		{"legacy", ProtocolLegacy, true}, {"07", ProtocolLegacy, true}, {"draft-07", ProtocolLegacy, true},
		{"modern", ProtocolModern, true}, {"1.0", ProtocolModern, true}, {"1", ProtocolModern, true},
		{"08", ProtocolModern, true}, {"draft-08", ProtocolModern, true}, {"Modern", ProtocolModern, true},
		{"nope", 0, false}, {"09", 0, false},
	}
	for _, tc := range tests {
		got, err := ParseProtocol(tc.in)
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Errorf("ParseProtocol(%q) = %v, %v", tc.in, got, err)
		}
	}
	if !ProtocolBoth.legacy() || !ProtocolBoth.modern() || !ProtocolLegacy.legacy() || ProtocolLegacy.modern() ||
		ProtocolModern.legacy() || !ProtocolModern.modern() || ProtocolDefault.legacy() || !ProtocolDefault.modern() {
		t.Error("legacy()/modern() do not describe the protocols")
	}
	if _, err := New(Config{Protocol: Protocol(7)}); err == nil {
		t.Error("an unknown Protocol was accepted")
	}
	if _, err := New(Config{Protocol: Protocol(-1)}); err == nil {
		t.Error("a negative Protocol was accepted")
	}
}

func TestMatchKindString(t *testing.T) {
	if kindSelector.String() != "" || kindExact.String() != "exact" || kindURLPattern.String() != "urlpattern" {
		t.Fatal("matcher kind names")
	}
	if k, ok := kindOf(""); !ok || k != kindExact {
		t.Fatal("the default matcher type is exact")
	}
	if _, ok := kindOf("Exact"); ok {
		t.Fatal("matcher type names are case-sensitive")
	}
	if _, ok := kindOf("regex"); ok {
		t.Fatal("an unknown matcher type was accepted")
	}
}

func TestValidText(t *testing.T) {
	good := []string{"", "a", "https://example.com/é", "日本語", "a b", "\U0001F600", "a\u00a0b" /* NBSP is Zs, not Cf */}
	for _, s := range good {
		if !validText(s) {
			t.Errorf("validText(%q) = false", s)
		}
	}
	bad := []string{"a\x00b", "a\nb", "a\rb", "a\tb", "a\x1fb", "a\x7fb", "a\u0080b", "a\u0085b", "a\u009fb",
		"a\u200bb" /* ZWSP, Cf */, "a\u202eb" /* RLO, Cf */, "a\u2060b", "a\ufeffb", "a\u00adb", /* soft hyphen, Cf */
		"\xff", "a\xc0\xafb"}
	for _, s := range bad {
		if validText(s) {
			t.Errorf("validText(%q) = true", s)
		}
	}
}

// TestLegacyHubRefusesMercure1: a hub on Protocol Legacy ignores or refuses everything of Mercure 1.0.
func TestLegacyHubRefusesMercure1(t *testing.T) {
	e := newEnv(t, Config{Protocol: ProtocolLegacy, TrustedIssuers: []string{testIssuer}, Anonymous: true})
	atok := e.access(t, mDetail(pubAndSb, mBare("*")))

	t.Run("access token publish", func(t *testing.T) {
		r := e.post(t, atok, form("topic", "a"))
		if r.code != 401 {
			t.Fatalf("%d %s", r.code, r.body)
		}
		wantChallenge(t, r.header, "invalid_token", "")
	})
	t.Run("access token subscribe", func(t *testing.T) {
		_, code, _ := e.tryOpenStream(t, http.MethodGet, url.Values{"topic": {"a"}}, bearer(atok), "")
		if code != 401 {
			t.Fatalf("%d", code)
		}
	})
	t.Run("no resource_metadata in challenge", func(t *testing.T) {
		r := e.post(t, "", form("topic", "a"))
		if r.code != 401 {
			t.Fatal(r.code)
		}
		wantChallenge(t, r.header, "", "")
		if r.header.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("challenge %q", r.header.Get("WWW-Authenticate"))
		}
	})
	t.Run("match parameters are not recognized", func(t *testing.T) {
		r := e.do(t, http.MethodGet, e.hubURL()+"?match=a", nil, "")
		if r.code != 400 || !strings.Contains(r.body, `Missing "topic" parameter`) {
			t.Fatalf("%d %q", r.code, r.body)
		}
	})
	t.Run("match prefix names are not reserved", func(t *testing.T) {
		c := e.openStream(t, http.MethodGet, url.Values{"topic": {"a"}, "match_foo": {"x"}, "MATCH": {"y"}}, nil, "")
		e.publish(t, "hello", "a")
		c.expect("hello")
	})
	t.Run("last_event_id is not a parameter", func(t *testing.T) {
		id := e.publish(t, "one", "lei")
		e.publish(t, "two", "lei")
		c := e.openStream(t, http.MethodGet, url.Values{"topic": {"lei"}, "last_event_id": {id}}, nil, "")
		if c.resp.Header.Get("Mercure-Last-Event-ID") != "" || c.resp.Header.Get("Last-Event-ID") != "" {
			t.Fatalf("headers %v", c.resp.Header)
		}
		e.publish(t, "three", "lei")
		c.expect("three")
	})
	t.Run("cursor headers use both names", func(t *testing.T) {
		id := e.publish(t, "one", "lei2")
		e.publish(t, "two", "lei2")
		c := e.openStream(t, http.MethodGet, url.Values{"topic": {"lei2"}}, http.Header{"Last-Event-ID": {id}}, "")
		if c.resp.Header.Get("Mercure-Last-Event-ID") != id || c.resp.Header.Get("Last-Event-ID") != id {
			t.Fatalf("headers %v", c.resp.Header)
		}
		c.expect("two")
	})
	t.Run("modern cookie is ignored", func(t *testing.T) {
		r := e.do(t, http.MethodPost, e.hubURL(), http.Header{
			"Cookie": {"__Secure-mercure_access_token=" + atok}, "Origin": {"https://app.example"}}, form("topic", "a").Encode())
		if r.code != 401 {
			t.Fatalf("%d %s", r.code, r.body)
		}
	})
	t.Run("no protected resource metadata", func(t *testing.T) {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			if r := e.do(t, m, e.metadataURL(), nil, ""); r.code != 404 {
				t.Fatalf("%s: %d", m, r.code)
			}
		}
	})
	t.Run("QUERY still carries draft-07 topics", func(t *testing.T) {
		c := e.openStream(t, "QUERY", nil, nil, url.Values{"topic": {"q"}}.Encode())
		e.publish(t, "via query", "q")
		c.expect("via query")
	})
}

// TestModernHubRefusesDraft07: a hub on Protocol Modern ignores or refuses everything of draft-07.
func TestModernHubRefusesDraft07(t *testing.T) {
	e := newEnv(t, mcfg(ProtocolModern))
	ltok := tokenFor(t, all, all)
	atok := e.access(t, mDetail(pubAndSb, mBare("*")))

	t.Run("draft-07 token refused for publishing", func(t *testing.T) {
		r := e.post(t, ltok, form("topic", "a"))
		if r.code != 401 {
			t.Fatalf("%d %s", r.code, r.body)
		}
		wantChallenge(t, r.header, "invalid_token", e.metadataURL())
	})
	t.Run("draft-07 token refused for subscribing", func(t *testing.T) {
		_, code, _ := e.tryOpenStream(t, http.MethodGet, url.Values{"match": {"a"}}, bearer(ltok), "")
		if code != 401 {
			t.Fatal(code)
		}
	})
	t.Run("topic is not a parameter", func(t *testing.T) {
		r := e.do(t, http.MethodGet, e.hubURL()+"?topic=a", bearer(atok), "")
		if r.code != 400 || !strings.Contains(r.body, `Missing "match" parameter`) {
			t.Fatalf("%d %q", r.code, r.body)
		}
	})
	t.Run("topic beside match is ignored", func(t *testing.T) {
		c := e.openStream(t, http.MethodGet, url.Values{"topic": {"ignored"}, "match": {"kept"}}, bearer(atok), "")
		e.publishA(t, "x", "ignored")
		e.publishA(t, "y", "kept")
		c.expect("y")
	})
	t.Run("authorization query parameter is ignored", func(t *testing.T) {
		r := e.do(t, http.MethodPost, e.hubURL()+"?authorization="+url.QueryEscape(atok), nil, form("topic", "a").Encode())
		if r.code != 401 {
			t.Fatalf("%d", r.code)
		}
		wantChallenge(t, r.header, "", e.metadataURL())
	})
	t.Run("draft-07 cookie is ignored", func(t *testing.T) {
		r := e.do(t, http.MethodPost, e.hubURL(), http.Header{
			"Cookie": {"mercureAuthorization=" + ltok}, "Origin": {"https://app.example"}}, form("topic", "a").Encode())
		if r.code != 401 {
			t.Fatalf("%d", r.code)
		}
	})
	t.Run("lastEventID is not a parameter", func(t *testing.T) {
		id := e.publishA(t, "one", "lei")
		e.publishA(t, "two", "lei")
		c := e.openStream(t, http.MethodGet, url.Values{"match": {"lei"}, "lastEventID": {id}}, bearer(atok), "")
		if c.resp.Header.Get("Mercure-Last-Event-ID") != "" {
			t.Fatalf("headers %v", c.resp.Header)
		}
		e.publishA(t, "three", "lei")
		c.expect("three")
	})
	t.Run("no Last-Event-ID response header", func(t *testing.T) {
		id := e.publishA(t, "one", "lei2")
		e.publishA(t, "two", "lei2")
		c := e.openStream(t, http.MethodGet, url.Values{"match": {"lei2"}}, http.Header{"Authorization": {"Bearer " + atok}, "Last-Event-ID": {id}}, "")
		if c.resp.Header.Get("Mercure-Last-Event-ID") != id {
			t.Fatalf("Mercure-Last-Event-ID %q, want %q", c.resp.Header.Get("Mercure-Last-Event-ID"), id)
		}
		if v, ok := c.resp.Header["Last-Event-Id"]; ok {
			t.Fatalf("Last-Event-ID response header %v on a hub that does not speak draft-07", v)
		}
		c.expect("two")
	})
	t.Run("draft-07 selectors are not templates", func(t *testing.T) {
		// The exact matcher "https://example.com/{id}" is a literal there.
		c := e.openStream(t, http.MethodGet, url.Values{"match": {"https://example.com/{id}"}}, bearer(atok), "")
		e.publishA(t, "no", "https://example.com/1")
		e.publishA(t, "yes", "https://example.com/{id}")
		c.expect("yes")
	})
}

// TestBothAcceptsEachRevision: one hub serves draft-07 and Mercure 1.0 clients side by side.
func TestBothAcceptsEachRevision(t *testing.T) {
	e := newEnv(t, mcfg(ProtocolBoth))
	legacySub := e.subscribe(t, tokenFor(t, nil, all), "t")
	modernSub := e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match", "t")
	r := e.post(t, e.access(t, mDetail(pubOnly, mBare("t"))), form("topic", "t", "data", "from modern"))
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if r = e.post(t, tokenFor(t, all, nil), form("topic", "t", "data", "from legacy")); r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	for _, c := range []*sseClient{legacySub, modernSub} {
		c.expect("from modern", "from legacy")
	}
	// Both the revisions' cursor headers.
	id := e.publish(t, "x", "t")
	c := e.openStream(t, http.MethodGet, url.Values{"match": {"t"}, "last_event_id": {id}}, bearer(tokenFor(t, nil, all)), "")
	if c.resp.Header.Get("Mercure-Last-Event-ID") != id || c.resp.Header.Get("Last-Event-ID") != id {
		t.Fatalf("headers %v", c.resp.Header)
	}
}

// TestReservedStrayPercent: a topic Go's URL parser refuses (a "%" that starts no escape) still cannot address the
// hub's namespace, as a browser's parser would read it.
func TestReservedStrayPercent(t *testing.T) {
	h := newHub(t, Config{})
	for _, topic := range []string{
		"/.well-known/mercure/subscriptions/%zz/x",
		"/.well-known/mercure/a%zz",
		"/.well-known/mercure/a%/x",
		"https://hub.example/.well-known/mercure/%",
		"/.well-known/%6Dercure/%zz",
	} {
		if err := h.validate(&Update{Topics: []string{topic}}); err != ErrReservedTopic {
			t.Errorf("%q: %v, want ErrReservedTopic", topic, err)
		}
	}
	for _, topic := range []string{"100%", "a%zz", "https://example.com/%zz/.well-known/mercure"} {
		if err := h.validate(&Update{Topics: []string{topic}}); err != nil {
			t.Errorf("%q refused: %v", topic, err)
		}
	}
}

func TestEscapeStrayPercent(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "a": "a", "%": "%25", "%2": "%252", "%2F": "%2F", "%zz": "%25zz", "%%41": "%25%41", "a%b%c3%A9": "a%25b%c3%A9",
	} {
		if got := escapeStrayPercent(in); got != want {
			t.Errorf("escapeStrayPercent(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIDQuotesEscaped: the spec allows quotes and backslashes in an ID; echoed inside quoted header values (the Link
// last-event-id, the ETag), they are escaped, so an ID cannot add a parameter or a link.
func TestIDQuotesEscaped(t *testing.T) {
	for _, tc := range []struct{ id, quoted, etag string }{
		{`a"b`, `"a\"b"`, `"a%22b"`},
		{`a\b`, `"a\\b"`, `"a\b"`},
		{`x", <https://evil>; rel="mercure`, `"x\", <https://evil>; rel=\"mercure"`, `"x%22,%20<https://evil>;%20rel=%22mercure"`},
		{"urn:plain", `"urn:plain"`, `"urn:plain"`},
	} {
		if err := (&Update{Topics: []string{"t"}, ID: tc.id}).validate(); err != nil {
			t.Errorf("%q refused: %v", tc.id, err)
		}
		if got := quotedString(tc.id); got != tc.quoted {
			t.Errorf("quotedString(%q) = %s, want %s", tc.id, got, tc.quoted)
		}
		if got := entityTag(tc.id); got != tc.etag {
			t.Errorf("entityTag(%q) = %s, want %s", tc.id, got, tc.etag)
		}
	}
}
