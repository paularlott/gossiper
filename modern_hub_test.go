package gossiper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// mdDoc is the protected resource metadata, read loosely so that absent members can be told from empty ones.
type mdDoc map[string]json.RawMessage

func (m mdDoc) str(t testing.TB, key string) string {
	t.Helper()
	var s string
	if raw, ok := m[key]; !ok || json.Unmarshal(raw, &s) != nil {
		t.Fatalf("metadata member %q is missing or not a string: %v", key, m)
	}
	return s
}

func (m mdDoc) strs(t testing.TB, key string) []string {
	t.Helper()
	var s []string
	if raw, ok := m[key]; !ok || json.Unmarshal(raw, &s) != nil {
		t.Fatalf("metadata member %q is missing or not a list of strings: %v", key, m)
	}
	return s
}

func readMetadata(t testing.TB, body string) mdDoc {
	t.Helper()
	var m mdDoc
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("metadata %q: %v", body, err)
	}
	return m
}

// TestMetadata: §9.2.
func TestMetadata(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		r := e.get(t, e.metadataURL(), nil)
		if r.code != 200 {
			t.Fatalf("%d %s", r.code, r.body)
		}
		if r.header.Get("Content-Type") != "application/json" || r.header.Get("Cache-Control") != "max-age=300" {
			t.Fatalf("headers %v", r.header)
		}
		md := readMetadata(t, r.body)
		if got := md.str(t, "resource"); got != e.hubURL() {
			t.Errorf("resource %q, want %q", got, e.hubURL())
		}
		if got := md.strs(t, "authorization_details_types_supported"); !reflect.DeepEqual(got, []string{"https://mercure.rocks/authorization-detail"}) {
			t.Errorf("authorization_details_types_supported %v", got)
		}
		if got := md.strs(t, "bearer_methods_supported"); !reflect.DeepEqual(got, []string{"header"}) {
			t.Errorf("bearer_methods_supported %v (the cookie is not an RFC 6750 method)", got)
		}
		if got := md.str(t, "mercure_cookie"); got != "__Secure-mercure_access_token" {
			t.Errorf("mercure_cookie %q", got)
		}
		if got := md.strs(t, "mercure_matcher_types_supported"); !reflect.DeepEqual(got, []string{"exact", "urlpattern"}) {
			t.Errorf("mercure_matcher_types_supported %v", got)
		}
		for _, absent := range []string{"mercure_subscriptions", "authorization_servers"} {
			if _, ok := md[absent]; ok {
				t.Errorf("%s is present: %s", absent, r.body)
			}
		}
		for k := range md {
			switch k {
			case "resource", "authorization_details_types_supported", "bearer_methods_supported", "mercure_cookie", "mercure_matcher_types_supported":
			default:
				t.Errorf("unexpected member %q", k)
			}
		}
	})
}

func TestMetadataMembers(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		t.Run("subscriptions and a cookie name", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.Subscriptions = true
			cfg.AccessTokenCookieName = "hub_token"
			e := newEnv(t, cfg)
			md := readMetadata(t, e.get(t, e.metadataURL(), nil).body)
			if string(md["mercure_subscriptions"]) != "true" {
				t.Errorf("mercure_subscriptions %s", md["mercure_subscriptions"])
			}
			if md.str(t, "mercure_cookie") != "hub_token" {
				t.Errorf("mercure_cookie %s", md["mercure_cookie"])
			}
		})
		t.Run("an authorization server", func(t *testing.T) {
			var as *httptest.Server
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"issuer":"` + as.URL + `","jwks_uri":"` + as.URL + `/jwks"}`))
			})
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"keys":[]}`))
			})
			as = httptest.NewServer(mux)
			t.Cleanup(as.Close)
			cfg := mcfg(p)
			cfg.AllowInsecureKeyURLs = true
			cfg.Issuers = []auth.Issuer{
				{Issuer: as.URL, Discover: true},
				{Issuer: "https://self.example", Key: "another-secret-another-secret-12345"}, // self-issued: not advertised
			}
			e := newEnv(t, cfg)
			md := readMetadata(t, e.get(t, e.metadataURL(), nil).body)
			if got := md.strs(t, "authorization_servers"); !reflect.DeepEqual(got, []string{as.URL}) {
				t.Errorf("authorization_servers %v, want [%s]", got, as.URL)
			}
		})
	})
}

func TestMetadataMethods(t *testing.T) {
	e := newEnv(t, mcfg(ProtocolBoth))
	r := e.do(t, http.MethodHead, e.metadataURL(), nil, "")
	if r.code != 200 || r.body != "" || r.header.Get("Content-Type") != "application/json" || r.header.Get("Cache-Control") != "max-age=300" {
		t.Errorf("HEAD: %d %q %v", r.code, r.body, r.header)
	}
	get := e.get(t, e.metadataURL(), nil)
	if r.header.Get("Content-Length") != "" && r.header.Get("Content-Length") != get.header.Get("Content-Length") {
		t.Errorf("HEAD Content-Length %q, GET %q", r.header.Get("Content-Length"), get.header.Get("Content-Length"))
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, "QUERY"} {
		r = e.do(t, m, e.metadataURL(), nil, "")
		if r.code != 405 || r.header.Get("Allow") != "GET, HEAD, OPTIONS" {
			t.Errorf("%s: %d %v", m, r.code, r.header)
		}
	}
	h := newModernHub(t, Config{CORSOrigins: []string{"https://app.example"}})
	w := hubDo(t, h, http.MethodOptions, metadataPath, http.Header{"Origin": {"https://app.example"}, "Access-Control-Request-Method": {"GET"}}, "")
	if w.Code != 204 {
		t.Errorf("OPTIONS: %d", w.Code)
	}
	// It needs no token, and a bad one does not matter.
	if r = e.get(t, e.metadataURL(), bearer("garbage")); r.code != 200 {
		t.Errorf("with a bad token: %d", r.code)
	}
	// Neighbours are not it.
	for _, path := range []string{metadataPath + "/", metadataPath + "/x", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/.well-known/mercure.json"} {
		if r = e.get(t, e.srv.URL+path, nil); r.code != 404 {
			t.Errorf("%s: %d", path, r.code)
		}
	}
}

func TestMetadataAbsentInLegacy(t *testing.T) {
	h := newModernHub(t, Config{Protocol: ProtocolLegacy})
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost} {
		if w := hubDo(t, h, m, metadataPath, nil, ""); w.Code != 404 {
			t.Errorf("%s: %d", m, w.Code)
		}
	}
}

// TestMetadataResource: the resource is what a token's aud must be: the URL the client contacted unless the hub
// is told otherwise.
func TestMetadataResource(t *testing.T) {
	get := func(t *testing.T, h *Hub, hdr http.Header) mdDoc {
		t.Helper()
		w := hubDo(t, h, http.MethodGet, metadataPath, hdr, "")
		if w.Code != 200 {
			t.Fatalf("%d", w.Code)
		}
		return readMetadata(t, w.Body.String())
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		h := newModernHub(t, mcfg(p))
		if got := get(t, h, nil).str(t, "resource"); got != hubAud {
			t.Errorf("resource %q", got)
		}
		if got := get(t, h, http.Header{"Host": {"alt.test:8443"}}).str(t, "resource"); got != "http://alt.test:8443"+hubPath {
			t.Errorf("resource %q", got)
		}
		if got := get(t, h, http.Header{"X-Forwarded-Proto": {"https"}}).str(t, "resource"); got != hubAud {
			t.Errorf("X-Forwarded-Proto is not trusted: resource %q", got)
		}
		trusted := mcfg(p)
		trusted.TrustForwardedProto = true
		th := newModernHub(t, trusted)
		if got := get(t, th, http.Header{"X-Forwarded-Proto": {"https"}}).str(t, "resource"); got != "https://example.com"+hubPath {
			t.Errorf("trusted X-Forwarded-Proto: resource %q", got)
		}
		if got := get(t, th, http.Header{"X-Forwarded-Proto": {"gopher"}}).str(t, "resource"); got != hubAud {
			t.Errorf("trusted, unknown protocol: resource %q", got)
		}

		cfg := mcfg(p)
		cfg.HubURL = "https://hub.example.com/.well-known/mercure"
		h = newModernHub(t, cfg)
		if got := get(t, h, http.Header{"Host": {"alt.test"}}).str(t, "resource"); got != cfg.HubURL {
			t.Errorf("with a hub URL: resource %q", got)
		}

		cfg.ResourceIdentifier = "urn:example:hub"
		h = newModernHub(t, cfg)
		if got := get(t, h, nil).str(t, "resource"); got != "urn:example:hub" {
			t.Errorf("with a resource identifier: resource %q", got)
		}
	})
}

// TestMetadataDiscoveryFlow: a client that reads the metadata and puts its resource in aud is accepted.
func TestMetadataDiscoveryFlow(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		for name, cfg := range map[string]Config{
			"default": mcfg(p),
			"resource identifier": func() Config {
				c := mcfg(p)
				c.ResourceIdentifier = "https://hub.example.com/.well-known/mercure"
				return c
			}(),
			"absolute hub URL": func() Config { c := mcfg(p); c.HubURL = "https://hub.example.com/.well-known/mercure"; return c }(),
		} {
			t.Run(name, func(t *testing.T) {
				e := newEnv(t, cfg)
				resource := readMetadata(t, e.get(t, e.metadataURL(), nil).body).str(t, "resource")
				tok := accessFor(t, resource, mDetail(pubOnly, mBare("*")))
				if r := e.post(t, tok, form("topic", "t")); r.code != 200 {
					t.Fatalf("a token for %q: %d %s", resource, r.code, r.body)
				}
			})
		}
	})
}

// TestTrustedIssuers: each issuer's tokens are verified with that issuer's key only (§6.3).
func TestTrustedIssuers(t *testing.T) {
	const (
		selfIssuer = "https://self.example"
		selfSecret = "another-secret-another-secret-12345"
	)
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Issuers = []auth.Issuer{{Issuer: selfIssuer, Key: selfSecret}}
		e := newEnv(t, cfg)
		sign := func(iss, secret string) string {
			c := accessClaims(e.hubURL(), time.Hour, mDetail(pubOnly, mBare("*")))
			c["iss"] = iss
			return signAccessTyp(t, secret, "at+jwt", c)
		}
		for _, tc := range []struct {
			name string
			tok  string
			code int
		}{
			{"trusted issuer, its key", sign(testIssuer, testSecret), 200},
			{"configured issuer, its key", sign(selfIssuer, selfSecret), 200},
			{"trusted issuer, the other issuer's key", sign(testIssuer, selfSecret), 401},
			{"configured issuer, the trusted issuer's key", sign(selfIssuer, testSecret), 401},
			{"unknown issuer, a known key", sign("https://unknown.example", testSecret), 401},
		} {
			if r := e.post(t, tc.tok, form("topic", "t")); r.code != tc.code {
				t.Errorf("%s: %d, want %d", tc.name, r.code, tc.code)
			}
		}
	})
	t.Run("no trusted issuer", func(t *testing.T) {
		e := newEnv(t, Config{Protocol: ProtocolBoth}) // keys, but no issuer: Mercure 1.0 tokens have no one to vouch for them
		tok := accessFor(t, e.hubURL(), mDetail(pubOnly, mBare("*")))
		if r := e.post(t, tok, form("topic", "t")); r.code != 401 {
			t.Fatalf("%d", r.code)
		}
		// draft-07 tokens still work.
		if r := e.post(t, tokenFor(t, all, nil), form("topic", "t")); r.code != 200 {
			t.Fatalf("%d", r.code)
		}
	})
}

// TestCloseEndsStalledModernStreams: a stream blocked writing to a client that never reads ends when the hub
// closes, quickly, for a Mercure 1.0 subscription too.
func TestCloseEndsStalledModernStreams(t *testing.T) {
	e := newEnv(t, Config{TrustedIssuers: []string{testIssuer}, WriteTimeout: time.Minute, DispatchBuffer: 1000, HistorySize: -1, Subscriptions: true})
	conn := stalledMatchClient(t, e, e.access(t, mDetail(subOnly, mBare("*"))), "t")
	defer conn.Close()
	waitSubscribers(t, e.hub, 1)
	blockWrites(t, e.hub)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := e.hub.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close waited %v for a stalled stream", d)
	}
}

// TestStalledModernClientDoesNotDelayOthers: one stalled subscriber costs the others nothing.
func TestStalledModernClientDoesNotDelayOthers(t *testing.T) {
	e := newEnv(t, Config{TrustedIssuers: []string{testIssuer}, WriteTimeout: time.Minute, DispatchBuffer: 100000, HistorySize: -1})
	tok := e.access(t, mDetail(subOnly, mBare("*")))
	stalledMatchClient(t, e, tok, "t")
	waitSubscribers(t, e.hub, 1)
	good := e.matchStream(t, tok, "match", "t")
	blockWrites(t, e.hub)
	start := time.Now()
	for i := 0; i < 20; i++ {
		if _, err := e.hub.Publish(t.Context(), &Update{Topics: []string{"t"}, Data: "small"}); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("publishing took %v with one stalled stream", d)
	}
	n := 0
	for n < 20 {
		ev := good.mustNext()
		if ev.Data == "small" {
			n++
		}
	}
}

// stalledMatchClient opens a Mercure 1.0 stream that never reads: once the kernel's buffers fill, the hub's writes
// to it block.
func stalledMatchClient(t *testing.T, e *env, tok string, matchers ...string) net.Conn {
	t.Helper()
	addr := e.srv.Listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(2048)
	}
	q := url.Values{"match": matchers}.Encode()
	fmt.Fprintf(conn, "GET %s?%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", hubPath, q, addr, tok)
	return conn
}

// TestPublishCopiesTheCallersUpdate: Hub.Publish keeps nothing of the caller's update.
func TestPublishCopiesTheCallersUpdate(t *testing.T) {
	ft := newFakeTransport("node-a")
	ft.deliverLocal = false
	h := newModernHub(t, Config{Transport: ft})
	u := &Update{Topics: []string{"a", "b"}, Data: "payload", Type: "kind", Private: true, Retry: 5, HasRetry: true}
	id, err := h.Publish(t.Context(), u)
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	// The caller's update is as it was.
	if u.ID != "" || u.Stamp != 0 || u.Origin != "" || u.encoded != nil {
		t.Fatalf("Publish changed the caller's update: %+v", u)
	}
	ft.mu.Lock()
	got := ft.published[0]
	ft.mu.Unlock()
	if got == u {
		t.Fatal("the hub published the caller's update itself")
	}
	if got.ID != id || got.Origin != "node-a" || got.Stamp == 0 || got.Data != "payload" || got.Type != "kind" || !got.Private || got.Retry != 5 || !got.HasRetry {
		t.Fatalf("published %+v", got)
	}
	// Changing the caller's update afterwards changes nothing the hub holds.
	u.Topics[0] = "mutated"
	u.Topics = append(u.Topics, "c")
	u.Data = "changed"
	if !reflect.DeepEqual(got.Topics, []string{"a", "b"}) || got.Data != "payload" {
		t.Fatalf("the hub's copy follows the caller's: %+v", got)
	}
	// The same update can be published again.
	u2 := &Update{Topics: []string{"a"}}
	id1, _ := h.Publish(t.Context(), u2)
	id2, _ := h.Publish(t.Context(), u2)
	if id1 == "" || id1 == id2 {
		t.Fatalf("ids %q %q", id1, id2)
	}
	// A chosen id is kept.
	if id, _ = h.Publish(t.Context(), &Update{ID: "mine", Topics: []string{"a"}}); id != "mine" {
		t.Fatalf("id %q", id)
	}
}

func TestPublishCopyDelivered(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		c := e.matchStream(t, e.access(t, mDetail(subOnly, mExact("a"))), "match", "a", "match", "b")
		u := &Update{Topics: []string{"a"}, Data: "one", Private: true}
		if _, err := e.hub.Publish(t.Context(), u); err != nil {
			t.Fatal(err)
		}
		u.Topics[0] = "b"
		u.Private = false
		u.Data = "two"
		c.expect("one")
		if got := e.settleOn(t, c, "a", "b"); len(got) != 0 {
			t.Fatalf("%v", got)
		}
	})
}

// settleOn publishes the sentinel on a topic the stream matches.
func (e *env) settleOn(t testing.TB, c *sseClient, topics ...string) []string {
	t.Helper()
	if _, err := e.hub.Publish(t.Context(), &Update{Topics: topics[:1], Data: "end"}); err != nil {
		t.Fatal(err)
	}
	return c.drain("end")
}

// TestHubPublishRefusesWhatHTTPDoes: the Go API validates updates as the HTTP endpoint does (the caller is trusted
// with authorization only).
func TestHubPublishValidatesLikeHTTP(t *testing.T) {
	h := newModernHub(t, mcfg(ProtocolBoth))
	for name, u := range map[string]*Update{
		"no topic":        {},
		"empty topic":     {Topics: []string{""}},
		"wildcard topic":  {Topics: []string{"*"}},
		"C1 topic":        {Topics: []string{"a\u0085"}},
		"hub namespace":   {Topics: []string{"https://x.example/.well-known/mercure/subscriptions/exact/a/b"}},
		"mercure type":    {Topics: []string{"a"}, Type: "mercure"},
		"Cf type":         {Topics: []string{"a"}, Type: "a\u200bb"},
		"Cf id":           {Topics: []string{"a"}, ID: "a\u200bb"},
		"fragment id":     {Topics: []string{"a"}, ID: "#1"},
		"earliest id":     {Topics: []string{"a"}, ID: "earliest"},
		"long topic":      {Topics: []string{strings.Repeat("a", MaxTopicLength+1)}},
		"bad UTF-8 data":  {Topics: []string{"a"}, Data: "\xff"},
		"too many topics": {Topics: make([]string, MaxTopics+1)},
	} {
		if _, err := h.Publish(t.Context(), u); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
