package gossiper

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
)

// form builds a publish form.
func form(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func TestPublishAuth(t *testing.T) {
	e := newEnv(t, Config{})
	good := form("topic", "https://example.com/a", "data", "x")

	expired := mercureClaims(all, nil)
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	notYet := mercureClaims(all, nil)
	notYet["nbf"] = time.Now().Add(time.Hour).Unix()
	noMercure := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}

	tests := []struct {
		name     string
		hdr      http.Header
		query    string
		form     url.Values
		wantCode int
		wantAuth string // WWW-Authenticate
	}{
		{"no token", nil, "", good, 401, "Bearer"},
		{"malformed token", http.Header{"Authorization": {"Bearer not-a-jwt"}}, "", good, 400, `Bearer error="invalid_request"`},
		{"not a bearer header", http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}}, "", good, 400, `Bearer error="invalid_request"`},
		{"bearer without token", http.Header{"Authorization": {"Bearer"}}, "", good, 400, `Bearer error="invalid_request"`},
		{"lowercase bearer", http.Header{"Authorization": {"bearer " + tokenFor(t, all, nil)}}, "", good, 200, ""},
		{"bad signature", bearer(signJWT(t, "some-other-secret-some-other-secret", mercureClaims(all, nil))), "", good, 401, `Bearer error="invalid_token"`},
		{"expired", bearer(signJWT(t, testSecret, expired)), "", good, 401, `Bearer error="invalid_token"`},
		{"not yet valid", bearer(signJWT(t, testSecret, notYet)), "", good, 401, `Bearer error="invalid_token"`},
		{"no mercure claim", bearer(signJWT(t, testSecret, noMercure)), "", good, 401, `Bearer error="invalid_token"`},
		{"publish absent", bearer(tokenFor(t, nil, all)), "", good, 403, `Bearer error="insufficient_scope"`},
		{"publish empty", bearer(tokenFor(t, []string{}, all)), "", good, 403, `Bearer error="insufficient_scope"`},
		{"topic not matched", bearer(tokenFor(t, []string{"https://example.com/b"}, nil)), "", good, 403, `Bearer error="insufficient_scope"`},
		{"exact selector", bearer(tokenFor(t, []string{"https://example.com/a"}, nil)), "", good, 200, ""},
		{"template selector", bearer(tokenFor(t, []string{"https://example.com/{id}"}, nil)), "", good, 200, ""},
		{"template selector no match", bearer(tokenFor(t, []string{"https://other.com/{id}"}, nil)), "", good, 403, `Bearer error="insufficient_scope"`},
		{"star selector", bearer(tokenFor(t, all, nil)), "", good, 200, ""},
		{"one of several selectors", bearer(tokenFor(t, []string{"x", "https://example.com/a", "y"}, nil)), "", good, 200, ""},
		{"all topics must match", bearer(tokenFor(t, []string{"https://example.com/a"}, nil)), "",
			form("topic", "https://example.com/a", "topic", "https://example.com/other"), 403, `Bearer error="insufficient_scope"`},
		{"all topics match different selectors", bearer(tokenFor(t, []string{"https://example.com/a", "https://example.com/{x}"}, nil)), "",
			form("topic", "https://example.com/a", "topic", "https://example.com/other"), 200, ""},
		{"alternate not matched", bearer(tokenFor(t, []string{"https://example.com/{x}"}, nil)), "",
			form("topic", "https://example.com/a", "topic", "https://elsewhere/b"), 403, `Bearer error="insufficient_scope"`},
		{"query token", nil, "authorization=" + tokenFor(t, all, nil), good, 200, ""},
		{"query token bad", nil, "authorization=garbage", good, 400, `Bearer error="invalid_request"`},
		{"header wins over query", bearer(tokenFor(t, all, nil)), "authorization=garbage", good, 200, ""},
		{"bad header wins over good query", bearer("garbage"), "authorization=" + tokenFor(t, all, nil), good, 400, `Bearer error="invalid_request"`},
		{"subscribe-only token", bearer(tokenFor(t, nil, all)), "", good, 403, `Bearer error="insufficient_scope"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := e.hubURL()
			if tc.query != "" {
				target += "?" + tc.query
			}
			r := e.do(t, "POST", target, tc.hdr, tc.form.Encode())
			if r.code != tc.wantCode {
				t.Fatalf("status %d (%s), want %d", r.code, strings.TrimSpace(r.body), tc.wantCode)
			}
			if got := challenge(r.header.Get("WWW-Authenticate")); got != tc.wantAuth {
				t.Fatalf("WWW-Authenticate %q, want %q", got, tc.wantAuth)
			}
			if tc.wantCode == 200 && !uuidV7.MatchString(r.body) {
				t.Fatalf("body %q is not a UUIDv7 event id", r.body)
			}
		})
	}
}

func TestPublishCookie(t *testing.T) {
	e := newEnv(t, Config{PublishOrigins: []string{"https://app.example.com"}})
	tok := tokenFor(t, all, nil)
	cookie := func(name string) http.Header { return http.Header{"Cookie": {name + "=" + tok}} }
	with := func(h http.Header, k, v string) http.Header {
		h = h.Clone()
		h.Set(k, v)
		return h
	}
	f := form("topic", "t")
	tests := []struct {
		name string
		hdr  http.Header
		want int
	}{
		{"no origin", cookie("mercureAuthorization"), 400},
		{"allowed origin", with(cookie("mercureAuthorization"), "Origin", "https://app.example.com"), 200},
		{"allowed origin case", with(cookie("mercureAuthorization"), "Origin", "https://APP.example.com"), 200},
		{"foreign origin", with(cookie("mercureAuthorization"), "Origin", "https://evil.example.com"), 400},
		{"null origin no referer", with(cookie("mercureAuthorization"), "Origin", "null"), 400},
		{"null origin allowed referer", with(with(cookie("mercureAuthorization"), "Origin", "null"), "Referer", "https://app.example.com/page?x=1"), 200},
		{"referer only", with(cookie("mercureAuthorization"), "Referer", "https://app.example.com/page"), 200},
		{"foreign referer", with(cookie("mercureAuthorization"), "Referer", "https://evil.example.com/page"), 400},
		{"junk referer", with(cookie("mercureAuthorization"), "Referer", "not a url"), 400},
		{"referer without host", with(cookie("mercureAuthorization"), "Referer", "/relative/path"), 400},
		{"wrong cookie name", with(cookie("other"), "Origin", "https://app.example.com"), 401},
		{"origin wins over referer", with(with(cookie("mercureAuthorization"), "Origin", "https://evil.example.com"), "Referer", "https://app.example.com/"), 400},
		{"bearer needs no origin", bearer(tok), 200},
		{"bearer wins over cookie", with(with(cookie("mercureAuthorization"), "Authorization", "Bearer "+tok), "Origin", "https://evil.example.com"), 200},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do(t, "POST", e.hubURL(), tc.hdr, f.Encode())
			if r.code != tc.want {
				t.Fatalf("status %d (%s), want %d", r.code, strings.TrimSpace(r.body), tc.want)
			}
			if tc.want == 400 && challenge(r.header.Get("WWW-Authenticate")) != `Bearer error="invalid_request"` {
				t.Fatalf("WWW-Authenticate %q", challenge(r.header.Get("WWW-Authenticate")))
			}
		})
	}
}

func TestPublishCookieOrigins(t *testing.T) {
	tok := tokenFor(t, all, nil)
	hdr := func(origin string) http.Header {
		return http.Header{"Cookie": {"mercureAuthorization=" + tok}, "Origin": {origin}}
	}
	t.Run("star allows any origin but still needs one", func(t *testing.T) {
		e := newEnv(t, Config{PublishOrigins: []string{"*"}})
		if r := e.do(t, "POST", e.hubURL(), hdr("https://anything.example"), form("topic", "t").Encode()); r.code != 200 {
			t.Fatalf("status %d", r.code)
		}
		if r := e.do(t, "POST", e.hubURL(), http.Header{"Cookie": {"mercureAuthorization=" + tok}}, form("topic", "t").Encode()); r.code != 400 {
			t.Fatalf("no origin: status %d", r.code)
		}
	})
	t.Run("no publish origins refuses every cookie publish", func(t *testing.T) {
		e := newEnv(t, Config{})
		if r := e.do(t, "POST", e.hubURL(), hdr("https://app.example.com"), form("topic", "t").Encode()); r.code != 400 {
			t.Fatalf("status %d", r.code)
		}
	})
	t.Run("custom cookie name", func(t *testing.T) {
		e := newEnv(t, Config{PublishOrigins: []string{"https://a.example"}, CookieName: "tok"})
		h := http.Header{"Cookie": {"tok=" + tok}, "Origin": {"https://a.example"}}
		if r := e.do(t, "POST", e.hubURL(), h, form("topic", "t").Encode()); r.code != 200 {
			t.Fatalf("status %d", r.code)
		}
		if r := e.do(t, "POST", e.hubURL(), hdr("https://a.example"), form("topic", "t").Encode()); r.code != 401 {
			t.Fatalf("default cookie name still honoured: %d", r.code)
		}
	})
	t.Run("query authorization disabled", func(t *testing.T) {
		e := newEnv(t, Config{DisableQueryAuthorization: true})
		if r := e.do(t, "POST", e.hubURL()+"?authorization="+tok, nil, form("topic", "t").Encode()); r.code != 401 {
			t.Fatalf("status %d", r.code)
		}
		if r := e.post(t, tok, form("topic", "t")); r.code != 200 {
			t.Fatalf("header token refused: %d", r.code)
		}
	})
}

func TestPublishNoPublisherKey(t *testing.T) {
	h, err := New(Config{Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(t.Context())
	srv := httptest.NewServer(h)
	defer srv.Close()
	e := &env{hub: h, srv: srv, client: srv.Client()}
	if r := e.post(t, "", form("topic", "t")); r.code != 401 || challenge(r.header.Get("WWW-Authenticate")) != "Bearer" {
		t.Fatalf("no token: %d %q", r.code, challenge(r.header.Get("WWW-Authenticate")))
	}
	// Without a key no token can be valid.
	if r := e.post(t, tokenFor(t, all, nil), form("topic", "t")); r.code != 401 {
		t.Fatalf("token: %d", r.code)
	}
	if r := e.do(t, "GET", e.hubURL()+"?topic=t", bearer(tokenFor(t, all, all)), ""); r.code != 401 {
		t.Fatalf("subscribe with a token and no key: %d", r.code)
	}
}

func TestPublishValidation(t *testing.T) {
	e := newEnv(t, Config{MaxPublishBytes: 16384})
	tok := tokenFor(t, all, nil)
	longTopic := strings.Repeat("a", MaxTopicLength+1)
	manyTopics := url.Values{}
	for i := 0; i <= MaxTopics; i++ {
		manyTopics.Add("topic", "t"+strconv.Itoa(i))
	}
	tests := []struct {
		name     string
		form     url.Values
		want     int
		wantBody string
	}{
		{"ok", form("topic", "t"), 200, ""},
		{"no topic", form("data", "x"), 400, `Missing "topic" parameter`},
		{"empty form", form(), 400, `Missing "topic" parameter`},
		{"empty topic", form("topic", ""), 400, `Invalid "topic" parameter`},
		{"topic too long", form("topic", longTopic), 413, ""},
		{"too many topics", manyTopics, 413, ""},
		{"reserved topic", form("topic", "/.well-known/mercure/subscriptions/x/y"), 400, `"topic" addresses the hub's reserved namespace`},
		{"reserved absolute", form("topic", "https://any.example/.well-known/mercure/subscriptions/x"), 400, ""},
		{"reserved encoded", form("topic", "/.well-known/%6Dercure/x"), 400, ""},
		{"reserved dot segments", form("topic", "/a/../.well-known/mercure/../mercure/x"), 400, ""},
		{"reserved backslash", form("topic", `https://x\.well-known\mercure\y`), 400, ""},
		{"reserved hub url itself", form("topic", "/.well-known/mercure"), 400, ""},
		{"not reserved lookalike", form("topic", "/.well-known/mercurex"), 200, ""},
		{"plain name with a fragment", form("topic", "#general"), 200, ""},
		{"plain name with a query", form("topic", "?x"), 200, ""},
		{"relative name under the hub", form("topic", "mercure/chat"), 400, ""},
		{"encoded slashes refused too (decoded, stricter than needed)", form("topic", "/.well-known%2Fmercure%2Fx"), 400, ""},
		{"not a url", form("topic", "urn:isbn:0451450523"), 200, ""},
		{"star topic", form("topic", "*"), 400, `Invalid "topic" parameter`},
		{"type mercure", form("topic", "t", "type", "mercure"), 400, `Invalid "type" parameter`},
		{"topic format char", form("topic", "a\u200bb"), 400, `Invalid "topic" parameter`},
		{"topic C1 char", form("topic", "a\u0085b"), 400, `Invalid "topic" parameter`},
		{"reserved alternate", form("topic", "ok", "topic", "/.well-known/mercure/x"), 400, `"topic" addresses the hub's reserved namespace`},
		{"topic with newline", form("topic", "a\nb"), 400, `Invalid "topic" parameter`},
		{"id with hash", form("topic", "t", "id", "#x"), 400, `Invalid "id" parameter`},
		{"id earliest", form("topic", "t", "id", "earliest"), 400, `Invalid "id" parameter`},
		{"id control char", form("topic", "t", "id", "a\x01b"), 400, `Invalid "id" parameter`},
		{"id newline", form("topic", "t", "id", "a\nb"), 400, `Invalid "id" parameter`},
		{"id too long", form("topic", "t", "id", strings.Repeat("a", MaxIDLength+1)), 413, ""},
		{"id max length", form("topic", "t", "id", strings.Repeat("a", MaxIDLength)), 200, ""},
		{"type too long", form("topic", "t", "type", strings.Repeat("a", MaxTypeLength+1)), 413, ""},
		{"type newline", form("topic", "t", "type", "a\nb"), 400, `Invalid "type" parameter`},
		{"data invalid utf8", form("topic", "t", "data", "a\xffb"), 400, `Invalid "data" parameter`},
		{"retry ok", form("topic", "t", "retry", "1000"), 200, ""},
		{"retry zero", form("topic", "t", "retry", "0"), 200, ""},
		{"retry letters", form("topic", "t", "retry", "abc"), 400, `Invalid "retry" parameter`},
		{"retry negative", form("topic", "t", "retry", "-1"), 400, `Invalid "retry" parameter`},
		{"retry fraction", form("topic", "t", "retry", "1.5"), 400, `Invalid "retry" parameter`},
		{"retry empty", form("topic", "t", "retry", ""), 400, `Invalid "retry" parameter`},
		{"retry overflow", form("topic", "t", "retry", "99999999999999999999"), 400, `Invalid "retry" parameter`},
		{"private empty value", form("topic", "t", "private", ""), 200, ""},
		{"private any value", form("topic", "t", "private", "false"), 200, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := e.post(t, tok, tc.form)
			if r.code != tc.want {
				t.Fatalf("status %d (%s), want %d", r.code, strings.TrimSpace(r.body), tc.want)
			}
			if tc.wantBody != "" && strings.TrimSpace(r.body) != tc.wantBody {
				t.Fatalf("body %q, want %q", strings.TrimSpace(r.body), tc.wantBody)
			}
		})
	}
	if rejected := e.hub.Stats().PublishRejected; rejected == 0 {
		t.Fatal("PublishRejected not counted")
	}
}

func TestPublishBodyHandling(t *testing.T) {
	e := newEnv(t, Config{MaxPublishBytes: 1000})
	tok := tokenFor(t, all, nil)
	t.Run("too large", func(t *testing.T) {
		r := e.post(t, tok, form("topic", "t", "data", strings.Repeat("x", 2000)))
		if r.code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", r.code)
		}
	})
	t.Run("just fits", func(t *testing.T) {
		r := e.post(t, tok, form("topic", "t", "data", strings.Repeat("x", 900)))
		if r.code != 200 {
			t.Fatalf("status %d", r.code)
		}
	})
	t.Run("malformed escape", func(t *testing.T) {
		r := e.do(t, "POST", e.hubURL(), bearer(tok), "topic=%zz")
		if r.code != 400 {
			t.Fatalf("status %d", r.code)
		}
	})
	t.Run("not a form content type", func(t *testing.T) {
		h := bearer(tok)
		h.Set("Content-Type", "application/json")
		r := e.do(t, "POST", e.hubURL(), h, `{"topic":"t"}`)
		if r.code != 400 || !strings.Contains(r.body, `Missing "topic"`) {
			t.Fatalf("status %d %q", r.code, r.body)
		}
	})
	t.Run("topic in the query string is ignored", func(t *testing.T) {
		r := e.do(t, "POST", e.hubURL()+"?topic=t", bearer(tok), "data=x")
		if r.code != 400 {
			t.Fatalf("status %d", r.code)
		}
	})
}

func TestPublishResponse(t *testing.T) {
	e := newEnv(t, Config{})
	tok := tokenFor(t, all, nil)
	r := e.post(t, tok, form("topic", "t", "id", "my-own-id"))
	if r.code != 200 || r.body != "my-own-id" {
		t.Fatalf("%d %q", r.code, r.body)
	}
	if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	if r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("no nosniff header")
	}
	r = e.post(t, tok, form("topic", "t"))
	if !uuidV7.MatchString(r.body) {
		t.Fatalf("generated id %q", r.body)
	}
	// The hub echoes a publisher's id even when it repeats.
	if r := e.post(t, tok, form("topic", "t", "id", "my-own-id")); r.body != "my-own-id" {
		t.Fatalf("repeated id %q", r.body)
	}
	s := e.hub.Stats()
	if s.Published != 3 || s.Applied != 3 {
		t.Fatalf("stats %+v", s)
	}
}

func TestPublishGeneratedIDsOrdered(t *testing.T) {
	e := newEnv(t, Config{})
	tok := tokenFor(t, all, nil)
	prev := ""
	for i := 0; i < 200; i++ {
		id := e.post(t, tok, form("topic", "t")).body
		if id <= prev {
			t.Fatalf("id %s does not sort after %s", id, prev)
		}
		prev = id
	}
}

func TestPublishCanonicalTopicFirst(t *testing.T) {
	e := newEnv(t, Config{})
	e.post(t, tokenFor(t, all, nil), form("topic", "canon", "topic", "alt1", "topic", "alt2", "data", "x"))
	ups, _ := e.hub.hist.since(earliest)
	if len(ups) != 1 || strings.Join(ups[0].Topics, ",") != "canon,alt1,alt2" {
		t.Fatalf("topics %+v", ups)
	}
	if ups[0].Origin != e.hub.NodeID() || ups[0].Stamp == 0 {
		t.Fatalf("origin/stamp not set: %+v", ups[0])
	}
}

func TestPublishMethodsAndPaths(t *testing.T) {
	e := newEnv(t, Config{})
	for _, m := range []string{"PUT", "DELETE", "PATCH"} {
		r := e.do(t, m, e.hubURL(), bearer(tokenFor(t, all, all)), "")
		if r.code != 405 || r.header.Get("Allow") != "GET, HEAD, QUERY, POST, OPTIONS" {
			t.Errorf("%s: %d allow %q", m, r.code, r.header.Get("Allow"))
		}
	}
	for _, p := range []string{"/", "/.well-known/mercure/", "/.well-known/mercurex", "/.well-known", "/hub"} {
		if r := e.do(t, "GET", e.srv.URL+p, nil, ""); r.code != 404 {
			t.Errorf("%s: %d", p, r.code)
		}
	}
}

func TestPublishRetryAndTypeReachSubscribers(t *testing.T) {
	e := newEnv(t, Config{})
	c := e.subscribe(t, tokenFor(t, nil, all), "t")
	e.post(t, tokenFor(t, all, nil), form("topic", "t", "id", "a", "type", "tick", "retry", "2500", "data", "l1\r\nl2\rl3\nl4"))
	ev := c.mustNext()
	want := "event: tick\nretry: 2500\nid: a\ndata: l1\ndata: l2\ndata: l3\ndata: l4\n\n"
	if ev.Raw != want {
		t.Fatalf("frame %q, want %q", ev.Raw, want)
	}
	e.post(t, tokenFor(t, all, nil), form("topic", "t", "id", "b"))
	if ev := c.mustNext(); ev.Raw != "id: b\ndata: \n\n" {
		t.Fatalf("empty data frame %q", ev.Raw)
	}
	e.post(t, tokenFor(t, all, nil), form("topic", "t", "id", "c", "retry", "0", "data", "z"))
	if ev := c.mustNext(); ev.Raw != "retry: 0\nid: c\ndata: z\n\n" {
		t.Fatalf("retry 0 frame %q", ev.Raw)
	}
}

func FuzzPublishForm(f *testing.F) {
	h, err := New(Config{PublisherKey: auth.KeyConfig{Key: testSecret}, HistorySize: 100, MaxPublishBytes: 1 << 16})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { h.Close(f.Context()) })
	tok := signJWT(f, testSecret, mercureClaims(all, nil))
	f.Add("topic=a&data=b&id=c&type=d&retry=1&private=")
	f.Add("topic=a&topic=b&topic=/.well-known/mercure/x")
	f.Add("data=only")
	f.Add("topic=%ff&id=%00&type=%0a&retry=-5&data=%ff")
	f.Add("topic=a&id=%23x&retry=99999999999999999999999")
	f.Add("%zz=1&;&&&=&topic")
	f.Add("topic=" + strings.Repeat("a", 5000))
	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequest(http.MethodPost, hubPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("status %d for body %q", rec.Code, body)
		}
		if rec.Code == 200 && rec.Body.Len() == 0 {
			t.Fatalf("200 with no event id for %q", body)
		}
	})
}
