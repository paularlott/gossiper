package gossiper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serve runs one request through the hub's handler.
func serve(t *testing.T, h *Hub, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func newHub(t *testing.T, cfg Config) *Hub {
	t.Helper()
	if !hasKey(cfg.PublisherKey) {
		cfg.PublisherKey.Key = testSecret
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close(t.Context()) })
	return h
}

func TestCORS(t *testing.T) {
	h := newHub(t, Config{CORSOrigins: []string{"https://app.example.com", "HTTP://Other.example/"}})
	tok := "Bearer " + tokenFor(t, all, all)
	tests := []struct {
		name   string
		origin string
		want   string // Access-Control-Allow-Origin
	}{
		{"allowed", "https://app.example.com", "https://app.example.com"},
		{"allowed, config normalised", "http://other.example", "http://other.example"},
		{"allowed, request case", "HTTPS://APP.example.com", "HTTPS://APP.example.com"},
		{"not allowed", "https://evil.example.com", ""},
		{"no origin", "", ""},
		{"scheme differs", "http://app.example.com", ""},
		{"port differs", "https://app.example.com:8443", ""},
	}
	for _, tc := range tests {
		for _, method := range []string{"GET", "HEAD"} {
			t.Run(tc.name+" "+method, func(t *testing.T) {
				hdr := map[string]string{"Authorization": tok}
				if tc.origin != "" {
					hdr["Origin"] = tc.origin
				}
				w := serve(t, h, method, "/.well-known/mercure", hdr)
				got := w.Header().Get("Access-Control-Allow-Origin")
				if got != tc.want {
					t.Fatalf("Allow-Origin %q, want %q", got, tc.want)
				}
				if tc.want != "" {
					if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
						t.Fatal("credentials not allowed")
					}
					if w.Header().Get("Access-Control-Expose-Headers") != "Link, Last-Event-ID, Mercure-Last-Event-ID, Accept-Query" {
						t.Fatalf("expose headers %q", w.Header().Get("Access-Control-Expose-Headers"))
					}
				} else if w.Header().Get("Access-Control-Allow-Credentials") != "" {
					t.Fatal("credentials header on a refused origin")
				}
				if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Origin") {
					t.Fatal("no Vary: Origin")
				}
			})
		}
	}
}

func TestCORSStarAllowsAnyOriginWithoutCredentials(t *testing.T) {
	h := newHub(t, Config{CORSOrigins: []string{"*"}})
	w := serve(t, h, "POST", "/.well-known/mercure", map[string]string{"Origin": "https://anywhere.example"})
	// A credentialed endpoint must never reflect arbitrary origins: "*" allows reading without the cookie only.
	if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("Allow-Origin %q credentials %q", w.Header().Get("Access-Control-Allow-Origin"),
			w.Header().Get("Access-Control-Allow-Credentials"))
	}
	// Errors carry the CORS headers too: a browser cannot read them otherwise.
	if w.Code != 401 {
		t.Fatalf("status %d", w.Code)
	}
	// A listed origin next to "*" is still echoed with credentials.
	h2 := newHub(t, Config{CORSOrigins: []string{"*", "https://app.example"}})
	w = serve(t, h2, "GET", "/.well-known/mercure", map[string]string{"Origin": "https://app.example"})
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("listed origin: %q %q", w.Header().Get("Access-Control-Allow-Origin"), w.Header().Get("Access-Control-Allow-Credentials"))
	}
}

func TestCORSDisabled(t *testing.T) {
	h := newHub(t, Config{})
	w := serve(t, h, "GET", "/.well-known/mercure", map[string]string{"Origin": "https://app.example.com"})
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS headers with no allowed origins")
	}
}

func TestPreflight(t *testing.T) {
	h := newHub(t, Config{CORSOrigins: []string{"https://app.example.com"}})
	tests := []struct {
		name                   string
		path                   string
		hdr                    map[string]string
		wantOrigin, wantMethod string
		wantHeaders            string
		wantMaxAge             string
	}{
		{"post", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST",
			"Access-Control-Request-Headers": "authorization, content-type"},
			"https://app.example.com", "POST", "authorization, content-type", "600"},
		{"get", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "GET"},
			"https://app.example.com", "GET", "", "600"},
		{"head", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "HEAD"},
			"https://app.example.com", "HEAD", "", "600"},
		{"put is not offered", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "PUT"},
			"https://app.example.com", "", "", "600"},
		{"unsafe request headers are not echoed", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST",
			"Access-Control-Request-Headers": "x\r\ninjected"},
			"https://app.example.com", "POST", "", "600"},
		{"bad header chars", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST",
			"Access-Control-Request-Headers": "a;b"},
			"https://app.example.com", "POST", "", "600"},
		{"header list too long", "/.well-known/mercure", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST",
			"Access-Control-Request-Headers": strings.Repeat("a", 1025)},
			"https://app.example.com", "POST", "", "600"},
		{"foreign origin", "/.well-known/mercure", map[string]string{
			"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"},
			"", "", "", ""},
		{"no request method", "/.well-known/mercure", map[string]string{"Origin": "https://app.example.com"},
			"https://app.example.com", "", "", ""},
		{"no origin", "/.well-known/mercure", map[string]string{"Access-Control-Request-Method": "POST"}, "", "", "", ""},
		{"subscriptions path", "/.well-known/mercure/subscriptions/x", map[string]string{
			"Origin": "https://app.example.com", "Access-Control-Request-Method": "GET"},
			"https://app.example.com", "GET", "", "600"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := serve(t, h, "OPTIONS", tc.path, tc.hdr)
			if w.Code != http.StatusNoContent {
				t.Fatalf("status %d", w.Code)
			}
			hd := w.Header()
			if got := hd.Get("Access-Control-Allow-Origin"); got != tc.wantOrigin {
				t.Errorf("Allow-Origin %q, want %q", got, tc.wantOrigin)
			}
			if got := hd.Get("Access-Control-Allow-Methods"); got != tc.wantMethod {
				t.Errorf("Allow-Methods %q, want %q", got, tc.wantMethod)
			}
			if got := hd.Get("Access-Control-Allow-Headers"); got != tc.wantHeaders {
				t.Errorf("Allow-Headers %q, want %q", got, tc.wantHeaders)
			}
			if got := hd.Get("Access-Control-Max-Age"); got != tc.wantMaxAge {
				t.Errorf("Max-Age %q, want %q", got, tc.wantMaxAge)
			}
			if hd.Get("Access-Control-Expose-Headers") != "" {
				t.Error("preflight exposes headers")
			}
			vary := strings.Join(hd.Values("Vary"), ",")
			for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
				if !strings.Contains(vary, want) {
					t.Errorf("Vary %q lacks %s", vary, want)
				}
			}
			if w.Body.Len() != 0 {
				t.Error("preflight has a body")
			}
		})
	}
}

func TestValidHeaderList(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "authorization": true, "Authorization, Content-Type": true, "x-custom_1.2": true, "a,b": true,
		"a;b": false, "a\nb": false, "a\"b": false, "é": false, "a(b)": false, "a:b": false,
	} {
		if got := validHeaderList(s); got != want {
			t.Errorf("validHeaderList(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestOriginIn(t *testing.T) {
	list := []string{"https://a.example", "http://b.example:8080"}
	for origin, want := range map[string]bool{
		"https://a.example": true, "https://A.EXAMPLE": true, "https://a.example/": true, "http://a.example": false,
		"http://b.example:8080": true, "http://b.example": false, "": false, "null": false,
	} {
		if got := originIn(origin, list); got != want {
			t.Errorf("originIn(%q) = %v, want %v", origin, got, want)
		}
	}
	if !originIn("anything", []string{"x", "*"}) {
		t.Error("star does not allow any origin")
	}
	if originIn("x", nil) {
		t.Error("empty list allows an origin")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHub(t, Config{})
	for _, path := range []string{"/.well-known/mercure", "/nowhere", "/.well-known/mercure/subscriptions"} {
		w := serve(t, h, "GET", path, nil)
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "DENY" ||
			w.Header().Get("Content-Security-Policy") != "default-src 'self'" {
			t.Errorf("%s: security headers %v", path, w.Header())
		}
	}
}

func TestPublishOriginAllowedUnit(t *testing.T) {
	h := newHub(t, Config{PublishOrigins: []string{"https://a.example"}})
	for _, tc := range []struct {
		origin, referer string
		want            bool
	}{
		{"https://a.example", "", true},
		{"", "https://a.example/path?q#f", true},
		{"null", "https://a.example/x", true},
		{"", "", false},
		{"null", "", false},
		{"https://b.example", "https://a.example/", false},
		{"", "https://b.example/", false},
		{"", "a.example/path", false},
		{"", "://bad", false},
		{"", "https:///nohost", false},
	} {
		r := httptest.NewRequest("POST", "/", nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.referer != "" {
			r.Header.Set("Referer", tc.referer)
		}
		if got := h.publishOriginAllowed(r); got != tc.want {
			t.Errorf("origin %q referer %q: %v, want %v", tc.origin, tc.referer, got, tc.want)
		}
	}
}

func TestTokenExtraction(t *testing.T) {
	h := newHub(t, Config{CookieName: "tok"})
	tests := []struct {
		name  string
		build func(*http.Request)
		want  string
		src   source
	}{
		{"none", func(*http.Request) {}, "", noToken},
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }, "abc", fromHeader},
		{"bearer lowercase", func(r *http.Request) { r.Header.Set("Authorization", "bearer abc") }, "abc", fromHeader},
		{"bearer mixed case", func(r *http.Request) { r.Header.Set("Authorization", "BeArEr abc") }, "abc", fromHeader},
		{"bearer extra spaces", func(r *http.Request) { r.Header.Set("Authorization", "Bearer   abc  ") }, "abc", fromHeader},
		{"other scheme", func(r *http.Request) { r.Header.Set("Authorization", "Basic xyz") }, "", fromHeader},
		{"bare token", func(r *http.Request) { r.Header.Set("Authorization", "abc.def.ghi") }, "", fromHeader},
		{"bearer without token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer   ") }, "", fromHeader},
		{"access token cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Secure-mercure_access_token", Value: "m"})
		}, "m", fromCookie},
		{"access token cookie beats the draft-07 one", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "tok", Value: "c"})
			r.AddCookie(&http.Cookie{Name: "__Secure-mercure_access_token", Value: "m"})
		}, "m", fromCookie},
		{"query", func(r *http.Request) { r.URL.RawQuery = "authorization=q" }, "q", fromQuery},
		{"empty query falls to cookie", func(r *http.Request) {
			r.URL.RawQuery = "authorization="
			r.AddCookie(&http.Cookie{Name: "tok", Value: "c"})
		}, "c", fromCookie},
		{"cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "tok", Value: "c"}) }, "c", fromCookie},
		{"cookie wrong name", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "mercureAuthorization", Value: "c"}) }, "", noToken},
		{"empty cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "tok", Value: ""}) }, "", noToken},
		{"header beats query and cookie", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer h")
			r.URL.RawQuery = "authorization=q"
			r.AddCookie(&http.Cookie{Name: "tok", Value: "c"})
		}, "h", fromHeader},
		{"query beats cookie", func(r *http.Request) {
			r.URL.RawQuery = "authorization=q"
			r.AddCookie(&http.Cookie{Name: "tok", Value: "c"})
		}, "q", fromQuery},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/.well-known/mercure", nil)
			tc.build(r)
			got, src, err := h.token(r)
			if (err != nil) != (tc.src == fromHeader && tc.want == "") {
				t.Fatalf("error %v", err)
			}
			if got != tc.want || src != tc.src {
				t.Fatalf("token %q from %d, want %q from %d", got, src, tc.want, tc.src)
			}
		})
	}
}

func TestUpperFirst(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "Abc", "Abc": "Abc", "1abc": "1abc", "é": "é", "z": "Z"} {
		if got := upperFirst(in); got != want {
			t.Errorf("upperFirst(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJSONMarshalDoesNotEscapeHTML(t *testing.T) {
	got := string(jsonMarshal(map[string]string{"t": "a&b<c>d"}))
	if got != `{"t":"a&b<c>d"}` {
		t.Fatalf("%q", got)
	}
	if got := string(jsonMarshal("x")); got != `"x"` {
		t.Fatalf("trailing newline kept: %q", got)
	}
}
