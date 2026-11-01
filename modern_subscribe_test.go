package gossiper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// publishPrivate publishes one private update (a wildcard publish grant) and returns its id.
func (e *env) publishPrivate(t testing.TB, data string, topics ...string) string {
	t.Helper()
	r := e.post(t, e.access(t, mDetail(pubOnly, mBare("*"))), url.Values{"topic": topics, "data": {data}, "private": {"on"}})
	if r.code != 200 {
		t.Fatalf("publish: %d %s", r.code, r.body)
	}
	return r.body
}

// publishID publishes a public update with a chosen id.
func (e *env) publishID(t testing.TB, id, data string, topics ...string) {
	t.Helper()
	r := e.post(t, e.access(t, mDetail(pubOnly, mBare("*"))), url.Values{"topic": topics, "data": {data}, "id": {id}})
	if r.code != 200 || r.body != id {
		t.Fatalf("publish: %d %s", r.code, r.body)
	}
}

// settle publishes the sentinel and reads everything the stream was sent before it. The stream must match the
// "sentinel" topic.
func (e *env) settle(t testing.TB, c *sseClient) []string {
	t.Helper()
	e.publishA(t, "end", "sentinel")
	return c.drain("end")
}

func sameData(t testing.TB, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s: received %q, want %q", what, got, want)
	}
}

// TestSubscribeMatchers: the match parameters select topics by their matcher type.
func TestSubscribeMatchers(t *testing.T) {
	const (
		b1   = "https://example.com/books/1"
		b2   = "https://example.com/books/2"
		a1   = "https://example.com/authors/1"
		o1   = "https://other.example/books/1"
		rel  = "/books/1"
		b3   = "https://EXAMPLE.com/books/3"
		urn  = "urn:uuid:60a76c80-d399-11d9-b93c-0003939e0af6"
		star = "*"
	)
	universe := []string{b1, b2, a1, o1, rel, b3, urn}
	tests := []struct {
		name string
		kv   []string
		want []string
	}{
		{"match", []string{"match", b1}, []string{b1}},
		{"match_exact", []string{"match_exact", b1}, []string{b1}},
		{"match is not a pattern", []string{"match", "https://example.com/books/:id"}, nil},
		{"match is not a wildcard prefix", []string{"match", "https://example.com/books/*"}, nil},
		{"match is not resolved", []string{"match", "books/1"}, nil},
		{"match is byte for byte", []string{"match", "https://EXAMPLE.com/books/1"}, nil},
		{"match of the relative topic", []string{"match", rel}, []string{rel}},
		{"match of an uppercase host topic", []string{"match", b3}, []string{b3}},
		{"match_urlpattern", []string{"match_urlpattern", "https://example.com/books/:id"}, []string{b1, b2, b3}},
		{"match_urlpattern wildcard", []string{"match_urlpattern", "https://example.com/*"}, []string{b1, b2, a1, b3}},
		{"match_urlpattern of another host", []string{"match_urlpattern", "https://other.example/*"}, []string{o1}},
		{"match_urlpattern, relative", []string{"match_urlpattern", "/books/:id"}, []string{rel}},
		{"match_urlpattern, regexp group", []string{"match_urlpattern", `https://example.com/books/:id(1|3)`}, []string{b1, b3}},
		{"match_urlpattern, host case", []string{"match_urlpattern", "https://EXAMPLE.COM/books/:id"}, []string{b1, b2, b3}},
		{"match_urlpattern, path case", []string{"match_urlpattern", "https://example.com/Books/:id"}, nil},
		{"match_urlpattern, other scheme topics are outside it", []string{"match_urlpattern", "https://example.com/*"}, []string{b1, b2, a1, b3}},
		{"wildcard", []string{"match", star}, universe},
		{"wildcard exact", []string{"match_exact", star}, universe},
		{"wildcard urlpattern", []string{"match_urlpattern", star}, universe},
		{"exact and pattern", []string{"match", a1, "match_urlpattern", "https://example.com/books/:id"}, []string{b1, b2, a1, b3}},
		{"two exact", []string{"match", b2, "match", urn}, []string{b2, urn}},
		{"exact repeated", []string{"match", b1, "match", b1, "match_exact", b1}, []string{b1}},
		{"exact inside a pattern", []string{"match", b1, "match_urlpattern", "https://example.com/books/:id"}, []string{b1, b2, b3}},
		{"overlapping patterns", []string{"match_urlpattern", "https://example.com/*", "match_urlpattern", "https://example.com/books/:id"}, []string{b1, b2, a1, b3}},
		{"percent-encoded matcher", []string{"match", "https%3A%2F%2Fexample.com%2Fbooks%2F1"}, nil}, // the value is decoded once only
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		sub := e.access(t, mDetail(subOnly, mBare("*")))
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				kv := append([]string{"match", "sentinel"}, tc.kv...)
				c := e.matchStream(t, sub, kv...)
				for _, tp := range universe {
					e.publishA(t, tp, tp)
				}
				sameData(t, tc.name, e.settle(t, c), tc.want)
			})
		}
	})
}

func TestSubscribeUpdateWithAlternateTopics(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		sub := e.access(t, mDetail(subOnly, mBare("*")))
		byAlternate := e.matchStream(t, sub, "match", "sentinel", "match", "alt")
		byBoth := e.matchStream(t, sub, "match", "sentinel", "match", "canon", "match", "alt")
		byPattern := e.matchStream(t, sub, "match", "sentinel", "match_urlpattern", "al*")
		none := e.matchStream(t, sub, "match", "sentinel", "match", "zzz")
		e.publishA(t, "u1", "canon", "alt")
		sameData(t, "alternate", e.settle(t, byAlternate), []string{"u1"})
		sameData(t, "both topics selected: once", byBoth.drain("end"), []string{"u1"})
		sameData(t, "pattern", byPattern.drain("end"), []string{"u1"})
		sameData(t, "none", none.drain("end"), nil)
	})
}

func TestSubscribeBothMixesRevisions(t *testing.T) {
	e := newEnv(t, mcfg(ProtocolBoth))
	sub := e.access(t, mDetail(subOnly, mBare("*")))
	c := e.matchStream(t, sub, "match", "sentinel", "topic", "https://example.com/{kind}/1", "match", "urn:x", "match_urlpattern", "https://other.example/*")
	for _, tp := range []string{"https://example.com/books/1", "https://example.com/books/2", "urn:x", "https://other.example/a", "nope"} {
		e.publishA(t, tp, tp)
	}
	sameData(t, "union", e.settle(t, c), []string{"https://example.com/books/1", "urn:x", "https://other.example/a"})

	// A draft-07 token with draft-07 and Mercure 1.0 parameters.
	l := e.matchStream(t, tokenFor(t, nil, all), "match", "sentinel", "topic", "{x}/q", "match", "plain")
	e.publishA(t, "1", "a/q")
	e.publishA(t, "2", "plain")
	e.publishA(t, "3", "other")
	sameData(t, "draft-07 token", e.settle(t, l), []string{"1", "2"})
}

func TestSubscribeModernIgnoresTopic(t *testing.T) {
	e := newEnv(t, mcfg(ProtocolModern))
	sub := e.access(t, mDetail(subOnly, mBare("*")))
	r := e.get(t, e.hubURL()+"?topic=a&topic=b", bearer(sub))
	if r.code != 400 || !strings.Contains(r.body, `Missing "match" parameter`) {
		t.Fatalf("%d %q", r.code, r.body)
	}
	c := e.matchStream(t, sub, "topic", "ignored", "match", "kept", "match", "sentinel")
	e.publishA(t, "x", "ignored")
	e.publishA(t, "y", "kept")
	sameData(t, "topic is not a parameter", e.settle(t, c), []string{"y"})
}

// TestSubscribeBadParameters: §3: matcher parameters that are malformed are refused with 400 before the token is
// looked at.
func TestSubscribeBadParameters(t *testing.T) {
	long := strings.Repeat("a", MaxTopicLength+1)
	okLong := strings.Repeat("a", MaxTopicLength)
	tests := []struct {
		name  string
		query string
		code  int
	}{
		{"ok", "match=a", 200},
		{"long matcher at the limit", "match=" + okLong, 200},
		{"match_foo", "match=a&match_foo=x", 400},
		{"match_foo alone", "match_foo=x", 400},
		{"MATCH_foo", "match=a&MATCH_foo=x", 400},
		{"Match", "match=a&Match=x", 400},
		{"MATCH", "match=a&MATCH=x", 400},
		{"matchX", "match=a&matchX=x", 400},
		{"matches", "match=a&matches=x", 400},
		{"match_", "match=a&match_=x", 400},
		{"match_Exact", "match=a&match_Exact=x", 400},
		{"match_URLPATTERN", "match=a&match_URLPATTERN=x", 400},
		{"match_urlpattern_", "match=a&match_urlpattern_=x", 400},
		{"match_regex", "match=a&match_regex=x", 400},
		{"match-exact", "match=a&match-exact=x", 400},
		{"name without a value", "match=a&match_foo", 400},
		{"empty matcher", "match=", 400},
		{"matcher without a value", "match", 400},
		{"empty matcher beside a good one", "match=a&match=", 400},
		{"empty pattern", "match_urlpattern=", 400},
		{"empty exact", "match_exact=", 400},
		{"NUL", "match=a%00b", 400},
		{"C0", "match=a%01b", 400},
		{"newline", "match=a%0Ab", 400},
		{"tab", "match=a%09b", 400},
		{"unit separator", "match=a%1Fb", 400},
		{"DEL", "match=a%7Fb", 400},
		{"C1 start", "match=a%C2%80b", 400},
		{"C1 NEL", "match=a%C2%85b", 400},
		{"C1 end", "match=a%C2%9Fb", 400},
		{"zero width space", "match=a%E2%80%8Bb", 400},
		{"right-to-left override", "match=a%E2%80%AEb", 400},
		{"byte order mark", "match=a%EF%BB%BFb", 400},
		{"word joiner", "match=a%E2%81%A0b", 400},
		{"soft hyphen", "match=a%C2%ADb", 400},
		{"invalid UTF-8", "match=a%FFb", 400},
		{"overlong UTF-8", "match=a%C0%AFb", 400},
		{"control in a pattern", "match_urlpattern=https://example.com/%01", 400},
		{"control in an exact", "match_exact=a%7Fb", 400},
		{"invalid pattern: open paren", "match_urlpattern=" + url.QueryEscape("https://example.com/("), 400},
		{"invalid pattern: open brace", "match_urlpattern=" + url.QueryEscape("https://example.com/{"), 400},
		{"invalid pattern: bad group", "match_urlpattern=" + url.QueryEscape("https://example.com/:id(["), 400},
		{"invalid pattern: bare colon", "match_urlpattern=" + url.QueryEscape("https://example.com/:"), 400},
		{"valid pattern", "match_urlpattern=" + url.QueryEscape("https://example.com/:id"), 200},
		{"a pattern syntax is no problem for exact", "match=" + url.QueryEscape("https://example.com/("), 200},
		{"matcher over the length limit", "match=" + long, 400},
		{"pattern over the length limit", "match_urlpattern=" + url.QueryEscape("https://example.com/"+long), 400},
		{"unrelated parameters are ignored", "match=a&matc=x&mat=y&foo=bar&topic=ignored&authorization=", 200},
		{"matcher with encoded delimiters", "match=" + url.QueryEscape("a&b=c+d;e%f"), 200},
	}
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		sub := e.access(t, mDetail(subOnly, mBare("*")))
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if tc.code == 200 {
					c, code, msg := e.tryOpenStream(t, http.MethodGet, mustQuery(tc.query), bearer(sub), "")
					if c == nil {
						t.Fatalf("%d %q", code, msg)
					}
					return
				}
				r := e.do(t, http.MethodGet, e.hubURL()+"?"+tc.query, bearer(sub), "")
				if r.code != 400 {
					t.Fatalf("%d %q", r.code, r.body)
				}
				// The token comes first: a request the hub refuses is not parsed at all.
				if r := e.do(t, http.MethodGet, e.hubURL()+"?"+tc.query, nil, ""); r.code != 401 {
					t.Fatalf("without a token: %d %q", r.code, r.body)
				}
			})
		}
		t.Run("too many matchers", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.MaxTopicSelectors = 3
			e := newEnv(t, cfg)
			sub := e.access(t, mDetail(subOnly, mBare("*")))
			if c, code, _ := e.tryOpenStream(t, http.MethodGet, mustQuery("match=a&match=b&match_urlpattern=*"), bearer(sub), ""); c == nil {
				t.Fatalf("at the limit: %d", code)
			}
			r := e.do(t, http.MethodGet, e.hubURL()+"?match=a&match=b&match=c&match=d", bearer(sub), "")
			if r.code != 400 || !strings.Contains(r.body, "Too many") {
				t.Fatalf("over the limit: %d %q", r.code, r.body)
			}
		})
		t.Run("missing matcher", func(t *testing.T) {
			r := e.get(t, e.hubURL(), bearer(sub))
			want := `Missing "match" parameter`
			if p.legacy() {
				want = `Missing "topic" parameter`
			}
			if r.code != 400 || !strings.Contains(r.body, want) {
				t.Fatalf("%d %q, want %q", r.code, r.body, want)
			}
		})
	})
	t.Run("legacy hub reserves nothing", func(t *testing.T) {
		e := newEnv(t, Config{Protocol: ProtocolLegacy})
		c := e.openStream(t, http.MethodGet, mustQuery("topic=a&match_foo=x&MATCH=y&match="), bearer(tokenFor(t, nil, all)), "")
		e.publish(t, "x", "a")
		c.expect("x")
	})
}

// TestSubscribeAnonymous: with Anonymous a subscriber needs no token and gets public updates only.
func TestSubscribeAnonymous(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Anonymous = true
		e := newEnv(t, cfg)
		c := e.matchStream(t, "", "match_urlpattern", "*")
		e.publishA(t, "public", "t")
		e.publishPrivate(t, "private", "t")
		e.publishA(t, "end", "sentinel")
		sameData(t, "anonymous", c.drain("end"), []string{"public"})
		// A bad token is refused even where anonymous subscribers are welcome.
		r := e.get(t, e.hubURL()+"?match=t", bearer("x.y.z"))
		if r.code != 400 && r.code != 401 {
			t.Fatalf("bad token: %d", r.code)
		}
		bad := signAccess(t, accessClaims("https://other.example", time.Hour, mDetail(subOnly, mBare("*"))))
		if r = e.get(t, e.hubURL()+"?match=t", bearer(bad)); r.code != 401 {
			t.Fatalf("token for another audience: %d", r.code)
		}
	})
	t.Run("not anonymous", func(t *testing.T) {
		e := newEnv(t, mcfg(ProtocolBoth))
		r := e.get(t, e.hubURL()+"?match=t", nil)
		if r.code != 401 {
			t.Fatalf("%d", r.code)
		}
		wantChallenge(t, r.header, "", e.metadataURL())
	})
}

// TestSubscribePrivateAuthorization: §6.6: a private update needs a subscribe grant on one of its topics; routing
// never widens what a token may read.
func TestSubscribePrivateAuthorization(t *testing.T) {
	const (
		b1 = "https://example.com/books/1"
		b2 = "https://example.com/books/2"
		b7 = "https://example.com/books/7"
		u1 = "https://example.com/users/42/books/1"
		u2 = "https://example.com/users/43/books/2"
	)
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Anonymous = true
		e := newEnv(t, cfg)
		route := []string{"match", "sentinel", "match_urlpattern", "https://example.com/books/:id"}

		t.Run("narrow grant, broad routing", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mExact(b1), mExact(b7))), route...)
			e.publishPrivate(t, "p1", b1)
			e.publishPrivate(t, "p2", b2)
			e.publishPrivate(t, "p7", b7)
			e.publishA(t, "pub2", b2)
			sameData(t, "books", e.settle(t, c), []string{"p1", "p7", "pub2"})
		})
		t.Run("alternate topic grant", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("https://example.com/users/42/*"))), route...)
			e.publishPrivate(t, "alt-ok", b1, u1)
			e.publishPrivate(t, "alt-wrong-user", b2, u2)
			e.publishPrivate(t, "no-alt", b7)
			sameData(t, "alternate", e.settle(t, c), []string{"alt-ok"})
		})
		t.Run("alternate topic first", func(t *testing.T) {
			// The canonical topic is outside the grant and the route; the alternate is inside both.
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("https://example.com/users/42/*"))),
				"match", "sentinel", "match_urlpattern", "https://example.com/users/:id/books/:book")
			e.publishPrivate(t, "ok", b1, u1)
			sameData(t, "alternate", e.settle(t, c), []string{"ok"})
		})
		t.Run("routing on a topic the token does not grant", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mExact(b1))), "match", "sentinel", "match", b2, "match", b1)
			e.publishPrivate(t, "b2 private", b2)
			e.publishPrivate(t, "b1 private", b1)
			e.publishA(t, "b2 public", b2)
			sameData(t, "routing", e.settle(t, c), []string{"b1 private", "b2 public"})
		})
		t.Run("grant without routing", func(t *testing.T) {
			// The token may read b1; the stream does not ask for it.
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match", "sentinel", "match", b2)
			e.publishPrivate(t, "b1", b1)
			e.publishPrivate(t, "b2", b2)
			sameData(t, "routing", e.settle(t, c), []string{"b2"})
		})
		t.Run("wildcard grant", func(t *testing.T) {
			for _, d := range []map[string]any{mDetail(subOnly, mBare("*")), mDetail(subOnly, mExact("*")), mDetail(subOnly, mPattern("*"))} {
				c := e.matchStream(t, e.access(t, d), route...)
				e.publishPrivate(t, "p1", b1)
				e.publishPrivate(t, "p2", b2)
				sameData(t, "wildcard", e.settle(t, c), []string{"p1", "p2"})
			}
		})
		t.Run("exact grant is not a pattern", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mExact("https://example.com/books/:id"), mExact("https://example.com/*"))), route...)
			e.publishPrivate(t, "p1", b1)
			sameData(t, "exact", e.settle(t, c), nil)
		})
		t.Run("publish grant does not read", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail(pubOnly, mBare("*"))), route...)
			e.publishPrivate(t, "p1", b1)
			e.publishA(t, "public", b1)
			sameData(t, "publish only", e.settle(t, c), []string{"public"})
		})
		t.Run("unknown action does not read", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail([]string{"frobnicate"}, mBare("*"))), route...)
			e.publishPrivate(t, "p1", b1)
			sameData(t, "unknown action", e.settle(t, c), nil)
		})
		t.Run("token without details", func(t *testing.T) {
			c := e.matchStream(t, e.access(t), route...)
			e.publishPrivate(t, "p1", b1)
			e.publishA(t, "public", b1)
			sameData(t, "no details", e.settle(t, c), []string{"public"})
		})
		t.Run("relative pattern grant", func(t *testing.T) {
			c := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("/rooms/:id"))), "match", "sentinel", "match", "/rooms/1", "match", "/rooms/2/x")
			e.publishPrivate(t, "rel", "/rooms/1")
			e.publishPrivate(t, "deep", "/rooms/2/x")
			sameData(t, "relative", e.settle(t, c), []string{"rel"})
		})
		t.Run("anonymous", func(t *testing.T) {
			c := e.matchStream(t, "", route...)
			e.publishPrivate(t, "p1", b1)
			e.publishA(t, "public", b1)
			sameData(t, "anonymous", e.settle(t, c), []string{"public"})
		})
		t.Run("grants are per detail", func(t *testing.T) {
			// A publish grant on b1 and a subscribe grant on b2 do not combine into a subscribe grant on b1.
			c := e.matchStream(t, e.access(t, mDetail(pubOnly, mExact(b1)), mDetail(subOnly, mExact(b2))), route...)
			e.publishPrivate(t, "p1", b1)
			e.publishPrivate(t, "p2", b2)
			sameData(t, "per detail", e.settle(t, c), []string{"p2"})
		})
	})
	t.Run("draft-07 token with match routing", func(t *testing.T) {
		e := newEnv(t, mcfg(ProtocolBoth))
		c := e.matchStream(t, tokenFor(t, nil, []string{b1, "https://example.com/users/{id}/books/1"}),
			"match", "sentinel", "match_urlpattern", "https://example.com/books/:id")
		e.publishPrivate(t, "p1", b1)
		e.publishPrivate(t, "p2", b2)
		e.publishPrivate(t, "alt", b7, u1)
		sameData(t, "selectors", e.settle(t, c), []string{"p1", "alt"})
	})
}

// TestSubscribeReplayAuthorization: §7: a replayed update is checked against the token like a live one.
func TestSubscribeReplayAuthorization(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		first := e.publishA(t, "first", "t")
		e.publishPrivate(t, "private-a", "a")
		e.publishPrivate(t, "private-b", "b")
		e.publishPrivate(t, "private-alt", "c", "a")
		e.publishA(t, "public", "b")
		route := []string{"match", "sentinel", "match_urlpattern", "*", "last_event_id", first}

		for _, tc := range []struct {
			name string
			tok  string
			want []string
		}{
			{"granted on a", e.access(t, mDetail(subOnly, mExact("a"))), []string{"private-a", "private-alt", "public"}},
			{"granted on b", e.access(t, mDetail(subOnly, mExact("b"))), []string{"private-b", "public"}},
			{"granted on the alternate topic c", e.access(t, mDetail(subOnly, mExact("c"))), []string{"private-alt", "public"}},
			{"wildcard", e.access(t, mDetail(subOnly, mPattern("*"))), []string{"private-a", "private-b", "private-alt", "public"}},
			{"nothing", e.access(t, mDetail(subOnly, mExact("zzz"))), []string{"public"}},
			{"publish grant only", e.access(t, mDetail(pubOnly, mBare("*"))), []string{"public"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := e.matchStream(t, tc.tok, route...)
				sameData(t, tc.name, e.settle(t, c), tc.want)
			})
		}
	})
}

// TestSubscribeCursor: the Mercure-Last-Event-ID response header and the cursor parameters.
func TestSubscribeCursor(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		// fresh is a hub holding d0..d3 on topic t, and the token and ids to use with it.
		fresh := func(t *testing.T) (*env, []string, http.Header) {
			e := newEnv(t, mcfg(p))
			var ids []string
			for i := 0; i < 4; i++ {
				ids = append(ids, e.publishA(t, fmt.Sprint("d", i), "t"))
			}
			return e, ids, bearer(e.access(t, mDetail(subOnly, mBare("*"))))
		}
		with := func(h http.Header, extra ...string) http.Header {
			h = h.Clone()
			for i := 0; i < len(extra); i += 2 {
				h.Set(extra[i], extra[i+1])
			}
			return h
		}
		checkHdr := func(t *testing.T, c *sseClient, want string) {
			t.Helper()
			if got := c.resp.Header.Get("Mercure-Last-Event-ID"); got != want {
				t.Fatalf("Mercure-Last-Event-ID %q, want %q", got, want)
			}
			legacy := c.resp.Header.Get("Last-Event-ID")
			if p.legacy() && legacy != want {
				t.Fatalf("Last-Event-ID %q, want %q", legacy, want)
			}
			if !p.legacy() && legacy != "" {
				t.Fatalf("Last-Event-ID response header %q on a hub without draft-07", legacy)
			}
		}
		get := func(e *env, q url.Values, h http.Header) *sseClient {
			q.Add("match", "t")
			return e.openStream(t, http.MethodGet, q, h, "")
		}

		t.Run("no cursor", func(t *testing.T) {
			e, _, h := fresh(t)
			c := get(e, url.Values{}, h)
			for _, name := range []string{"Mercure-Last-Event-ID", "Last-Event-ID"} {
				if v, ok := c.resp.Header[name]; ok {
					t.Fatalf("%s %v without a cursor", name, v)
				}
			}
			e.publishA(t, "live", "t")
			c.expect("live")
		})
		t.Run("last_event_id", func(t *testing.T) {
			e, ids, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {ids[1]}}, h)
			checkHdr(t, c, ids[1])
			c.expect("d2", "d3")
		})
		t.Run("last_event_id of the last update", func(t *testing.T) {
			e, ids, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {ids[3]}}, h)
			checkHdr(t, c, ids[3])
			e.publishA(t, "live", "t")
			c.expect("live")
		})
		t.Run("earliest", func(t *testing.T) {
			e, _, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {"earliest"}}, h)
			checkHdr(t, c, "earliest")
			c.expect("d0", "d1", "d2", "d3")
		})
		t.Run("unknown id", func(t *testing.T) {
			e, _, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {"urn:uuid:does-not-exist"}}, h)
			checkHdr(t, c, "earliest")
			e.publishA(t, "live", "t")
			c.expect("live") // nothing is replayed for an id the hub does not know
		})
		t.Run("Last-Event-ID header", func(t *testing.T) {
			e, ids, h := fresh(t)
			c := get(e, url.Values{}, with(h, "Last-Event-ID", ids[2]))
			checkHdr(t, c, ids[2])
			c.expect("d3")
		})
		t.Run("header wins over the parameter", func(t *testing.T) {
			e, ids, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {ids[0]}}, with(h, "Last-Event-ID", ids[2]))
			checkHdr(t, c, ids[2])
			c.expect("d3")
		})
		t.Run("empty parameter is no cursor", func(t *testing.T) {
			e, _, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {""}}, h)
			if _, ok := c.resp.Header["Mercure-Last-Event-Id"]; ok {
				t.Fatalf("headers %v", c.resp.Header)
			}
		})
		t.Run("replay then live, once each", func(t *testing.T) {
			e, ids, h := fresh(t)
			c := get(e, url.Values{"last_event_id": {ids[2]}}, h)
			e.publishA(t, "d4", "t")
			c.expect("d3", "d4")
			e.publishA(t, "d5", "t")
			c.expect("d5")
		})
		t.Run("replay only what the matchers select", func(t *testing.T) {
			e, ids, h := fresh(t)
			e.publishA(t, "other-topic", "other")
			e.publishA(t, "d4", "t")
			c := get(e, url.Values{"last_event_id": {ids[2]}}, h)
			c.expect("d3", "d4")
			e.publishA(t, "d5", "t")
			c.expect("d5")
		})
		t.Run("QUERY, cursor in the body", func(t *testing.T) {
			e, ids, h := fresh(t)
			body := url.Values{"match": {"t"}, "last_event_id": {ids[1]}}.Encode()
			c := e.openStream(t, "QUERY", nil, h, body)
			checkHdr(t, c, ids[1])
			c.expect("d2", "d3")
		})
		t.Run("QUERY, query cursor beats body cursor", func(t *testing.T) {
			e, ids, h := fresh(t)
			body := url.Values{"match": {"t"}, "last_event_id": {ids[0]}}.Encode()
			c := e.openStream(t, "QUERY", url.Values{"last_event_id": {ids[2]}}, h, body)
			checkHdr(t, c, ids[2])
			c.expect("d3")
		})
		t.Run("QUERY, header beats both", func(t *testing.T) {
			e, ids, h := fresh(t)
			e.publishA(t, "d4", "t")
			body := url.Values{"match": {"t"}, "last_event_id": {ids[0]}}.Encode()
			c := e.openStream(t, "QUERY", url.Values{"last_event_id": {ids[1]}}, with(h, "Last-Event-ID", ids[3]), body)
			checkHdr(t, c, ids[3])
			c.expect("d4")
		})
	})
	t.Run("draft-07 cursor names", func(t *testing.T) {
		e := newEnv(t, mcfg(ProtocolBoth))
		sub := e.access(t, mDetail(subOnly, mBare("*")))
		var ids []string
		for i := 0; i < 3; i++ {
			ids = append(ids, e.publishA(t, fmt.Sprint("d", i), "t"))
		}
		c := e.matchStream(t, sub, "match", "t", "lastEventID", ids[0])
		c.expect("d1", "d2")
		c = e.matchStream(t, sub, "match", "t", "Last-Event-ID", ids[1])
		c.expect("d2")
		// last_event_id comes first when both are given.
		c = e.matchStream(t, sub, "match", "t", "last_event_id", ids[1], "lastEventID", ids[0])
		c.expect("d2")
	})
}

// TestSubscribeReusedIDs: §7: an ID that was reused resolves to its earliest update.
func TestSubscribeReusedIDs(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		sub := e.access(t, mDetail(subOnly, mBare("*")))
		e.publishID(t, "dup", "a", "t")
		e.publishID(t, "x", "b", "t")
		e.publishID(t, "dup", "c", "t")
		e.publishID(t, "y", "d", "t")
		c := e.matchStream(t, sub, "match", "t", "last_event_id", "dup")
		if c.resp.Header.Get("Mercure-Last-Event-ID") != "dup" {
			t.Fatalf("headers %v", c.resp.Header)
		}
		c.expect("b", "c", "d")
		// The later duplicate is not the cursor.
		h := bearer(sub)
		h.Set("Last-Event-ID", "x")
		c2 := e.openStream(t, http.MethodGet, url.Values{"match": {"t"}}, h, "")
		c2.expect("c", "d")
	})
}

// TestSubscribeQuery: §3: the QUERY method carries the matchers in a form body.
func TestSubscribeQuery(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.MaxTopicSelectors = 1000
		e := newEnv(t, cfg)
		sub := e.access(t, mDetail(subOnly, mBare("*")))
		h := bearer(sub)

		t.Run("body only", func(t *testing.T) {
			body := url.Values{"match": {"sentinel", "a"}, "match_urlpattern": {"https://example.com/:x"}}.Encode()
			c := e.openStream(t, "QUERY", nil, h, body)
			for _, tp := range []string{"a", "b", "https://example.com/z", "https://example.org/z"} {
				e.publishA(t, tp, tp)
			}
			sameData(t, "body", e.settle(t, c), []string{"a", "https://example.com/z"})
		})
		t.Run("union of query and body", func(t *testing.T) {
			c := e.openStream(t, "QUERY", url.Values{"match": {"sentinel", "q"}}, h, url.Values{"match": {"b"}, "match_urlpattern": {"https://x.example/*"}}.Encode())
			for _, tp := range []string{"q", "b", "https://x.example/1", "other"} {
				e.publishA(t, tp, tp)
			}
			sameData(t, "union", e.settle(t, c), []string{"q", "b", "https://x.example/1"})
		})
		t.Run("a large matcher list", func(t *testing.T) {
			v := url.Values{"match": {"sentinel"}}
			for i := 0; i < 600; i++ {
				v.Add("match", fmt.Sprintf("https://example.com/books/%d", i))
			}
			c := e.openStream(t, "QUERY", nil, h, v.Encode())
			e.publishA(t, "hit", "https://example.com/books/599")
			e.publishA(t, "miss", "https://example.com/books/600")
			sameData(t, "large", e.settle(t, c), []string{"hit"})
		})
		t.Run("accept-query", func(t *testing.T) {
			for _, method := range []string{http.MethodGet, "QUERY", http.MethodHead} {
				body := ""
				if method == "QUERY" {
					body = "match=a"
				}
				q := url.Values{}
				if method != "QUERY" {
					q.Set("match", "a")
				}
				c := e.openStream(t, method, q, h, body)
				if got := c.resp.Header.Get("Accept-Query"); got != "application/x-www-form-urlencoded" {
					t.Fatalf("%s: Accept-Query %q", method, got)
				}
				if ct := c.resp.Header.Get("Content-Type"); ct != "text/event-stream" {
					t.Fatalf("%s: Content-Type %q", method, ct)
				}
			}
		})
		t.Run("HEAD", func(t *testing.T) {
			r := e.do(t, http.MethodHead, e.hubURL()+"?match=a", h, "")
			if r.code != 200 || r.body != "" || r.header.Get("Content-Type") != "text/event-stream" {
				t.Fatalf("%d %q %v", r.code, r.body, r.header)
			}
		})
		for _, tc := range []struct {
			name, body string
		}{
			{"invalid escape", "match=%zz"},
			{"unknown matcher in the body", "match=a&match_foo=b"},
			{"uppercase matcher in the body", "match=a&MATCH_x=b"},
			{"empty matcher in the body", "match="},
			{"control in the body", "match=a%00"},
			{"C1 in the body", "match=%C2%85"},
			{"Cf in the body", "match=%E2%80%8B"},
			{"invalid pattern in the body", "match_urlpattern=" + url.QueryEscape("https://example.com/(")},
			{"no matcher in the body", "other=1"},
			{"empty body", ""},
		} {
			t.Run("bad body: "+tc.name, func(t *testing.T) {
				r := e.do(t, "QUERY", e.hubURL(), http.Header{"Authorization": {"Bearer " + sub}, "Content-Type": {formType}}, tc.body)
				if r.code != 400 {
					t.Fatalf("%d %q", r.code, r.body)
				}
			})
		}
		t.Run("a bad query component beside a good body", func(t *testing.T) {
			r := e.do(t, "QUERY", e.hubURL()+"?match_foo=1", http.Header{"Authorization": {"Bearer " + sub}, "Content-Type": {formType}}, "match=a")
			if r.code != 400 {
				t.Fatalf("%d", r.code)
			}
		})
		t.Run("too many matchers over both components", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.MaxTopicSelectors = 3
			e := newEnv(t, cfg)
			r := e.do(t, "QUERY", e.hubURL()+"?match=a&match=b", withType(bearer(e.access(t, mDetail(subOnly, mBare("*"))))), "match=c&match=d")
			if r.code != 400 || !strings.Contains(r.body, "Too many") {
				t.Fatalf("%d %q", r.code, r.body)
			}
		})
		t.Run("media type", func(t *testing.T) {
			for _, ct := range []string{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded; charset=utf-8",
				"Application/X-WWW-Form-Urlencoded;charset=UTF-8"} {
				c := e.openStream(t, "QUERY", nil, withContentType(h, ct), "match=sentinel")
				e.publishA(t, "end", "sentinel")
				c.expect("end")
			}
			for _, ct := range []string{"", "text/plain", "application/json", "multipart/form-data; boundary=x", "application/x-www-form-urlencoded2", "x-www-form-urlencoded", ";;"} {
				hdr := h.Clone()
				hdr.Del("Content-Type")
				if ct != "" {
					hdr.Set("Content-Type", ct)
				}
				r := e.do(t, "QUERY", e.hubURL(), hdr, "match=a")
				if r.code != 415 {
					t.Errorf("Content-Type %q: %d, want 415", ct, r.code)
				}
			}
			// Checked before the token, and with the matchers in the query component only.
			r := e.do(t, "QUERY", e.hubURL()+"?match=a", h, "")
			if r.code != 415 {
				t.Errorf("QUERY without a Content-Type: %d, want 415", r.code)
			}
			// GET needs none.
			e.openStream(t, http.MethodGet, url.Values{"match": {"a"}}, h, "")
		})
		t.Run("authorization still applies", func(t *testing.T) {
			r := e.do(t, "QUERY", e.hubURL(), http.Header{"Content-Type": {formType}}, "match=a")
			if r.code != 401 {
				t.Fatalf("%d", r.code)
			}
			wantChallenge(t, r.header, "", e.metadataURL())
		})
		t.Run("private updates need a grant", func(t *testing.T) {
			c := e.openStream(t, "QUERY", nil, bearer(e.access(t, mDetail(subOnly, mExact("pq")))), url.Values{"match": {"sentinel", "pq", "pq2"}}.Encode())
			e.publishPrivate(t, "ok", "pq")
			e.publishPrivate(t, "denied", "pq2")
			sameData(t, "query", e.settle(t, c), []string{"ok"})
		})
	})
	t.Run("oversized body", func(t *testing.T) {
		h := newModernHub(t, mcfg(ProtocolBoth))
		tok := accessFor(t, hubAud, mDetail(subOnly, mBare("*")))
		body := "match=" + strings.Repeat("a", maxQueryBody+10)
		w := hubDo(t, h, "QUERY", hubPath, withType(bearer(tok)), body)
		if w.Code != 413 {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("QUERY is not served by the publish or API endpoints", func(t *testing.T) {
		h := newModernHub(t, Config{Subscriptions: true})
		if w := hubDo(t, h, "QUERY", subscriptionsPath, nil, ""); w.Code != 405 {
			t.Fatalf("subscriptions API: %d", w.Code)
		}
		if w := hubDo(t, h, "QUERY", metadataPath, nil, ""); w.Code != 405 {
			t.Fatalf("metadata: %d", w.Code)
		}
	})
}

// TestSubscribeEndsAtTokenExpiry: §6.6: the stream of a Mercure 1.0 token ends when the token does.
func TestSubscribeEndsAtTokenExpiry(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		t.Parallel()
		e := newEnv(t, mcfg(p))
		tok := signAccess(t, accessClaims(e.hubURL(), 3*time.Second, mDetail(subOnly, mBare("*"))))
		start := time.Now()
		c := e.matchStream(t, tok, "match", "t")
		e.publishA(t, "alive", "t")
		c.expect("alive")
		if !c.waitClosed(wait) {
			t.Fatal("the stream outlived its token")
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("the stream ended after %v, the token lasts 3s", d)
		}
		eventually(t, "the subscriber to be removed", func() bool { return e.hub.Stats().Subscribers == 0 })
		// The same token is refused once it has expired.
		time.Sleep(100 * time.Millisecond)
		r := e.get(t, e.hubURL()+"?match=t", bearer(tok))
		if r.code != 401 {
			t.Fatalf("expired token: %d", r.code)
		}
	})
}

func TestSubscribeEndsAtLifetime(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		t.Parallel()
		cfg := mcfg(p)
		cfg.MaxConnectionLifetime = 600 * time.Millisecond
		e := newEnv(t, cfg)
		tok := e.access(t, mDetail(subOnly, mBare("*")))
		start := time.Now()
		c := e.matchStream(t, tok, "match", "t")
		if !c.waitClosed(wait) {
			t.Fatal("the stream outlived the connection lifetime")
		}
		if d := time.Since(start); d < 600*time.Millisecond {
			t.Fatalf("the stream ended after %v, before its lifetime", d)
		}
		// Streams with no token end then too.
		cfg.Anonymous = true
		e2 := newEnv(t, cfg)
		c2 := e2.matchStream(t, "", "match", "t")
		if !c2.waitClosed(wait) {
			t.Fatal("an anonymous stream outlived the connection lifetime")
		}
	})
	t.Run("token expiry comes first", func(t *testing.T) {
		t.Parallel()
		cfg := mcfg(ProtocolModern)
		cfg.MaxConnectionLifetime = time.Hour
		e := newEnv(t, cfg)
		tok := signAccess(t, accessClaims(e.hubURL(), 3*time.Second, mDetail(subOnly, mBare("*"))))
		c := e.matchStream(t, tok, "match", "t")
		if !c.waitClosed(wait) {
			t.Fatal("the stream outlived its token")
		}
	})
}

// TestSubscribeDraft07TokenExpiry: a draft-07 token's stream outlives its token unless the hub is told otherwise;
// a Mercure 1.0 token's never does.
func TestSubscribeDraft07TokenExpiry(t *testing.T) {
	t.Parallel()
	short := func() string {
		c := mercureClaims(nil, all)
		c["exp"] = time.Now().Add(2 * time.Second).Unix()
		return signJWT(t, testSecret, c)
	}
	e := newEnv(t, mcfg(ProtocolBoth))
	keep := e.matchStream(t, short(), "match", "t")
	closing := newEnv(t, Config{CloseOnTokenExpiry: true})
	end := closing.subscribe(t, short(), "t")
	if !end.waitClosed(wait) {
		t.Fatal("CloseOnTokenExpiry did not end the stream")
	}
	time.Sleep(2500 * time.Millisecond) // the token is expired now
	e.publishA(t, "still here", "t")
	keep.expect("still here")
}

// TestSubscribeTokenRoles: a Mercure 1.0 token is checked with the key of the role it is used in.
func TestSubscribeTokenRoles(t *testing.T) {
	const subSecret = "fedcba9876543210fedcba9876543210"
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.SubscriberKey = auth.KeyConfig{Key: subSecret}
		e := newEnv(t, cfg)
		grants := []any{mDetail(pubAndSb, mBare("*"))}
		pubTok := signAccessTyp(t, testSecret, "at+jwt", accessClaims(e.hubURL(), time.Hour, grants...))
		subTok := signAccessTyp(t, subSecret, "at+jwt", accessClaims(e.hubURL(), time.Hour, grants...))
		if r := e.post(t, pubTok, form("topic", "t")); r.code != 200 {
			t.Fatalf("publisher key, publish: %d", r.code)
		}
		if r := e.post(t, subTok, form("topic", "t")); r.code != 401 {
			t.Fatalf("subscriber key, publish: %d", r.code)
		}
		if r := e.get(t, e.hubURL()+"?match=t", bearer(pubTok)); r.code != 401 {
			t.Fatalf("publisher key, subscribe: %d", r.code)
		}
		c := e.matchStream(t, subTok, "match", "t")
		e.publishA(t, "x", "t")
		c.expect("x")
	})
}

// TestSubscribeCookies: the access token cookie, and who wins when several tokens are sent.
func TestSubscribeCookies(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.PublishOrigins = []string{"https://app.example"}
		cfg.CORSOrigins = []string{"https://app.example"}
		e := newEnv(t, cfg)
		granted := e.access(t, mDetail(subOnly, mExact("secret")))
		none := e.access(t, mDetail(subOnly, mExact("nothing")))
		cookie := func(name, v string) http.Header { return http.Header{"Cookie": {name + "=" + v}} }

		t.Run("cookie token reads private updates", func(t *testing.T) {
			c := e.openStream(t, http.MethodGet, url.Values{"match": {"secret", "sentinel"}}, cookie("__Secure-mercure_access_token", granted), "")
			e.publishPrivate(t, "private", "secret")
			sameData(t, "cookie", e.settle(t, c), []string{"private"})
		})
		t.Run("header beats cookie", func(t *testing.T) {
			// The header's token reads nothing; the cookie's would read the private update.
			h := cookie("__Secure-mercure_access_token", granted)
			h.Set("Authorization", "Bearer "+none)
			c := e.openStream(t, http.MethodGet, url.Values{"match": {"secret", "sentinel"}}, h, "")
			e.publishPrivate(t, "private", "secret")
			sameData(t, "header", e.settle(t, c), nil)
		})
		t.Run("a bad header is not rescued by a good cookie", func(t *testing.T) {
			h := cookie("__Secure-mercure_access_token", granted)
			h.Set("Authorization", "Bearer "+signAccess(t, accessClaims("https://other.example", time.Hour, mDetail(subOnly, mBare("*")))))
			r := e.do(t, http.MethodGet, e.hubURL()+"?match=secret", h, "")
			if r.code != 401 {
				t.Fatalf("%d", r.code)
			}
		})
		t.Run("a good header is not spoiled by a bad cookie", func(t *testing.T) {
			h := cookie("__Secure-mercure_access_token", "garbage")
			h.Set("Authorization", "Bearer "+granted)
			e.openStream(t, http.MethodGet, url.Values{"match": {"secret"}}, h, "")
		})
		t.Run("bad cookie", func(t *testing.T) {
			r := e.do(t, http.MethodGet, e.hubURL()+"?match=secret", cookie("__Secure-mercure_access_token", "garbage"), "")
			if r.code != 400 && r.code != 401 {
				t.Fatalf("%d", r.code)
			}
		})
		t.Run("draft-07 cookie", func(t *testing.T) {
			h := cookie("mercureAuthorization", tokenFor(t, nil, all))
			if p.legacy() {
				e.openStream(t, http.MethodGet, url.Values{"match": {"secret"}}, h, "")
				return
			}
			if r := e.do(t, http.MethodGet, e.hubURL()+"?match=secret", h, ""); r.code != 401 {
				t.Fatalf("%d", r.code)
			}
		})
		t.Run("cookie names are exact", func(t *testing.T) {
			r := e.do(t, http.MethodGet, e.hubURL()+"?match=secret", cookie("mercure_access_token", granted), "")
			if r.code != 401 {
				t.Fatalf("%d", r.code)
			}
		})
		t.Run("modern cookie beats the draft-07 cookie", func(t *testing.T) {
			if !p.legacy() {
				t.Skip("draft-07 is off")
			}
			h := http.Header{"Cookie": {"mercureAuthorization=garbage; __Secure-mercure_access_token=" + granted}}
			e.openStream(t, http.MethodGet, url.Values{"match": {"secret"}}, h, "")
			h = http.Header{"Cookie": {"mercureAuthorization=" + tokenFor(t, nil, all) + "; __Secure-mercure_access_token=garbage"}}
			if c, _, _ := e.tryOpenStream(t, http.MethodGet, url.Values{"match": {"secret"}}, h, ""); c != nil {
				t.Fatal("the draft-07 cookie was used though the Mercure 1.0 cookie is set")
			}
		})
		t.Run("custom cookie name", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.AccessTokenCookieName = "hub_token"
			e := newEnv(t, cfg)
			tok := e.access(t, mDetail(subOnly, mBare("*")))
			e.openStream(t, http.MethodGet, url.Values{"match": {"x"}}, cookie("hub_token", tok), "")
			if r := e.do(t, http.MethodGet, e.hubURL()+"?match=x", cookie("__Secure-mercure_access_token", tok), ""); r.code != 401 {
				t.Fatalf("the default name when another is configured: %d", r.code)
			}
		})
	})
}

// TestPublishCookies: a publish authorized by a cookie needs a publish origin (CSRF).
func TestPublishCookies(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.PublishOrigins = []string{"https://app.example", "HTTP://Other.example:8080/"}
		e := newEnv(t, cfg)
		tok := e.access(t, mDetail(pubOnly, mBare("*")))
		cookie := "__Secure-mercure_access_token=" + tok
		f := form("topic", "t").Encode()
		post := func(hdr http.Header) result {
			t.Helper()
			return e.do(t, http.MethodPost, e.hubURL(), hdr, f)
		}
		for _, tc := range []struct {
			name string
			hdr  http.Header
			code int
		}{
			{"no origin, no referer", http.Header{"Cookie": {cookie}}, 400},
			{"origin allowed", http.Header{"Cookie": {cookie}, "Origin": {"https://app.example"}}, 200},
			{"origin allowed, other case", http.Header{"Cookie": {cookie}, "Origin": {"HTTPS://App.Example"}}, 200},
			{"origin allowed with a port", http.Header{"Cookie": {cookie}, "Origin": {"http://other.example:8080"}}, 200},
			{"origin of another port", http.Header{"Cookie": {cookie}, "Origin": {"http://other.example:9090"}}, 400},
			{"origin of another scheme", http.Header{"Cookie": {cookie}, "Origin": {"http://app.example"}}, 400},
			{"origin refused", http.Header{"Cookie": {cookie}, "Origin": {"https://evil.example"}}, 400},
			{"origin is a prefix match only", http.Header{"Cookie": {cookie}, "Origin": {"https://app.example.evil.example"}}, 400},
			{"null origin", http.Header{"Cookie": {cookie}, "Origin": {"null"}}, 400},
			{"null origin, allowed referer", http.Header{"Cookie": {cookie}, "Origin": {"null"}, "Referer": {"https://app.example/page"}}, 200},
			{"referer allowed", http.Header{"Cookie": {cookie}, "Referer": {"https://app.example/some/page?x=1"}}, 200},
			{"referer refused", http.Header{"Cookie": {cookie}, "Referer": {"https://evil.example/page"}}, 400},
			{"referer that is not a URL", http.Header{"Cookie": {cookie}, "Referer": {"%%%"}}, 400},
			{"referer without a host", http.Header{"Cookie": {cookie}, "Referer": {"/page"}}, 400},
			{"origin wins over the referer", http.Header{"Cookie": {cookie}, "Origin": {"https://evil.example"}, "Referer": {"https://app.example/"}}, 400},
			{"header token needs no origin", http.Header{"Authorization": {"Bearer " + tok}}, 200},
			{"header token beats a refused cookie origin", http.Header{"Authorization": {"Bearer " + tok}, "Cookie": {"__Secure-mercure_access_token=garbage"}}, 200},
			{"bad header token beats a good cookie", http.Header{"Authorization": {"Bearer garbage"}, "Cookie": {cookie}, "Origin": {"https://app.example"}}, -1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := post(tc.hdr)
				switch tc.code {
				case -1:
					if r.code != 400 && r.code != 401 {
						t.Fatalf("%d", r.code)
					}
				case 400:
					if r.code != 400 {
						t.Fatalf("%d %q", r.code, r.body)
					}
					wantChallenge(t, r.header, "invalid_request", e.metadataURL())
				default:
					if r.code != tc.code {
						t.Fatalf("%d %q", r.code, r.body)
					}
				}
			})
		}
		t.Run("draft-07 cookie", func(t *testing.T) {
			r := post(http.Header{"Cookie": {"mercureAuthorization=" + tokenFor(t, all, nil)}, "Origin": {"https://app.example"}})
			want := 401
			if p.legacy() {
				want = 200
			}
			if r.code != want {
				t.Fatalf("%d, want %d", r.code, want)
			}
			if p.legacy() { // and its CSRF check
				if r = post(http.Header{"Cookie": {"mercureAuthorization=" + tokenFor(t, all, nil)}, "Origin": {"https://evil.example"}}); r.code != 400 {
					t.Fatalf("draft-07 cookie from a refused origin: %d", r.code)
				}
			}
		})
	})
	t.Run("wildcard publish origins", func(t *testing.T) {
		cfg := mcfg(ProtocolBoth)
		cfg.PublishOrigins = []string{"*"}
		e := newEnv(t, cfg)
		cookie := "__Secure-mercure_access_token=" + e.access(t, mDetail(pubOnly, mBare("*")))
		f := form("topic", "t").Encode()
		if r := e.do(t, http.MethodPost, e.hubURL(), http.Header{"Cookie": {cookie}, "Origin": {"https://anything.example"}}, f); r.code != 200 {
			t.Fatalf("%d", r.code)
		}
		if r := e.do(t, http.MethodPost, e.hubURL(), http.Header{"Cookie": {cookie}}, f); r.code != 400 {
			t.Fatalf("neither Origin nor Referer: %d", r.code)
		}
	})
	t.Run("no publish origins", func(t *testing.T) {
		e := newEnv(t, mcfg(ProtocolBoth))
		cookie := "__Secure-mercure_access_token=" + e.access(t, mDetail(pubOnly, mBare("*")))
		r := e.do(t, http.MethodPost, e.hubURL(), http.Header{"Cookie": {cookie}, "Origin": {"https://app.example"}}, form("topic", "t").Encode())
		if r.code != 400 {
			t.Fatalf("%d", r.code)
		}
	})
}

// TestCORSModern: "*" never comes with credentials; a listed origin does; Accept-Query is exposed.
func TestCORSModern(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		get := func(t *testing.T, h *Hub, method, target, origin string, extra http.Header) *httptest.ResponseRecorder {
			t.Helper()
			hdr := http.Header{"Origin": {origin}}
			for k, v := range extra {
				hdr[k] = v
			}
			return hubDo(t, h, method, target, hdr, "")
		}
		t.Run("wildcard", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.CORSOrigins = []string{"*"}
			h := newModernHub(t, cfg)
			for _, target := range []string{hubPath + "?match=a", subscriptionsPath, metadataPath} {
				w := get(t, h, http.MethodHead, target, "https://anything.example", nil)
				if w.Header().Get("Access-Control-Allow-Origin") != "*" {
					t.Errorf("%s: Allow-Origin %q", target, w.Header().Get("Access-Control-Allow-Origin"))
				}
				if v := w.Header().Get("Access-Control-Allow-Credentials"); v != "" {
					t.Errorf("%s: wildcard origin with credentials %q", target, v)
				}
				if !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "Accept-Query") {
					t.Errorf("%s: Accept-Query is not exposed: %v", target, w.Header())
				}
			}
		})
		t.Run("listed origins", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.CORSOrigins = []string{"https://app.example", "https://Other.example/"}
			h := newModernHub(t, cfg)
			for _, o := range []string{"https://app.example", "https://other.example", "https://OTHER.example"} {
				w := get(t, h, http.MethodHead, hubPath+"?match=a", o, nil)
				if w.Header().Get("Access-Control-Allow-Origin") != o || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Errorf("%s: %v", o, w.Header())
				}
				ex := w.Header().Get("Access-Control-Expose-Headers")
				for _, name := range []string{"Link", "Mercure-Last-Event-ID", "Accept-Query"} {
					if !strings.Contains(ex, name) {
						t.Errorf("%s not exposed: %q", name, ex)
					}
				}
			}
			for _, o := range []string{"https://evil.example", "http://app.example", "https://app.example.evil.example", "null"} {
				w := get(t, h, http.MethodHead, hubPath+"?match=a", o, nil)
				if v := w.Header().Get("Access-Control-Allow-Origin"); v != "" {
					t.Errorf("%s: Allow-Origin %q", o, v)
				}
				if v := w.Header().Get("Access-Control-Allow-Credentials"); v != "" {
					t.Errorf("%s: credentials %q", o, v)
				}
			}
			if v := get(t, h, http.MethodHead, hubPath+"?match=a", "https://app.example", nil).Header().Values("Vary"); !strings.Contains(strings.Join(v, ","), "Origin") {
				t.Errorf("Vary %v", v)
			}
		})
		t.Run("listed and wildcard", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.CORSOrigins = []string{"https://app.example", "*"}
			h := newModernHub(t, cfg)
			w := get(t, h, http.MethodHead, hubPath+"?match=a", "https://app.example", nil)
			if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
				t.Errorf("listed: %v", w.Header())
			}
			w = get(t, h, http.MethodHead, hubPath+"?match=a", "https://random.example", nil)
			if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Errorf("other: %v", w.Header())
			}
		})
		t.Run("preflight", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.CORSOrigins = []string{"https://app.example"}
			h := newModernHub(t, cfg)
			for _, target := range []string{hubPath, subscriptionsPath, subscriptionsPath + "/exact/a", metadataPath} {
				w := get(t, h, http.MethodOptions, target, "https://app.example", http.Header{
					"Access-Control-Request-Method":  {"QUERY"},
					"Access-Control-Request-Headers": {"Authorization, Content-Type"},
				})
				if target == hubPath && (w.Code != 204 || w.Header().Get("Access-Control-Allow-Methods") != "QUERY") {
					t.Errorf("%s: %d %v", target, w.Code, w.Header())
				}
				if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
					w.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Errorf("%s: %v", target, w.Header())
				}
			}
			w := get(t, h, http.MethodOptions, hubPath, "https://evil.example", http.Header{"Access-Control-Request-Method": {"GET"}})
			if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Methods") != "" {
				t.Errorf("preflight for a refused origin: %v", w.Header())
			}
			w = get(t, h, http.MethodOptions, hubPath, "https://app.example", http.Header{"Access-Control-Request-Method": {"DELETE"}})
			if w.Header().Get("Access-Control-Allow-Methods") != "" {
				t.Errorf("DELETE allowed: %v", w.Header())
			}
		})
		t.Run("no origin, no CORS headers", func(t *testing.T) {
			cfg := mcfg(p)
			cfg.CORSOrigins = []string{"*", "https://app.example"}
			h := newModernHub(t, cfg)
			w := hubDo(t, h, http.MethodHead, hubPath+"?match=a", nil, "")
			for k := range w.Header() {
				if strings.HasPrefix(k, "Access-Control-") {
					t.Errorf("%s without an Origin", k)
				}
			}
		})
	})
}

// TestSubscribeRelativeTopicsResolveAgainstTheHubURL: with an absolute hub URL, URL patterns naming the hub's host
// match relative topics; without one, the base is https://localhost.
func TestSubscribeRelativeTopicsResolveAgainstTheHubURL(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.HubURL = "https://hub.example.com/.well-known/mercure"
		cfg.ResourceIdentifier = cfg.HubURL
		e := newEnv(t, cfg)
		sub := accessFor(t, cfg.HubURL, mDetail(subOnly, mBare("*")))
		pub := accessFor(t, cfg.HubURL, mDetail(pubOnly, mPattern("https://hub.example.com/rooms/:id")))
		c := e.matchStream(t, sub,
			"match", "sentinel",
			"match_urlpattern", "https://hub.example.com/rooms/:id",
			"match_urlpattern", "https://localhost/rooms/:id")
		for _, tp := range []string{"/rooms/1", "https://hub.example.com/rooms/2", "https://localhost/rooms/3", "/rooms/4/x", "rooms/5"} {
			// A relative topic with no leading slash resolves against /.well-known/, so it is not under /rooms.
			if r := e.post(t, accessFor(t, cfg.HubURL, mDetail(pubOnly, mBare("*"))), url.Values{"topic": {tp}, "data": {tp}}); r.code != 200 {
				t.Fatalf("%s: %d", tp, r.code)
			}
		}
		sameData(t, "resolution", func() []string {
			if r := e.post(t, accessFor(t, cfg.HubURL, mDetail(pubOnly, mBare("*"))), form("topic", "sentinel", "data", "end")); r.code != 200 {
				t.Fatal(r.code)
			}
			return c.drain("end")
		}(), []string{"/rooms/1", "https://hub.example.com/rooms/2", "https://localhost/rooms/3"})
		// The publisher's pattern grant resolves the same way.
		if r := e.post(t, pub, form("topic", "/rooms/9")); r.code != 200 {
			t.Fatalf("relative topic, absolute pattern of the hub's host: %d", r.code)
		}
		if r := e.post(t, pub, form("topic", "https://localhost/rooms/9")); r.code != 403 {
			t.Fatalf("topic of another host: %d", r.code)
		}
	})
}

// TestSubscribeHeadAnnouncesNothing: a HEAD request opens no stream, so there is no subscription to announce.
func TestSubscribeHeadAnnouncesNothing(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		mon := e.monitor(t)
		tok := e.access(t, mDetail(subOnly, mBare("*")))
		if r := e.do(t, http.MethodHead, e.hubURL()+"?match=head-only", bearer(tok), ""); r.code != 200 {
			t.Fatalf("%d", r.code)
		}
		e.matchStream(t, tok, "match", "sentinel") // announced after the HEAD request
		for {
			ev := mon.mustNext()
			var d msDoc
			if err := json.Unmarshal([]byte(ev.Data), &d); err != nil {
				continue
			}
			if d.Match == "head-only" {
				t.Fatalf("a HEAD request was announced: %s", ev.Data)
			}
			if d.Match == "sentinel" {
				break
			}
		}
	})
}

const formType = "application/x-www-form-urlencoded"

// withType adds the form media type to request headers.
func withType(h http.Header) http.Header {
	h = h.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set("Content-Type", formType)
	return h
}

func withContentType(h http.Header, ct string) http.Header {
	h = h.Clone()
	h.Set("Content-Type", ct)
	return h
}
