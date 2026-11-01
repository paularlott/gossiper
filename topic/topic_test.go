package topic

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
)

type matchCase struct {
	selector string
	topic    string
	want     bool
}

// runCases checks every case with a cached and an uncached matcher, with the
// result cache cold and warm, and through MatchAny.
func runCases(t *testing.T, cases []matchCase) {
	t.Helper()
	matchers := map[string]*Matcher{
		"nocache": NewMatcher(0),
		"cache":   NewMatcher(1000),
	}
	for name, m := range matchers {
		for pass := 0; pass < 2; pass++ { // second pass hits the caches
			for _, c := range cases {
				if got := m.Match(c.topic, c.selector); got != c.want {
					t.Errorf("%s pass %d: Match(%q, %q) = %v, want %v", name, pass, c.topic, c.selector, got, c.want)
				}
				if got := m.MatchAny([]string{"\x00\x01", c.topic}, []string{"\x00\x02", c.selector}); got != c.want {
					t.Errorf("%s: MatchAny(%q, %q) = %v, want %v", name, c.topic, c.selector, got, c.want)
				}
			}
		}
	}
}

func TestRules(t *testing.T) {
	runCases(t, []matchCase{
		// Rule 1: "*".
		{"*", "https://ex.com/a", true},
		{"*", "", true},
		{"*", "*", true},
		{"*", "{x}", true},
		{"**", "a", false},
		{"* ", "a", false},
		// Rule 2: equality.
		{"https://ex.com/a", "https://ex.com/a", true},
		{"https://ex.com/a", "https://ex.com/b", false},
		{"https://ex.com/a", "https://ex.com/a/", false},
		{"https://ex.com/a", "https://ex.com/A", false},
		{"", "", true},
		{"", "a", false},
		{"a", "", false},
		{"urn:uuid:ec6b4e8a-019e-4778-ba34-2a7d16f43026", "urn:uuid:ec6b4e8a-019e-4778-ba34-2a7d16f43026", true},
		// A string without "{" is never a template: no wildcard semantics.
		{"https://ex.com/.*", "https://ex.com/abc", false},
		{"a+", "aa", false},
		// Rule 2 applies to templates too: a template is a topic itself.
		{"https://ex.com/{id}", "https://ex.com/{id}", true},
		{"{x,y}", "{x,y}", true},
		{"{+a}/{#b}", "{+a}/{#b}", true},
		// ... and to invalid templates.
		{"{", "{", true},
		{"a{b", "a{b", true},
		{"{=x}", "{=x}", true},
		// Rule 3.
		{"https://ex.com/{id}", "https://ex.com/1", true},
		// Rule 4.
		{"https://ex.com/{id}", "https://other.com/1", false},
	})
}

func TestMercureExamples(t *testing.T) {
	const sub = "/.well-known/mercure/subscriptions"
	const topic = "https%3A%2F%2Fex.com%2F%7Bx%7D"
	const subscriber = "urn%3Auuid%3Aec6b4e8a-019e-4778-ba34-2a7d16f43026"
	runCases(t, []matchCase{
		{sub + "{/topic}{/subscriber}", sub + "/" + topic + "/" + subscriber, true},
		{sub + "{/topic}{/subscriber}", sub, true},
		{sub + "{/topic}{/subscriber}", sub + "/foo", true},
		{sub + "{/topic}{/subscriber}", sub + "/" + topic, true},
		{sub + "{/topic}{/subscriber}", sub + "/", true}, // topic defined but empty
		{sub + "{/topic}{/subscriber}", sub + "/a/b/c", false},
		{sub + "{/topic}{/subscriber}", sub + "x", false},
		{sub + "{/topic}{/subscriber}", "/.well-known/mercure/subscription/foo", false},
		{sub + "{/topic}{/subscriber}", "/other" + sub, false},
		{sub + "{/topic}{/subscriber}", sub + "/https://ex.com/{x}", false}, // not encoded
		{sub + "/{topic}/{subscriber}", sub + "/" + topic + "/" + subscriber, true},
		{sub + "/{topic}/{subscriber}", sub + "/" + topic, false},
		{"https://example.com/users/foo/{?topic}", "https://example.com/users/foo/?topic=https%3A%2F%2Fexample.com%2Fbooks%2F1", true},
		{"https://example.com/users/foo/{?topic}", "https://example.com/users/foo/", true},
		{"https://example.com/users/foo/{?topic}", "https://example.com/users/foo/?topic=", true},
		{"https://example.com/users/foo/{?topic}", "https://example.com/users/foo/?topic=https://example.com/books/1", false},
		{"https://example.com/users/foo/{?topic}", "https://example.com/users/foo/&topic=a", false},
		{"https://example.com/users/foo/{?topic}", "https://example.com/users/bar/?topic=a", false},
		{"https://ex.com/books/{id}", "https://ex.com/books/1", true},
		{"https://ex.com/books/{id}", "https://ex.com/books/a%2Fb", true},
		{"https://ex.com/books/{id}", "https://ex.com/books/1/reviews", false},
		{"https://ex.com/books/{id}", "https://ex.com/books/", true},
		{"https://ex.com/books/{id}", "https://ex.com/books", false},
		{"https://ex.com/books/{id}/reviews", "https://ex.com/books/1/reviews", true},
		{"https://ex.com/books/{id}/reviews", "https://ex.com/books/1/2/reviews", false},
		{"https://example.com/{+path}", "https://example.com/a/b/c", true},
		{"https://example.com/{+path}", "https://example.com/a/b?c=d#e", true},
	})
}

func TestOperators(t *testing.T) {
	runCases(t, []matchCase{
		// Simple string expansion.
		{"{x}", "", true},
		{"{x}", "abc", true},
		{"{x}", "a.b-c_d~e", true},
		{"{x}", "a%2Fb", true},
		{"{x}", "a%2fb", true},
		{"{x}", "%C3%A9", true},
		{"{x}", "a/b", false},
		{"{x}", "a b", false},
		{"{x}", "a?b", false},
		{"{x}", "a#b", false},
		{"{x}", "a%", false},
		{"{x}", "a%2", false},
		{"{x}", "a%zz", false},
		{"{x}", "é", false},
		{"{x}", "a;b", false},
		{"{x}", "a=b", false},
		{"{x}", "a{b", false}, // not a template match, and braces are not allowed
		{"/a{x}b", "/ab", true},
		{"/a{x}b", "/aXb", true},
		{"/a{x}b", "/aX/b", false},
		{"/a{x}b", "/aXc", false},

		// Reserved expansion.
		{"{+path}/here", "/foo/bar/here", true},
		{"{+path}/here", "/here", true},
		{"{+path}/here", "x%20y/here", true},
		{"{+path}/here", "x%2/here", false},
		{"{+path}/here", "a b/here", false},
		{"{+x}", "a,b;c=d/e?f#g[h]@i!$&'()*+", true},
		{"{+x}", "a{b", false},
		{"{+x}", "a}b", false},
		{"{+x}", "a b", false},
		{"{+x}", "a%", false},
		{"{+x}", "a|b", false},
		{"{+x}", "a\"b", false},
		{"{+x}", "é", false},
		{"here?ref={+path}", "here?ref=/foo/bar", true},
		{"here?ref={+path}", "here?ref=", true},
		{"here?ref={+path}", "here", false},

		// Fragment expansion.
		{"{#x}", "", true},
		{"{#x}", "#", true},
		{"{#x}", "#a/b?c", true},
		{"{#x}", "##", true},
		{"{#x}", "a", false},
		{"{#x}", "#a b", false},
		{"{#path,x}/here", "#/foo/bar,1024/here", true},
		{"{#path,x}/here", "/here", true},
		{"{#path,x}/here", "#/here", true},

		// Label expansion.
		{"X{.var}", "X", true},
		{"X{.var}", "X.", true},
		{"X{.var}", "X.value", true},
		{"X{.var}", "X.a.b", true}, // "." is unreserved so a value may contain it
		{"X{.var}", "Xvalue", false},
		{"X{.var}", "X/a", false},
		{"X{.var}", "X.a/b", false},
		{"X{.x,y}", "X.1024.768", true},
		{"X{.x,y}", "X.1024", true},

		// Path segments.
		{"{/var}", "", true},
		{"{/var}", "/", true},
		{"{/var}", "/a", true},
		{"{/var}", "/a/b", false},
		{"{/var}", "a", false},
		{"{/var}", "//", false},
		{"{/a,b}", "", true},
		{"{/a,b}", "/x/y", true},
		{"{/a,b}", "/x", true},
		{"{/a,b}", "//y", true},
		{"{/a,b}", "/x/", true},
		{"{/a,b}", "/x//", false},
		{"{/a,b}", "/x/y/z", false},
		{"{/a,b}", "x/y", false},
		{"/p{/a}{/b}", "/p", true},
		{"/p{/a}{/b}", "/p/1/2", true},
		{"/p{/a}{/b}", "/p/1/2/3", false},

		// Path-style parameters.
		{"{;x,y}", "", true},
		{"{;x,y}", ";x=1", true},
		{"{;x,y}", ";y=2", true},
		{"{;x,y}", ";x=1;y=2", true},
		{"{;x,y}", ";x", true},
		{"{;x,y}", ";x=1;y", true},
		{"{;x,y}", ";x;y", true},
		{"{;x,y}", ";y=2;x=1", false},
		{"{;x,y}", ";z=1", false},
		{"{;x,y}", ";x=1;x=2", false},
		{"{;x,y}", ";x=", false},
		{"{;x,y}", "x=1", false},
		{"{;x,y}", ";x=1/2", false},
		{"{;x,y}", ";x=a%2Fb", true},

		// Form-style query.
		{"{?x,y}", "", true},
		{"{?x,y}", "?x=1", true},
		{"{?x,y}", "?y=2", true},
		{"{?x,y}", "?x=1&y=2", true},
		{"{?x,y}", "?x=", true},
		{"{?x,y}", "?x=1&y=", true},
		{"{?x,y}", "?x=&y=", true},
		{"{?x,y}", "&x=1", false},
		{"{?x,y}", "?x=1?y=2", false},
		{"{?x,y}", "?y=2&x=1", false},
		{"{?x,y}", "?x", false},
		{"{?x,y}", "?z=1", false},
		{"{?x,y}", "?x=1&", false},
		{"{?x,y}", "?x=a&b", false},

		// Form-style query continuation.
		{"?fixed=yes{&x}", "?fixed=yes", true},
		{"?fixed=yes{&x}", "?fixed=yes&x=1", true},
		{"?fixed=yes{&x}", "?fixed=yes&x=", true},
		{"?fixed=yes{&x}", "?fixed=yes&y=1", false},
		{"?fixed=yes{&x}", "?fixed=yes?x=1", false},
		{"?fixed=yes{&x}", "?fixed=yes&x=1&x=2", false},
		{"?fixed=yes{&x,y}", "?fixed=yes&x=1&y=2", true},
		{"?fixed=yes{&x,y}", "?fixed=yes&y=2", true},
	})
}

func TestMultipleVariables(t *testing.T) {
	runCases(t, []matchCase{
		{"{x,y}", "", true},
		{"{x,y}", "1", true},
		{"{x,y}", "1,2", true},
		{"{x,y}", ",", true},
		{"{x,y}", ",2", true},
		{"{x,y}", "1,", true},
		{"{x,y}", "1;2", false},
		{"{x,y}", "1 2", false},
		{"map?{x,y}", "map?1024,768", true},
		{"map?{x,y}", "map?", true},
		{"map?{x,y}", "map", false},
		{"{x,hello,y}", "1024,Hello%20World%21,768", true},
		{"{+x,hello,y}", "1024,Hello%20World!,768", true},
		{"{+x,hello,y}", "1024,Hello World!,768", false},
		// Several expressions.
		{"{a}/{b}/{c}", "1/2/3", true},
		{"{a}/{b}/{c}", "1//3", true},
		{"{a}/{b}/{c}", "1/2", false},
		{"{a}{b}", "abc", true},
		{"{a}{b}", "", true},
		{"{a}-{b}", "x-y", true},
		{"{a}-{b}", "x-y-z", true}, // "-" is unreserved: a="x-y", b="z" or a="x", b="y-z"
		{"{a}/{b}", "x/y/z", false},
		// The same name may be repeated; occurrences are independent matches.
		{"{a}/{a}", "1/2", true},
		{"{a,a}", "1,2", true},
	})
}

func TestExplode(t *testing.T) {
	runCases(t, []matchCase{
		{"{list*}", "red,green,blue", true},
		{"{list*}", "", true},
		{"{list*}", "a;b", false},
		{"{keys*}", "semi=%3B,dot=.,comma=%2C", true},
		{"{keys*}", "a=b", true},
		{"{keys*}", "a=b,c=d", true},
		{"{keys*}", "=b", false}, // empty key
		{"{keys*}", "a=b=c", false},
		{"{+list*}", "red,green,blue", true},
		{"{+keys*}", "semi=;,dot=.,comma=,", true},
		{"{#list*}", "#red,green,blue", true},
		{"{#keys*}", "#semi=;,dot=.,comma=,", true},
		{"X{.list*}", "X.red.green.blue", true},
		{"X{.list*}", "X.red/green", false},
		{"X{.keys*}", "X.semi=%3B.dot=..comma=%2C", true},
		{"{/list*}", "", true},
		{"{/list*}", "/red/green/blue", true},
		{"{/list*}", "/a", true},
		{"{/list*}", "/a/b/c/d", true},
		{"{/list*}", "/a b", false},
		{"{/list*}", "red/green", false},
		{"{/list*,path:4}", "/red/green/blue/%2Ffoo", true},
		{"{/keys*}", "/semi=%3B/dot=./comma=%2C", true},
		{"{/keys*}", "/semi=%3B/dot", false},
		{"{;list*}", ";list=red;list=green;list=blue", true},
		{"{;list*}", ";list", true},
		{"{;list*}", ";list=a;list", true},
		{"{;list*}", ";semi=%3B;dot=.;comma=%2C", true},
		{"{;list*}", ";list=a,b", false},
		{"{;list*}", "list=a", false},
		{"{;list*}", ";list=", false},
		{"{?list*}", "?list=red&list=green&list=blue", true},
		{"{?list*}", "?semi=%3B&dot=.&comma=%2C", true},
		{"{?list*}", "?list=&list=", true},
		{"{?list*}", "?list", false},
		{"{?list*}", "?list=a?list=b", false},
		{"{&list*}", "&list=red&list=green", true},
		{"{&list*}", "&semi=%3B&dot=.", true},
		{"{&list*}", "?list=red", false},
		{"{?a*,b}", "?x=1&y=2&b=3", true},
		{"{?a*,b}", "?b=3", true},
		{"{?a*,b}", "?x=1", true},
		{"{?a*,b}", "?x=1&y=2&b=3&c=4", true}, // keys of an exploded map are arbitrary
		{"{?a*,b}", "?x=1&y=2&b=3&", false},
	})
}

func TestPrefix(t *testing.T) {
	runCases(t, []matchCase{
		{"{x:3}", "", true},
		{"{x:3}", "ab", true},
		{"{x:3}", "abc", true},
		{"{x:3}", "abcd", false},
		{"{x:3}", "a%20b", true},
		{"{x:3}", "a%20bc", false},
		{"{x:3}", "%C3%A9%C3%A9%C3%A9", true},
		{"{x:3}", "%C3%A9%C3%A9%C3%A9%C3%A9", false},
		{"{x:3}", "%E6%97%A5%E6%9C%AC", true}, // two 3-octet characters
		{"{x:1}", "%E6%97%A5%E6%9C%AC", false},
		{"{x:1}", "%E6%97%A5", true},
		{"{x:1}", "%F0%9F%98%80", true}, // one 4-octet character
		{"{x:2}", "%F0%9F%98%80%F0%9F%98%80", true},
		{"{x:2}", "%F0%9F%98%80%F0%9F%98%80a", false},
		{"{x:3}", "a,b", false}, // "," in a string value is encoded
		{"{x:3}", "ab/", false},
		{"{x:3}", "a%zz", false},
		{"{x:9}", "123456789", true},
		{"{x:9}", "1234567890", false},
		{"{x:30}", "value", true},
		{"{+path:6}/here", "/foo/b/here", true},
		{"{+path:6}/here", "/foo/ba/here", false},
		{"{+x:3}", "a/b", true},
		{"{+x:3}", "a/bc", false},
		{"{#x:2}", "#a/", true},
		{"{#x:2}", "#a/b", false},
		{"X{.var:3}", "X.val", true},
		{"X{.var:3}", "X.valu", false},
		{"{/var:1,var}", "/v/value", true},
		{"{/var:1,var}", "/v", true},
		{"{/var:1,var}", "/vv/value", false},
		{"{;hello:5}", ";hello=Hello", true},
		{"{;hello:5}", ";hello=Hello!", false},
		{"{;hello:5}", ";hello", true},
		{"{?x:2,y:1}", "?x=ab&y=c", true},
		{"{?x:2,y:1}", "?x=ab&y=cd", false},
		{"{?x:2,y:1}", "?x=&y=", true},
		{"{?x:2,y:1}", "?y=c", true},
		{"{&x:2}", "&x=ab", true},
		{"{&x:2}", "&x=abc", false},
		{"{x:512}", strings.Repeat("a", 512), true},
		{"{x:512}", strings.Repeat("a", 513), false},
		// Beyond the prefix budget the selector is not a template.
		{"{x:513}", "abc", false},
		{"{x:9999}", "abc", false},
		{"{x:9999}", "{x:9999}", true},
		{"{a:300,b:300}", "a", false},
	})
}

func TestUndefined(t *testing.T) {
	runCases(t, []matchCase{
		{"O{undef}X", "OX", true},
		{"O{empty}X", "OX", true},
		{"?{x,empty}", "?1024,", true},
		{"?{x,undef}", "?1024", true},
		{"?{undef,y}", "?768", true},
		{"X{#undef}", "X", true},
		{"X{#empty}", "X#", true},
		{"X{.undef}", "X", true},
		{"X{.empty}", "X.", true},
		{"{/undef}", "", true},
		{"{/empty}", "/", true},
		{"{;undef}", "", true},
		{"{;empty}", ";empty", true},
		{"{?undef}", "", true},
		{"{?empty}", "?empty=", true},
		{"{&undef}", "", true},
		{"{&empty}", "&empty=", true},
		{"a{?x}b", "ab", true},
		{"a{?x}b", "a?x=1b", true},
		{"a{?x}b", "a?b", false},
	})
}

func TestLiterals(t *testing.T) {
	runCases(t, []matchCase{
		// Regexp metacharacters in literals are literal.
		{"https://ex.com/a.b/{id}", "https://ex.com/a.b/1", true},
		{"https://ex.com/a.b/{id}", "https://ex.com/aXb/1", false},
		{"/a+b/{x}", "/a+b/1", true},
		{"/a+b/{x}", "/aab/1", false},
		{"/a+b/{x}", "/aaab/1", false},
		{"/q?{x}", "/q?1", true},
		{"/q?{x}", "/q1", false},
		{"/q?{x}", "/q", false},
		{"/f(x)/{y}", "/f(x)/2", true},
		{"/f(x)/{y}", "/fx/2", false},
		{"/[a]/{x}", "/[a]/1", true},
		{"/[a]/{x}", "/a/1", false},
		{"/a|b/{x}", "/a|b/1", true},
		{"/a|b/{x}", "/a/1", false},
		{"/a|b/{x}", "/b/1", false},
		{`a\{x}`, `a\1`, true},
		{`a\{x}`, `a1`, false},
		{"^x${y}", "^x$1", true},
		{"^x${y}", "x1", false},
		{"/a*{x}", "/a*1", true},
		{"/a*{x}", "/aaa1", false},
		{"/(?i){x}", "/(?i)1", true},
		{"/(?i){x}", "/1", false},
		{"/a{x}\n", "/a1\n", true},
		{"/a{x}\n", "/a1", false},
		{"/a{x}.", "/a1.", true},
		{"/a{x}.", "/a1x", false},
		{"/{x}", "/1\n", false},
		{"/{x}", "\n/1", false},
		{"[{x}]", "[1]", true},
		{"[{x}]", "1", false},
		{"%41{x}", "%41b", true}, // literal pct-encoding is literal, not decoded
		{"%41{x}", "Ab", false},
		{"%41{x}", "%61b", false},
		{"a b/{x}", "a b/1", true}, // lenient literals
		{"a b/{x}", "a%20b/1", false},
		// IRI literals.
		{"https://例え.jp/{x}/é", "https://例え.jp/1/é", true},
		{"https://例え.jp/{x}/é", "https://例え.jp/1/e", false},
		{"https://例え.jp/{x}/é", "https://例え.jp/1/%C3%A9", false},
		{"https://例え.jp/{x}/é", "https://例えxjp/1/é", false},
		{"https://例え.jp/{x}", "https://例え.jp/%E4%BE%8B", true},
		{"https://例え.jp/{x}", "https://例え.jp/例", false}, // values are pct-encoded
		{"https://例え.jp/{+x}", "https://例え.jp/例", false},
		{"😀{x}", "😀1", true},
		{"😀{x}", "1", false},
		// Values containing pct-encoding of metacharacters.
		{"/{x}", "/%2E%2E", true},
		{"/{x}/{y}", "/a%2Fb/c", true},
	})
}

func TestInvalidTemplates(t *testing.T) {
	invalid := []string{
		"{", "}", "a{b", "a}b", "{}", "{{x}}", "{x", "x}", "{x}}", "{{x}", "{x{y}}",
		"{=x}", "{,x}", "{!x}", "{@x}", "{|x}", "{+=x}", "{x,}", "{,}", "{x,,y}",
		"{x y}", "{x-y}", "{a..b}", "{.}", "{.a.}", "{..a}", "{x:0}", "{x:10000}", "{x:}", "{x:a}",
		"{x:-1}", "{x:01}", "{x*:3}", "{x:3*}", "{x**}", "{x*,}", "{%2}", "{%zz}", "{x%2}", "{?}", "{+}",
		"{ x}", "{x }", "{x:3:4}", "{x/y}", "{x=1}", "{é}", "{x:3,}", "{+,x}", "{*}", "{:3}",
	}
	m := NewMatcher(10)
	for _, s := range invalid {
		if IsTemplate(s) {
			t.Errorf("IsTemplate(%q) = true, want false", s)
		}
		if !m.Match(s, s) {
			t.Errorf("Match(%q, %q) = false, want true (rule 2)", s, s)
		}
		for _, topic := range []string{"", "x", "1", "a", "a,b", "3", "é", "%2"} {
			if m.Match(topic, s) {
				t.Errorf("Match(%q, %q) = true for invalid template", topic, s)
			}
		}
	}

	valid := []string{
		"{x}", "{+x}", "{#x}", "{.x}", "{/x}", "{;x}", "{?x}", "{&x}", "{x,y}", "{x*}", "{x:1}", "{x:9999}",
		"{a.b}", "{%41}", "{_x}", "{x_1}", "{a.b.c}", "{.a.b}", "{x%2Fy}", "a{x}b", "{x}{y}", "{9}",
		"{a,b,c,d}", "{?a*,b:2}", "{X}", "{_}",
	}
	for _, s := range valid {
		if !IsTemplate(s) {
			t.Errorf("IsTemplate(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "*", "abc", "https://ex.com/a", "a}b"} {
		if IsTemplate(s) {
			t.Errorf("IsTemplate(%q) = true, want false", s)
		}
	}
}

func TestLimits(t *testing.T) {
	m := NewMatcher(100)

	// Length: exactly 4096 bytes is accepted, 4097 is not.
	pad := func(n int) string { return strings.Repeat("a", n-len("{x}")) + "{x}" }
	at, over := pad(maxTemplateLen), pad(maxTemplateLen+1)
	if !IsTemplate(at) || IsTemplate(over) {
		t.Errorf("IsTemplate length limit: at=%v over=%v", IsTemplate(at), IsTemplate(over))
	}
	if !m.Match(strings.Repeat("a", maxTemplateLen-3)+"b", at) {
		t.Error("template at the length limit does not match")
	}
	if m.Match(strings.Repeat("a", maxTemplateLen-2)+"b", over) {
		t.Error("template over the length limit matched")
	}
	if !m.Match(over, over) {
		t.Error("template over the length limit does not match itself")
	}

	// Expressions.
	if !IsTemplate(strings.Repeat("{x}", maxExpressions)) || IsTemplate(strings.Repeat("{x}", maxExpressions+1)) {
		t.Error("expression limit not enforced")
	}
	over65 := strings.Repeat("{x}", maxExpressions+1)
	if m.Match("abc", over65) || !m.Match(over65, over65) {
		t.Error("over-limit expression count should be exact-only")
	}
	at64 := strings.Repeat("{x}", maxExpressions)
	if !m.Match("abc", at64) {
		t.Error("template with the maximum number of expressions should match")
	}

	// Variables.
	mkVars := func(n int) string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("v%d", i)
		}
		return "{" + strings.Join(names, ",") + "}"
	}
	if !IsTemplate(mkVars(maxVariables)) || IsTemplate(mkVars(maxVariables+1)) {
		t.Error("variable limit not enforced")
	}
	if !m.Match("1,2,3", mkVars(maxVariables)) || m.Match("1,2,3", mkVars(maxVariables+1)) {
		t.Error("variable limit not applied by matcher")
	}
	// A maximum-size multi-variable expression stays correct.
	for _, op := range []string{"", "+", "#", ".", "/", ";", "?", "&"} {
		sel := strings.Replace(mkVars(maxVariables), "{", "{"+op, 1)
		if !m.Match("", sel) {
			t.Errorf("empty expansion of %.20q... not matched", sel)
		}
	}

	// Prefix modifier range.
	for _, s := range []string{"{x:1}", "{x:9999}"} {
		if !IsTemplate(s) {
			t.Errorf("IsTemplate(%q) = false", s)
		}
	}
	for _, s := range []string{"{x:0}", "{x:10000}", "{x:99999}"} {
		if IsTemplate(s) {
			t.Errorf("IsTemplate(%q) = true", s)
		}
	}
}

func TestParseTemplateDirect(t *testing.T) {
	// parseTemplate is also safe to call on strings the Matcher pre-filters.
	for _, s := range []string{"", "abc", strings.Repeat("{x}", 10) + strings.Repeat("a", maxTemplateLen), "{x:1a}", "{x:12345}"} {
		if parts, ok := parseTemplate(s); ok || parts != nil {
			t.Errorf("parseTemplate(%q) = %v, %v", s, parts, ok)
		}
	}
	parts, ok := parseTemplate("a{+b,c:3}d{e*}")
	if !ok || len(parts) != 4 {
		t.Fatalf("parseTemplate = %+v, %v", parts, ok)
	}
	e := parts[1].expr
	if e == nil || e.op != '+' || len(e.vars) != 2 || e.vars[1] != (varSpec{name: "c", prefix: 3}) {
		t.Errorf("unexpected expression %+v", e)
	}
	if e := parts[3].expr; e == nil || e.op != 0 || !e.vars[0].explode {
		t.Errorf("unexpected expression %+v", e)
	}
}

func TestMatchAny(t *testing.T) {
	m := NewMatcher(16)
	tests := []struct {
		name      string
		topics    []string
		selectors []string
		want      bool
	}{
		{"no topics", nil, []string{"*"}, false},
		{"no selectors", []string{"a"}, nil, false},
		{"both empty", nil, nil, false},
		{"wildcard", []string{"a"}, []string{"x", "*"}, true},
		{"exact", []string{"x", "a"}, []string{"y", "a"}, true},
		{"template", []string{"https://ex.com/books/1"}, []string{"https://ex.com/{kind}/2", "https://ex.com/books/{id}"}, true},
		{"second topic", []string{"nope", "https://ex.com/books/1"}, []string{"https://ex.com/books/{id}"}, true},
		{"none", []string{"a", "b"}, []string{"c", "https://ex.com/{id}", "{x}x"}, false},
		{"invalid template exact", []string{"{x"}, []string{"{x"}, true},
		{"empty topic", []string{""}, []string{"{x}"}, true},
	}
	for _, tt := range tests {
		if got := m.MatchAny(tt.topics, tt.selectors); got != tt.want {
			t.Errorf("%s: MatchAny(%q, %q) = %v, want %v", tt.name, tt.topics, tt.selectors, got, tt.want)
		}
	}
}

// rfcVectors are the RFC 6570 examples (sections 1.2 and 3.2) using rfcVars.
var rfcVectors = []struct{ tpl, want string }{
	{"{count}", "one,two,three"},
	{"{count*}", "one,two,three"},
	{"{/count}", "/one,two,three"},
	{"{/count*}", "/one/two/three"},
	{"{;count}", ";count=one,two,three"},
	{"{;count*}", ";count=one;count=two;count=three"},
	{"{?count}", "?count=one,two,three"},
	{"{?count*}", "?count=one&count=two&count=three"},
	{"{&count*}", "&count=one&count=two&count=three"},
	{"{var}", "value"},
	{"{hello}", "Hello%20World%21"},
	{"{half}", "50%25"},
	{"O{empty}X", "OX"},
	{"O{undef}X", "OX"},
	{"{x,y}", "1024,768"},
	{"{x,hello,y}", "1024,Hello%20World%21,768"},
	{"?{x,empty}", "?1024,"},
	{"?{x,undef}", "?1024"},
	{"?{undef,y}", "?768"},
	{"{undef,y}", "768"},
	{"{var:3}", "val"},
	{"{var:30}", "value"},
	{"{list}", "red,green,blue"},
	{"{list*}", "red,green,blue"},
	{"{keys}", "semi,%3B,dot,.,comma,%2C"},
	{"{keys*}", "semi=%3B,dot=.,comma=%2C"},
	{"{+var}", "value"},
	{"{+hello}", "Hello%20World!"},
	{"{+half}", "50%25"},
	{"{base}index", "http%3A%2F%2Fexample.com%2Fhome%2Findex"},
	{"{+base}index", "http://example.com/home/index"},
	{"O{+empty}X", "OX"},
	{"O{+undef}X", "OX"},
	{"{+path}/here", "/foo/bar/here"},
	{"here?ref={+path}", "here?ref=/foo/bar"},
	{"up{+path}{var}/here", "up/foo/barvalue/here"},
	{"{+x,hello,y}", "1024,Hello%20World!,768"},
	{"{+path,x}/here", "/foo/bar,1024/here"},
	{"{+path:6}/here", "/foo/b/here"},
	{"{+list}", "red,green,blue"},
	{"{+list*}", "red,green,blue"},
	{"{+keys}", "semi,;,dot,.,comma,,"},
	{"{+keys*}", "semi=;,dot=.,comma=,"},
	{"{#var}", "#value"},
	{"{#hello}", "#Hello%20World!"},
	{"{#half}", "#50%25"},
	{"foo{#empty}", "foo#"},
	{"foo{#undef}", "foo"},
	{"{#x,hello,y}", "#1024,Hello%20World!,768"},
	{"{#path,x}/here", "#/foo/bar,1024/here"},
	{"{#path:6}/here", "#/foo/b/here"},
	{"{#list}", "#red,green,blue"},
	{"{#list*}", "#red,green,blue"},
	{"{#keys}", "#semi,;,dot,.,comma,,"},
	{"{#keys*}", "#semi=;,dot=.,comma=,"},
	{"X{.var}", "X.value"},
	{"X{.empty}", "X."},
	{"X{.undef}", "X"},
	{"X{.x,y}", "X.1024.768"},
	{"{x,y}", "1024,768"},
	{"X{.var:3}", "X.val"},
	{"X{.list}", "X.red,green,blue"},
	{"X{.list*}", "X.red.green.blue"},
	{"X{.keys}", "X.semi,%3B,dot,.,comma,%2C"},
	{"X{.keys*}", "X.semi=%3B.dot=..comma=%2C"},
	{"X{.empty_keys}", "X"},
	{"X{.empty_keys*}", "X"},
	{"{/var}", "/value"},
	{"{/var,undef}", "/value"},
	{"{/var,x}/here", "/value/1024/here"},
	{"{/var:1,var}", "/v/value"},
	{"{/list}", "/red,green,blue"},
	{"{/list*}", "/red/green/blue"},
	{"{/list*,path:4}", "/red/green/blue/%2Ffoo"},
	{"{/keys}", "/semi,%3B,dot,.,comma,%2C"},
	{"{/keys*}", "/semi=%3B/dot=./comma=%2C"},
	{"{;who}", ";who=fred"},
	{"{;half:2}", ";half=50"},
	{"{;empty}", ";empty"},
	{"{;v,empty,who}", ";v=6;empty;who=fred"},
	{"{;v,bar,who}", ";v=6;who=fred"},
	{"{;x,y}", ";x=1024;y=768"},
	{"{;x,y,empty}", ";x=1024;y=768;empty"},
	{"{;x,y,undef}", ";x=1024;y=768"},
	{"{;hello:5}", ";hello=Hello"},
	{"{;list}", ";list=red,green,blue"},
	{"{;list*}", ";list=red;list=green;list=blue"},
	{"{;keys}", ";keys=semi,%3B,dot,.,comma,%2C"},
	{"{;keys*}", ";semi=%3B;dot=.;comma=%2C"},
	{"{?who}", "?who=fred"},
	{"{?half:2}", "?half=50"},
	{"{?x,y}", "?x=1024&y=768"},
	{"{?x,y,empty}", "?x=1024&y=768&empty="},
	{"{?x,y,undef}", "?x=1024&y=768"},
	{"{?var:3}", "?var=val"},
	{"{?list}", "?list=red,green,blue"},
	{"{?list*}", "?list=red&list=green&list=blue"},
	{"{?keys}", "?keys=semi,%3B,dot,.,comma,%2C"},
	{"{?keys*}", "?semi=%3B&dot=.&comma=%2C"},
	{"{&who}", "&who=fred"},
	{"{&half:2}", "&half=50"},
	{"?fixed=yes{&x}", "?fixed=yes&x=1024"},
	{"{&x,y,empty}", "&x=1024&y=768&empty="},
	{"{&x,y,undef}", "&x=1024&y=768"},
	{"{&var:3}", "&var=val"},
	{"{&list}", "&list=red,green,blue"},
	{"{&list*}", "&list=red&list=green&list=blue"},
	{"{&keys}", "&keys=semi,%3B,dot,.,comma,%2C"},
	{"{&keys*}", "&semi=%3B&dot=.&comma=%2C"},
	{"{empty_keys}", ""},
	{"{empty_keys*}", ""},
	{"{/empty_keys*}", ""},
	{"{;empty_keys*}", ""},
	{"{?empty_keys}", ""},
	{"{dub}", "me%2Ftoo"},
	{"{+dub}", "me/too"},
	{"{dom*}", "example,com"},
	{"{/dom*}", "/example/com"},
	{"{.dom*}", ".example.com"},
	{"{who}/{who}", "fred/fred"},
	{"http://example.com/~{who}", "http://example.com/~fred"},
	{"http://example.com/{who}{?x,y}", "http://example.com/fred?x=1024&y=768"},
	{"http://example.com/{who}/{+path}{?x}", "http://example.com/fred//foo/bar?x=1024"},
	{"{/who,v}{?x}", "/fred/6?x=1024"},
	{"{#v}{#x}", "#6#1024"},
}

// TestRFC6570Examples validates the test oracle against the RFC's published
// expansions, then checks that the matcher accepts each of them.
func TestRFC6570Examples(t *testing.T) {
	vs := rfcVars()
	m := NewMatcher(1000)
	for _, v := range rfcVectors {
		if got := expand(v.tpl, vs); got != v.want {
			t.Errorf("oracle: expand(%q) = %q, want %q", v.tpl, got, v.want)
		}
		if !IsTemplate(v.tpl) {
			t.Errorf("IsTemplate(%q) = false", v.tpl)
		}
		if !m.Match(v.want, v.tpl) {
			t.Errorf("Match(%q, %q) = false", v.want, v.tpl)
		}
	}
}

var randTemplates = []string{
	"{a}", "{+a}", "{#a}", "{.a}", "{/a}", "{;a}", "{?a}", "{&a}",
	"{a,b}", "{+a,b}", "{#a,b,c}", "{.a,b}", "{/a,b}", "{;a,b}", "{?a,b}", "{&a,b}",
	"{a,b,c,d}", "{+a,b,c,d}", "{#a,b,c,d}", "{.a,b,c,d}", "{/a,b,c,d}", "{;a,b,c,d}", "{?a,b,c,d}", "{&a,b,c,d}",
	"{a*}", "{a*,b}", "{+a*}", "{#a*}", "{.a*}", "{/a*}", "{;a*}", "{?a*}", "{&a*}",
	"{/a*,b*,c*}", "{;a*,b*}", "{?a*,b*}", "{&a*,b*,c}", "{.a*,b*}", "{+a*,b*}", "{#a*,b}",
	"{p:3}", "{+p:5,b}", "{#p:2}", "{.p:3,q:1}", "{/p:1,q:2}", "{;p:2,q}", "{?p:2,a*,c}", "{&p:4,q:4}",
	"http://ex.com/a.b+c(1)?x[{a}]|{b}/tail", "/x{/a}{/b}{/c}", "/x{?a,b}", "/x/{a}/{+b}{?c*}",
	"https://例え.jp/é/{a}{?b}", "{a}{b}{c}", "{+a}{#b}{.c}{/d}", "x{?a}{&b}{&c}", "{a:2}{b:2}{c}",
	"/.well-known/mercure/subscriptions{/a}{/b}", "{a.b}", "{.a.b,c}", "{%41}", "{%41,b}",
}

func randString(r *rand.Rand) string {
	const alphabet = "abcXYZ019-._~ :/?#[]@!$&'()*+,;=%é日😀{}\"<>"
	runes := []rune(alphabet)
	n := r.Intn(7)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(runes[r.Intn(len(runes))])
	}
	// Occasionally include pre-encoded triplets, which "+" and "#" preserve.
	if r.Intn(8) == 0 {
		b.WriteString("%2F%c3%A9")
	}
	return b.String()
}

func randValue(r *rand.Rand, stringOnly bool) value {
	k := r.Intn(4)
	if stringOnly && k > 1 {
		k = 1
	}
	switch k {
	case 0:
		return value{} // undefined
	case 1:
		return S(randString(r))
	case 2:
		n := r.Intn(4)
		l := make([]string, n)
		for i := range l {
			l[i] = randString(r)
		}
		return L(l...)
	}
	n := r.Intn(4)
	var kvs []string
	for i := 0; i < n; i++ {
		key := randString(r)
		if key == "" {
			key = "k"
		}
		kvs = append(kvs, key, randString(r))
	}
	return M(kvs...)
}

// TestRoundTrip expands templates for random variable assignments with the
// oracle expander and requires the matcher to accept every expansion, and to
// reject expansions corrupted with characters no expansion can contain.
func TestRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(6570))
	m := NewMatcher(0)
	corrupt := []string{" ", "\"", "<", ">", "\\", "^", "`", "|", "%zq", "%g1"}
	for _, tpl := range randTemplates {
		if !IsTemplate(tpl) {
			t.Fatalf("test template %q is not a template", tpl)
		}
		for i := 0; i < 400; i++ {
			vs := vars{}
			for _, name := range []string{"a", "b", "c", "d", "a.b", "%41"} {
				vs[name] = randValue(r, false)
			}
			for _, name := range []string{"p", "q"} {
				vs[name] = randValue(r, true)
			}
			exp := expand(tpl, vs)
			if !m.Match(exp, tpl) {
				t.Fatalf("Match(%q, %q) = false; vars %+v", exp, tpl, vs)
			}
			// Corrupt the expansion at a random position. Template literals
			// contain none of the inserted sequences, so no expansion can.
			pos := r.Intn(len(exp) + 1)
			for pos > 0 && pos < len(exp) && exp[pos]&0xC0 == 0x80 { // keep UTF-8 intact
				pos--
			}
			bad := exp[:pos] + corrupt[r.Intn(len(corrupt))] + exp[pos:]
			if bad != tpl && m.Match(bad, tpl) {
				t.Fatalf("Match(%q, %q) = true for corrupted expansion of %q", bad, tpl, exp)
			}
		}
	}
}

func TestConcurrent(t *testing.T) {
	m := NewMatcher(64)
	type tc struct {
		sel, topic string
		want       bool
	}
	cases := []tc{
		{"https://ex.com/books/{id}", "https://ex.com/books/1", true},
		{"https://ex.com/books/{id}", "https://ex.com/books/1/x", false},
		{"/.well-known/mercure/subscriptions{/topic}{/subscriber}", "/.well-known/mercure/subscriptions/a/b", true},
		{"{?a,b}", "?a=1&b=2", true},
		{"*", "x", true},
		{"{bad", "{bad", true},
		{"{bad", "x", false},
	}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 3000; i++ {
				c := cases[r.Intn(len(cases))]
				if i%5 == 0 { // churn the caches with unique selectors/topics
					sel := fmt.Sprintf("https://ex.com/%d/{x}", r.Intn(1000))
					topic := fmt.Sprintf("https://ex.com/%d/%d", r.Intn(1000), i)
					_ = m.Match(topic, sel)
					_ = m.MatchAny([]string{topic, c.topic}, []string{sel, c.sel})
				}
				if got := m.Match(c.topic, c.sel); got != c.want {
					t.Errorf("Match(%q, %q) = %v, want %v", c.topic, c.sel, got, c.want)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestCacheBounds(t *testing.T) {
	for _, size := range []int{2, 3, 10, 64, 1000} {
		m := NewMatcher(size)
		for i := 0; i < 5000; i++ {
			sel := fmt.Sprintf("https://ex.com/%d/{x}", i)
			topic := fmt.Sprintf("https://ex.com/%d/y", i)
			if !m.Match(topic, sel) {
				t.Fatalf("size %d: Match(%q, %q) = false", size, topic, sel)
			}
			if n := m.templates.len(); n > size {
				t.Fatalf("size %d: template cache holds %d entries", size, n)
			}
			if n := m.results.len(); n > size {
				t.Fatalf("size %d: result cache holds %d entries", size, n)
			}
		}
	}

	// Disabled result cache: templates still cached with a small bound.
	m := NewMatcher(0)
	if m.results != nil {
		t.Error("result cache should be disabled")
	}
	for i := 0; i < 5000; i++ {
		m.Match("x", fmt.Sprintf("a{x}%d", i))
		if n := m.templates.len(); n > defaultTemplateCache {
			t.Fatalf("template cache holds %d entries, default bound %d", n, defaultTemplateCache)
		}
	}
	if n := m.templates.len(); n == 0 {
		t.Error("templates should be cached when the result cache is disabled")
	}

	// Invalid templates are cached negatively, but bounded as well.
	m = NewMatcher(32)
	for i := 0; i < 5000; i++ {
		m.Match("x", fmt.Sprintf("{%d", i))
		if n := m.templates.len(); n > 32 {
			t.Fatalf("template cache holds %d entries", n)
		}
	}
}

func TestCacheNotUsedForOversizedKeys(t *testing.T) {
	m := NewMatcher(100)
	big := strings.Repeat("a", maxResultKeyLen)
	for i := 0; i < 50; i++ {
		m.Match(fmt.Sprintf("%s%d", big, i), "https://ex.com/{x}")
	}
	if n := m.results.len(); n != 0 {
		t.Errorf("oversized keys were cached: %d entries", n)
	}
	// Selectors over the template length limit are not cached at all.
	m = NewMatcher(100)
	long := strings.Repeat("a", maxTemplateLen) + "{x}"
	for i := 0; i < 50; i++ {
		m.Match(fmt.Sprintf("%s%d", "b", i), long)
	}
	if n := m.templates.len(); n != 0 {
		t.Errorf("over-limit selectors were cached: %d entries", n)
	}
	// Exact and wildcard matches do not touch the caches.
	m.Match("a", "a")
	m.Match("a", "*")
	m.Match("a", "b")
	if m.templates.len() != 0 || m.results.len() != 0 {
		t.Error("non-template selectors should not be cached")
	}
}

func TestTemplateCostBound(t *testing.T) {
	m := NewMatcher(1000)
	// Large templates are admitted only within the total cost budget.
	for i := 0; i < 300; i++ {
		sel := fmt.Sprintf("{a:500}/%d", i)
		if !m.Match("abc/"+fmt.Sprint(i), sel) {
			t.Fatalf("Match failed for %q", sel)
		}
	}
	total := 0
	for i := range m.templates.shards {
		s := &m.templates.shards[i]
		s.mu.RLock()
		for _, e := range s.young {
			total += e.cost
		}
		for _, e := range s.old {
			total += e.cost
		}
		s.mu.RUnlock()
	}
	if total > templateCostBudget {
		t.Errorf("cached template cost %d exceeds budget %d", total, templateCostBudget)
	}
}

func TestCacheHitReturnsSameTemplate(t *testing.T) {
	m := NewMatcher(10)
	a := m.template("a{x}")
	b := m.template("a{x}")
	if a == nil || a != b {
		t.Error("template not cached")
	}
	if m.template("a{x") != nil {
		t.Error("invalid template should be nil")
	}
	if m.template("a{x") != nil {
		t.Error("invalid template should stay nil from the cache")
	}
}

func TestLinearTime(t *testing.T) {
	// Pathological templates must not exhibit super-linear behaviour: this
	// would be a classic ReDoS shape for a backtracking engine.
	m := NewMatcher(0)
	sel := strings.Repeat("{x}", 32) + "z"
	topic := strings.Repeat("a", 4000)
	if m.Match(topic, sel) {
		t.Error("unexpected match")
	}
	sel = "{x*,y*,z*}{/a*}{.b*}{;c*}"
	if m.Match(strings.Repeat("a=b,", 1000)+"%", sel) {
		t.Error("unexpected match")
	}
}

func FuzzMatch(f *testing.F) {
	seeds := []struct{ topic, selector string }{
		{"https://ex.com/books/1", "https://ex.com/books/{id}"},
		{"/.well-known/mercure/subscriptions", "/.well-known/mercure/subscriptions{/topic}{/subscriber}"},
		{"?a=1&b=2", "{?a,b}"},
		{"a", "*"},
		{"{x", "{x"},
		{"é", "{+x}"},
		{"/a/b", "{/x*}"},
		{";a=1", "{;a*}"},
		{"%C3%A9", "{x:1}"},
		{"x", "{x:0}"},
		{"x", "{=x}"},
		{"", "{}"},
		{"a,b", "{x,y}"},
		{"#a", "{#x}"},
		{".a.b", "{.x*}"},
		{"x", strings.Repeat("{x}", 70)},
		{"\xff", "{x}\xff"},
	}
	for _, s := range seeds {
		f.Add(s.topic, s.selector)
	}
	cached, uncached := NewMatcher(64), NewMatcher(0)
	f.Fuzz(func(t *testing.T, topic, selector string) {
		got := cached.Match(topic, selector)
		if got != cached.Match(topic, selector) {
			t.Fatalf("Match(%q, %q) not stable", topic, selector)
		}
		if got != uncached.Match(topic, selector) {
			t.Fatalf("cached and uncached disagree on Match(%q, %q)", topic, selector)
		}
		if (selector == "*" || selector == topic) && !got {
			t.Fatalf("Match(%q, %q) = false, want true", topic, selector)
		}
		if !IsTemplate(selector) && selector != "*" && selector != topic && got {
			t.Fatalf("Match(%q, %q) = true for a non-template", topic, selector)
		}
		if !cached.Match(selector, selector) {
			t.Fatalf("selector %q does not match itself", selector)
		}
		if cached.MatchAny([]string{topic}, []string{selector}) != got {
			t.Fatalf("MatchAny disagrees with Match for (%q, %q)", topic, selector)
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	b.Run("exact", func(b *testing.B) {
		m := NewMatcher(1000)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.Match("https://ex.com/books/1", "https://ex.com/books/1")
		}
	})
	b.Run("exact-miss", func(b *testing.B) {
		m := NewMatcher(1000)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.Match("https://ex.com/books/1", "https://ex.com/books/2")
		}
	})
	b.Run("template-cached", func(b *testing.B) {
		m := NewMatcher(1000)
		m.Match("https://ex.com/books/1", "https://ex.com/books/{id}")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.Match("https://ex.com/books/1", "https://ex.com/books/{id}")
		}
	})
	b.Run("template-cached-parallel", func(b *testing.B) {
		m := NewMatcher(1000)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m.Match("https://ex.com/books/1", "https://ex.com/books/{id}")
			}
		})
	})
	b.Run("template-no-result-cache", func(b *testing.B) {
		m := NewMatcher(0)
		m.Match("https://ex.com/books/1", "https://ex.com/books/{id}")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.Match("https://ex.com/books/1", "https://ex.com/books/{id}")
		}
	})
	b.Run("template-mercure", func(b *testing.B) {
		m := NewMatcher(0)
		const sel = "/.well-known/mercure/subscriptions{/topic}{/subscriber}"
		const topic = "/.well-known/mercure/subscriptions/https%3A%2F%2Fex.com%2F%7Bx%7D/urn%3Auuid%3Aec6b4e8a-019e-4778-ba34-2a7d16f43026"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.Match(topic, sel)
		}
	})
	b.Run("template-uncached", func(b *testing.B) {
		// Cycling through more selectors than the cache holds forces a
		// compilation on every call.
		m := NewMatcher(0)
		sels := make([]string, 4*defaultTemplateCache*2)
		for i := range sels {
			sels[i] = fmt.Sprintf("https://ex.com/books/%d/{id}", i)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.Match("https://ex.com/books/x/1", sels[i%len(sels)])
		}
	})
}
