package urlpattern

import (
	"strings"
	"testing"
	"time"
)

const hubBase = "https://hub.example.com/.well-known/mercure"

func TestMercureMatching(t *testing.T) {
	tests := []struct {
		name, pattern, topic string
		want                 bool
	}{
		{"relative pattern, relative topic",
			"/.well-known/mercure/subscriptions/exact/:topic/:subscriber",
			"/.well-known/mercure/subscriptions/exact/https%3A%2F%2Fexample.com%2Ffoo/urn%3Auuid%3Abb3de268-05b0-4c65-b44e-8f9acefc29d6",
			true},
		{"relative pattern, absolute topic",
			"/.well-known/mercure/subscriptions/exact/:topic/:subscriber",
			"https://hub.example.com/.well-known/mercure/subscriptions/exact/a/b", true},
		{"relative pattern, other host", "/.well-known/mercure/subscriptions/exact/:topic/:subscriber",
			"https://evil.example.com/.well-known/mercure/subscriptions/exact/a/b", false},
		{"relative pattern, too few segments", "/.well-known/mercure/subscriptions/exact/:topic/:subscriber",
			"/.well-known/mercure/subscriptions/exact/a", false},
		{"absolute exact", "https://example.com/books/:id", "https://example.com/books/1", true},
		{"host is case-insensitive", "https://example.com/books/:id", "https://EXAMPLE.com/books/1", true},
		{"pattern host case", "https://EXAMPLE.com/books/:id", "https://example.com/books/1", true},
		{"path is case-sensitive", "https://example.com/books/:id", "https://example.com/Books/1", false},
		{"scheme differs", "https://example.com/books/:id", "http://example.com/books/1", false},
		{"default port", "https://example.com/books/:id", "https://example.com:443/books/1", true},
		{"other port", "https://example.com/books/:id", "https://example.com:8443/books/1", false},
		{"nested segment", "https://example.com/books/:id", "https://example.com/books/1/2", false},
		{"wildcard", "https://example.com/users/42/*", "https://example.com/users/42/posts/7", true},
		{"wildcard other user", "https://example.com/users/42/*", "https://example.com/users/43/posts/7", false},
		{"wildcard needs the slash", "https://example.com/users/42/*", "https://example.com/users/42", false},
		{"any query and hash", "https://example.com/books/:id", "https://example.com/books/1?x=1#frag", true},
		{"relative topic resolves to hub path", "https://hub.example.com/.well-known/bar", "bar", true},
		{"relative topic is not just bar", "https://hub.example.com/bar", "bar", false},
		{"dot segments", "https://hub.example.com/foo", "../../foo", true},
		{"unescaped colon is not a valid pattern", "urn:uuid:60a76c80-d399-11d9-b93C-0003939e0af6", "urn:uuid:60a76c80-d399-11d9-b93C-0003939e0af6", false},
		{"urn pattern with escaped colons", `urn\:uuid\:60a76c80-d399-11d9-b93C-0003939e0af6`, "urn:uuid:60a76c80-d399-11d9-b93C-0003939e0af6", true},
		{"urn pattern is case-sensitive", `urn\:uuid\:60a76c80-d399-11d9-b93c-0003939e0af6`, "urn:uuid:60a76c80-d399-11d9-b93C-0003939e0af6", false},
		{"urn wildcard", `urn\:uuid\:*`, "urn:uuid:60a76c80", true},
		{"unparsable topic", "https://example.com/*", "http://[::1", false},
		{"unparsable topic, wildcard", "*", "http://[::1", false},
		{"bad port topic", "https://example.com/*", "https://example.com:99999/a", false},
		{"regexp group", "https://example.com/books/:id(\\d+)", "https://example.com/books/12", true},
		{"regexp group mismatch", "https://example.com/books/:id(\\d+)", "https://example.com/books/x", false},
		{"optional segment", "https://example.com/books{/:id}?", "https://example.com/books", true},
		{"IDN host", "https://bücher.example/*", "https://xn--bcher-kva.example/x", true},
	}
	m := NewMatcher(hubBase, 64)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.Match(tc.topic, tc.pattern); got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.topic, tc.pattern, got, tc.want)
			}
			// Same result through the uncached API.
			p, err := Compile(tc.pattern, hubBase)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.pattern, err)
			}
			if got := p.Test(tc.topic, hubBase); got != tc.want {
				t.Errorf("Pattern.Test(%q) = %v, want %v", tc.topic, got, tc.want)
			}
		})
	}
}

func TestMercureExecGroups(t *testing.T) {
	p, err := Compile("/.well-known/mercure/subscriptions/exact/:topic/:subscriber", hubBase)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Exec("/.well-known/mercure/subscriptions/exact/https%3A%2F%2Fexample.com%2Ffoo/urn%3Auuid%3Aabc", hubBase)
	if r == nil {
		t.Fatal("no match")
	}
	g := r.Pathname.Groups
	if g["topic"] != "https%3A%2F%2Fexample.com%2Ffoo" || g["subscriber"] != "urn%3Auuid%3Aabc" {
		t.Errorf("groups = %v", g)
	}
	if r.Hostname.Input != "hub.example.com" || r.Protocol.Input != "https" {
		t.Errorf("components = %+v", r)
	}
	if p.Exec("/nope", hubBase) != nil {
		t.Error("unexpected match")
	}
}

func TestMatcherInvalidPatterns(t *testing.T) {
	m := NewMatcher(hubBase, 16)
	for _, pat := range []string{
		"https://example.com/(a)(\\1)",          // backreference
		"https://example.com/(?=a)a",            // lookahead
		"https://example.com/(?<=a)b",           // lookbehind
		"https://example.com/:a/:a",             // duplicate name
		"https://example.com/(unclosed",         // syntax
		"https://example.com/{a",                // unbalanced group
		"https://[::1/",                         // bad IPv6
		"https://example.com:99999/",            // bad port
		strings.Repeat("a", MaxPatternLength+1), // too long
	} {
		if err := m.Valid(pat); err == nil {
			t.Errorf("Valid(%q) = nil, want error", pat)
		}
		if m.Match("https://example.com/a", pat) {
			t.Errorf("Match with invalid pattern %q returned true", pat)
		}
	}
	if err := m.Valid("https://example.com/:id"); err != nil {
		t.Errorf("Valid: %v", err)
	}
}

func TestMatcherNoBase(t *testing.T) {
	m := NewMatcher("", 8)
	if err := m.Valid("/foo"); err == nil {
		t.Error("relative pattern without base must be invalid")
	}
	if !m.Match("https://example.com/foo", "https://example.com/*") {
		t.Error("absolute pattern should work without base")
	}
	if m.Match("/foo", "https://example.com/*") {
		t.Error("relative topic without base must not match")
	}
	bad := NewMatcher("http://[::1", 8)
	if bad.Match("/x", "/x") {
		t.Error("unparsable base: relative pattern must not match")
	}
}

func TestLinearTime(t *testing.T) {
	long := strings.Repeat("a", 10000)
	cases := []struct{ pattern, input string }{
		{"https://example.com/((?:a+)+)b", "https://example.com/" + long},
		{"https://example.com/((?:a|aa)+)b", "https://example.com/" + long},
		{"https://example.com/((?:a*)*)c", "https://example.com/" + long + "!"},
		{"https://example.com/(.*)(.*)(.*)(.*)(.*)x", "https://example.com/" + long},
		{"https://example.com/:a*:b*:c*x", "https://example.com/" + strings.Repeat("a/", 3000)},
		{"https://example.com/((?:\\w+\\d?)+)$", "https://example.com/" + long + "-"},
	}
	// Largest allowed program against the longest allowed input.
	cases = append(cases, struct{ pattern, input string }{
		"https://example.com/((?:a{30}){30})b", "https://example.com/" + strings.Repeat("a", MaxInputLength-40) + "c"})
	for _, tc := range cases {
		m := NewMatcher("", 8)
		if err := m.Valid(tc.pattern); err != nil {
			t.Fatalf("Valid(%q): %v", tc.pattern, err)
		}
		start := time.Now()
		if m.Match(tc.input, tc.pattern) {
			t.Errorf("unexpected match for %q", tc.pattern)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("%q took %v, want < 100ms", tc.pattern, d)
		}
	}
}

func TestInputLengthLimit(t *testing.T) {
	m := NewMatcher("", 8)
	if !m.Match("https://example.com/"+strings.Repeat("a", 1000), "https://example.com/*") {
		t.Error("expected match")
	}
	if m.Match("https://example.com/"+strings.Repeat("a", MaxInputLength), "https://example.com/*") {
		t.Error("input over MaxInputLength must not match")
	}
}
