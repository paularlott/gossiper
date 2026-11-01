package urlpattern

import (
	"regexp"
	"strings"
	"testing"
)

func TestTranslateRegexp(t *testing.T) {
	tests := []struct {
		src        string
		ignoreCase bool
		in         string
		want       bool
	}{
		{`^a+$`, false, "aaa", true},
		{`^a+$`, false, "", false},
		{`^[^\/]+?$`, false, "abc", true},
		{`^[^\/]+?$`, false, "a/c", false},
		{`^\d{2,3}$`, false, "12", true},
		{`^\d{2,3}$`, false, "1234", false},
		{`^\d+$`, false, "٣", false}, // ASCII digits only
		{`^\w+$`, false, "ab_9", true},
		{`^\w+$`, false, "é", false},
		{`^\s+$`, false, " \t\U000000A0\U00002028\U0000FEFF", true},
		{`^\S+$`, false, "a b", false},
		{`^[\w--[a-c]]+$`, false, "xyz", true},
		{`^[\w--[a-c]]+$`, false, "abc", false},
		{`^[[a-z]&&[^aeiou]]$`, false, "b", true},
		{`^[[a-z]&&[^aeiou]]$`, false, "a", false},
		{`^[\d&&[0-1]]$`, false, "1", true},
		{`^[\d&&[0-1]]$`, false, "3", false},
		{`^\p{Lu}\p{Ll}+$`, false, "Hello", true},
		{`^\p{Lu}\p{Ll}+$`, false, "hello", false},
		{`^\p{General_Category=Decimal_Number}+$`, false, "123", true},
		{`^\p{Script=Greek}+$`, false, "αβ", true},
		{`^\p{Script=Greek}+$`, false, "ab", false},
		{`^\p{ASCII}+$`, false, "abc", true},
		{`^\P{ASCII}+$`, false, "abc", false},
		{`^\p{Alphabetic}+$`, false, "abcé", true},
		{`^[\p{L}\p{N}]+$`, false, "a1", true},
		{`^[\u{1F600}-\u{1F64F}]$`, false, "\U0001F600", true},
		{`^\uD83D\uDE00$`, false, "\U0001F600", true},
		{`^.$`, false, "\n", false},
		{`^.$`, false, "\U00002028", false},
		{`^.$`, false, "é", true},
		{`^.*$`, false, "abc", true},
		{`^(?:a|b)+c$`, false, "abac", true},
		{`^a{2}$`, false, "aa", true},
		{`^a{2,}$`, false, "aaaa", true},
		{`^\x41\u0042$`, false, "AB", true},
		{`^\t\n$`, false, "\t\n", true},
		{`^\cJ$`, false, "\n", true},
		{`^\0$`, false, "\x00", true},
		{`^[^]$`, false, "\n", true},
		{`^[]$`, false, "a", false},
		{`^[\b]$`, false, "\b", true},
		{`^\bfoo\b$`, false, "foo", true},
		{`^a\Bb$`, false, "ab", true},
		{`^(?<year>\d{4})-(?<month>\d{2})$`, false, "2024-05", true},
		{`^[\-a]+$`, false, "-a", true},
		{`^[a\-z]+$`, false, "-", true},
		{`^[\q{a|b}c]+$`, false, "abc", true},
		{`^[a-c[x-z]]+$`, false, "ax", true},
		{`^[^a-c]$`, false, "d", true},
		{`^[^a-c]$`, false, "b", false},
		{`^a|b$`, false, "xb", true},
		{`^(?:)$`, false, "", true},
		{`^a??$`, false, "", true},
		{`^\p{LC}+$`, false, "aB", true},
		{`^\p{Cn}$`, false, "\U000E0080", true},
		{`^\p{Assigned}$`, false, "a", true},
		{`^\p{Any}$`, false, "\U0010FFFF", true},
		{`^\p{Lowercase}\p{Uppercase}$`, false, "aB", true},
		{`^\p{Hex}+$`, false, "09af", true},
		{`^\p{White_Space}$`, false, " ", true},
		{`^\p{Letter}\p{Nd}\p{Number}\p{Punctuation}\p{Symbol}$`, false, "a1\u00b2!+", true},
		{`^\p{gc=Lu}\p{sc=Latin}$`, false, "AB", true},
		{`^\p{Cc}\p{Control}$`, false, "\x00\x01", true},
		{`^[\q{\n|\b|x}]+$`, false, "\n\bx", true},
		{`^\w\D\W\S$`, false, "a-\n!", true},
		{`^\u{61}\u0062$`, false, "ab", true},
		{`^[\-\&\!\#\%\,\:\;\<\=\>\@\` + "`" + `\~]+$`, false, "-&!#%,:;<=>@`~", true},
		{`^foo$`, true, "FOO", true},
		{`^[^a]$`, true, "A", false},
		{`^\/\.\?\+\*\(\)\[\]\{\}\|\^\$\\$`, false, `/.?+*()[]{}|^$\`, true},
	}
	for _, tc := range tests {
		goSrc, err := translateRegexp(tc.src, tc.ignoreCase)
		if err != nil {
			t.Errorf("translate(%q): %v", tc.src, err)
			continue
		}
		re, err := regexp.Compile(goSrc)
		if err != nil {
			t.Errorf("translate(%q) = %q does not compile: %v", tc.src, goSrc, err)
			continue
		}
		if got := re.MatchString(tc.in); got != tc.want {
			t.Errorf("translate(%q) = %q; match(%q) = %v, want %v", tc.src, goSrc, tc.in, got, tc.want)
		}
	}
}

func TestTranslateRegexpRejects(t *testing.T) {
	for _, src := range []string{
		`(a)\1`, `\k<x>`, `(?<x>a)\k<x>`, `(?=a)`, `(?!a)`, `(?<=a)`, `(?<!a)`, `(?i:a)`, `(?-i:a)`, `(?`,
		`a**`, `*a`, `+`, `?`, `a{2,1}`, `a{`, `a{,2}`, `a{x}`, `{`, `}`, `]`, `^*`, `$+`, `\b+`, `\B*`,
		`[a-]`, `[b-a]`, `[a-\d]`, `[\d-a]`, `[/]`, `[(]`, `[a&&&b]`, `[a&&]`, `[a--]`, `[a-c&&b]`, `[&&a]`, `[!!]`, `[a`, `[`,
		`[\q{ab}]`, `[\q{}]`, `[\q{a`, `\q{a}`,
		`\p{Foo}`, `\p{Script=Nope}`, `\p`, `\p{L`, `\8`, `\1`, `\00`, `\c`, `\c1`, `\xZ`, `\x4`, `\u12`, `\u{110000}`, `\u{}`, `\u{`,
		`\a`, `\e`, `\-`, `\ `, `\`, `(`, `a)`, `(a`, `(?<`, `(?<1a>x)`, `(?<a`, `(?<>x)`, `\p{Script_Extensions=Latin}`,
		`a{1000000}{1000000}`, `(?:(?:a{1000}){1000}){1000}`,
	} {
		if goSrc, err := translateRegexp(src, false); err == nil {
			t.Errorf("translate(%q) = %q, want error", src, goSrc)
		}
	}
}

func TestRegexpComplexityLimit(t *testing.T) {
	if _, err := translateRegexp(`^(?:a{20}){20}$`, false); err != nil {
		t.Errorf("moderate repetition rejected: %v", err)
	}
	if _, err := translateRegexp(`^(?:(?:a{20}){20}){20}$`, false); err == nil {
		t.Error("expected complexity error")
	}
	// Through the public API, an over-large counted repetition is an error.
	if _, err := Compile("https://example.com/(a{2000})", ""); err == nil {
		t.Error("a{2000} should be rejected")
	}
}

func TestPatternStrings(t *testing.T) {
	tests := []struct{ pattern, pathname string }{
		{"https://example.com/:id", "/:id"},
		{"https://example.com/:id(\\d+)", "/:id(\\d+)"},
		{"https://example.com/([^\\/]+?)", "/([^\\/]+?)"},
		{"https://example.com/:a/:b?", "/:a/:b?"},
		{"https://example.com/foo{/bar}?", "/foo{/bar}?"},
		{"https://example.com/foo{/:bar}*", "/foo/:bar*"},
		{"https://example.com/foo{/:bar}+x", "/foo/:bar+x"},
		{"https://example.com/foo{-:bar}*", "/foo{-:bar}*"},
		{"https://example.com/:a+", "/:a+"},
		{"https://example.com/*", "/*"},
		{"https://example.com/a/*/b", "/a/*/b"},
		{"https://example.com/:foo-bar", "/:foo-bar"},
		{"https://example.com/:foo\\-bar", "/:foo-bar"},
		{"https://example.com/{:foo}bar", "/{:foo}bar"},
		{"https://example.com/a b", "/a%20b"},
		{"https://example.com/../a", "/a"},
		{"https://example.com/:été", "/:été"},
	}
	for _, tc := range tests {
		p, err := Compile(tc.pattern, "")
		if err != nil {
			t.Errorf("Compile(%q): %v", tc.pattern, err)
			continue
		}
		if p.Pathname() != tc.pathname {
			t.Errorf("Compile(%q).Pathname() = %q, want %q", tc.pattern, p.Pathname(), tc.pathname)
		}
		// Normalised pattern strings are fixed points.
		q, err := CompileInit(Init{Pathname: S(p.Pathname()), Protocol: S("https")}, "")
		if err != nil || q.Pathname() != p.Pathname() {
			t.Errorf("pattern string %q is not a fixed point (%v, %q)", p.Pathname(), err, q.Pathname())
		}
	}
}

func TestTokenizer(t *testing.T) {
	for _, bad := range []string{"(", "(a", "()", "(?a)", "(a(b))", "\\", ":", ":1", "(é)", "(a\\", "(a\\é)", "((?:a)"} {
		if _, err := tokenize([]rune(bad), true); err == nil {
			t.Errorf("strict tokenize(%q) succeeded", bad)
		}
		toks, err := tokenize([]rune(bad), false)
		if err != nil || toks[len(toks)-1].typ != tkEnd {
			t.Errorf("lenient tokenize(%q) = %v, %v", bad, toks, err)
		}
	}
	toks, err := tokenize([]rune(`/:foo(\d+)?{a}*\+`), true)
	if err != nil {
		t.Fatal(err)
	}
	var types []tokenType
	for _, tk := range toks {
		types = append(types, tk.typ)
	}
	want := []tokenType{tkChar, tkName, tkRegexp, tkOtherModifier, tkOpen, tkChar, tkClose, tkAsterisk, tkEscapedChar, tkEnd}
	if len(types) != len(want) {
		t.Fatalf("tokens = %v", toks)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("token %d = %v, want %v", i, types[i], want[i])
		}
	}
}

func TestInitCompileAndMatch(t *testing.T) {
	p, err := CompileInit(Init{Hostname: S("*.example.com"), Pathname: S("/:id"), Protocol: S("https")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Pathname() != "/:id" || p.Hostname() != "*.example.com" || p.Port() != "*" {
		t.Errorf("components: %q %q %q", p.Pathname(), p.Hostname(), p.Port())
	}
	if !p.Test("https://www.example.com:8443/7?x#y", "") {
		t.Error("expected match")
	}
	if p.Test("https://example.com/7", "") {
		t.Error("expected no match")
	}
	r := p.ExecInit(Init{Protocol: S("https"), Hostname: S("a.example.com"), Pathname: S("/9")})
	if r == nil || r.Pathname.Groups["id"] != "9" || r.Hostname.Groups["0"] != "a" {
		t.Errorf("ExecInit = %+v", r)
	}
	if !p.TestInit(Init{BaseURL: S("https://a.example.com/x"), Pathname: S("/1")}) {
		t.Error("TestInit with base")
	}
	if p.TestInit(Init{BaseURL: S("nonsense")}) {
		t.Error("bad base must not match")
	}
	if _, err := CompileInit(Init{}, "https://example.com"); err == nil {
		t.Error("baseURL argument with init must be an error")
	}
	if _, err := CompileInit(Init{Pathname: S(strings.Repeat("a", MaxPatternLength+1))}, ""); err == nil {
		t.Error("over-long init component must be an error")
	}
	if p.HasRegexpGroups() {
		t.Error("HasRegexpGroups")
	}
	if q, _ := Compile("https://example.com/:id(\\d+)", ""); !q.HasRegexpGroups() {
		t.Error("HasRegexpGroups should be true")
	}
}

func TestOptionalGroupUndefined(t *testing.T) {
	p, err := Compile("https://example.com/:a?/:b", "")
	if err != nil {
		t.Fatal(err)
	}
	r := p.Exec("https://example.com/x", "")
	if r == nil {
		t.Fatal("no match")
	}
	if _, ok := r.Pathname.Groups["a"]; ok {
		t.Errorf("group a should be undefined: %v", r.Pathname.Groups)
	}
	if r.Pathname.Groups["b"] != "x" {
		t.Errorf("groups: %v", r.Pathname.Groups)
	}
}

func TestIgnoreCaseOption(t *testing.T) {
	p, err := CompileWithOptions("https://example.com/Foo/:x", "", Options{IgnoreCase: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Test("https://example.com/fOO/Bar", "") {
		t.Error("expected case-insensitive match")
	}
	q, _ := Compile("https://example.com/Foo/:x", "")
	if q.Test("https://example.com/fOO/Bar", "") {
		t.Error("default must be case-sensitive")
	}
}

func TestExecResult(t *testing.T) {
	p, err := Compile("https://:sub.example.com:8443/a/:b/*\\?q=:v#*", "")
	if err != nil {
		t.Fatal(err)
	}
	r := p.Exec("https://www.example.com:8443/a/b/c/d?q=1#top", "")
	if r == nil {
		t.Fatal("no match")
	}
	if r.Hostname.Groups["sub"] != "www" || r.Pathname.Groups["b"] != "b" || r.Pathname.Groups["0"] != "c/d" ||
		r.Search.Groups["v"] != "1" || r.Hash.Groups["0"] != "top" || r.Port.Input != "8443" {
		t.Errorf("result = %+v", r)
	}
}
