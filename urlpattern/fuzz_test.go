package urlpattern

import (
	"fmt"
	"testing"
	"time"
)

func addSeeds(f *testing.F) {
	for _, s := range [][3]string{
		{"https://example.com/books/:id", "https://example.com/books/1", ""},
		{"/.well-known/mercure/subscriptions/exact/:topic/:subscriber", "/.well-known/mercure/subscriptions/exact/a/b", hubBase},
		{"https://example.com/users/42/*", "https://example.com/users/42/x", ""},
		{"https://:sub.example.com:8443/a/:b(\\d+)?/*\\?q=:v#*", "https://www.example.com:8443/a/1/c?q=2#h", ""},
		{"http{s}?://{*.}?example.com/:product/:endpoint", "https://sub.example.com/foo/bar", ""},
		{"data\\:text/javascript,let x = 100/:tens?5;", "data:text/javascript,let x = 100/5;", ""},
		{"https://[\\:\\:1]:8080/", "https://[::1]:8080/", ""},
		{"https://example.com/([[a-z]--a])", "https://example.com/b", ""},
		{"https://example.com/((?:a+)+)b", "https://example.com/aaaaaaaaaaaaaaaac", ""},
		{"https://example.com/(\\p{Lu}+)", "https://example.com/ABC", ""},
		{"https://bücher.example/*", "https://xn--bcher-kva.example/x", ""},
		{"bar", "bar", hubBase},
		{"*", "http://[::1", ""},
	} {
		f.Add(s[0], s[1], s[2])
	}
	// Seed with every string-form pattern of the WPT data.
	for _, c := range loadWPT(f) {
		if len(c.Pattern) > 0 && isJSONString(c.Pattern[0]) {
			base := ""
			if len(c.Pattern) > 1 && isJSONString(c.Pattern[1]) {
				base = rawString(c.Pattern[1])
			}
			input := ""
			if len(c.Inputs) > 0 && isJSONString(c.Inputs[0]) {
				input = rawString(c.Inputs[0])
			}
			f.Add(rawString(c.Pattern[0]), input, base)
		}
	}
}

// watchdog fails the test if the returned func is not called within 2s, and
// reports slow (> 500ms) iterations.
func watchdog(t *testing.T, args ...string) func() {
	start := time.Now()
	timer := time.AfterFunc(2*time.Second, func() {
		panic(fmt.Sprintf("iteration hung (> 2s) for %q", args))
	})
	return func() {
		timer.Stop()
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("iteration took %v for %q", d, args)
		}
	}
}

func FuzzCompile(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, pattern, input, base string) {
		defer watchdog(t, pattern, input, base)()
		p, err := Compile(pattern, base)
		if err != nil {
			return
		}
		_ = p.Protocol() + p.Username() + p.Password() + p.Hostname() + p.Port() + p.Pathname() + p.Search() + p.Hash()
		got := p.Test(input, base)
		r := p.Exec(input, base)
		if got != (r != nil) {
			t.Fatalf("Test = %v but Exec = %v", got, r)
		}
	})
}

func FuzzMatch(f *testing.F) {
	addSeeds(f)
	m := NewMatcher(hubBase, 128)
	f.Fuzz(func(t *testing.T, pattern, input, _ string) {
		defer watchdog(t, pattern, input, "")()
		got := m.Match(input, pattern)
		if got && m.Valid(pattern) != nil {
			t.Fatal("matched with an invalid pattern")
		}
		// The matcher agrees with the plain API.
		if p, err := Compile(pattern, hubBase); err == nil {
			if want := p.Test(input, hubBase); want != got {
				t.Fatalf("Matcher.Match = %v, Pattern.Test = %v", got, want)
			}
		}
	})
}
