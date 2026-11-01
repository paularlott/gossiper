package urlpattern

import (
	"fmt"
	"sync"
	"testing"
)

func TestMatcherCacheBound(t *testing.T) {
	for _, size := range []int{1, 2, 3, 10, 64, 300} {
		m := NewMatcher(hubBase, size)
		limit := size
		if limit < 2 {
			limit = 2
		}
		for i := 0; i < 800; i++ {
			pat := fmt.Sprintf("https://example.com/p%d/:id", i)
			if !m.Match(fmt.Sprintf("https://example.com/p%d/x", i), pat) {
				t.Fatalf("size %d: pattern %d did not match", size, i)
			}
			if n := m.Len(); n > limit {
				t.Fatalf("size %d: cache holds %d entries after %d inserts, limit %d", size, n, i+1, limit)
			}
		}
		if m.Len() == 0 {
			t.Errorf("size %d: cache empty", size)
		}
	}
}

func TestMatcherCachesFailures(t *testing.T) {
	m := NewMatcher(hubBase, 16)
	bad := "https://example.com/(?=a)"
	for i := 0; i < 3; i++ {
		if m.Valid(bad) == nil {
			t.Fatal("expected error")
		}
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1 (failure cached once)", m.Len())
	}
}

func TestMatcherHitPromotion(t *testing.T) {
	// A frequently used pattern survives generation rotation.
	m := NewMatcher("", 8)
	hot := "https://hot.example/:id"
	for i := 0; i < 200; i++ {
		m.Match("https://hot.example/1", hot)
		m.Match("https://x.example/1", fmt.Sprintf("https://x.example/p%d", i))
	}
	p1, _ := m.get(hot)
	p2, _ := m.get(hot)
	if p1 != p2 {
		t.Error("hot pattern not stable")
	}
}

func TestMatcherConcurrent(t *testing.T) {
	m := NewMatcher(hubBase, 8) // tiny cache to force rotation
	patterns := make([]string, 50)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("https://example.com/%d/:id", i)
	}
	patterns = append(patterns, "/.well-known/mercure/subscriptions/exact/:topic/:subscriber", "https://example.com/(?=x)")
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				pi := (i*7 + g) % len(patterns)
				pat := patterns[pi]
				var topic string
				var want bool
				switch {
				case pi < 50:
					topic, want = fmt.Sprintf("https://example.com/%d/z", pi), true
				case pi == 50:
					topic, want = "/.well-known/mercure/subscriptions/exact/a/b", true
				default:
					topic = "https://example.com/x"
				}
				if got := m.Match(topic, pat); got != want {
					t.Errorf("Match(%q, %q) = %v", topic, pat, got)
					return
				}
				if (m.Valid(pat) == nil) != (pi != 51) {
					t.Errorf("Valid(%q) wrong", pat)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestPatternConcurrent(t *testing.T) {
	p, err := Compile("https://example.com/:a/:b(\\d+)?/*", "")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if r := p.Exec("https://example.com/x/12/rest", ""); r == nil || r.Pathname.Groups["b"] != "12" {
					t.Error("bad exec")
					return
				}
			}
		}()
	}
	wg.Wait()
}
