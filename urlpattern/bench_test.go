package urlpattern

import (
	"fmt"
	"testing"
)

func BenchmarkCompile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Compile("/.well-known/mercure/subscriptions/exact/:topic/:subscriber", hubBase); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileAbsolute(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Compile("https://example.com/books/:id(\\d+)/*", ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTestRelative(b *testing.B) {
	p, _ := Compile("/.well-known/mercure/subscriptions/exact/:topic/:subscriber", hubBase)
	topic := "/.well-known/mercure/subscriptions/exact/https%3A%2F%2Fexample.com%2Ffoo/urn%3Auuid%3Abb3de268-05b0-4c65-b44e-8f9acefc29d6"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !p.Test(topic, hubBase) {
			b.Fatal("no match")
		}
	}
}

func BenchmarkTestAbsolute(b *testing.B) {
	p, _ := Compile("https://example.com/books/:id", "")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !p.Test("https://example.com/books/1", "") {
			b.Fatal("no match")
		}
	}
}

func BenchmarkTestMiss(b *testing.B) {
	p, _ := Compile("https://example.com/books/:id", "")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if p.Test("https://example.com/authors/1", "") {
			b.Fatal("match")
		}
	}
}

func BenchmarkExec(b *testing.B) {
	p, _ := Compile("https://example.com/books/:id", "")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if p.Exec("https://example.com/books/1", "") == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkMatcherHit(b *testing.B) {
	m := NewMatcher(hubBase, 1024)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !m.Match("https://example.com/books/1", "https://example.com/books/:id") {
				b.Fatal("no match")
			}
		}
	})
}

func BenchmarkMatcherChurn(b *testing.B) {
	m := NewMatcher(hubBase, 64)
	pats := make([]string, 256)
	for i := range pats {
		pats[i] = fmt.Sprintf("https://example.com/%d/:id", i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Match("https://example.com/1/x", pats[i%len(pats)])
	}
}

func BenchmarkParseURL(b *testing.B) {
	base, _ := parseURL(hubBase, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := parseURL("/.well-known/mercure/subscriptions/exact/a/b?x=1", base); !ok {
			b.Fatal("parse")
		}
	}
}
