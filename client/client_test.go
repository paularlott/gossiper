package client

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const secret = "client-test-secret-0123456789abcdef0123"

// conns tracks a listener's connections, so a test can drop them all.
type conns struct {
	net.Listener
	mu sync.Mutex
	cs []net.Conn
}

func (l *conns) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.cs = append(l.cs, c)
		l.mu.Unlock()
	}
	return c, err
}

// drop closes every connection accepted so far.
func (l *conns) drop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.cs {
		c.Close()
	}
	l.cs = nil
}

func all(t testing.TB) string { return token(t, []string{"*"}, []string{"*"}, time.Time{}) }

func newClient(t *testing.T, o Options) *Client {
	t.Helper()
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func next(t *testing.T, s *Subscription) Event {
	t.Helper()
	select {
	case ev, ok := <-s.Events():
		if !ok {
			t.Fatalf("subscription ended: %v", s.Err())
		}
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

// noStreams is a hub that refuses streaming publishes, as another Mercure hub does (it reads the body as a form).
func noStreams(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-ndjson") {
			http.Error(w, `Missing "topic" parameter`, http.StatusBadRequest)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func TestPublishSubscribe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport Transport
		streams   bool
		h2c       bool
		want      Transport
	}{
		{"http, hub without streams", HTTP, false, false, HTTP},
		{"http over HTTP/2", HTTP, true, true, HTTP},
		{"auto, gossiper hub", Auto, true, false, Stream},
		{"auto, gossiper hub over HTTP/2", Auto, true, true, Stream},
		{"auto, hub without streams", Auto, false, false, HTTP},
		{"stream", Stream, true, false, Stream},
		{"http", HTTP, true, false, HTTP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wrap func(http.Handler) http.Handler
			if !tc.streams {
				wrap = noStreams
			}
			_, srv, _ := hubWith(t, wrap)
			c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Token: all(t), Transport: tc.transport, CleartextHTTP2: tc.h2c})
			sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/books/{id}"}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/books/1"}, Data: "line 1\nline \"2\"",
				Type: "book", Retry: 1500 * time.Millisecond, Private: true, ID: "urn:book:1"})
			if err != nil || id != "urn:book:1" {
				t.Fatalf("publish: %q %v", id, err)
			}
			id2, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/books/2"}})
			if err != nil || id2 == "" {
				t.Fatalf("publish: %q %v", id2, err)
			}
			if got := c.Transport(); got != tc.want {
				t.Fatalf("transport %v, want %v", got, tc.want)
			}
			ev := next(t, sub)
			if ev.ID != "urn:book:1" || ev.Data != "line 1\nline \"2\"" || ev.Type != "book" || ev.Retry != 1500*time.Millisecond {
				t.Errorf("event %+v", ev)
			}
			if ev := next(t, sub); ev.ID != id2 || ev.Data != "" {
				t.Errorf("empty event %+v", ev)
			}
			if sub.LastEventID() != id2 {
				t.Errorf("last event ID %q", sub.LastEventID())
			}
			sub.Close()
			for range sub.Events() {
			}
			if sub.Err() != nil {
				t.Errorf("closed subscription: %v", sub.Err())
			}
		})
	}
}

// By default the client publishes with a POST per update, even to a gossiper hub that offers streams.
func TestDefaultPostPerUpdate(t *testing.T) {
	var forms, streams atomic.Int64
	_, srv, _ := hubWith(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				if strings.HasPrefix(r.Header.Get("Content-Type"), ndjson) {
					streams.Add(1)
				} else {
					forms.Add(1)
				}
			}
			h.ServeHTTP(w, r)
		})
	})
	if (Options{}).Transport != HTTP || HTTP.String() != "http" {
		t.Fatalf("default transport %v", Options{}.Transport)
	}
	c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Token: all(t)})
	for i := range 3 {
		if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/d"}, Data: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if c.Transport() != HTTP || forms.Load() != 3 || streams.Load() != 0 {
		t.Errorf("transport %v, %d form POSTs, %d streams", c.Transport(), forms.Load(), streams.Load())
	}
}

func TestErrors(t *testing.T) {
	for _, tr := range []Transport{Stream, HTTP} {
		t.Run(tr.String(), func(t *testing.T) {
			_, srv, _ := hub(t)
			url := srv.URL + "/.well-known/mercure"
			narrow := newClient(t, Options{URL: url, Token: token(t, []string{"https://example.com/mine"}, []string{"https://example.com/mine"}, time.Time{}), Transport: tr})
			_, err := narrow.Publish(ctx(t), Update{Topics: []string{"https://example.com/other"}})
			var e *Error
			if !errors.As(err, &e) || e.Status != http.StatusForbidden {
				t.Errorf("publish beyond the grants: %v", err)
			}
			_, err = narrow.Publish(ctx(t), Update{Topics: nil})
			if !errors.As(err, &e) || e.Status != http.StatusBadRequest {
				t.Errorf("publish without topic: %v", err)
			}
			// A refused publish leaves the stream open: the next one goes through.
			if _, err := narrow.Publish(ctx(t), Update{Topics: []string{"https://example.com/mine"}}); err != nil {
				t.Errorf("publish after a refused one: %v", err)
			}
			anon := newClient(t, Options{URL: url, Transport: tr})
			if _, err := anon.Publish(ctx(t), Update{Topics: []string{"https://example.com/mine"}}); !errors.As(err, &e) || e.Status != http.StatusUnauthorized {
				t.Errorf("anonymous publish: %v", err)
			}
			if _, err := anon.Subscribe(ctx(t), Subscribe{Topics: []string{"*"}}); !errors.As(err, &e) || e.Status != http.StatusUnauthorized {
				t.Errorf("anonymous subscribe: %v", err)
			}
		})
	}
}

// Private updates reach only the subscribers allowed their topic.
func TestPrivateUpdates(t *testing.T) {
	_, srv, _ := hub(t, "--anonymous")
	url := srv.URL + "/.well-known/mercure"
	pub := newClient(t, Options{URL: url, Token: all(t)})
	var subs []*Subscription
	allowed := newClient(t, Options{URL: url, Token: token(t, nil, []string{"https://example.com/p"}, time.Time{})})
	anon := newClient(t, Options{URL: url})
	for _, c := range []*Client{allowed, anon} {
		s, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/p"}})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, s)
	}
	if _, err := pub.Publish(ctx(t), Update{Topics: []string{"https://example.com/p"}, Data: "secret", Private: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Publish(ctx(t), Update{Topics: []string{"https://example.com/p"}, Data: "public"}); err != nil {
		t.Fatal(err)
	}
	for i, s := range subs {
		want := "public"
		if i%2 == 0 {
			want = "secret"
		}
		if ev := next(t, s); ev.Data != want {
			t.Errorf("subscriber %d got %q first, want %q", i, ev.Data, want)
		}
	}
}

// PublishAsync pipelines publishes on one stream: they arrive, all of them, in order.
func TestPublishAsyncOrdered(t *testing.T) {
	_, srv, _ := hub(t, "--history-size", "100000")
	c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Token: all(t), MaxInFlight: 256, Transport: Stream})
	sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/n"}, Buffer: 20000})
	if err != nil {
		t.Fatal(err)
	}
	const n = 20000
	var failed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		err := c.PublishAsync(ctx(t), Update{Topics: []string{"https://example.com/n"}, Data: fmt.Sprint(i)}, func(_ string, err error) {
			if err != nil {
				failed.Add(1)
			}
			wg.Done()
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d publishes failed", failed.Load())
	}
	for i := range n {
		if ev := next(t, sub); ev.Data != fmt.Sprint(i) {
			t.Fatalf("event %d is %q", i, ev.Data)
		}
	}
}

// A subscription resumes from its last event ID, from the history: given one, and after its connection drops.
func TestResume(t *testing.T) {
	for _, tr := range []Transport{Stream, HTTP} {
		t.Run(tr.String(), func(t *testing.T) {
			_, srv, drop := hub(t)
			url := srv.URL + "/.well-known/mercure"
			pub := newClient(t, Options{URL: url, Token: all(t), Transport: HTTP})
			var ids []string
			for i := range 3 {
				id, err := pub.Publish(ctx(t), Update{Topics: []string{"https://example.com/r"}, Data: fmt.Sprint(i)})
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, id)
			}
			var lost atomic.Int64
			c := newClient(t, Options{URL: url, Token: all(t), Transport: tr, OnError: func(error) { lost.Add(1) }})
			if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/other"}}); err != nil { // a publish stream to drop too
				t.Fatal(err)
			}
			sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/r"}, LastEventID: ids[0]})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"1", "2"} {
				if ev := next(t, sub); ev.Data != want {
					t.Fatalf("replay: %q, want %q", ev.Data, want)
				}
			}
			// The connection drops; what is published meanwhile comes from the history once it resumes.
			drop()
			for i := 3; i < 6; i++ {
				_, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/r"}, Data: fmt.Sprint(i)})
				if errors.Is(err, ErrDisconnected) { // sent on the dropped stream before the client knew: not published
					_, err = c.Publish(ctx(t), Update{Topics: []string{"https://example.com/r"}, Data: fmt.Sprint(i)})
				}
				if err != nil {
					t.Fatal(err) // over a new stream
				}
			}
			for i := 3; i < 6; i++ {
				if ev := next(t, sub); ev.Data != fmt.Sprint(i) {
					t.Fatalf("after the drop: %q, want %d", ev.Data, i)
				}
			}
			if lost.Load() == 0 {
				t.Error("the connection was not dropped")
			}
		})
	}
}

// A reader that falls a full buffer behind misses nothing: the stream waits for it.
func TestSlowReader(t *testing.T) {
	_, srv, _ := hub(t)
	c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Token: all(t), Transport: Stream})
	sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/s"}, Buffer: 4})
	if err != nil {
		t.Fatal(err)
	}
	const n = 200
	for i := range n {
		if err := c.PublishAsync(ctx(t), Update{Topics: []string{"https://example.com/s"}, Data: fmt.Sprint(i)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := range n {
		if i%50 == 0 {
			time.Sleep(50 * time.Millisecond)
		}
		if ev := next(t, sub); ev.Data != fmt.Sprint(i) {
			t.Fatalf("event %d is %q", i, ev.Data)
		}
	}
}

// The hub ends a publish stream when its token expires; with TokenFunc the client opens another with a new token, and
// sends it the publishes the hub did not take.
func TestTokenExpiry(t *testing.T) {
	_, srv, _ := hub(t)
	var issued atomic.Int64
	c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Transport: Stream, TokenFunc: func(context.Context) (string, error) {
		if issued.Add(1) == 1 { // the first expires soon; the one that replaces it lasts
			return token(t, []string{"*"}, []string{"*"}, time.Now().Add(1500*time.Millisecond)), nil
		}
		return token(t, []string{"*"}, []string{"*"}, time.Now().Add(time.Hour)), nil
	}})
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/t"}, Data: "before"}); err != nil {
		t.Fatal(err) // opens the stream with the first token
	}
	sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/t"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // past the first token's expiry
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/t"}, Data: "after"}); err != nil {
		t.Fatal(err)
	}
	if ev := next(t, sub); ev.Data != "after" {
		t.Fatalf("event %q", ev.Data)
	}
	if issued.Load() < 2 {
		t.Errorf("%d tokens issued: the stream did not renew its token", issued.Load())
	}
}

func TestClose(t *testing.T) {
	_, srv, _ := hub(t)
	c, err := New(Options{URL: srv.URL + "/.well-known/mercure", Token: all(t)})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Fatal("an event after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription did not end")
	}
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"x"}}); !errors.Is(err, ErrClosed) {
		t.Errorf("publish after Close: %v", err)
	}
	if _, err := New(Options{URL: "ftp://x"}); err == nil {
		t.Error("an ftp URL was accepted")
	}
}

// A publish the hub refuses fails alone: the client goes on publishing (a line over the hub's limit ends its stream,
// and the next publish opens another).
func TestRefusedLocally(t *testing.T) {
	_, srv, _ := hub(t, "--max-publish-size", "65536")
	c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Token: all(t), Transport: Stream})
	sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/l"}})
	if err != nil {
		t.Fatal(err)
	}
	var e *Error
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/l"}, Data: strings.Repeat("x", 2<<20)}); !errors.As(err, &e) || e.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized publish: %v", err)
	}
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/l"}, Data: "bad \xff"}); !errors.As(err, &e) || e.Status != http.StatusBadRequest {
		t.Errorf("invalid UTF-8: %v", err)
	}
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/l"}, Data: "fine"}); err != nil {
		t.Fatal(err)
	}
	if ev := next(t, sub); ev.Data != "fine" {
		t.Errorf("event %q", ev.Data)
	}
}

// A client can reach a node directly and name the hub's host: every request asks for Host.
func TestHost(t *testing.T) {
	var mu sync.Mutex
	hosts := map[string]bool{}
	_, srv, _ := hubWith(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hosts[r.Method+" "+r.Host] = true
			mu.Unlock()
			h.ServeHTTP(w, r)
		})
	})
	c := newClient(t, Options{URL: srv.URL + "/.well-known/mercure", Host: "events.example", Token: all(t)})
	sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/h"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx(t), Update{Topics: []string{"https://example.com/h"}, Data: "x"}); err != nil {
		t.Fatal(err)
	}
	next(t, sub)
	mu.Lock()
	defer mu.Unlock()
	if !hosts["GET events.example"] || !hosts["POST events.example"] || len(hosts) != 2 {
		t.Errorf("hosts asked for: %v", hosts)
	}
}

// streamHub is a hub of publish streams only (over HTTP/1.1), its answers given by answer: for the stream's number
// and a line's (both from 1) and the line, the answer line to write ("" for none) and whether the stream then ends.
func streamHub(t *testing.T, answer func(stream, n int, l line) (string, bool)) *httptest.Server {
	t.Helper()
	var streams atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != ndjson {
			http.Error(w, "streams only", http.StatusBadRequest)
			return
		}
		_ = http.NewResponseController(w).EnableFullDuplex()
		w.Header().Set("Content-Type", ndjson)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		stream := int(streams.Add(1))
		sc := bufio.NewScanner(r.Body)
		for n := 1; sc.Scan(); n++ {
			var l line
			if json.Unmarshal(sc.Bytes(), &l) != nil {
				return
			}
			a, end := answer(stream, n, l)
			if a != "" {
				_, _ = io.WriteString(w, a+"\n")
				w.(http.Flusher).Flush()
			}
			if end {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The publishes a hub did not answer before it ended their stream go first on the next one, before any published
// since: the order holds.
func TestResendOrder(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := streamHub(t, func(stream, n int, l line) (string, bool) {
		if stream == 1 && n == 3 {
			return `{"status":503,"error":"closing"}`, true
		}
		mu.Lock()
		got = append(got, l.Data)
		mu.Unlock()
		return `{"id":"urn:` + l.Data + `"}`, false
	})
	c := newClient(t, Options{URL: srv.URL, Transport: Stream})
	const n = 5000
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		err := c.PublishAsync(ctx(t), Update{Topics: []string{"t"}, Data: fmt.Sprint(i)}, func(id string, err error) {
			if err != nil {
				t.Errorf("publish: %v", err)
			}
			wg.Done()
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("%d published, want %d", len(got), n)
	}
	for i, d := range got {
		if d != fmt.Sprint(i) {
			t.Fatalf("published %d is %q", i, d)
		}
	}
}

// A hub ends a stream idle for long: the client says nothing of it, sends again what it had not answered, and
// opens another when next it publishes.
func TestIdleEnd(t *testing.T) {
	srv := streamHub(t, func(stream, n int, l line) (string, bool) {
		if stream == 1 && n == 2 {
			return `{"status":408,"error":"idle"}`, true
		}
		return fmt.Sprintf(`{"id":"urn:%d:%d"}`, stream, n), false
	})
	var reported atomic.Int64
	c := newClient(t, Options{URL: srv.URL, Transport: Stream, OnError: func(err error) { reported.Add(1); t.Log(err) }})
	if id, err := c.Publish(ctx(t), Update{Topics: []string{"t"}}); err != nil || id != "urn:1:1" {
		t.Fatalf("publish: %q %v", id, err)
	}
	if id, err := c.Publish(ctx(t), Update{Topics: []string{"t"}}); err != nil || id != "urn:2:1" {
		t.Fatalf("publish across the idle end: %q %v", id, err)
	}
	if id, err := c.Publish(ctx(t), Update{Topics: []string{"t"}}); err != nil || id != "urn:2:2" {
		t.Fatalf("publish after: %q %v", id, err)
	}
	if reported.Load() != 0 {
		t.Errorf("%d errors reported", reported.Load())
	}
}

// An update published but not stored is answered with its ID and an error: it fails, and is not sent again; what
// the hub did not answer before it ended the stream is.
func TestPublishedNotStored(t *testing.T) {
	var mu sync.Mutex
	var resent []string
	srv := streamHub(t, func(stream, n int, l line) (string, bool) {
		switch {
		case stream == 1 && n == 1:
			return `{"id":"urn:1","status":503,"error":"published, not stored"}`, false
		case stream == 1:
			return `{"status":503,"error":"store failed"}`, true
		}
		mu.Lock()
		resent = append(resent, l.Data)
		mu.Unlock()
		return `{"id":"urn:` + l.Data + `"}`, false
	})
	c := newClient(t, Options{URL: srv.URL, Transport: Stream})
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 2)
	for _, d := range []string{"a", "b"} {
		if err := c.PublishAsync(ctx(t), Update{Topics: []string{"t"}, Data: d}, func(id string, err error) { results <- result{id, err} }); err != nil {
			t.Fatal(err)
		}
	}
	r := <-results
	var e *Error
	if r.id != "urn:1" || !errors.As(r.err, &e) || e.Status != http.StatusServiceUnavailable || e.Message != "published, not stored" {
		t.Errorf("not stored: %q %v", r.id, r.err)
	}
	if r := <-results; r.id != "urn:b" || r.err != nil {
		t.Errorf("unanswered: %q %v", r.id, r.err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resent) != 1 || resent[0] != "b" {
		t.Errorf("sent again: %q", resent)
	}
}

// A stream that fails to open fails every publish waiting for it at once, and the next try waits a while: the hub
// is not asked again by each in turn. A failing hub is no reason to give up streams for POSTs either.
func TestOpenBackoff(t *testing.T) {
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		_ = http.NewResponseController(w).EnableFullDuplex() // answers before the body ends
		time.Sleep(20 * time.Millisecond)
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	for _, tr := range []Transport{Stream, Auto} {
		t.Run(tr.String(), func(t *testing.T) {
			asked.Store(0)
			c := newClient(t, Options{URL: srv.URL, Transport: tr})
			var wg sync.WaitGroup
			for range 20 {
				wg.Go(func() {
					var e *Error
					if _, err := c.Publish(ctx(t), Update{Topics: []string{"t"}}); !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable {
						t.Errorf("publish: %v", err)
					}
				})
			}
			wg.Wait()
			if _, err := c.Publish(ctx(t), Update{Topics: []string{"t"}}); err == nil {
				t.Error("a publish went through")
			}
			if asked.Load() != 1 {
				t.Errorf("the hub was asked %d times", asked.Load())
			}
			if c.Transport() == HTTP {
				t.Error("fell back to POSTs")
			}
			time.Sleep(150 * time.Millisecond) // past the first backoff
			_, _ = c.Publish(ctx(t), Update{Topics: []string{"t"}})
			if asked.Load() != 2 {
				t.Errorf("after the backoff, the hub was asked %d times", asked.Load())
			}
		})
	}
}

// Auto falls back to POSTs when a stream gets no answer though the probe did (a proxy that buffers request bodies).
func TestAutoOpenTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Content-Type") != ndjson:
			_, _ = io.WriteString(w, "urn:form")
		case r.ContentLength == 0: // the probe
			w.Header().Set("Content-Type", ndjson)
		default: // the body buffered, until the client gives up
			_, _ = io.Copy(io.Discard, r.Body)
		}
	}))
	t.Cleanup(srv.Close)
	c := newClient(t, Options{URL: srv.URL, Transport: Auto})
	c.openTimeout = 300 * time.Millisecond
	if id, err := c.Publish(ctx(t), Update{Topics: []string{"t"}}); err != nil || id != "urn:form" {
		t.Fatalf("publish: %q %v", id, err)
	}
	if c.Transport() != HTTP {
		t.Errorf("transport %v", c.Transport())
	}
}

// A subscription refused for good once reconnecting ends, with why; with TokenFunc a 401 is tried again once, with
// a new token.
func TestSubscriptionRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		tokens bool
		asks   int64
	}{
		{"forbidden", http.StatusForbidden, false, 2},
		{"unauthorized", http.StatusUnauthorized, false, 2},
		{"unauthorized, token func", http.StatusUnauthorized, true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if asked.Add(1) > 1 {
					http.Error(w, "no", tc.status)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "id: 1\ndata: x\n\n")
			}))
			t.Cleanup(srv.Close)
			o := Options{URL: srv.URL, Token: "t"}
			var issued atomic.Int64
			if tc.tokens {
				o.TokenFunc = func(context.Context) (string, error) { issued.Add(1); return "t", nil }
			}
			c := newClient(t, o)
			sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"*"}})
			if err != nil {
				t.Fatal(err)
			}
			if ev := next(t, sub); ev.Data != "x" {
				t.Fatalf("event %+v", ev)
			}
			select {
			case _, ok := <-sub.Events():
				if ok {
					t.Fatal("an event")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the subscription did not end")
			}
			var e *Error
			if !errors.As(sub.Err(), &e) || e.Status != tc.status {
				t.Errorf("ended with %v", sub.Err())
			}
			if asked.Load() != tc.asks {
				t.Errorf("the hub was asked %d times, want %d", asked.Load(), tc.asks)
			}
			if tc.tokens && issued.Load() != tc.asks {
				t.Errorf("%d tokens issued", issued.Load())
			}
		})
	}
}

// Replicas asks the hub for copies: more than it has nodes fails; an update asking for copies gets an ID of the
// client's when it has none, and published again with its ID it is answered as the first. Over a POST (a hub refusing
// streams) the copies go in a header.
func TestReplicas(t *testing.T) {
	for _, tr := range []Transport{Stream, HTTP} {
		t.Run(tr.String(), func(t *testing.T) {
			h, srv, _ := hub(t)
			c, err := New(Options{URL: srv.URL + "/.well-known/mercure", Token: token(t, []string{"*"}, nil, time.Time{}), Transport: tr})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx := context.Background()
			var e *Error
			if _, err := c.Publish(ctx, Update{Topics: []string{"https://r.test/a"}, Replicas: 2}); !errors.As(err, &e) || e.Status != 503 {
				t.Fatalf("2 copies on one node: %v", err)
			}
			id, err := c.Publish(ctx, Update{Topics: []string{"https://r.test/a"}, Replicas: 1})
			if err != nil || !strings.HasPrefix(id, "urn:uuid:") {
				t.Fatalf("1 copy without an ID: %q %v", id, err)
			}
			for range 2 {
				if got, err := c.Publish(ctx, Update{ID: "urn:r", Topics: []string{"https://r.test/a"}, Replicas: 1}); err != nil || got != "urn:r" {
					t.Fatalf("1 copy with an ID: %q %v", got, err)
				}
			}
			if n := h.duplicates(t); n != 1 {
				t.Errorf("%d duplicates, want 1", n)
			}
		})
	}
}

// A lost connection fails the publishes the hub did not answer, but those that asked for copies (idempotent) are
// sent again on a new stream.
func TestResendAfterDisconnect(t *testing.T) {
	srv := streamHub(t, func(stream, n int, l line) (string, bool) {
		if stream == 1 {
			return "", n == 2 // reads both, answers none, and drops the stream
		}
		return `{"id":"` + l.ID + `"}`, false
	})
	c := newClient(t, Options{URL: srv.URL, Transport: Stream})
	var mu sync.Mutex
	got := map[string]error{}
	var wg sync.WaitGroup
	for _, u := range []Update{{ID: "urn:copies", Topics: []string{"t"}, Replicas: 1}, {ID: "urn:plain", Topics: []string{"t"}}} {
		wg.Add(1)
		if err := c.PublishAsync(ctx(t), u, func(id string, err error) {
			defer wg.Done()
			mu.Lock()
			defer mu.Unlock()
			if err == nil && id != u.ID {
				err = fmt.Errorf("answered %q", id)
			}
			got[u.ID] = err
		}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err := got["urn:copies"]; err != nil {
		t.Errorf("the publish that asked for copies: %v", err)
	}
	if err := got["urn:plain"]; !errors.Is(err, ErrDisconnected) {
		t.Errorf("the plain publish: %v, want ErrDisconnected", err)
	}
}

// A hub over HTTPS with a certificate the system does not trust (a gossiper hub's self-signed one): refused, but
// taken with its certificate as CAFile, or with InsecureSkipVerify.
func TestTLSOptions(t *testing.T) {
	srv := httptest.NewUnstartedServer(forward(t, startHub(t, nil).direct))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "hub.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := token(t, []string{"*"}, nil, time.Time{})
	for _, tc := range []struct {
		name     string
		ca       string
		insecure bool
		ok       bool
	}{{"untrusted", "", false, false}, {"ca file", caFile, false, true}, {"insecure", "", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(Options{URL: srv.URL + "/.well-known/mercure", Token: tok, CAFile: tc.ca, InsecureSkipVerify: tc.insecure})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.Publish(ctx(t), Update{Topics: []string{"https://example.com/tls"}})
			if (err == nil) != tc.ok {
				t.Fatalf("publish: %v", err)
			}
		})
	}
	bad := filepath.Join(t.TempDir(), "none.crt")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	for _, f := range []string{bad, filepath.Join(t.TempDir(), "missing.crt")} {
		if _, err := New(Options{URL: srv.URL, CAFile: f}); err == nil {
			t.Errorf("CA file %s accepted", f)
		}
	}
}

// A hub answering with a redirect is not followed: the token goes to the hub's URL only. The target here is another
// port of the same host, where Go would send the Authorization header on; also with a caller's HTTP client.
func TestRedirectsNotFollowed(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		t.Errorf("redirect followed: %s %s, Authorization %q", r.Method, r.URL, r.Header.Get("Authorization"))
	}))
	defer target.Close()
	var asked atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		http.Redirect(w, r, target.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer hub.Close()

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"post", Options{Transport: HTTP}},
		{"stream", Options{Transport: Stream}},
		{"caller's client", Options{Transport: HTTP, HTTPClient: &http.Client{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			o.URL, o.Token = hub.URL+"/.well-known/mercure", "SECRET-TOKEN"
			c, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			pctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := c.Publish(pctx, Update{Topics: []string{"https://example.com/x"}}); err == nil {
				t.Error("a redirect answered as a publish")
			}
			n := asked.Load()
			if sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/x"}}); err == nil {
				sub.Close()
				t.Error("a redirect answered as a subscription")
			}
			if asked.Load() == n {
				t.Error("the subscription did not ask the hub")
			}
		})
	}
	if asked.Load() == 0 || reached.Load() != 0 {
		t.Fatalf("hub asked %d times, redirect target reached %d times", asked.Load(), reached.Load())
	}
}

// endless is a stream that never ends a line: "data:" then as many bytes as are read. It counts what it gave.
type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	if e.n == 0 && len(p) >= 5 {
		e.n = copy(p, "data:")
		return e.n, nil
	}
	for i := range p {
		p[i] = 'A'
	}
	e.n += len(p)
	return len(p), nil
}

// An event over the limit ends the stream, whether one line that never ends or many lines of data, without reading
// (or holding) much past the limit; events up to it are delivered.
func TestMaxEventSize(t *testing.T) {
	const limit = 1 << 20
	r := &endless{}
	if err := readSSE(r, limit, func(Event) bool { t.Error("an event from an endless line"); return true }); err == nil || !strings.Contains(err.Error(), "MaxEventSize") {
		t.Fatalf("endless line: %v", err)
	}
	if r.n > limit+256<<10 {
		t.Errorf("read %d bytes of an endless line with a limit of %d", r.n, limit)
	}

	lines := strings.Repeat("data: "+strings.Repeat("x", 1000)+"\n", 2000) + "\n" // 2 MB in one event
	if err := readSSE(strings.NewReader(lines), limit, func(Event) bool { t.Error("an event over the limit"); return true }); err == nil {
		t.Fatal("many data lines over the limit: no error")
	}

	var got []Event
	ok := "id: a\ndata: " + strings.Repeat("y", limit) + "\n\nid: b\ndata: one\ndata: two\n\n"
	if err := readSSE(strings.NewReader(ok), limit, func(ev Event) bool { got = append(got, ev); return true }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[0].Data) != limit || got[1].Data != "one\ntwo" {
		t.Fatalf("events up to the limit: %d events", len(got))
	}
}

// A hub streaming an endless line to a subscription: the client tells OnError and does not hold it.
func TestSubscriptionEventTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data:")
		chunk := []byte(strings.Repeat("A", 64<<10))
		for range 1000 { // 64 MB, unless the client stops reading
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	errs := make(chan error, 16)
	c, err := New(Options{URL: srv.URL, Token: "t", MaxEventSize: 256 << 10, OnError: func(err error) {
		select {
		case errs <- err:
		default:
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if sub, err := c.Subscribe(ctx(t), Subscribe{Topics: []string{"https://example.com/x"}}); err == nil {
		defer sub.Close()
	}
	select {
	case err := <-errs:
		if !strings.Contains(err.Error(), "MaxEventSize") {
			t.Fatalf("OnError: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no error for an event over MaxEventSize")
	}
}
