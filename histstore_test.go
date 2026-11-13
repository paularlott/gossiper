package gossiper

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// fakeStore is a HistoryStore that records what it is given.
type fakeStore struct {
	mu      sync.Mutex
	saved   []string
	dropped []string
}

func (f *fakeStore) Load(string, func(*Update)) error { return nil }

func (f *fakeStore) Trim(string, uint64, string) {}

func (f *fakeStore) Save(u *Update) {
	f.mu.Lock()
	f.saved = append(f.saved, u.Data)
	f.mu.Unlock()
}

func (f *fakeStore) Drop(_ context.Context, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, tenant)
	return nil
}

func (f *fakeStore) savedData() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.saved...)
}

// The hub saves every update it applies to its store, and a publish is answered without waiting for the disk: on a
// form POST and on a stream alike.
func TestStoreSavesWithoutWaiting(t *testing.T) {
	st := &fakeStore{}
	e := newEnv(t, Config{Anonymous: true, HistoryStore: st})
	sub := e.subscribe(t, "", "https://s.test/a")
	tok := tokenFor(t, all, nil)
	if r := e.post(t, tok, url.Values{"topic": {"https://s.test/a"}, "data": {"posted"}}); r.code != 200 {
		t.Fatalf("form publish: %d %q", r.code, r.body)
	}
	c := e.stream(t, tok)
	c.send(t, `{"topic":["https://s.test/a"],"data":"streamed"}`)
	if a := c.answer(t); a.ID == "" || a.Status != 0 {
		t.Fatalf("stream publish: %+v", a)
	}
	sub.expect("posted", "streamed")
	if got := st.savedData(); strings.Join(got, ",") != "posted,streamed" {
		t.Fatalf("saved %v", got)
	}
}

// A stream idle for streamIdle ends with a 408 line; a closing hub ends an idle stream at once.
func TestStreamIdleAndClose(t *testing.T) {
	defer func(d time.Duration) { streamIdle = d }(streamIdle)
	streamIdle = 200 * time.Millisecond
	e := newEnv(t, Config{Anonymous: true})
	if a := e.stream(t, tokenFor(t, all, nil)).answer(t); a.Status != http.StatusRequestTimeout || a.Line != 0 {
		t.Fatalf("idle: %+v", a)
	}
	streamIdle = time.Minute
	c := e.stream(t, tokenFor(t, all, nil))
	start := time.Now()
	go func() { time.Sleep(100 * time.Millisecond); _ = e.hub.Close(context.Background()) }()
	if a := c.answer(t); a.Status != http.StatusServiceUnavailable || a.Line != 0 {
		t.Fatalf("on close: %+v", a)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the idle stream ended %v after the hub closed", d)
	}
}

// Removing a tenant drops its stored history.
func TestTenantRemovalDropsStore(t *testing.T) {
	st := &fakeStore{}
	ts, err := NewTenants([]Tenant{{Name: "acme", Hosts: []string{"acme.test"},
		Config: Config{PublisherKey: auth.KeyConfig{Key: testSecret}, HistoryStore: st}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close(context.Background())
	if err := ts.Remove(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.dropped) != 1 || st.dropped[0] != "acme" {
		t.Fatalf("dropped %v", st.dropped)
	}
}
