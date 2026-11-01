package gossiper

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// fakeStore is a HistoryStore whose health, saves and writes the test decides.
type fakeStore struct {
	unhealthy atomic.Bool
	refuse    atomic.Bool // Save takes nothing
	fail      atomic.Bool // Wait fails
	mu        sync.Mutex
	next      uint64
	dropped   []string
}

func (f *fakeStore) Load(string, func(*Update)) error { return nil }

func (f *fakeStore) Trim(string, uint64, string) {}

func (f *fakeStore) Ready(ctx context.Context) error {
	for f.unhealthy.Load() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	return nil
}

func (f *fakeStore) Save(*Update) uint64 {
	if f.refuse.Load() {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	return f.next
}

func (f *fakeStore) Wait(context.Context, uint64) error {
	if f.fail.Load() {
		return errors.New("disk failing")
	}
	return nil
}

func (f *fakeStore) Drop(_ context.Context, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, tenant)
	return nil
}

// A store that cannot keep up refuses publishes before they are delivered; one that does not take or write an
// update reports it published but not stored.
func TestStoreRefusesOrReportsNotStored(t *testing.T) {
	defer func(d time.Duration) { storeWait = d }(storeWait)
	storeWait = 100 * time.Millisecond
	st := &fakeStore{}
	e := newEnv(t, Config{Anonymous: true, HistoryStore: st})
	sub := e.subscribe(t, "", "https://s.test/a")
	tok := tokenFor(t, all, nil)
	form := func(d string) url.Values { return url.Values{"topic": {"https://s.test/a"}, "data": {d}} }

	st.unhealthy.Store(true)
	if r := e.post(t, tok, form("refused")); r.code != 503 || !strings.Contains(r.body, "History store unavailable") {
		t.Fatalf("unhealthy store: %d %q", r.code, r.body)
	}
	st.unhealthy.Store(false)

	// A store that catches up within storeWait (a burst) only slows the publish down.
	st.unhealthy.Store(true)
	time.AfterFunc(30*time.Millisecond, func() { st.unhealthy.Store(false) })
	if r := e.post(t, tok, form("waited")); r.code != 200 {
		t.Fatalf("store caught up: %d %q", r.code, r.body)
	}

	st.refuse.Store(true)
	if r := e.post(t, tok, form("unsaved")); r.code != 503 || !strings.Contains(r.body, "Published, not stored") {
		t.Fatalf("save refused: %d %q", r.code, r.body)
	}
	st.refuse.Store(false)

	st.fail.Store(true)
	if r := e.post(t, tok, form("unwritten")); r.code != 503 || !strings.Contains(r.body, "Published, not stored") {
		t.Fatalf("write failed: %d %q", r.code, r.body)
	}
	st.fail.Store(false)
	// The refused update was never delivered; the others were.
	sub.expect("waited", "unsaved", "unwritten")
}

// On a stream, an update published but not stored is answered with its id and 503; once the store fails, what was
// published is answered so, and the stream ends with a last line.
func TestStreamNotStored(t *testing.T) {
	defer func(d time.Duration) { storeWait = d }(storeWait)
	storeWait = 100 * time.Millisecond
	st := &fakeStore{}
	e := newEnv(t, Config{Anonymous: true, HistoryStore: st})
	c := e.stream(t, tokenFor(t, all, nil))
	line := `{"topic":["https://s.test/a"],"data":"x"}`

	st.refuse.Store(true)
	c.send(t, line)
	if a := c.answer(t); a.ID == "" || a.Status != 503 || a.Error != "Published, not stored" {
		t.Fatalf("save refused: %+v", a)
	}
	st.refuse.Store(false)
	st.unhealthy.Store(true)
	c.send(t, line)
	if a := c.answer(t); a.ID != "" || a.Line != 2 || a.Status != 503 {
		t.Fatalf("unhealthy store: %+v", a)
	}
	st.unhealthy.Store(false)
	st.fail.Store(true)
	c.send(t, line)
	if a := c.answer(t); a.ID == "" || a.Status != 503 {
		t.Fatalf("write failed: %+v", a)
	}
	if a := c.answer(t); a.ID != "" || a.Line != 0 || a.Status != 503 {
		t.Fatalf("the stream should end: %+v", a)
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
