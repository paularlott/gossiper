package historydb

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/gossiper/client"
)

// testFlush is the tests' flush interval: short, so they do not wait.
const testFlush = 20 * time.Millisecond

func open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, testFlush, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func loaded(t *testing.T, s *Store, tenant string) []string {
	t.Helper()
	var ids []string
	if err := s.Load(tenant, func(u *gossiper.Update) { ids = append(ids, u.ID) }); err != nil {
		t.Fatal(err)
	}
	return ids
}

// Updates saved concurrently are all written by Close, and a reopened store loads them in stamp order, each tenant
// its own.
func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	s := open(t, path)
	clock := hlc.NewClock()
	var mu sync.Mutex
	var want []string
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			for i := range 200 {
				mu.Lock() // stamps and saves in the same order, so want is in stamp order
				u := &gossiper.Update{ID: fmt.Sprint(w, "-", i), Topics: []string{"https://t.test/a"}, Data: "x", Stamp: uint64(clock.Now()), Origin: "n"}
				want = append(want, u.ID)
				s.Save(u)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	s.Save(&gossiper.Update{ID: "other", Topics: []string{"t"}, Stamp: uint64(clock.Now()), Origin: "n", Tenant: "acme"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := open(t, path)
	if got := loaded(t, s2, ""); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("loaded %d updates, want %d in stamp order", len(got), len(want))
	}
	if got := loaded(t, s2, "acme"); fmt.Sprint(got) != "[other]" {
		t.Fatalf("tenant acme: %v", got)
	}
}

// The store writes in the background, every flush interval: a saved update is not on disk at once, then is, with
// no Close.
func TestFlushesPeriodically(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "h.db"), 300*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.Save(&gossiper.Update{ID: "a", Topics: []string{"t"}, Stamp: 1, Origin: "n"})
	if got := loaded(t, s, ""); len(got) != 0 {
		t.Fatalf("written at once: %v", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(loaded(t, s, "")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("not written within the flush interval")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Trim deletes what sorts before the bound (with the next write); Drop deletes what a tenant saved before it, not
// after, and returns once that is done. Nothing is saved after Close.
func TestTrimDrop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	s := open(t, path)
	for i := 1; i <= 5; i++ {
		s.Save(&gossiper.Update{ID: fmt.Sprint(i), Topics: []string{"t"}, Stamp: uint64(i), Origin: "b"})
		s.Save(&gossiper.Update{ID: fmt.Sprint("x", i), Topics: []string{"t"}, Stamp: uint64(i), Origin: "b", Tenant: "x"})
	}
	s.Trim("", 3, "b")
	if err := s.Drop(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if got := loaded(t, s, "x"); len(got) != 0 {
		t.Errorf("Drop returned with %v still stored", got)
	}
	// Saved after the drop (the tenant added again at once): kept.
	s.Save(&gossiper.Update{ID: "x-again", Topics: []string{"t"}, Stamp: 9, Origin: "b", Tenant: "x"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := open(t, path)
	if got := loaded(t, s2, ""); fmt.Sprint(got) != "[3 4 5]" {
		t.Errorf("after the trim: %v", got)
	}
	if got := loaded(t, s2, "x"); fmt.Sprint(got) != "[x-again]" {
		t.Errorf("after the drop: %v, want only what was saved after it", got)
	}
	s2.Save(&gossiper.Update{ID: "late", Topics: []string{"t"}, Stamp: 10, Origin: "b"})
	s2.Close()
	s2.Save(&gossiper.Update{ID: "closed", Topics: []string{"t"}, Stamp: 11, Origin: "b"})
	if got := loaded(t, open(t, path), ""); fmt.Sprint(got) != "[3 4 5 late]" {
		t.Errorf("after Close: %v, want the save before it and not the one after", got)
	}
	if err := s2.Drop(context.Background(), "x"); err != ErrClosed {
		t.Errorf("Drop after Close: %v, want ErrClosed", err)
	}
}

const secret = "historydb-secret-historydb-secret-historydb-secret"

func token(t *testing.T) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A hub with a store keeps its history across a restart: a subscriber resumes from an update published before it.
func TestHubRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	start := func(s *Store) (*gossiper.Hub, *httptest.Server) {
		h, err := gossiper.New(gossiper.Config{PublisherKey: auth.KeyConfig{Key: secret}, Protocol: gossiper.ProtocolBoth, Anonymous: true, HistoryStore: s, Heartbeat: -1})
		if err != nil {
			t.Fatal(err)
		}
		return h, httptest.NewServer(h)
	}
	s := open(t, path)
	h, srv := start(s)
	var ids []string
	for i := range 5 {
		req, _ := http.NewRequest("POST", srv.URL+"/.well-known/mercure",
			strings.NewReader(url.Values{"topic": {"https://t.test/a"}, "data": {fmt.Sprint("d", i)}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token(t))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		_, _ = bufio.NewReader(resp.Body).WriteTo(&b)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("publish: %d", resp.StatusCode)
		}
		ids = append(ids, b.String())
	}
	srv.Close()
	h.Close(context.Background())
	s.Close()

	s2 := open(t, path)
	h2, srv2 := start(s2)
	defer func() { srv2.Close(); h2.Close(context.Background()) }()
	if n := h2.Stats().HistoryLen; n != 5 {
		t.Fatalf("the restarted hub holds %d updates, want 5", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv2.URL+"/.well-known/mercure?topic="+url.QueryEscape("https://t.test/a"), nil)
	req.Header.Set("Last-Event-ID", ids[1])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	var got []string
	for len(got) < 3 && sc.Scan() {
		if id, ok := strings.CutPrefix(sc.Text(), "id: "); ok {
			got = append(got, id)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(ids[2:]) {
		t.Fatalf("resumed after a restart with %v, want %v", got, ids[2:])
	}
}

// Every update a stream published is stored once the hub and the store close cleanly: a restart has them all.
func TestStreamStored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	s := open(t, path)
	h, err := gossiper.New(gossiper.Config{PublisherKey: auth.KeyConfig{Key: secret}, Protocol: gossiper.ProtocolBoth, HistoryStore: s, Heartbeat: -1})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	c, err := client.New(client.Options{URL: srv.URL + "/.well-known/mercure", Token: token(t), Transport: client.Stream})
	if err != nil {
		t.Fatal(err)
	}
	const n = 2000
	var wg sync.WaitGroup
	var failed atomic.Int64
	wg.Add(n)
	for i := range n {
		if err := c.PublishAsync(context.Background(), client.Update{Topics: []string{"https://t.test/s"}, Data: fmt.Sprint(i)}, func(_ string, err error) {
			if err != nil {
				failed.Add(1)
			}
			wg.Done()
		}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d publishes failed", failed.Load())
	}
	c.Close()
	srv.Close()
	h.Close(context.Background())
	s.Close()
	if got := len(loaded(t, open(t, path), "")); got != n {
		t.Fatalf("%d updates stored, want %d", got, n)
	}
}

func TestSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	s, err := Open(path, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode: %v %v, want 0600", fi.Mode().Perm(), err)
	}
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("user_version %d %v, want %d", v, err, schemaVersion)
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path, 0, nil); err == nil {
		s.Close()
		t.Fatal("a file of a later schema was opened")
	}
}
