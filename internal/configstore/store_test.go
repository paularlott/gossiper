package configstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossiper/internal/configstore"
)

// openSingle opens a store without a cluster at path, closed when the test ends.
func openSingle(t testing.TB, path string, ch *changes) *configstore.Store {
	t.Helper()
	o := configstore.Options{Path: path}
	if ch != nil {
		o.OnChange = ch.add
	}
	s, err := configstore.Open(o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func keysOf(recs []configstore.Record) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r.Key)
	}
	return out
}

func TestPutGetListDelete(t *testing.T) {
	s := openSingle(t, filepath.Join(t.TempDir(), "sub", "dir", "c.db"), nil) // the directory is created
	put(t, s, "tenant/a", "A", "tenant/b", "B", "tenant/a/user/1", "u1", "tenant/a/user/2", "u2", "other", "o")

	if v, ok := value(s, "tenant/a"); !ok || v != "A" {
		t.Fatalf("Get tenant/a = %q, %v", v, ok)
	}
	if _, ok := s.Get("missing"); ok {
		t.Fatal("Get of a missing key found a record")
	}
	r, _ := s.Get("tenant/b")
	if r.Version == 0 || r.Origin == "" || r.Deleted {
		t.Fatalf("record has no version or origin: %+v", r)
	}
	if got, want := keysOf(s.List("tenant/")), []string{"tenant/a", "tenant/a/user/1", "tenant/a/user/2", "tenant/b"}; !slices.Equal(got, want) {
		t.Fatalf("List tenant/ = %v, want %v", got, want)
	}
	if got := len(s.List("")); got != 5 {
		t.Fatalf("List all = %d records, want 5", got)
	}
	if got := s.List("nothing/"); len(got) != 0 {
		t.Fatalf("List nothing/ = %v", keysOf(got))
	}

	// The value returned is the caller's to modify.
	r, _ = s.Get("tenant/a")
	r.Value[0] = 'X'
	if v, _ := value(s, "tenant/a"); v != "A" {
		t.Fatalf("modifying a returned value changed the store: %q", v)
	}

	del(t, s, "tenant/b")
	if _, ok := s.Get("tenant/b"); ok {
		t.Fatal("deleted key still found")
	}
	if err := s.Update(context.Background(), func(tx *configstore.Tx) error {
		deletePrefix(tx, "tenant/a/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := keysOf(s.List("")), []string{"other", "tenant/a"}; !slices.Equal(got, want) {
		t.Fatalf("after deletes List = %v, want %v", got, want)
	}
	st := s.Stats()
	if st.Records != 2 || st.Tombstones != 3 {
		t.Fatalf("stats = %+v, want 2 records and 3 tombstones", st)
	}

	// A deleted key can be written again, with a newer version than its tombstone.
	tomb := s.All()[slices.IndexFunc(s.All(), func(r configstore.Record) bool { return r.Key == "tenant/b" })]
	put(t, s, "tenant/b", "B2")
	r, ok := s.Get("tenant/b")
	if !ok || string(r.Value) != "B2" || r.Version <= tomb.Version {
		t.Fatalf("rewritten key = %+v, %v (tombstone v%d)", r, ok, tomb.Version)
	}

	// An empty value is a live record with an empty, non-nil value.
	put(t, s, "empty", "")
	if r, ok := s.Get("empty"); !ok || r.Value == nil || len(r.Value) != 0 {
		t.Fatalf("empty value = %+v, %v", r, ok)
	}
}

func TestTxSeesItsOwnWrites(t *testing.T) {
	s := openSingle(t, filepath.Join(t.TempDir(), "c.db"), nil)
	put(t, s, "p/1", "one", "p/2", "two", "q/1", "q")
	err := s.Update(context.Background(), func(tx *configstore.Tx) error {
		tx.Put("p/3", []byte("three"))
		tx.Delete("p/1")
		if _, ok := tx.Get("p/1"); ok {
			return errors.New("tx sees a key it deleted")
		}
		if r, ok := tx.Get("p/3"); !ok || string(r.Value) != "three" {
			return errors.New("tx does not see a key it put")
		}
		if got, want := keysOf(tx.List("p/")), []string{"p/2", "p/3"}; !slices.Equal(got, want) {
			return fmt.Errorf("tx List = %v, want %v", got, want)
		}
		// Outside the transaction nothing has changed yet.
		if _, ok := s.Get("p/3"); ok {
			return errors.New("an uncommitted write is visible")
		}
		tx.Put("p/4", []byte("four"))
		deletePrefix(tx, "p/") // deletes stored keys and the transaction's own puts
		if got := tx.List("p/"); len(got) != 0 {
			return fmt.Errorf("after DeletePrefix tx List = %v", keysOf(got))
		}
		tx.Put("p/2", []byte("again"))
		tx.Delete("never-existed") // no tombstone for a key that has no record
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := keysOf(s.List("")), []string{"p/2", "q/1"}; !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	if v, _ := value(s, "p/2"); v != "again" {
		t.Fatalf("p/2 = %q", v)
	}
	var keys []string
	for _, r := range s.All() {
		keys = append(keys, r.Key)
	}
	// p/3 and p/4 were put and deleted in the same transaction: nothing of them is stored.
	if want := []string{"p/1", "p/2", "q/1"}; !slices.Equal(keys, want) {
		t.Fatalf("records with tombstones = %v, want %v", keys, want)
	}
}

func TestUpdateIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	ch := &changes{}
	s := openSingle(t, path, ch)
	put(t, s, "keep", "1")
	waitFor(t, waitMax, "OnChange for keep", func() bool { return ch.has("keep") })
	before := dump(s)

	boom := errors.New("boom")
	err := s.Update(context.Background(), func(tx *configstore.Tx) error {
		tx.Put("a", []byte("x"))
		tx.Delete("keep")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update = %v, want the function's error", err)
	}
	for _, c := range []struct {
		name string
		fn   func(tx *configstore.Tx)
		want error
	}{
		{"empty key", func(tx *configstore.Tx) { tx.Put("", nil) }, configstore.ErrInvalidKey},
		{"long key", func(tx *configstore.Tx) { tx.Put(strings.Repeat("k", configstore.MaxKeyBytes+1), nil) }, configstore.ErrInvalidKey},
		{"bad utf8", func(tx *configstore.Tx) { tx.Put("\xff", nil) }, configstore.ErrInvalidKey},
		{"nul", func(tx *configstore.Tx) { tx.Put("a\x00b", nil) }, configstore.ErrInvalidKey},
		{"delete bad", func(tx *configstore.Tx) { tx.Delete("") }, configstore.ErrInvalidKey},
		{"big value", func(tx *configstore.Tx) { tx.Put("big", make([]byte, configstore.MaxValueBytes+1)) }, configstore.ErrValueTooLarge},
	} {
		err := s.Update(context.Background(), func(tx *configstore.Tx) error {
			tx.Put("a", []byte("x"))
			tx.Delete("keep")
			c.fn(tx)
			return nil
		})
		if !errors.Is(err, c.want) {
			t.Fatalf("%s: Update = %v, want %v", c.name, err, c.want)
		}
	}
	if got := dump(s); got != before {
		t.Fatalf("a failed Update changed the store:\n%s\nwant\n%s", got, before)
	}

	// Nor did it reach the database.
	s.Close()
	s2 := openSingle(t, path, nil)
	if got := dump(s2); got != before {
		t.Fatalf("after reopening:\n%s\nwant\n%s", got, before)
	}

	// The largest key and value are accepted.
	big := strings.Repeat("k", configstore.MaxKeyBytes)
	if err := s2.Update(context.Background(), func(tx *configstore.Tx) error {
		tx.Put(big, make([]byte, configstore.MaxValueBytes))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r, ok := s2.Get(big); !ok || len(r.Value) != configstore.MaxValueBytes {
		t.Fatal("largest record not stored")
	}
	time.Sleep(50 * time.Millisecond)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if slices.ContainsFunc(ch.calls, func(keys []string) bool { return slices.Contains(keys, "a") }) {
		t.Fatal("OnChange was called for a failed Update")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s := openSingle(t, path, nil)
	put(t, s, "a", "1", "b", "2", "c", "3")
	del(t, s, "b")
	origin := s.NodeID()
	before := dump(s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil { // a second Close does nothing
		t.Fatal(err)
	}
	if err := s.Update(context.Background(), func(tx *configstore.Tx) error { return nil }); !errors.Is(err, configstore.ErrClosed) {
		t.Fatalf("Update after Close = %v, want ErrClosed", err)
	}
	if v, ok := value(s, "a"); !ok || v != "1" { // reads go on from memory
		t.Fatalf("Get after Close = %q, %v", v, ok)
	}

	s2 := openSingle(t, path, nil)
	if got := dump(s2); got != before {
		t.Fatalf("reopened store:\n%s\nwant\n%s", got, before)
	}
	if s2.NodeID() != origin {
		t.Fatalf("origin changed across restarts: %s, was %s", s2.NodeID(), origin)
	}
	if st := s2.Stats(); st.Records != 2 || st.Tombstones != 1 {
		t.Fatalf("stats = %+v", st)
	}
	// The clock starts past every stored version: a new write wins over the stored records.
	var maxV uint64
	for _, r := range s2.All() {
		maxV = max(maxV, r.Version)
	}
	put(t, s2, "a", "new")
	if r, _ := s2.Get("a"); r.Version <= maxV || r.Origin != origin {
		t.Fatalf("new write v%d %s, stored max v%d", r.Version, r.Origin, maxV)
	}
	// So does a write after records from a peer far ahead in time were merged and the store reopened.
	future := maxV + uint64(time.Hour.Microseconds())<<10
	if n, err := s2.Merge([]configstore.Record{{Key: "z", Value: []byte("peer"), Version: future, Origin: "peer"}}); err != nil || n != 1 {
		t.Fatalf("merge = %d, %v", n, err)
	}
	s2.Close()
	s3 := openSingle(t, path, nil)
	put(t, s3, "z", "mine")
	if r, _ := s3.Get("z"); r.Version <= future || string(r.Value) != "mine" {
		t.Fatalf("write after reopening: %+v, want a version over %d", r, future)
	}
}

func TestMergeRule(t *testing.T) {
	s := openSingle(t, filepath.Join(t.TempDir(), "c.db"), nil)
	rec := func(v uint64, origin, val string, deleted bool) configstore.Record {
		r := configstore.Record{Key: "k", Version: v, Origin: origin, Deleted: deleted}
		if !deleted {
			r.Value = []byte(val)
		}
		return r
	}
	steps := []struct {
		r       configstore.Record
		applied int
		want    string // value after; "" for none
	}{
		{rec(100, "b", "b100", false), 1, "b100"},
		{rec(100, "b", "b100", false), 0, "b100"}, // the same record again
		{rec(99, "z", "z99", false), 0, "b100"},   // older
		{rec(100, "a", "a100", false), 0, "b100"}, // same version, smaller origin
		{rec(100, "c", "c100", false), 1, "c100"}, // same version, greater origin
		{rec(200, "a", "", true), 1, ""},          // a newer delete
		{rec(150, "z", "z150", false), 0, ""},     // a put older than the tombstone arrives later
		{rec(300, "a", "a300", false), 1, "a300"}, // a newer put revives the key
		{rec(300, "a", "a300", false), 0, "a300"},
	}
	for i, st := range steps {
		n, err := s.Merge([]configstore.Record{st.r})
		if err != nil || n != st.applied {
			t.Fatalf("step %d: merge = %d, %v; want %d", i, n, err, st.applied)
		}
		if v, _ := value(s, "k"); v != st.want {
			t.Fatalf("step %d: value %q, want %q", i, v, st.want)
		}
	}
	// In one message the newest record of a key wins, whatever the order.
	n, err := s.Merge([]configstore.Record{rec(500, "a", "a500", false), rec(400, "a", "a400", false)})
	if err != nil || n != 1 {
		t.Fatalf("merge = %d, %v", n, err)
	}
	if v, _ := value(s, "k"); v != "a500" {
		t.Fatalf("value %q, want a500", v)
	}
	// A local write wins over every record merged.
	put(t, s, "k", "local")
	if r, _ := s.Get("k"); r.Version <= 500 || string(r.Value) != "local" {
		t.Fatalf("local write %+v", r)
	}
}

func TestOnChange(t *testing.T) {
	ch := &changes{}
	s := openSingle(t, filepath.Join(t.TempDir(), "c.db"), ch)
	put(t, s, "a", "1", "b", "2")
	waitFor(t, waitMax, "OnChange for a and b", func() bool { return ch.has("a", "b") })
	del(t, s, "a")
	if _, err := s.Merge([]configstore.Record{{Key: "remote", Value: []byte("r"), Version: 1, Origin: "peer"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, waitMax, "OnChange for remote", func() bool { return ch.has("remote") })
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.seen["a"] != 2 || ch.seen["b"] != 1 {
		t.Fatalf("OnChange calls %v", ch.calls)
	}
	for _, keys := range ch.calls {
		if !slices.IsSorted(keys) || len(keys) == 0 {
			t.Fatalf("OnChange keys %v not sorted or empty", keys)
		}
	}
}

// OnChange may use the store: read it, and update it (which calls OnChange again later).
func TestOnChangeMayUseTheStore(t *testing.T) {
	var s *configstore.Store
	var mu sync.Mutex
	var seen []string
	done := make(chan struct{})
	s, err := configstore.Open(configstore.Options{
		Path: filepath.Join(t.TempDir(), "c.db"),
		OnChange: func(keys []string) {
			for _, k := range keys {
				r, _ := s.Get(k)
				mu.Lock()
				seen = append(seen, k+"="+string(r.Value))
				mu.Unlock()
				if k == "a" {
					if err := s.Update(context.Background(), func(tx *configstore.Tx) error {
						tx.Put("derived", []byte("from-a"))
						return nil
					}); err != nil {
						t.Error(err)
					}
				}
				if k == "derived" {
					close(done)
				}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	put(t, s, "a", "1")
	select {
	case <-done:
	case <-time.After(waitMax):
		t.Fatal("OnChange for derived never came")
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(seen, []string{"a=1", "derived=from-a"}) {
		t.Fatalf("seen %v", seen)
	}
}

// OnChange is never called concurrently, even with writes from many goroutines.
func TestOnChangeNotConcurrent(t *testing.T) {
	var running, overlaps, calls int32
	var mu sync.Mutex
	got := map[string]bool{}
	s, err := configstore.Open(configstore.Options{
		Path: filepath.Join(t.TempDir(), "c.db"),
		OnChange: func(keys []string) {
			mu.Lock()
			running++
			if running > 1 {
				overlaps++
			}
			calls++
			for _, k := range keys {
				got[k] = true
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			running--
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 20 {
				put(t, s, fmt.Sprintf("g%d/%d", g, i), "v")
			}
		})
	}
	wg.Wait()
	s.Close() // delivers what is pending before it returns
	mu.Lock()
	defer mu.Unlock()
	if overlaps != 0 {
		t.Fatalf("OnChange ran concurrently %d times", overlaps)
	}
	if len(got) != 160 {
		t.Fatalf("OnChange was given %d keys, want 160", len(got))
	}
}

// Many goroutines read and update one store at once; read-modify-writes are serialised.
func TestConcurrentUpdates(t *testing.T) {
	s := openSingle(t, filepath.Join(t.TempDir(), "c.db"), nil)
	concurrentCounter(t, []*configstore.Store{s})
}

// concurrentCounter has goroutines increment a counter in turn through every store, reading as they go, and checks
// that no increment was lost on the stores it went through.
func concurrentCounter(t *testing.T, stores []*configstore.Store) {
	t.Helper()
	const goroutines, per = 8, 25
	var wg sync.WaitGroup
	for g := range goroutines {
		s := stores[g%len(stores)]
		wg.Go(func() {
			for i := range per {
				err := s.Update(context.Background(), func(tx *configstore.Tx) error {
					n := 0
					if r, ok := tx.Get(fmt.Sprintf("counter/%d", g%len(stores))); ok {
						fmt.Sscan(string(r.Value), &n)
					}
					tx.Put(fmt.Sprintf("counter/%d", g%len(stores)), []byte(fmt.Sprint(n+1)))
					tx.Put(fmt.Sprintf("item/%d/%d", g, i), []byte("x"))
					return nil
				})
				if err != nil {
					t.Error(err)
					return
				}
				s.Get("counter/0")
				s.List("item/")
				s.Stats()
			}
		})
	}
	wg.Wait()
	for i, s := range stores {
		want := per * goroutines / len(stores)
		if v, _ := value(s, fmt.Sprintf("counter/%d", i)); v != fmt.Sprint(want) {
			t.Fatalf("counter/%d = %s, want %d", i, v, want)
		}
	}
}

// A new database is readable by its owner only: its records may hold secrets.
func TestNewDatabaseIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	path := filepath.Join(t.TempDir(), "sub", "c.db")
	s, err := configstore.Open(configstore.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Update(context.Background(), func(tx *configstore.Tx) error { tx.Put("k", []byte("v")); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if m := fi.Mode().Perm(); m&0o077 != 0 {
			t.Errorf("%s: mode %v", filepath.Base(p), m)
		}
	}
}

// deletePrefix deletes every key under prefix, the transaction's own puts included.
func deletePrefix(tx *configstore.Tx, prefix string) {
	for _, r := range tx.List(prefix) {
		tx.Delete(r.Key)
	}
}
