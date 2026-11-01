package gossiper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
)

// base is a fixed instant the history tests count from.
var base = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// at returns the stamp of base plus d.
func at(d time.Duration) hlc.Timestamp { return hlc.FromTime(base.Add(d)) }

// upd returns an update with the given origin, id and stamp, encoded as the hub would.
func upd(origin, id string, stamp hlc.Timestamp) *Update {
	u := &Update{ID: id, Origin: origin, Stamp: uint64(stamp), Topics: []string{"t"}, Data: "x"}
	u.encoded = u.encode()
	return u
}

func ids(us []*Update) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.ID
	}
	return out
}

func sameIDs(t *testing.T, got []*Update, want ...string) {
	t.Helper()
	g := ids(got)
	if fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

func newTestHistory(count int, bytes int64, age, window time.Duration) (*history, *time.Time) {
	h := newHistory(count, bytes, age, window)
	clock := base
	h.now = func() time.Time { return clock }
	return h, &clock
}

func TestHistoryOrdering(t *testing.T) {
	tests := []struct {
		name  string
		order []int // stamps in the order they are added
		want  []string
	}{
		{"in order", []int{1, 2, 3, 4}, []string{"u1", "u2", "u3", "u4"}},
		{"reversed", []int{4, 3, 2, 1}, []string{"u1", "u2", "u3", "u4"}},
		{"interleaved", []int{3, 1, 4, 2}, []string{"u1", "u2", "u3", "u4"}},
		{"late head", []int{2, 3, 4, 1}, []string{"u1", "u2", "u3", "u4"}},
		{"middle", []int{1, 2, 4, 3}, []string{"u1", "u2", "u3", "u4"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newTestHistory(100, 0, 0, time.Second)
			for _, n := range tc.order {
				if !h.add(upd("a", fmt.Sprintf("u%d", n), at(time.Duration(n)*time.Second)), at(time.Hour)) {
					t.Fatalf("add u%d refused", n)
				}
			}
			got, ok := h.since(earliest)
			if !ok {
				t.Fatal("earliest not found")
			}
			sameIDs(t, got, tc.want...)
			if h.len() != 4 || h.last() != "u4" {
				t.Fatalf("len %d last %q", h.len(), h.last())
			}
		})
	}
}

func TestHistorySameStampOrdersByOrigin(t *testing.T) {
	h, _ := newTestHistory(100, 0, 0, time.Second)
	s := at(time.Second)
	h.add(upd("c", "from-c", s), s)
	h.add(upd("a", "from-a", s), s)
	h.add(upd("b", "from-b", s), s)
	got, _ := h.since(earliest)
	sameIDs(t, got, "from-a", "from-b", "from-c")
	// A cursor on the middle one: the ones ordered after it follow.
	got, ok := h.since("from-b")
	if !ok {
		t.Fatal("cursor not found")
	}
	sameIDs(t, got, "from-c")
}

func TestHistoryDuplicateRefused(t *testing.T) {
	h, _ := newTestHistory(100, 0, 0, time.Second)
	u := upd("a", "u", at(time.Second))
	if !h.add(u, at(time.Hour)) {
		t.Fatal("first add refused")
	}
	if h.add(upd("a", "other-id-same-publication", at(time.Second)), at(time.Hour)) {
		t.Fatal("same origin and stamp accepted twice")
	}
	if !h.add(upd("b", "u", at(time.Second)), at(time.Hour)) {
		t.Fatal("same stamp from another origin refused")
	}
	if h.len() != 2 {
		t.Fatalf("len %d, want 2", h.len())
	}
}

func TestHistoryTrimByCount(t *testing.T) {
	h, _ := newTestHistory(3, 0, 0, time.Second)
	for i := 1; i <= 5; i++ {
		h.add(upd("a", fmt.Sprintf("u%d", i), at(time.Duration(i)*time.Second)), at(time.Hour))
	}
	if h.len() != 3 {
		t.Fatalf("len %d, want 3", h.len())
	}
	got, _ := h.since(earliest)
	sameIDs(t, got, "u3", "u4", "u5")
	if _, ok := h.since("u2"); ok {
		t.Fatal("a trimmed update is still found")
	}
	if _, ok := h.since("u3"); !ok {
		t.Fatal("a kept update is not found")
	}
	if len(h.byID) != 3 {
		t.Fatalf("byID holds %d ids", len(h.byID))
	}
}

func TestHistoryTrimByBytes(t *testing.T) {
	one := upd("a", "u1", at(time.Second)).size()
	h, _ := newTestHistory(1000, int64(one)*5/2, 0, time.Second) // room for two
	for i := 1; i <= 5; i++ {
		h.add(upd("a", fmt.Sprintf("u%d", i), at(time.Duration(i)*time.Second)), at(time.Hour))
	}
	got, _ := h.since(earliest)
	sameIDs(t, got, "u4", "u5")
	if h.bytes != int64(2*one) {
		t.Fatalf("bytes %d, want %d", h.bytes, 2*one)
	}
	// An update bigger than the whole bound is not kept at all.
	big := upd("a", "big", at(10*time.Second))
	big.Data = string(make([]byte, 10*one))
	big.encoded = big.encode()
	h.add(big, at(time.Hour))
	if h.len() != 0 || h.bytes != 0 {
		t.Fatalf("history holds %d updates, %d bytes after an oversized one", h.len(), h.bytes)
	}
}

func TestHistoryTrimByAge(t *testing.T) {
	h, now := newTestHistory(100, 0, 10*time.Second, time.Second)
	add := func(id string, s time.Duration) { h.add(upd("a", id, at(s)), at(time.Hour)) }
	add("u1", time.Second)
	*now = base.Add(5 * time.Second)
	add("u2", 2*time.Second)
	*now = base.Add(12 * time.Second) // u1 (applied at +0) is over the age, u2 (+5) is not
	add("u3", 3*time.Second)
	got, _ := h.since(earliest)
	sameIDs(t, got, "u2", "u3")
	// A quiet hub: expire drops what has aged, with no new update.
	*now = base.Add(20 * time.Second)
	h.expire()
	got, _ = h.since(earliest)
	sameIDs(t, got, "u3")
	*now = base.Add(40 * time.Second)
	h.expire()
	if h.len() != 0 || h.last() != "" || len(h.byID) != 0 {
		t.Fatalf("history not empty: %d %q %d", h.len(), h.last(), len(h.byID))
	}
}

// A node that was busy and goes quiet gives back the history's memory and the publications it remembers, once they
// are older than the age bound; a duplicate is still refused until then.
func TestHistoryQuietNodeLetsGo(t *testing.T) {
	h, now := newTestHistory(100000, 0, 10*time.Second, time.Second)
	for i := range 5000 {
		h.add(upd("a", fmt.Sprintf("u%d", i), at(time.Duration(i+1)*time.Millisecond)), at(time.Hour))
	}
	*now = base.Add(5 * time.Second)
	h.expire()
	if h.len() != 5000 || h.add(upd("a", "again", at(time.Millisecond)), at(time.Hour)) {
		t.Fatal("expired too early, or a duplicate was taken")
	}
	*now = base.Add(11 * time.Second) // everything was published at +0
	h.expire()
	if h.len() != 0 || h.entries != nil || len(h.byID) != 0 || h.seenCur != nil || h.seenOld != nil {
		t.Fatalf("after the age: %d entries (slice %v), %d IDs, seen %v", h.len(), h.entries != nil, len(h.byID), h.seenCur != nil)
	}
	// It works on as before.
	if !h.add(upd("a", "new", at(time.Hour)), at(2*time.Hour)) || h.last() != "new" {
		t.Fatal("history unusable after letting go")
	}
}

func TestHistoryExpireWithoutAgeBound(t *testing.T) {
	h, now := newTestHistory(100, 0, 0, time.Second)
	h.add(upd("a", "u1", at(time.Second)), at(time.Hour))
	*now = base.Add(1000 * time.Hour)
	h.expire()
	if h.len() != 1 {
		t.Fatal("expire dropped an update with no age bound")
	}
}

func TestHistoryReclaimsDroppedPrefix(t *testing.T) {
	h, _ := newTestHistory(10, 0, 0, time.Second)
	const n = 5000
	for i := 1; i <= n; i++ {
		h.add(upd("a", fmt.Sprintf("u%d", i), at(time.Duration(i)*time.Millisecond)), at(time.Hour))
	}
	if h.len() != 10 {
		t.Fatalf("len %d, want 10", h.len())
	}
	if cap(h.entries) > 2048 {
		t.Fatalf("dropped prefix never reclaimed: capacity %d", cap(h.entries))
	}
	got, _ := h.since(earliest)
	if len(got) != 10 || got[0].ID != fmt.Sprintf("u%d", n-9) || got[9].ID != fmt.Sprintf("u%d", n) {
		t.Fatalf("wrong updates kept: %v", ids(got))
	}
}

func TestHistoryDisabled(t *testing.T) {
	h, _ := newTestHistory(0, 0, 0, time.Second)
	u := upd("a", "u1", at(time.Second))
	if !h.add(u, at(time.Hour)) {
		t.Fatal("first add refused")
	}
	if h.add(upd("a", "u1", at(time.Second)), at(time.Hour)) {
		t.Fatal("a disabled history must still deduplicate")
	}
	if h.len() != 0 || h.last() != "" {
		t.Fatal("a disabled history kept an update")
	}
	if got, ok := h.since("u1"); ok || got != nil {
		t.Fatal("cursor found in a disabled history")
	}
	if got, ok := h.since(earliest); !ok || len(got) != 0 {
		t.Fatalf("earliest on a disabled history: %v %v", got, ok)
	}
}

// TestHistoryByIDKeepsEarliest: a reused ID names the earliest update holding it, and a cursor at it is followed
// by every later update, the later ones with the same ID included.
func TestHistoryByIDKeepsEarliest(t *testing.T) {
	h, _ := newTestHistory(100, 0, 0, time.Second)
	h.add(upd("a", "dup", at(2*time.Second)), at(time.Hour))
	h.add(upd("a", "x", at(3*time.Second)), at(time.Hour))
	h.add(upd("a", "dup", at(4*time.Second)), at(time.Hour))
	got, ok := h.since("dup")
	if !ok {
		t.Fatal("dup not found")
	}
	sameIDs(t, got, "x", "dup")                              // the cursor is the update at +2s
	h.add(upd("a", "dup", at(1*time.Second)), at(time.Hour)) // an older one arriving late becomes the earliest
	got, _ = h.since("dup")
	sameIDs(t, got, "dup", "x", "dup")
}

func TestHistoryDroppedDuplicateIDKeepsNewer(t *testing.T) {
	h, _ := newTestHistory(2, 0, 0, time.Second)
	h.add(upd("a", "dup", at(1*time.Second)), at(time.Hour))
	h.add(upd("a", "dup", at(2*time.Second)), at(time.Hour))
	h.add(upd("a", "other", at(3*time.Second)), at(time.Hour)) // drops the first dup
	if _, ok := h.since("dup"); !ok {
		t.Fatal("the newer update of the id was forgotten when the older was dropped")
	}
	h.add(upd("a", "other2", at(4*time.Second)), at(time.Hour)) // drops the second dup
	if _, ok := h.since("dup"); ok {
		t.Fatal("id still found after both updates were dropped")
	}
}

// TestHistorySeenAcrossGenerations: the seen set remembers a publication for between one and two generations.
func TestHistorySeenAcrossGenerations(t *testing.T) {
	h, _ := newTestHistory(0, 0, 0, time.Second) // disabled: only the seen set
	first := key{"o", 0}
	h.mu.Lock()
	if h.seen(first) {
		t.Fatal("fresh key reported seen")
	}
	fill := func(from, n uint64) {
		for i := from; i < from+n; i++ {
			h.seen(key{"o", i})
		}
	}
	fill(1, minSeenGeneration-1) // the current generation is exactly full
	if !h.seen(first) {
		t.Fatal("key forgotten within its generation")
	}
	fill(minSeenGeneration, 1) // rotates: the first generation is now the old one
	if !h.seen(first) {
		t.Fatal("key forgotten while its generation is the old one")
	}
	if !h.seen(key{"o", minSeenGeneration - 1}) {
		t.Fatal("last key of the old generation forgotten")
	}
	fill(minSeenGeneration+1, minSeenGeneration) // fills the second generation and rotates again
	if h.seen(first) {
		t.Fatal("key remembered after two rotations")
	}
	if !h.seen(key{"o", minSeenGeneration + 1}) {
		t.Fatal("a key of the previous generation was forgotten")
	}
	h.mu.Unlock()
}

func TestHistoryLast(t *testing.T) {
	h, _ := newTestHistory(100, 0, 0, time.Second)
	if h.last() != "" {
		t.Fatal("last of an empty history")
	}
	h.add(upd("a", "u2", at(2*time.Second)), at(time.Hour))
	h.add(upd("a", "u1", at(1*time.Second)), at(time.Hour))
	if h.last() != "u2" {
		t.Fatalf("last %q, want the latest stamped", h.last())
	}
}

func TestHistorySinceBasics(t *testing.T) {
	h, _ := newTestHistory(100, 0, 0, 5*time.Second)
	if got, ok := h.since(earliest); !ok || len(got) != 0 {
		t.Fatalf("earliest of nothing: %v %v", got, ok)
	}
	for i := 1; i <= 4; i++ {
		h.add(upd("a", fmt.Sprintf("u%d", i), at(time.Duration(i)*time.Second)), at(time.Duration(i)*time.Second+time.Microsecond))
	}
	for cursor, want := range map[string][]string{
		earliest: {"u1", "u2", "u3", "u4"},
		"u1":     {"u2", "u3", "u4"},
		"u3":     {"u4"},
		"u4":     {},
	} {
		got, ok := h.since(cursor)
		if !ok {
			t.Fatalf("cursor %s not found", cursor)
		}
		sameIDs(t, got, want...)
	}
	if got, ok := h.since("nope"); ok || got != nil {
		t.Fatalf("unknown cursor: %v %v", got, ok)
	}
}

// TestHistorySinceLateArrival: updates stamped up to a window before the cursor that were applied after the cursor
// was stamped are sent again; others are not.
func TestHistorySinceLateArrival(t *testing.T) {
	const window = 5 * time.Second
	h, _ := newTestHistory(100, 0, 0, window)
	cursor := upd("a", "cursor", at(10*time.Second))
	cursorRecv := at(10*time.Second + time.Millisecond)

	h.add(upd("b", "too-old-late", at(3*time.Second)), at(11*time.Second))   // late, but before the window
	h.add(upd("b", "on-window-edge", at(5*time.Second)), at(11*time.Second)) // exactly a window before: excluded
	h.add(upd("b", "late-1", at(6*time.Second)), at(11*time.Second))         // in the window, applied after the cursor
	h.add(upd("b", "seen-before", at(7*time.Second)), at(9*time.Second))     // in the window, applied before the cursor stamp
	h.add(upd("b", "late-2", at(8*time.Second)), at(12*time.Second))         // in the window, applied after
	h.add(upd("b", "seen-at-stamp", at(9*time.Second)), at(10*time.Second))  // applied exactly at the cursor's stamp: not after
	h.add(cursor, cursorRecv)
	h.add(upd("b", "after-1", at(10*time.Second+time.Microsecond)), at(13*time.Second))
	h.add(upd("a", "after-2", at(20*time.Second)), at(20*time.Second))

	got, ok := h.since("cursor")
	if !ok {
		t.Fatal("cursor not found")
	}
	sameIDs(t, got, "late-1", "late-2", "after-1", "after-2")
}

func TestHistorySinceLateArrivalOutOfOrderAdds(t *testing.T) {
	h, _ := newTestHistory(100, 0, 0, 5*time.Second)
	h.add(upd("a", "cursor", at(10*time.Second)), at(10*time.Second+time.Millisecond))
	// A remote update stamped before the cursor reaches the node after it: placed before the cursor in stamp order,
	// and replayed after it.
	h.add(upd("r", "late", at(9*time.Second)), at(11*time.Second))
	all, _ := h.since(earliest)
	sameIDs(t, all, "late", "cursor")
	got, _ := h.since("cursor")
	sameIDs(t, got, "late")
}

func TestHistorySinceWindowLargerThanStamp(t *testing.T) {
	// A window longer than the time since the clock's epoch must not underflow.
	h, _ := newTestHistory(100, 0, 0, time.Duration(1<<62))
	h.add(upd("r", "early", 5), 100)
	h.add(upd("a", "cursor", 10), 11)
	h.add(upd("a", "next", 12), 13)
	got, ok := h.since("cursor")
	if !ok {
		t.Fatal("cursor not found")
	}
	sameIDs(t, got, "early", "next")
}

// held reports whether the history holds an update with the ID.
func (h *history) held(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byID[id] != nil
}

// add records u, applied at recv; false when the publication is already recorded.
func (h *history) add(u *Update, recv hlc.Timestamp) bool { return h.addAt(u, recv, time.Time{}) }

// since is replay keeping every update.
func (h *history) since(cursor string) ([]*Update, bool) {
	out, _, found := h.replay(cursor, nil)
	return out, found
}

// TestSeenSetCoversHistory: a publication delivered again is recognised as long as the history could hold it,
// however large the history.
func TestSeenSetCoversHistory(t *testing.T) {
	h := newHistory(200000, 0, 0, time.Second)
	if h.seenGen != 200000 {
		t.Fatalf("seen generation %d", h.seenGen)
	}
	if newHistory(10, 0, 0, time.Second).seenGen != minSeenGeneration {
		t.Fatal("small histories keep the minimum generation")
	}
}

// TestRestoreIsNotALateArrival: updates restored after a restart count as received when they were published, so a
// cursor after them is not sent them again, while updates applied now within the window still are.
func TestRestoreIsNotALateArrival(t *testing.T) {
	h := newHub(t, Config{NodeID: "n", ReplayWindow: time.Hour})
	base := hlc.Now()
	mk := func(id string, d time.Duration) *Update {
		return &Update{ID: id, Topics: []string{"t"}, Stamp: uint64(base + hlc.Timestamp(d.Microseconds()<<hlc.CounterBits)), Origin: "other"}
	}
	h.Restore(mk("r1", 1*time.Millisecond))
	h.Restore(mk("cursor", 2*time.Millisecond))
	h.Restore(mk("r1", 1*time.Millisecond)) // the same publication twice: one entry
	got, ok := h.hist.since("cursor")
	if !ok || len(got) != 0 {
		t.Fatalf("restored updates before the cursor were sent again: %v", ids(got))
	}
	h.Apply(mk("late", 1500*time.Microsecond)) // stamped before the cursor, applied now: a late arrival
	got, _ = h.hist.since("cursor")
	if len(got) != 1 || got[0].ID != "late" {
		t.Fatalf("late arrival not replayed: %v", ids(got))
	}
	if s := h.Stats(); s.Applied != 3 || s.Duplicates != 1 {
		t.Fatalf("stats %+v", s)
	}
}

// A restored update ages from when it was published, not from when it was restored: a node that restarts does not
// revive updates its history age had dropped.
func TestRestoredUpdateAgesFromItsStamp(t *testing.T) {
	h, err := New(Config{Anonymous: true, HistoryAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	old := hlc.FromTime(time.Now().Add(-2 * time.Hour))
	recent := hlc.FromTime(time.Now().Add(-time.Minute))
	h.Restore(&Update{ID: "old", Topics: []string{"t"}, Stamp: uint64(old), Origin: "o"})
	h.Restore(&Update{ID: "recent", Topics: []string{"t"}, Stamp: uint64(recent), Origin: "o"})
	if h.hist.held("old") || !h.hist.held("recent") {
		t.Errorf("held old %v, recent %v; want only the recent one", h.hist.held("old"), h.hist.held("recent"))
	}
}
