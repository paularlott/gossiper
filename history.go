package gossiper

import (
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/paularlott/gossip/hlc"
)

// key identifies one publication: the publishing node and its clock reading. A node never issues the same stamp
// twice, so a key never repeats, while a publisher's own IDs may.
type key struct {
	origin string
	stamp  uint64
}

type entry struct {
	u    *Update
	recv hlc.Timestamp // this node's clock when it applied the update (never below the update's stamp)
	at   time.Time     // when it was applied, for the age bound
	size int
}

// history is the node's record of recent updates, in stamp order, bounded by count, bytes and age. Updates usually
// arrive in stamp order; one that arrives late (published on another node, or by a concurrent publish on this one)
// is placed where its stamp belongs.
type history struct {
	mu       sync.RWMutex
	entries  []*entry // stamp order; entries[head:] are live
	head     int
	byID     map[string]*entry   // the earliest update of each ID
	reused   map[string][]*entry // the later updates of an ID used again, in stamp order
	seenCur  map[key]struct{}    // publications applied recently, for deduplication (two generations)
	seenOld  map[key]struct{}
	seenGen  int
	seenLast time.Time // when the last publication was added to seenCur
	used     bool      // updates were held since the slice and maps were last made afresh
	bytes    int64
	budget   *budget // shared with other hubs' histories, or nil
	maxCount int
	maxBytes int64
	maxAge   time.Duration
	window   time.Duration // the replay window: how late an update may arrive and still be replayed after a later one
	now      func() time.Time
}

func newHistory(maxCount int, maxBytes int64, maxAge, window time.Duration) *history {
	return &history{
		byID:     map[string]*entry{},
		reused:   map[string][]*entry{},
		seenGen:  max(maxCount, minSeenGeneration),
		maxCount: maxCount, maxBytes: maxBytes, maxAge: maxAge, window: window, now: time.Now,
	}
}

// addAt is add for an update applied at a given time (zero: now), for the age bound.
func (h *history) addAt(u *Update, recv hlc.Timestamp, at time.Time) bool {
	k := key{u.Origin, u.Stamp}
	e := &entry{u: u, recv: recv, size: u.size()}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen(k) {
		return false
	}
	if h.maxCount <= 0 && h.maxBytes <= 0 {
		return true // history disabled: only the seen set remembers it
	}
	if e.at = at; at.IsZero() {
		e.at = h.now()
	}
	h.insert(e)
	h.trim()
	return true
}

// insert places e where its stamp belongs. Called with mu held.
func (h *history) insert(e *entry) {
	h.used = true
	u := e.u
	live := h.entries[h.head:]
	if n := len(live); n == 0 || !after(live[n-1].u, u) { // in order, as nearly always
		h.entries = append(h.entries, e)
	} else {
		i := sort.Search(n, func(k int) bool { return after(live[k].u, u) })
		h.entries = slices.Insert(h.entries, h.head+i, e)
	}
	switch prev, ok := h.byID[u.ID]; {
	case !ok:
		h.byID[u.ID] = e
	case after(prev.u, u): // a reused ID names its earliest update
		h.byID[u.ID] = e
		h.reuse(prev)
	default:
		h.reuse(e)
	}
	h.account(int64(e.size))
}

// account adds n to the bytes held, here and in the budget. Called with mu held.
func (h *history) account(n int64) {
	h.bytes += n
	if h.budget != nil {
		h.budget.add(n)
	}
}

// share makes the history count what it holds against b (nil: against nothing from now on).
func (h *history) share(b *budget) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.budget != nil {
		h.budget.add(-h.bytes)
	}
	if h.budget = b; b != nil {
		b.add(h.bytes)
	}
}

// size returns the bytes the history holds.
func (h *history) size() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.bytes
}

// shed drops the oldest updates until the history holds at most target bytes, and returns how many bytes it freed.
func (h *history) shed(target int64) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	before := h.bytes
	for h.head < len(h.entries) && h.bytes > target {
		h.dropOldest()
	}
	h.compact()
	return before - h.bytes
}

// adopt records the updates o holds that h has not recorded, each as applied when o applied it: a hub that replaces
// another takes over its history, so a subscriber resuming on the new hub misses nothing.
func (h *history) adopt(o *history) {
	o.mu.RLock()
	live := slices.Clone(o.entries[o.head:])
	o.mu.RUnlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range live {
		if h.seen(key{e.u.Origin, e.u.Stamp}) || h.maxCount <= 0 && h.maxBytes <= 0 {
			continue
		}
		h.insert(&entry{u: e.u, recv: e.recv, at: e.at, size: e.size})
	}
	h.trim()
}

// minSeenGeneration is the fewest publications one generation of the seen set holds: the set remembers between
// one and two generations of the latest publications, and a generation is at least the history's size, so a
// publication delivered again is recognised for as long as the history could hold it.
const minSeenGeneration = 1 << 16

// seen reports whether k was recorded before, and records it. Called with mu held.
func (h *history) seen(k key) bool {
	if _, ok := h.seenCur[k]; ok {
		return true
	}
	if _, ok := h.seenOld[k]; ok {
		return true
	}
	if h.seenCur == nil || len(h.seenCur) >= h.seenGen {
		h.seenOld, h.seenCur = h.seenCur, make(map[key]struct{}, 1024)
	}
	h.seenCur[k] = struct{}{}
	h.seenLast = h.now()
	return false
}

// after reports whether a is ordered after b.
func after(a, b *Update) bool {
	if a.Stamp != b.Stamp {
		return a.Stamp > b.Stamp
	}
	return a.Origin > b.Origin
}

// trim drops the oldest entries over the bounds. Called with mu held.
func (h *history) trim() {
	cutoff := time.Time{}
	if h.maxAge > 0 {
		cutoff = h.now().Add(-h.maxAge)
	}
	for h.head < len(h.entries) {
		live := len(h.entries) - h.head
		e := h.entries[h.head]
		over := (h.maxCount > 0 && live > h.maxCount) || (h.maxBytes > 0 && h.bytes > h.maxBytes) ||
			(!cutoff.IsZero() && e.at.Before(cutoff))
		if !over {
			break
		}
		h.dropOldest()
	}
	h.compact()
}

// dropOldest drops the oldest entry. Called with mu held, on a history that has one.
func (h *history) dropOldest() {
	h.drop(h.entries[h.head])
	h.entries[h.head] = nil
	h.head++
}

// compact reclaims the dropped prefix of the entries once it is large. Called with mu held.
func (h *history) compact() {
	if h.head > 1024 && h.head > len(h.entries)/2 {
		h.entries = append(h.entries[:0:0], h.entries[h.head:]...)
		h.head = 0
	}
}

// reuse files e, held, among the later updates of its ID. Called with mu held.
func (h *history) reuse(e *entry) {
	l := h.reused[e.u.ID]
	i := sort.Search(len(l), func(k int) bool { return after(l[k].u, e.u) })
	h.reused[e.u.ID] = slices.Insert(l, i, e)
}

func (h *history) drop(e *entry) {
	id := e.u.ID
	l := h.reused[id]
	switch {
	case h.byID[id] != e: // one of the later updates of a reused ID
		l = slices.DeleteFunc(l, func(n *entry) bool { return n == e })
	case len(l) > 0: // the next update with the ID is now the earliest
		h.byID[id], l = l[0], l[1:]
	default:
		delete(h.byID, id)
	}
	if len(l) == 0 {
		delete(h.reused, id)
	} else if h.byID[id] != e {
		h.reused[id] = l
	}
	h.account(-int64(e.size))
}

// expire drops entries past the age bound; the hub calls it periodically so a quiet hub frees them too.
func (h *history) expire() {
	if h.maxAge <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.trim()
	// A node that was busy and is now quiet gives back what the busy spell left: the history's slice and maps, once
	// every update in them has aged out (maps do not shrink), and the publications it remembers, once the newest of
	// them is older than the history keeps updates.
	if h.head == len(h.entries) && h.used {
		h.entries, h.head, h.used = nil, 0, false
		h.byID, h.reused = map[string]*entry{}, map[string][]*entry{}
	}
	if h.seenCur != nil && h.now().Sub(h.seenLast) > h.maxAge {
		h.seenCur, h.seenOld = nil, nil
	}
}

// oldest returns the stamp and origin of the oldest update held, if any.
func (h *history) oldest() (uint64, string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.head == len(h.entries) {
		return 0, "", false
	}
	u := h.entries[h.head].u
	return u.Stamp, u.Origin, true
}

// page returns the updates held that sort after the one stamped stamp by origin, oldest first, about maxBytes of
// them (at least one), and whether more follow.
func (h *history) page(stamp uint64, origin string, maxBytes int) ([]*Update, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	live := h.entries[h.head:]
	ref := &Update{Stamp: stamp, Origin: origin}
	i, _ := slices.BinarySearchFunc(live, ref, func(e *entry, r *Update) int {
		if after(e.u, r) {
			return 1
		}
		return -1
	})
	var out []*Update
	size := 0
	for ; i < len(live); i++ {
		if len(out) > 0 && size+live[i].size > maxBytes {
			return out, true
		}
		out = append(out, live[i].u)
		size += live[i].size
	}
	return out, false
}

// last returns the ID of the latest update in the history, or "" when it is empty.
func (h *history) last() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.head == len(h.entries) {
		return ""
	}
	return h.entries[len(h.entries)-1].u.ID
}

// replay returns the updates a subscriber that last received the event with ID cursor has not seen and that keep
// accepts (all with nil), in stamp order, and whether the cursor was found; with cursor "earliest", everything held.
//
// That is every update ordered after the cursor's, and the late arrivals: updates ordered up to window before it
// that this node applied after the cursor's update was published. A subscriber that saw the cursor's update on
// another node may not have seen those, since they reached the hub after it; one that did gets them twice, which
// is better than never. Updates older than the window are never sent again.
//
// It also returns the cursor the updates follow: cursor itself, earliest when it is not held, or the event before a
// late arrival sent ahead of the cursor's successors (a client comparing the two then sees no loss where there was
// none).
func (h *history) replay(cursor string, keep func(*Update) bool) (out []*Update, at string, found bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	live := h.entries[h.head:]
	if cursor == earliest {
		for _, e := range live {
			if keep == nil || keep(e.u) {
				out = append(out, e.u)
			}
		}
		return out, earliest, true
	}
	c, ok := h.byID[cursor]
	if !ok {
		return nil, earliest, false
	}
	i, _ := slices.BinarySearchFunc(live, c, func(a, b *entry) int { return compare(a.u, b.u) })
	lo := hlc.Timestamp(c.u.Stamp)
	from := hlc.Timestamp(0)
	if w := uint64(h.window.Microseconds()) << hlc.CounterBits; uint64(lo) > w {
		from = lo - hlc.Timestamp(w)
	}
	first := -1 // the index of the earliest late arrival kept
	for j := i - 1; j >= 0 && hlc.Timestamp(live[j].u.Stamp) > from; j-- {
		if live[j].recv > lo && (keep == nil || keep(live[j].u)) {
			out = append(out, live[j].u)
			first = j
		}
	}
	slices.Reverse(out)
	for _, e := range live[i+1:] {
		if keep == nil || keep(e.u) {
			out = append(out, e.u)
		}
	}
	at = cursor
	switch {
	case first == 0:
		at = earliest
	case first > 0:
		at = live[first-1].u.ID
	}
	return out, at, true
}

// compare orders a and b as the history does: -1, 0 or 1.
func compare(a, b *Update) int {
	switch {
	case after(b, a):
		return -1
	case after(a, b):
		return 1
	}
	return 0
}

// len returns the number of updates held.
func (h *history) len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries) - h.head
}
