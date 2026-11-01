package gossiper

import (
	"math/rand/v2"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
)

var (
	uuidV7 = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	uuidV4 = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func TestNewEventIDFormat(t *testing.T) {
	clock := hlc.NewClock()
	for i := 0; i < 100; i++ {
		if id := newEventID(clock.Now()); !uuidV7.MatchString(id) {
			t.Fatalf("%q is not a UUIDv7 URN", id)
		}
	}
}

func TestNewEventIDCarriesStamp(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 123456000, time.UTC)
	ts := hlc.FromTime(at)
	id := newEventID(ts)
	// The first 48 bits are the Unix milliseconds of the stamp.
	hexTime := strings.ReplaceAll(strings.TrimPrefix(id, "urn:uuid:")[:13], "-", "")
	var ms uint64
	for _, c := range hexTime {
		ms = ms<<4 | uint64(strings.IndexRune("0123456789abcdef", c))
	}
	if want := uint64(ts.Time().UnixMilli()); ms != want {
		t.Fatalf("id milliseconds %d, want %d (%s)", ms, want, id)
	}
}

// TestNewEventIDSortsWithStamp: IDs sort as the stamps they are made from, across milliseconds, microseconds and
// the logical counter.
func TestNewEventIDSortsWithStamp(t *testing.T) {
	base := hlc.FromTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var stamps []hlc.Timestamp
	for _, us := range []uint64{0, 1, 2, 999, 1000, 1001, 1999, 2000, 123456, 999999, 1000000} {
		for _, ctr := range []uint64{0, 1, 2, 3, 255, 256, 257, 511, 512, 767, 768, 1023} {
			stamps = append(stamps, base+hlc.Timestamp(us<<hlc.CounterBits|ctr))
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	rng.Shuffle(len(stamps), func(i, j int) { stamps[i], stamps[j] = stamps[j], stamps[i] })
	sort.Slice(stamps, func(i, j int) bool { return stamps[i] < stamps[j] })
	prev := ""
	for i, ts := range stamps {
		id := newEventID(ts)
		if i > 0 && id <= prev {
			t.Fatalf("id of stamp %d (%s) does not sort after the id of stamp %d (%s)", ts, id, stamps[i-1], prev)
		}
		prev = id
	}
}

func TestNewEventIDMonotonicFromClock(t *testing.T) {
	clock := hlc.NewClock()
	prev := ""
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		id := newEventID(clock.Now())
		if id <= prev {
			t.Fatalf("id %d (%s) does not sort after %s", i, id, prev)
		}
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id], prev = true, id
	}
}

func TestNewEventIDRandomTailDiffers(t *testing.T) {
	ts := hlc.FromTime(time.Now())
	a, b := newEventID(ts), newEventID(ts)
	if a == b {
		t.Fatalf("same stamp gave the same id twice: %s", a)
	}
	if a[:23] != b[:23] {
		t.Fatalf("same stamp gave different time parts: %s %s", a, b)
	}
}

func TestNewSubscriberID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newSubscriberID()
		if !uuidV4.MatchString(id) {
			t.Fatalf("%q is not a UUIDv4 URN", id)
		}
		if seen[id] {
			t.Fatalf("duplicate subscriber id %s", id)
		}
		seen[id] = true
	}
}
