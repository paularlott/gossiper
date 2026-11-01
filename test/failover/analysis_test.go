//go:build failover

package failover

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// gap describes the updates a subscriber missed from one publisher.
type gap struct {
	missing        int
	firstSeq, last int
	from, to       time.Time // when the first and last missing message were sent
}

func (g gap) String() string {
	if g.missing == 0 {
		return "none"
	}
	return fmt.Sprintf("%d (seq %d..%d, sent over %v)", g.missing, g.firstSeq, g.last, g.to.Sub(g.from).Round(time.Millisecond))
}

// sseGap compares the Mercure updates acked with what the subscriber got.
func sseGap(s *sent, c *sseClient) gap {
	datas := c.datas()
	var g gap
	for _, seq := range s.seqs() {
		if datas[strconv.Itoa(seq)] {
			continue
		}
		s.mu.Lock()
		at := s.at[seq]
		s.mu.Unlock()
		if g.missing == 0 {
			g.firstSeq, g.from = seq, at
		}
		g.missing++
		g.last, g.to = seq, at
	}
	return g
}

// waitDelivered waits until the subscribers hold everything the publishers sent, except what the allowed gaps
// excuse, for at most d; it does not fail (the caller checks).
func settle(d time.Duration, done func() bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && !done() {
		time.Sleep(50 * time.Millisecond)
	}
}

// timings collects named durations for the test's log.
type timings struct {
	t     *testing.T
	names []string
	vals  map[string]time.Duration
}

func newTimings(t *testing.T) *timings { return &timings{t: t, vals: map[string]time.Duration{}} }

func (tm *timings) add(name string, d time.Duration) {
	if _, ok := tm.vals[name]; !ok {
		tm.names = append(tm.names, name)
	}
	tm.vals[name] = d
}

func (tm *timings) report() {
	tm.t.Helper()
	for _, n := range tm.names {
		tm.t.Logf("TIMING %-48s %8s", n, ms(tm.vals[n]))
	}
}

// firstSSEAfter returns when the Mercure subscriber c first received an update acked after t0; updates acked
// before t0 and delivered late do not count.
func firstSSEAfter(s *sent, c *sseClient, t0 time.Time) (time.Time, bool) {
	evs, _, _ := c.snapshot()
	seqs := map[string]time.Time{}
	for _, e := range evs {
		seqs[e.Data] = e.At
	}
	var best time.Time
	for _, seq := range s.seqs() {
		s.mu.Lock()
		at := s.at[seq]
		s.mu.Unlock()
		if at.Before(t0) {
			continue
		}
		if got, ok := seqs[strconv.Itoa(seq)]; ok && (best.IsZero() || got.Before(best)) {
			best = got
		}
	}
	return best, !best.IsZero()
}
