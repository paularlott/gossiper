package gossiper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// A publish may ask for copies (Update.Replicas, a Gossiper extension): it is answered once that many nodes, this one
// included, hold the update (and have stored it, on nodes with a HistoryStore). A publish that asks for copies is also
// idempotent by its ID: an update published again with the ID of one applied in the last idempotencyWindow is
// dropped on every node, and its publish answered as the first was, so a client may safely publish again an update
// whose answer it did not get.

// MaxReplicas is the most copies a publish may ask for.
const MaxReplicas = 64

// Errors of a publish that asks for copies.
var (
	// ErrTooFewNodes: fewer nodes than the copies asked for can take the update, and it was not published.
	ErrTooFewNodes = errors.New("too few nodes")
	// ErrNotReplicated: the update was published, but did not reach as many nodes as asked in time.
	ErrNotReplicated = errors.New("published, not on enough nodes")
	// ErrInvalidReplicas: the copies asked for are out of range.
	ErrInvalidReplicas = errors.New(`invalid "replicas"`)
)

// Replicator is a Transport that confirms that an update reached other nodes (the cluster transport).
type Replicator interface {
	// PublishCopies publishes u as Publish does, unless fewer than n nodes, this one included, can take it
	// (ErrTooFewNodes, wrapped). wait returns once n nodes hold u (stored, on nodes with a HistoryStore), or
	// ErrNotReplicated (wrapped) when its ctx ends first.
	PublishCopies(ctx context.Context, u *Update, n int) (wait func(context.Context) error, err error)
}

// copiesTimeout bounds how long a publish waits for its copies.
const copiesTimeout = 10 * time.Second

// publishCopies hands u, which asks for copies, to the transport.
func (h *Hub) publishCopies(ctx context.Context, u *Update) error {
	if u.Replicas == 1 {
		return h.transport.Publish(ctx, u)
	}
	r, ok := h.transport.(Replicator)
	if !ok {
		return fmt.Errorf("%w: 1 of %d", ErrTooFewNodes, u.Replicas)
	}
	wait, err := r.PublishCopies(ctx, u, u.Replicas)
	u.copied, u.copiesBy = wait, time.Now().Add(copiesTimeout)
	return err
}

// replicated waits until u, published on this node, has its copies (a no-op for one that asked for none), until
// copiesTimeout after it was published: a stream waiting for many in turn waits that long once, not for each.
func (h *Hub) replicated(ctx context.Context, u *Update) error {
	if u.copied == nil {
		return nil
	}
	ctx, cancel := context.WithDeadline(ctx, u.copiesBy)
	defer cancel()
	return u.copied(ctx)
}

// Idempotent updates are remembered by ID for idempotencyWindow, and up to idempotencyMax at a time (a busier hub
// remembers them for less): two generations of a set, the older dropped when the newer is full or old enough.
const (
	idempotencyWindow = 5 * time.Minute
	idempotencyMax    = 1 << 18
)

// idempotency remembers the IDs of the idempotent updates a hub applied.
type idempotency struct {
	mu       sync.Mutex
	cur, old map[string]struct{}
	since    time.Time // when cur started
}

// first records id and reports whether it is new.
func (s *idempotency) first(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch age := now.Sub(s.since); {
	case s.cur == nil || age >= idempotencyWindow: // both generations are older than the window
		s.old, s.cur, s.since = nil, map[string]struct{}{}, now
	case age >= idempotencyWindow/2 || len(s.cur) >= idempotencyMax/2:
		s.old, s.cur, s.since = s.cur, map[string]struct{}{}, now
	}
	if _, ok := s.cur[id]; ok {
		return false
	}
	if _, ok := s.old[id]; ok {
		return false
	}
	s.cur[id] = struct{}{}
	return true
}
