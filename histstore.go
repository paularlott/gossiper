package gossiper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/paularlott/gossip/hlc"
)

// HistoryStore keeps a node's history on disk, so that it survives a restart (Config.HistoryStore). The hub saves
// every update it records, published on this node or another, and deletes what its history drops; a publish on
// this node returns once its update is on disk. A store writes in batches: the updates saved while one batch is
// being written go in the next, so a busy hub pays for one write and one sync per batch, not per update.
//
// A store that cannot keep up (a burst, or a full or failing disk) is not Ready: publishes on the hub wait for it
// (storeWait), then are refused (503) rather than publish updates it cannot store. Updates from other nodes are
// still applied, and Save, which never blocks, leaves out what it cannot take.
//
// Hubs of several tenants may share one store; an update's Tenant names the hub it belongs to.
type HistoryStore interface {
	// Load calls fn with every stored update of the tenant ("" for a hub that is not a tenant's), in stamp order.
	Load(tenant string, fn func(*Update)) error
	// Save queues u to be written and returns a ticket for Wait, or 0 when the store cannot take it. It never blocks.
	Save(u *Update) uint64
	// Ready returns once the store can take an update, waiting while it is behind; an error when it cannot (it
	// failed, it is closed) or ctx ends first.
	Ready(ctx context.Context) error
	// Wait returns once the update of the ticket is on disk, or with ctx's error.
	Wait(ctx context.Context, ticket uint64) error
	// Trim deletes the tenant's updates that sort before the one stamped stamp by origin, with the next write: the hub
	// calls it as its history moves.
	Trim(tenant string, stamp uint64, origin string)
	// Drop deletes every update of the tenant saved before it (not those saved after), and returns once it is done.
	Drop(ctx context.Context, tenant string) error
}

// Errors of a publish on a hub with a HistoryStore.
var (
	// ErrStoreUnavailable: the store cannot keep up, and the update was not published.
	ErrStoreUnavailable = errors.New("history store unavailable")
	// ErrNotStored: the update was published, but not stored.
	ErrNotStored = errors.New("published, not stored")
)

// persistTimeout bounds how long a publish waits for its update to reach the disk before it fails (503).
const persistTimeout = 10 * time.Second

// storeWait bounds how long a publish waits for a store that is behind to catch up: a burst slows the publishers
// down, a store that cannot write refuses them (503). A variable for the tests.
var storeWait = 5 * time.Second

// storeReady reports whether the store keeps up, waiting for it for storeWait at most.
func (h *Hub) storeReady(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, storeWait)
	defer cancel()
	stop := context.AfterFunc(h.closingCtx, cancel)
	defer stop()
	return h.store.Ready(ctx) == nil
}

// storeTrimEvery is how often housekeeping trims the store of a history that emptied (its updates aged out): the hub
// trims it as it saves otherwise.
const storeTrimEvery = 30 * time.Second

// persisted waits until u, published on this node, is on disk (a no-op without a store): ErrNotStored when the
// store did not take it or did not write it in time.
func (h *Hub) persisted(ctx context.Context, u *Update) error {
	if u.unstored {
		return ErrNotStored
	}
	if h.store == nil || u.ticket == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, persistTimeout)
	defer cancel()
	if err := h.store.Wait(ctx, u.ticket); err != nil {
		return fmt.Errorf("%w: %w", ErrNotStored, err)
	}
	return nil
}

// save hands u, just recorded, to the store (not while the history is loaded from it).
func (h *Hub) save(u *Update) {
	if h.store == nil || h.loading {
		return
	}
	if u.ticket = h.store.Save(u); u.ticket == 0 {
		u.unstored = true
	} else {
		h.noteTicket(u.ticket)
	}
	if stamp, origin, ok := h.hist.oldest(); ok { // the store keeps what the history holds, batch by batch
		h.store.Trim(h.tenant, stamp, origin)
	}
}

// loadHistory fills the history from the store, before the hub serves.
func (h *Hub) loadHistory() error {
	if h.store == nil {
		return nil
	}
	h.loading = true
	defer func() { h.loading = false }()
	return h.store.Load(h.tenant, h.Restore)
}

// trimStore trims the store of a history that emptied, keeping nothing older than a minute (an update arriving
// meanwhile may be older than now); housekeeping calls it every storeTrimEvery.
func (h *Hub) trimStore() {
	if h.store == nil {
		return
	}
	if _, _, ok := h.hist.oldest(); !ok {
		h.store.Trim(h.tenant, uint64(hlc.FromTime(time.Now().Add(-time.Minute))), "")
	}
}
