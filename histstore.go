package gossiper

import (
	"context"
	"time"

	"github.com/paularlott/gossip/hlc"
)

// HistoryStore keeps a copy of a node's history on disk, so that it survives a restart (Config.HistoryStore).
// The history itself is in memory: the hub serves replays from there, saves each update it records to the store, and
// tells it what the history drops. The store writes in the background, every so often, so a publish never waits for
// the disk; a crash loses what was not written yet, a clean stop (Close) writes it all.
//
// In a cluster a starting node also copies the history of a peer; a store keeps the history through a restart of
// every node at once.
//
// Hubs of several tenants may share one store; an update's Tenant names the hub it belongs to.
type HistoryStore interface {
	// Load calls fn with every stored update of the tenant ("" for a hub that is not a tenant's), in stamp order.
	Load(tenant string, fn func(*Update)) error
	// Save queues u to be written. It never blocks: an update it cannot take (it is far behind) is not stored.
	Save(u *Update)
	// Trim deletes the tenant's updates that sort before the one stamped stamp by origin, with the next write: the hub
	// calls it as its history moves.
	Trim(tenant string, stamp uint64, origin string)
	// Drop deletes every update of the tenant saved before it (not those saved after), and returns once it is done.
	Drop(ctx context.Context, tenant string) error
}

// storeTrimEvery is how often housekeeping trims the store of a history that emptied (its updates aged out): the hub
// trims it as it saves otherwise.
const storeTrimEvery = 30 * time.Second

// save hands u, just recorded, to the store (not while the history is loaded from it).
func (h *Hub) save(u *Update) {
	if h.store == nil || h.loading {
		return
	}
	h.store.Save(u)
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
