package gossiper

import (
	"context"
	"encoding/json"
)

// Transport carries updates between the nodes of a cluster. The hub calls Start once, before it serves, and Close
// once, when it stops.
//
// Publish must see that every node's hub, this one's included, is given the update through Hub.Apply. Applying
// one update twice on a node is harmless (the hub drops the second), so a transport may deliver at least once.
type Transport interface {
	// Start connects the transport to the hub (a *Hub, or the Tenants serving several).
	Start(h Host) error
	// Publish replicates u, already stamped and given its ID, to every node. It returns once u is applied on this
	// node and on its way to the others.
	Publish(ctx context.Context, u *Update) error
	// RemoteSubscriptions returns the active subscriptions of the other nodes, and whether every node answered.
	RemoteSubscriptions(ctx context.Context) (subs []Subscription, complete bool, err error)
	// NodeID returns this node's id in the cluster.
	NodeID() string
	// Close stops the transport.
	Close() error
}

// Host is what a Transport delivers to: a *Hub, or the Tenants that serve several hubs over one transport.
type Host interface {
	// Apply applies an update published on any node.
	Apply(u *Update)
	// Restore applies an update retained from before this node restarted.
	Restore(u *Update)
	// LocalSubscriptions returns the active subscriptions of this node's subscribers.
	LocalSubscriptions() []Subscription
	// History returns the updates this node's history holds that sort after the update stamped stamp by origin,
	// oldest first, about maxBytes of them (at least one), and whether more follow: a node that starts copies a
	// peer's history with it.
	History(stamp uint64, origin string, maxBytes int) (updates []*Update, more bool)
}

// RunPublisher is a Transport that publishes several updates in one go (the local and cluster transports, and the
// Tenants' share of either). The hub hands it a run of updates that arrived in a row on one streaming publish, none
// asking for copies; a transport without it is handed them one at a time.
type RunPublisher interface {
	// PublishRun publishes us, each already stamped and given its ID, in order, as Publish publishes each, and hands
	// every node's hub the run through RunApplier.ApplyRun where the hub has it (Apply otherwise). It returns nil when
	// all are published, or each update's error (nil for those published).
	PublishRun(ctx context.Context, us []*Update) []error
}

// RunApplier is a Host that applies a run of updates together: each subscriber is woken once for the updates of the
// run it receives, instead of once for each. A *Hub and the Tenants are RunAppliers.
type RunApplier interface {
	// ApplyRun applies us, in order, as Apply applies each.
	ApplyRun(us []*Update)
}

// ApplyRun hands us to h as one run when h is a RunApplier, one at a time otherwise. Transports call it.
func ApplyRun(h Host, us []*Update) {
	if ra, ok := h.(RunApplier); ok {
		ra.ApplyRun(us)
		return
	}
	for _, u := range us {
		h.Apply(u)
	}
}

// Subscription is one active subscription: a subscriber and one of its topic matchers. A draft-07 subscription
// has a Topic (its selector); a Mercure 1.0 one has a MatchType and a Match.
type Subscription struct {
	Context    string          `json:"@context,omitempty" msgpack:"-"`
	ID         string          `json:"id" msgpack:"i"`
	Type       string          `json:"type" msgpack:"-"`
	MatchType  string          `json:"match_type,omitempty" msgpack:"k,omitempty"`
	Match      string          `json:"match,omitempty" msgpack:"m,omitempty"`
	Topic      string          `json:"topic,omitempty" msgpack:"t,omitempty"`
	Subscriber string          `json:"subscriber" msgpack:"s"`
	Active     bool            `json:"active" msgpack:"a"`
	Payload    json.RawMessage `json:"payload,omitempty" msgpack:"p,omitempty"`
	Tenant     string          `json:"-" msgpack:"n,omitempty"` // see Update.Tenant
}

// modern reports whether the subscription was made with a Mercure 1.0 matcher.
func (s Subscription) modern() bool { return s.MatchType != "" }

// local is the transport of a hub that runs alone.
type local struct {
	h Host
}

func (l *local) Start(h Host) error { l.h = h; return nil }

func (l *local) Publish(_ context.Context, u *Update) error {
	l.h.Apply(u)
	return nil
}

func (l *local) PublishRun(_ context.Context, us []*Update) []error {
	ApplyRun(l.h, us)
	return nil
}

func (l *local) RemoteSubscriptions(context.Context) ([]Subscription, bool, error) {
	return nil, true, nil
}

func (l *local) NodeID() string { return "" }

func (l *local) Close() error { return nil }
