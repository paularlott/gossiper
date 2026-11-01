package gossiper

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/paularlott/gossip/hlc"

	"github.com/paularlott/logger"
)

// Tenant is one tenant of a Tenants: a hub of its own, with its own keys, subscribers and history.
type Tenant struct {
	// Name identifies the tenant across the cluster.
	Name string
	// Hosts are the host names the tenant's hub is reached at (at least one).
	Hosts []string
	// Config configures the tenant's hub. Its Transport must be nil: the hubs share the Tenants' transport.
	Config Config
}

// Tenants serves the hubs of several tenants on one set of paths, over one transport. A tenant's subscribers
// receive its updates only, and its tokens are good for its hub only.
//
// The request's host name picks the hub: each tenant has host names of its own, and a request for any other host
// is refused. A request is never routed by its token, so tokens are verified once, by the hub, as in a single hub.
//
// Tenants are added, changed and removed while the Tenants serve (Set, SetHosts, Remove). Requests and updates see
// the tenants as they were before a change or after it, never part of one.
type Tenants struct {
	set     atomic.Pointer[tenantSet] // the current tenants: replaced, never changed
	shared  Transport
	clock   *hlc.Clock // every hub's
	started bool       // the shared transport

	mu     sync.Mutex // serializes the changes, and the changes with Close
	closed bool
	busy   sync.WaitGroup // changes under way, and the hubs they replaced or removed, still closing

	budget     *budget // the histories' shared budget, or nil
	stopBudget chan struct{}
	budgetDone chan struct{}
}

// TenantsOption configures Tenants.
type TenantsOption func(*Tenants)

// HistoryBudget bounds the memory the tenants' histories hold together, in bytes, on top of each hub's own
// HistoryBytes: when they hold more, the largest histories drop their oldest updates first, so one busy tenant cannot
// take the memory the others' histories need. 0 or less: no budget.
func HistoryBudget(bytes int64) TenantsOption {
	return func(ts *Tenants) {
		if bytes > 0 {
			ts.budget = newBudget(bytes)
		}
	}
}

// tenantSet is the tenants at one moment. Once published it is never changed: a change publishes a copy.
type tenantSet struct {
	hubs  map[string]*Hub   // tenant name -> hub
	specs map[string]Tenant // tenant name -> the tenant as given, to check a change against
	names []string          // in the order the tenants were added
	hosts map[string]*Hub   // normalized host name -> hub
}

func newTenantSet() *tenantSet {
	return &tenantSet{hubs: map[string]*Hub{}, specs: map[string]Tenant{}, hosts: map[string]*Hub{}}
}

// put makes t, served by h, one of s's tenants, in place of the tenant of its name if there is one. s must not be
// published yet.
func (s *tenantSet) put(t Tenant, h *Hub) {
	if old, ok := s.specs[t.Name]; ok {
		for _, host := range old.Hosts {
			delete(s.hosts, normalizeHost(host))
		}
	} else {
		s.names = append(s.names, t.Name)
	}
	s.hubs[t.Name], s.specs[t.Name] = h, t
	for _, host := range t.Hosts {
		s.hosts[normalizeHost(host)] = h
	}
}

// clone returns a copy of s to change.
func (s *tenantSet) clone() *tenantSet {
	return &tenantSet{hubs: maps.Clone(s.hubs), specs: maps.Clone(s.specs), names: slices.Clone(s.names), hosts: maps.Clone(s.hosts)}
}

// with returns a copy of s in which t, served by h, is the tenant of its name.
func (s *tenantSet) with(t Tenant, h *Hub) *tenantSet {
	n := s.clone()
	n.put(t, h)
	return n
}

// without returns a copy of s without the named tenant.
func (s *tenantSet) without(name string) *tenantSet {
	n := s.clone()
	for _, host := range n.specs[name].Hosts {
		delete(n.hosts, normalizeHost(host))
	}
	delete(n.hubs, name)
	delete(n.specs, name)
	n.names = slices.DeleteFunc(n.names, func(v string) bool { return v == name })
	return n
}

// others returns s's tenants but the named one, in order.
func (s *tenantSet) others(name string) []Tenant {
	out := make([]Tenant, 0, len(s.names))
	for _, n := range s.names {
		if n != name {
			out = append(out, s.specs[n])
		}
	}
	return out
}

var _ Host = (*Tenants)(nil)

// ErrNoTenant is returned (wrapped) by SetHosts and Remove for a tenant the Tenants do not have.
var ErrNoTenant = errors.New("gossiper: no such tenant")

// startParallel is how many hubs NewTenants starts at once.
const startParallel = 16

// NewTenants starts a hub for every tenant (none at all is fine: add them with Set). transport (nil to run alone)
// carries every tenant's updates, each marked with its tenant. The tenants must pass ValidateTenants.
func NewTenants(tenants []Tenant, transport Transport, opts ...TenantsOption) (*Tenants, error) {
	if err := ValidateTenants(tenants); err != nil {
		return nil, err
	}
	if transport == nil {
		transport = &local{}
	}
	ts := &Tenants{shared: transport, clock: hlc.NewClock()}
	for _, o := range opts {
		o(ts)
	}
	s := newTenantSet()
	ts.set.Store(s)
	if ts.budget != nil {
		ts.stopBudget, ts.budgetDone = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(ts.budgetDone)
			ts.budget.enforce(func() map[string]*Hub { return ts.set.Load().hubs }, ts.stopBudget)
		}()
	}
	fail := func(err error) (*Tenants, error) {
		_ = ts.close(context.Background())
		return nil, err
	}
	// The hubs start in parallel (startParallel at a time): a hub's key set fetch may take seconds.
	hubs := make([]*Hub, len(tenants))
	errs := make([]error, len(tenants))
	var wg sync.WaitGroup
	slots := make(chan struct{}, startParallel)
	for i, t := range tenants {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			hubs[i], errs[i] = ts.newHub(t)
		})
	}
	wg.Wait()
	for i, t := range tenants {
		if hubs[i] == nil {
			continue
		}
		t.Hosts = slices.Clone(t.Hosts)
		s.put(t, hubs[i]) // not yet seen by anyone: the transport starts below
	}
	if err := errors.Join(errs...); err != nil {
		return fail(err)
	}
	if err := transport.Start(ts); err != nil {
		return fail(err)
	}
	ts.started = true
	return ts, nil
}

// ValidateTenants checks a whole set of tenants as NewTenants and Set do, without starting anything. Every tenant
// needs a name and host names of its own (without a port), and a Config that New accepts, with a nil Transport: the
// hubs share the Tenants' transport. Keys fetched from a URL are checked only when the hub starts. Keys must differ
// between tenants, so a token of one tenant is never good on another's host; so must the explicit resource
// identifiers of tenants that trust the same authorization server, as its tokens name the resource they are for.
func ValidateTenants(tenants []Tenant) error {
	return validateTenants(tenants, true)
}

// validateTenants is ValidateTenants; withConfigs false skips checking each tenant's Config on its own.
func validateTenants(tenants []Tenant, withConfigs bool) error {
	names := map[string]bool{}
	hosts := map[string]bool{}
	keys := map[string]string{}                  // key or key URL -> tenant
	discovered := map[string]map[string]string{} // authorization server -> tenant -> resource identifier
	for _, t := range tenants {
		if t.Name == "" {
			return errors.New("tenants: a tenant needs a name")
		}
		if names[t.Name] {
			return fmt.Errorf("tenants: duplicate tenant %q", t.Name)
		}
		names[t.Name] = true
		if len(t.Hosts) == 0 {
			return fmt.Errorf("tenants: tenant %q: give it host names: the host picks a tenant's hub", t.Name)
		}
		if t.Config.Transport != nil {
			return fmt.Errorf("tenants: tenant %q: the hubs share the tenants' transport", t.Name)
		}
		if withConfigs {
			if err := checkConfig(t.Config); err != nil {
				return fmt.Errorf("tenants: tenant %q: %w", t.Name, err)
			}
		}
		material := []string{t.Config.PublisherKey.Key, t.Config.PublisherKey.JWKSURL, t.Config.SubscriberKey.Key, t.Config.SubscriberKey.JWKSURL}
		for _, is := range t.Config.Issuers {
			material = append(material, is.Key, is.JWKSURL)
			if is.Key != "" || is.JWKSURL != "" { // an issuer with keys of its own is told apart by them
				continue
			}
			for other, resource := range discovered[is.Issuer] {
				// Without an explicit resource identifier a hub's is the URL it is reached at: its own host's.
				if other != t.Name && resource != "" && resource == t.Config.ResourceIdentifier {
					return fmt.Errorf("tenants: tenants %q and %q trust the authorization server %q: give each its own resource identifier", other, t.Name, is.Issuer)
				}
			}
			if discovered[is.Issuer] == nil {
				discovered[is.Issuer] = map[string]string{}
			}
			discovered[is.Issuer][t.Name] = t.Config.ResourceIdentifier
		}
		for _, v := range material {
			if v == "" {
				continue
			}
			v = keyIdentity(v)
			if other, used := keys[v]; used && other != t.Name {
				return fmt.Errorf("tenants: tenants %q and %q share a key: a token must belong to one tenant", other, t.Name)
			}
			keys[v] = t.Name
		}
		for _, host := range t.Hosts {
			host = normalizeHost(host)
			if host == "" || strings.ContainsAny(host, "/ \t") {
				return fmt.Errorf("tenants: tenant %q: host %q is not a host name", t.Name, host)
			}
			if _, _, err := net.SplitHostPort(host); err == nil {
				return fmt.Errorf("tenants: tenant %q: host %q has a port: hosts are matched without it", t.Name, host)
			}
			if hosts[host] {
				return fmt.Errorf("tenants: host %q is given to two tenants", host)
			}
			hosts[host] = true
		}
	}
	return nil
}

// checkConfig returns the error New would return for c, as far as it can tell without starting anything: the
// settings, and the keys when none is fetched from a URL.
func checkConfig(c Config) error {
	cfg, err := c.withDefaults()
	if err != nil {
		return err
	}
	if cfg.PublisherKey.JWKSURL != "" || cfg.SubscriberKey.JWKSURL != "" {
		return nil
	}
	for _, is := range cfg.Issuers {
		if is.JWKSURL != "" || is.Discover {
			return nil
		}
	}
	h := &Hub{cfg: cfg, log: logger.NewNullLogger()} // static keys only: building the verifiers starts nothing
	defer h.closeVerifiers()
	return h.newVerifiers()
}

// newHub starts the hub of t, over its share of the shared transport.
func (ts *Tenants) newHub(t Tenant) (*Hub, error) {
	cfg := t.Config
	cfg.Transport = &tenantTransport{shared: ts.shared, tenant: t.Name}
	h, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("tenants: tenant %q: %w", t.Name, err)
	}
	if ts.budget != nil {
		h.hist.share(ts.budget)
	}
	// The hubs stamp with one clock: they share this node's origin, and two updates stamped alike by two tenants would
	// be one publication to whatever orders them by (stamp, origin) across tenants (a peer's history pages). The hub
	// is not reachable yet: nothing reads its clock meanwhile.
	ts.clock.Witness(h.clock.Now()) // what its history restored
	h.clock = ts.clock
	return h, nil
}

// Set adds t, or replaces the tenant of its name with it. t must pass ValidateTenants together with the other
// tenants; when it does not, or the Tenants are closed (ErrClosed), nothing changes.
//
// A replaced tenant's new hub takes over the old one's history, and serves the tenant's hosts from the moment Set
// swaps it in; the old hub is then closed, and Set returns once its streams have ended. Their clients reconnect to
// the new hub and resume from their last event ID. Use SetHosts to change only the host names.
func (ts *Tenants) Set(t Tenant) error {
	t.Hosts = slices.Clone(t.Hosts)
	ts.mu.Lock()
	if ts.closed {
		ts.mu.Unlock()
		return ErrClosed
	}
	// The others' configs were checked when they were set: only t's is, and what it must not share with them.
	err := checkConfig(t.Config)
	if err != nil {
		err = fmt.Errorf("tenants: tenant %q: %w", t.Name, err)
	} else {
		err = validateTenants(append(ts.set.Load().others(t.Name), t), false)
	}
	if err != nil {
		ts.mu.Unlock()
		return err
	}
	ts.busy.Add(1)
	ts.mu.Unlock()
	defer ts.busy.Done()

	h, err := ts.newHub(t) // without the lock: fetching keys may take a while
	if err != nil {
		return err
	}
	ts.mu.Lock()
	cur := ts.set.Load()
	switch {
	case ts.closed:
		err = ErrClosed
	default: // another change may have come first
		err = validateTenants(append(cur.others(t.Name), t), false)
	}
	if err != nil {
		ts.mu.Unlock()
		_ = h.Close(context.Background())
		return err
	}
	old := cur.hubs[t.Name]
	if old != nil {
		// The new hub stamps with the old one's clock, so its updates order after the old one's, and takes over its
		// history; it is not serving yet, so nothing else uses either.
		h.clock = old.clock
		h.hist.adopt(old.hist)
	}
	ts.set.Store(cur.with(t, h))
	ts.mu.Unlock()
	if old != nil {
		h.hist.adopt(old.hist) // the updates the old hub applied while the history was copied
		old.hist.share(nil)    // the new hub holds them now
		_ = old.Close(context.Background())
	}
	return nil
}

// SetHosts changes the named tenant's host names, keeping its hub: its open streams stay open. The hosts must pass
// ValidateTenants together with the other tenants'; when they do not, or there is no such tenant (ErrNoTenant),
// nothing changes. The tenant's Config, an absolute HubURL included, is kept as it was.
func (ts *Tenants) SetHosts(name string, hosts []string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.closed {
		return ErrClosed
	}
	cur := ts.set.Load()
	t, ok := cur.specs[name]
	if !ok {
		return fmt.Errorf("%w %q", ErrNoTenant, name)
	}
	t.Hosts = slices.Clone(hosts)
	if err := validateTenants(append(cur.others(name), t), false); err != nil {
		return err
	}
	ts.set.Store(cur.with(t, cur.hubs[name]))
	return nil
}

// Remove removes the named tenant: requests for its hosts are refused from now on, as for any unknown host, and its
// hub is closed. It waits for the hub's streams to end, or for ctx. A tenant the Tenants do not have is an error
// (ErrNoTenant).
func (ts *Tenants) Remove(ctx context.Context, name string) error {
	ts.mu.Lock()
	if ts.closed {
		ts.mu.Unlock()
		return ErrClosed
	}
	cur := ts.set.Load()
	h := cur.hubs[name]
	if h == nil {
		ts.mu.Unlock()
		return fmt.Errorf("%w %q", ErrNoTenant, name)
	}
	ts.set.Store(cur.without(name))
	ts.busy.Add(1)
	ts.mu.Unlock()
	defer ts.busy.Done()
	h.hist.share(nil) // gone from the budget at once, not when its streams have ended
	err := h.Close(ctx)
	// A tenant added again later starts afresh: its stored history does not come back.
	if h.store != nil {
		if derr := h.store.Drop(ctx, name); derr != nil {
			h.log.Error("the tenant's stored history could not be deleted", "tenant", name, "error", derr.Error())
		}
	}
	return err
}

// keyIdentity is a key (or key URL) as tenants compare them: a PEM key by its contents, whatever its line endings
// and surrounding space, so that one key written twice is still one key.
func keyIdentity(v string) string {
	if !strings.Contains(v, "-----BEGIN") {
		return v
	}
	var der []byte
	rest := []byte(v)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		der = append(der, b.Bytes...)
	}
	if len(der) == 0 {
		return v
	}
	return "pem:" + string(der)
}

// Hub returns the named tenant's hub, or nil. Set replaces a tenant's hub, and closes the old one.
func (ts *Tenants) Hub(name string) *Hub { return ts.set.Load().hubs[name] }

// Names returns the tenants' names, in the order they were added.
func (ts *Tenants) Names() []string { return slices.Clone(ts.set.Load().names) }

// Apply implements Host: the update goes to its tenant's hub. An update of a tenant this node does not have is
// dropped.
func (ts *Tenants) Apply(u *Update) {
	if h := ts.set.Load().hubs[u.Tenant]; h != nil {
		h.Apply(u)
	}
}

// Stored implements Host: every hub's saves are stored (the hubs may share a store, or not).
func (ts *Tenants) Stored(ctx context.Context) error {
	for _, h := range ts.set.Load().hubs {
		if err := h.Stored(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Restore implements Host.
func (ts *Tenants) Restore(u *Update) {
	if h := ts.set.Load().hubs[u.Tenant]; h != nil {
		h.Restore(u)
	}
}

// History implements Host: every tenant's history, merged in stamp order.
func (ts *Tenants) History(stamp uint64, origin string, maxBytes int) ([]*Update, bool) {
	var all []*Update
	var bound *Update // the earliest last update of the hubs that have more: nothing after it is complete yet
	for _, h := range ts.set.Load().hubs {
		ups, more := h.History(stamp, origin, maxBytes)
		all = append(all, ups...)
		if last := len(ups) - 1; more && last >= 0 && (bound == nil || after(bound, ups[last])) {
			bound = ups[last]
		}
	}
	slices.SortFunc(all, func(a, b *Update) int {
		if after(a, b) {
			return 1
		}
		return -1
	})
	size := 0
	for i, u := range all {
		if bound != nil && after(u, bound) {
			return all[:i], true
		}
		if size += u.size(); i > 0 && size > maxBytes {
			return all[:i], true
		}
	}
	return all, bound != nil
}

// LocalSubscriptions implements Host: every tenant's subscriptions, each marked with its tenant.
func (ts *Tenants) LocalSubscriptions() []Subscription {
	var out []Subscription
	for name, h := range ts.set.Load().hubs {
		for _, s := range h.LocalSubscriptions() {
			s.Tenant = name
			out = append(out, s)
		}
	}
	return out
}

// Stats returns the sum of the tenants' counters.
func (ts *Tenants) Stats() StatsSnapshot {
	var sum StatsSnapshot
	for _, h := range ts.set.Load().hubs {
		s := h.Stats()
		sum.Subscribers += s.Subscribers
		sum.Published += s.Published
		sum.Applied += s.Applied
		sum.Delivered += s.Delivered
		sum.Dropped += s.Dropped
		sum.Replayed += s.Replayed
		sum.ReplayMisses += s.ReplayMisses
		sum.Duplicates += s.Duplicates
		sum.PublishRejected += s.PublishRejected
		sum.Refused += s.Refused
		sum.KeySetsFailing += s.KeySetsFailing
		sum.HistoryLen += s.HistoryLen
		sum.HistoryBytes += s.HistoryBytes
	}
	return sum
}

// ServeHTTP serves each request with the hub of the tenant its host belongs to.
func (ts *Tenants) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := ts.byHost(r); h != nil {
		h.ServeHTTP(w, r)
		return
	}
	setSecurityHeaders(w)
	writeError(w, http.StatusNotFound, "no hub at this host")
}

// byHost returns the hub of the tenant that has the request's host, or nil.
func (ts *Tenants) byHost(r *http.Request) *Hub {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return ts.set.Load().hosts[normalizeHost(host)]
}

// normalizeHost is a host name as tenants compare them: lower case, without the root label's dot.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// Close stops every hub, waits for the changes under way, then stops the transport. Changes fail from now on.
func (ts *Tenants) Close(ctx context.Context) error {
	return ts.close(ctx)
}

func (ts *Tenants) close(ctx context.Context) error {
	ts.mu.Lock()
	if ts.closed {
		ts.mu.Unlock()
		return nil
	}
	ts.closed = true
	hubs := ts.set.Load().hubs
	ts.mu.Unlock()
	var errs []error
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range hubs {
		wg.Go(func() {
			if err := h.Close(ctx); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	settled := make(chan struct{})
	go func() { ts.busy.Wait(); close(settled) }()
	select {
	case <-settled:
	case <-ctx.Done():
		errs = append(errs, ctx.Err())
	}
	if ts.started {
		if err := ts.shared.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if ts.stopBudget != nil {
		close(ts.stopBudget)
		<-ts.budgetDone
	}
	return errors.Join(errs...)
}

// tenantTransport is a tenant hub's share of the Tenants' transport: it marks the hub's updates with the tenant
// and sees the subscriptions of the tenant only.
type tenantTransport struct {
	shared Transport
	tenant string
}

func (t *tenantTransport) Start(Host) error { return nil } // the Tenants start the shared transport

func (t *tenantTransport) Publish(ctx context.Context, u *Update) error {
	u.Tenant = t.tenant
	return t.shared.Publish(ctx, u)
}

// PublishCopies implements Replicator for a shared transport that does.
func (t *tenantTransport) PublishCopies(ctx context.Context, u *Update, n int) (func(context.Context) error, error) {
	r, ok := t.shared.(Replicator)
	if !ok {
		return nil, fmt.Errorf("%w: 1 of %d", ErrTooFewNodes, n)
	}
	u.Tenant = t.tenant
	return r.PublishCopies(ctx, u, n)
}

func (t *tenantTransport) RemoteSubscriptions(ctx context.Context) ([]Subscription, bool, error) {
	subs, complete, err := t.shared.RemoteSubscriptions(ctx)
	return slices.DeleteFunc(subs, func(s Subscription) bool { return s.Tenant != t.tenant }), complete, err
}

func (t *tenantTransport) NodeID() string { return t.shared.NodeID() }

func (t *tenantTransport) Close() error { return nil } // the Tenants close the shared transport
