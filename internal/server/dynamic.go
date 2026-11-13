package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/internal/configstore"
)

// The database holds a record per tenant.
const tenantPrefix = "tenant/" // tenant/<name>: storedTenant

func tenantKey(name string) string { return tenantPrefix + name }
func specJSON(v any) []byte        { b, _ := json.Marshal(v); return b }
func sameJSON(a, b any) bool       { return bytes.Equal(specJSON(a), specJSON(b)) }

// storeList is the database's List, or nil without a database.
func (s *Server) storeList() func(string) []configstore.Record {
	if s.store == nil {
		return nil
	}
	return s.store.List
}

// resolvedTenant is a tenant the server serves, with where it is defined.
type resolvedTenant struct {
	spec     tenantSpec
	fromFile bool
}

// problem is a tenant of the database the server cannot serve alongside the others.
type problem struct {
	tenant string
	msg    string
}

// resolveTenants merges the tenants of the file with those of the database, read through list. The file's are
// served as they are (they were checked at start). The database's are taken oldest first (by creation), and one that
// fails check (its own settings) or clashes with those already taken (its name, a host, a key) is left out: every
// node holds the same records, so every node leaves out the same ones. The API refuses a change that would leave
// anything out, so this happens only to changes made on two nodes at the same moment.
func (s *Server) resolveTenants(list func(string) []configstore.Record, check func(tenantSpec) error) ([]resolvedTenant, []problem) {
	var out []resolvedTenant
	names := map[string]bool{}
	taken := newClashes()
	for _, t := range s.tenants {
		out = append(out, resolvedTenant{spec: t, fromFile: true})
		names[t.Name] = true
		_ = taken.add(t)
	}
	if list == nil {
		return out, nil
	}
	var problems []problem
	type entry struct {
		name    string
		spec    tenantSpec
		created int64
		bad     string
	}
	var recs []entry
	for _, r := range list(tenantPrefix) {
		name := strings.TrimPrefix(r.Key, tenantPrefix)
		var st storedTenant
		e := entry{name: name}
		if err := json.Unmarshal(r.Value, &st); err != nil || st.Spec.Name != name {
			e.bad = "unreadable record"
		}
		e.spec, e.created = st.Spec, st.Created
		recs = append(recs, e)
	}
	slices.SortFunc(recs, func(a, b entry) int {
		return cmp.Or(cmp.Compare(a.created, b.created), strings.Compare(a.name, b.name))
	})
	for _, e := range recs {
		name, t := e.name, e.spec
		if e.bad != "" {
			problems = append(problems, problem{name, e.bad})
			continue
		}
		if names[name] {
			problems = append(problems, problem{name, "the tenants file has a tenant of this name"})
			continue
		}
		if err := check(t); err != nil {
			problems = append(problems, problem{name, err.Error()})
			continue
		}
		if err := taken.add(t); err != nil {
			problems = append(problems, problem{name, err.Error()})
			continue
		}
		names[name] = true
		t.created = e.created
		out = append(out, resolvedTenant{spec: t})
	}
	return out, problems
}

// checkRecord is a database tenant's own check: the tenants file's rules, and its hub's settings, keys parsed. Each
// spec is checked once.
func (s *Server) checkRecord(t tenantSpec) error {
	key := string(specJSON(t))
	if err, ok := s.checked.get(key); ok {
		return err
	}
	err := checkSpec(t)
	if err == nil {
		s.validated.Add(1)
		err = gossiper.ValidateTenants(mercureTenants(s.baseConfig, []tenantSpec{t}))
	}
	s.checked.put(key, err)
	return err
}

// knownProblem is checkRecord without checking any hub's settings: the result of the last check of the spec, or
// the tenants file's rules alone when it has none. The API reads and writes with it.
func (s *Server) knownProblem(t tenantSpec) error {
	if err, ok := s.checked.get(string(specJSON(t))); ok {
		return err
	}
	return checkSpec(t)
}

// checkCache holds the results of checkRecord, by spec.
type checkCache struct {
	mu   sync.Mutex
	m    map[string]error
	used map[string]bool // during a sweep, the specs looked up
}

// maxChecked bounds the checkCache.
const maxChecked = 1 << 17

func (c *checkCache) get(key string) (error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err, ok := c.m[key]
	if ok && c.used != nil {
		c.used[key] = true
	}
	return err, ok
}

func (c *checkCache) put(key string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= maxChecked {
		c.m = map[string]error{} // only a cache: refused writes do not pile up
	}
	c.m[key] = err
	if c.used != nil {
		c.used[key] = true
	}
}

// sweep runs fn, then forgets the specs it did not look up.
func (c *checkCache) sweep(fn func()) {
	c.mu.Lock()
	c.used = map[string]bool{}
	c.mu.Unlock()
	fn()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if !c.used[k] {
			delete(c.m, k)
		}
	}
	c.used = nil
}

// clashes is what tenants must not share, as gossiper.ValidateTenants checks between them: names, hosts, keys, and
// the resource identifiers of those trusting the same authorization server. Adding one costs no key parsing.
type clashes struct {
	names, hosts, keys map[string]string            // -> tenant
	discovered         map[string]map[string]string // authorization server -> tenant -> resource identifier
}

func newClashes() *clashes {
	return &clashes{names: map[string]string{}, hosts: map[string]string{}, keys: map[string]string{},
		discovered: map[string]map[string]string{}}
}

// add takes t when it clashes with none of those taken.
func (c *clashes) add(t tenantSpec) error {
	if _, dup := c.names[t.Name]; dup {
		return fmt.Errorf("tenants: duplicate tenant %q", t.Name)
	}
	m := t.Mercure
	if m == nil {
		m = &tenantMercure{}
	}
	for _, as := range m.AuthorizationServers {
		for other, resource := range c.discovered[as] {
			if other != t.Name && resource != "" && resource == m.ResourceIdentifier {
				return fmt.Errorf("tenants: tenants %q and %q trust the authorization server %q: give each its own resource identifier", other, t.Name, as)
			}
		}
	}
	var keys []string
	for _, v := range []string{m.PublisherKey, m.PublisherJWKSURL, m.SubscriberKey, m.SubscriberJWKSURL} {
		if v == "" {
			continue
		}
		v = keyIdentity(v)
		if other, used := c.keys[v]; used && other != t.Name {
			return fmt.Errorf("tenants: tenants %q and %q share a key: a token must belong to one tenant", other, t.Name)
		}
		keys = append(keys, v)
	}
	var hosts []string
	for _, h := range t.Hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if other, used := c.hosts[h]; used && other != t.Name {
			return fmt.Errorf("tenants: host %q is given to two tenants", h)
		}
		hosts = append(hosts, h)
	}
	c.names[t.Name] = t.Name
	for _, as := range m.AuthorizationServers {
		if c.discovered[as] == nil {
			c.discovered[as] = map[string]string{}
		}
		c.discovered[as][t.Name] = m.ResourceIdentifier
	}
	for _, v := range keys {
		c.keys[v] = t.Name
	}
	for _, h := range hosts {
		c.hosts[h] = t.Name
	}
	return nil
}

// keyIdentity is a key as the hubs compare them: a PEM key by its DER bytes (the same key however it is wrapped).
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

// checkSpec applies the tenants file's rules to one tenant.
func checkSpec(t tenantSpec) error {
	_, err := parseTenants(specJSON(tenantsFile{Tenants: []tenantSpec{t}}))
	return err
}

// specs returns the tenants' specs.
func specs(ts []resolvedTenant) []tenantSpec {
	out := make([]tenantSpec, len(ts))
	for i, t := range ts {
		out[i] = t.spec
	}
	return out
}

// watchStore applies the database's changes as they come, from this node's API or another node's, until stop.
func (s *Server) watchStore(changed <-chan struct{}, stop <-chan struct{}) {
	defer close(s.watchDone)
	for {
		select {
		case <-stop:
			return
		case <-changed:
		}
		// Changes come in bursts (several tenants at once, a catch-up from a peer): take them together.
		select {
		case <-stop:
			return
		case <-time.After(20 * time.Millisecond):
		}
		select {
		case <-changed:
		default:
		}
		s.applyTenants()
	}
}

// applyTenants brings the tenants' hubs in line with the file and the database.
func (s *Server) applyTenants() {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	var resolved []resolvedTenant
	var problems []problem
	s.checked.sweep(func() { resolved, problems = s.resolveTenants(s.storeList(), s.checkRecord) })
	for _, p := range problems {
		key := p.tenant + "\x00" + p.msg
		if !s.reported[key] {
			s.log.Warn("tenant left out", "tenant", p.tenant, "reason", p.msg)
		}
	}
	s.reported = map[string]bool{}
	for _, p := range problems {
		s.reported[p.tenant+"\x00"+p.msg] = true
	}
	s.applyMercure(specs(resolved))
}

// applyMercure adds, changes and removes tenants' hubs to match all. A tenant whose hosts alone changed keeps its hub
// (and its streams); any other change starts it over. A host moving from one tenant to another needs the first to let
// go before the second takes it, so changes that fail are tried again while others succeed.
// applyParallel is how many tenant hubs applyMercure starts at once.
const applyParallel = 16

func (s *Server) applyMercure(all []tenantSpec) {
	want := map[string]tenantSpec{}
	for _, t := range all {
		want[t.Name] = t
	}
	for _, name := range slices.Sorted(maps.Keys(s.mercureApplied)) {
		if _, keep := want[name]; !keep {
			if err := s.Tenants.Remove(context.Background(), name); err != nil {
				s.log.Warn("tenant hub not removed", "tenant", name, "error", err.Error())
			}
			delete(s.mercureApplied, name)
		}
	}
	pending := map[string]tenantSpec{}
	for name, t := range want {
		if old, ok := s.mercureApplied[name]; !ok || old.created != t.created || !sameJSON(old, t) {
			pending[name] = t
		}
	}
	// Rounds until nothing more applies: a tenant may wait for another to give up a host. Within a round the hubs
	// start in parallel (applyParallel at a time): a hub's key set fetch may take seconds, and the others need not wait.
	for len(pending) > 0 {
		progress := false
		lastErr := map[string]error{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		slots := make(chan struct{}, applyParallel)
		type job struct {
			name   string
			t, old tenantSpec
			had    bool
		}
		var jobs []job // read before the goroutines write to the maps
		for _, name := range slices.Sorted(maps.Keys(pending)) {
			old, had := s.mercureApplied[name]
			jobs = append(jobs, job{name, pending[name], old, had})
		}
		for _, j := range jobs {
			name, t, old, had := j.name, j.t, j.old, j.had
			slots <- struct{}{}
			wg.Go(func() {
				defer func() { <-slots }()
				var err error
				// A tenant created again (another created) is a new tenant: Set replaces it, history and all.
				if had && old.created == t.created && sameJSON(old.Mercure, t.Mercure) {
					err = s.Tenants.SetHosts(name, t.Hosts)
				} else {
					err = s.Tenants.Set(mercureTenants(s.baseConfig, []tenantSpec{t})[0])
				}
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					lastErr[name] = err
					return
				}
				s.mercureApplied[name] = t
				delete(pending, name)
				progress = true
			})
		}
		wg.Wait()
		if !progress {
			for name, err := range lastErr {
				s.log.Warn("tenant hub not applied", "tenant", name, "error", err.Error())
			}
			return
		}
	}
}
