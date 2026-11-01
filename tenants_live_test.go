package gossiper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// tnLive is a test tenant with an HMAC key of its own (the secret's suffix tells keys apart) and an explicit
// resource identifier, so its tokens do not depend on the host it is reached at.
func tnLive(name, host, keySuffix string) *tnTenant {
	return &tnTenant{name: name, hosts: []string{host}, pubKey: tnHS(name + "-secret-" + keySuffix + "-0123456789abcdef0123456"),
		iss: "https://iss." + name, aud: "https://" + name + ".example" + hubPath}
}

// tnPublish publishes data on topic as tenant d through its host, and returns the event ID.
func (f *tnFixture) tnPublish(d *tnTenant, topic, data string) string {
	f.t.Helper()
	res := f.do(tnReq{d: d, tok: d.draft(f.t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {topic}, "data": {data}})
	if res.code != 200 {
		f.t.Fatalf("publish %s %q: %d %s", d.name, data, res.code, res.body)
	}
	return res.body
}

// tnSubscribeAll opens a stream of every topic of tenant d, through its host.
func (f *tnFixture) tnSubscribeAll(d *tnTenant, hdr http.Header) *sseClient {
	f.t.Helper()
	return f.open(tnReq{d: d, tok: d.draft(f.t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"*"}}, hdr: hdr})
}

// isOpen reports whether the stream is still open.
func (c *sseClient) isOpen() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

// TestTenantsLiveAdd: a tenant added while the Tenants serve serves its host, isolated from the others, which carry on
// undisturbed.
func TestTenantsLiveAdd(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false)[:2], nil) // umbra and acme
	acme := f.byName("acme")
	early := f.tnSubscribeAll(acme, nil)
	newco := tnLive("newco", "newco.test", "1")
	if res := f.do(tnReq{d: newco, tok: newco.draft(t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {tnB1}, "data": {"x"}}); res.code != 404 {
		t.Fatalf("publish before the tenant exists: %d", res.code)
	}
	if err := f.ts.Set(newco.tenant(t)); err != nil {
		t.Fatal(err)
	}
	f.tenants = append(f.tenants, newco)
	if got := f.ts.Names(); !slices.Equal(got, []string{"umbra", "acme", "newco"}) {
		t.Errorf("names %q", got)
	}
	var streams []tnStream
	for _, d := range f.tenants {
		streams = append(streams, f.openStreams(d)...)
	}
	for _, d := range f.tenants {
		f.publishAll(d)
	}
	checkStreams(t, streams)
	// The stream opened before the change stayed open and got acme's updates only.
	if !early.isOpen() {
		t.Fatal("acme's stream ended when a tenant was added")
	}
	if got := early.received(); len(got) != len(tnPublications) {
		t.Errorf("acme's early stream received %q", got)
	}
	// Tokens stay with their tenant, both ways.
	for _, tc := range []struct{ host, tok string }{
		{"acme.test", newco.draft(t, roleSubscriber, nil, []string{"*"})},
		{"newco.test", acme.draft(t, roleSubscriber, nil, []string{"*"})},
		{"newco.test", acme.modern(t, roleSubscriber, f.srv.URL, subOnly, "*")},
	} {
		if c, res := f.tryOpen(tnReq{host: tc.host, tok: tc.tok, q: url.Values{"topic": {"*"}}}); c != nil || res.code != 401 {
			t.Errorf("foreign token on %s: %d, want 401", tc.host, res.code)
		}
	}
	if res := f.do(tnReq{host: "newco.test", tok: acme.draft(t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {tnB1}, "data": {"x"}}); res.code != 401 {
		t.Errorf("acme's publisher token on newco's host: %d, want 401", res.code)
	}
}

// TestTenantsLiveStartEmpty: Tenants may start with no tenant at all and get them later.
func TestTenantsLiveStartEmpty(t *testing.T) {
	for _, tenants := range [][]Tenant{nil, {}} {
		tn, err := NewTenants(tenants, nil)
		if err != nil {
			t.Fatal(err)
		}
		f := serveTenants(t, tn, nil)
		d := tnLive("first", "first.test", "1")
		if res := f.do(tnReq{d: d}, nil); res.code != 404 {
			t.Fatalf("no tenant yet: %d", res.code)
		}
		if n := len(tn.Names()) + len(tn.LocalSubscriptions()); n != 0 || tn.Stats() != (StatsSnapshot{}) {
			t.Fatalf("empty tenants: %d, %+v", n, tn.Stats())
		}
		if err := tn.Set(d.tenant(t)); err != nil {
			t.Fatal(err)
		}
		f.tenants = append(f.tenants, d)
		c := f.tnSubscribeAll(d, nil)
		f.tnPublish(d, tnB1, "hello")
		c.expect("hello")
	}
}

// TestTenantsLiveReplace: replacing a tenant's keys refuses its old tokens and accepts the new ones; its streams end
// and resume on the new hub from their last event ID, with nothing missed; the other tenants' streams stay open.
func TestTenantsLiveReplace(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false)[1:3], nil) // acme and globex
	acme, globex := f.byName("acme"), f.byName("globex")
	oldSub, oldPub := acme.draft(t, roleSubscriber, nil, []string{"*"}), acme.draft(t, rolePublisher, []string{"*"}, nil)
	oldModern := acme.modern(t, roleSubscriber, f.srv.URL, subOnly, "*")
	sa := f.tnSubscribeAll(acme, nil)
	sg := f.tnSubscribeAll(globex, nil)
	a1 := f.tnPublish(acme, tnB1, "a1")
	a2 := f.tnPublish(acme, tnB1, "a2")
	sa.expect("a1", "a2")
	oldHub := f.ts.Hub("acme")

	next := tnLive("acme", "acme.test", "2") // new keys, a new issuer, the same host
	if err := f.ts.Set(next.tenant(t)); err != nil {
		t.Fatal(err)
	}
	if !sa.waitClosed(wait) {
		t.Fatal("acme's stream stayed open on the replaced hub")
	}
	if h := f.ts.Hub("acme"); h == oldHub || h == nil {
		t.Fatal("the hub was not replaced")
	}
	if _, err := oldHub.Publish(context.Background(), &Update{Topics: []string{tnB1}}); !errors.Is(err, ErrClosed) {
		t.Errorf("the old hub still publishes: %v", err)
	}
	// The old tokens are refused, for publishing and subscribing.
	if res := f.do(tnReq{host: "acme.test", tok: oldPub}, url.Values{"topic": {tnB1}, "data": {"x"}}); res.code != 401 {
		t.Errorf("old publisher token: %d", res.code)
	}
	for _, tok := range []string{oldSub, oldModern} {
		if c, res := f.tryOpen(tnReq{host: "acme.test", tok: tok, q: url.Values{"topic": {"*"}}}); c != nil || res.code != 401 {
			t.Errorf("old subscriber token: %d", res.code)
		}
	}
	// The new tokens are accepted, and a subscriber resumes where it was: the history moved to the new hub.
	f.tnSubscribeAll(next, http.Header{"Last-Event-ID": {a1}}).expect("a2")
	f.tnSubscribeAll(next, http.Header{"Last-Event-ID": {"earliest"}}).expect("a1", "a2")
	resumed := f.tnSubscribeAll(next, http.Header{"Last-Event-ID": {a2}})
	modern := f.open(tnReq{d: next, tok: next.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"), q: url.Values{"match": {"*"}}})
	f.tnPublish(next, tnB1, "a3")
	resumed.expect("a3")
	modern.expect("a3")
	f.tnSubscribeAll(next, http.Header{"Last-Event-ID": {a2}}).expect("a3") // the new hub's updates order after the old one's
	// globex was not disturbed.
	f.tnPublish(globex, tnB1, "g1")
	sg.expect("g1")
	if !sg.isOpen() {
		t.Error("globex's stream ended")
	}
	time.Sleep(tnSettle / 2)
	if got := sg.received(); len(got) != 0 {
		t.Errorf("globex received %q", got)
	}
}

// TestTenantsLiveSetHosts: changing a tenant's hosts keeps its hub and its streams; the old host is refused at once.
func TestTenantsLiveSetHosts(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false)[1:3], nil) // acme and globex
	acme := f.byName("acme")
	h := f.ts.Hub("acme")
	s := f.tnSubscribeAll(acme, nil)
	if err := f.ts.SetHosts("acme", []string{"acme2.test", "ACME3.test."}); err != nil {
		t.Fatal(err)
	}
	if f.ts.Hub("acme") != h {
		t.Fatal("SetHosts replaced the hub")
	}
	if res := f.do(tnReq{host: "acme.test", tok: acme.draft(t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {tnB1}, "data": {"x"}}); res.code != 404 {
		t.Errorf("the old host: %d, want 404", res.code)
	}
	moved := *acme
	moved.hosts = []string{"acme2.test"}
	f.tnPublish(&moved, tnB1, "via-acme2")
	moved.hosts = []string{"acme3.test:8443"}
	f.tnPublish(&moved, tnB1, "via-acme3")
	s.expect("via-acme2", "via-acme3")
	if !s.isOpen() {
		t.Error("the stream ended")
	}
	// Refused: a host of another tenant, a port, no hosts, an unknown tenant. Nothing changes.
	for _, hosts := range [][]string{{"globex.test"}, {"acme2.test", "globex.test"}, {"a.test:80"}, nil, {"x.test", "X.test"}} {
		if err := f.ts.SetHosts("acme", hosts); err == nil {
			t.Errorf("SetHosts %q accepted", hosts)
		}
	}
	if err := f.ts.SetHosts("nobody", []string{"nobody.test"}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("SetHosts of an unknown tenant: %v", err)
	}
	f.tnPublish(&moved, tnB1, "still")
	s.expect("still")
	f.tnSubscribeAll(f.byName("globex"), nil)
	// A host freed by one tenant can go to another.
	if err := f.ts.SetHosts("globex", []string{"globex.test", "acme.test"}); err != nil {
		t.Errorf("taking a freed host: %v", err)
	}
}

// TestTenantsLiveRemove: a removed tenant's hosts are refused and its streams end; the others carry on; the tenant
// can be added again.
func TestTenantsLiveRemove(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false)[1:3], nil) // acme and globex
	acme, globex := f.byName("acme"), f.byName("globex")
	sa := f.tnSubscribeAll(acme, nil)
	sg := f.tnSubscribeAll(globex, nil)
	if err := f.ts.Remove(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if !sa.waitClosed(wait) {
		t.Fatal("acme's stream stayed open")
	}
	if res := f.do(tnReq{d: acme, tok: acme.draft(t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {tnB1}, "data": {"x"}}); res.code != 404 || !strings.Contains(res.body, "no hub at this host") {
		t.Errorf("removed tenant's host: %d %q", res.code, res.body)
	}
	if f.ts.Hub("acme") != nil || !slices.Equal(f.ts.Names(), []string{"globex"}) {
		t.Errorf("acme still listed: %q", f.ts.Names())
	}
	if err := f.ts.Remove(context.Background(), "acme"); !errors.Is(err, ErrNoTenant) {
		t.Errorf("removing it again: %v", err)
	}
	f.ts.Apply(&Update{ID: "urn:late", Topics: []string{tnB1}, Stamp: uint64(f.ts.Hub("globex").clock.Now()), Origin: "other", Tenant: "acme"})
	f.tnPublish(globex, tnB1, "g1")
	sg.expect("g1")
	if !sg.isOpen() {
		t.Error("globex's stream ended")
	}
	// Added again, with a fresh hub.
	if err := f.ts.Set(acme.tenant(t)); err != nil {
		t.Fatal(err)
	}
	c := f.tnSubscribeAll(acme, http.Header{"Last-Event-ID": {"earliest"}})
	f.tnPublish(acme, tnB1, "again")
	c.expect("again")
	time.Sleep(tnSettle / 2)
	if got := sg.received(); len(got) != 0 {
		t.Errorf("globex received %q", got)
	}
}

// TestTenantsLiveValidation: a change that NewTenants would refuse leaves everything as it was.
func TestTenantsLiveValidation(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	before := f.ts.set.Load()
	acme, globex := f.byName("acme"), f.byName("globex")
	hooliCfg := f.byName("hooli").config(t)
	key := func(cfg Config, k string) Config { cfg.PublisherKey = auth.KeyConfig{Key: k}; return cfg }
	fresh := tnLive("fresh", "fresh.test", "1")
	tests := []struct {
		name string
		t    Tenant
	}{
		{"no name", Tenant{Hosts: []string{"x.test"}, Config: fresh.config(t)}},
		{"no hosts", Tenant{Name: "fresh", Config: fresh.config(t)}},
		{"another tenant's host", Tenant{Name: "fresh", Hosts: []string{"fresh.test", "ACME.test"}, Config: fresh.config(t)}},
		{"a host twice", Tenant{Name: "fresh", Hosts: []string{"fresh.test", "fresh.test."}, Config: fresh.config(t)}},
		{"a port", Tenant{Name: "fresh", Hosts: []string{"fresh.test:443"}, Config: fresh.config(t)}},
		{"a path", Tenant{Name: "fresh", Hosts: []string{"fresh.test/x"}, Config: fresh.config(t)}},
		{"another tenant's key", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: key(fresh.config(t), acme.subKey.secret)}},
		{"another tenant's PEM key", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: globex.config(t)}},
		{"a transport", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: func() Config { c := fresh.config(t); c.Transport = &local{}; return c }()}},
		{"another tenant's resource at its authorization server", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: hooliCfg}},
		{"a bad protocol", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: func() Config { c := fresh.config(t); c.Protocol = 99; return c }()}},
		{"a bad key", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: "not a key", Algorithm: "RS256"}}}},
		{"a bad hub URL", Tenant{Name: "fresh", Hosts: []string{"fresh.test"}, Config: func() Config { c := fresh.config(t); c.HubURL = "/elsewhere"; return c }()}},
		// Replacing acme: with globex's host, or with umbra's key.
		{"acme takes globex's host", Tenant{Name: "acme", Hosts: []string{"globex.test"}, Config: acme.config(t)}},
		{"acme takes umbra's key", Tenant{Name: "acme", Hosts: []string{"acme.test"}, Config: key(acme.config(t), f.byName("umbra").pubKey.secret)}},
	}
	for _, tc := range tests {
		if err := f.ts.Set(tc.t); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if f.ts.set.Load() != before {
			t.Fatalf("%s: the tenants changed", tc.name)
		}
	}
	for _, d := range f.tenants {
		f.tnSubscribeAll(d, nil)
	}
	// Replacing a tenant may keep its own keys and hosts: they are checked against the other tenants only.
	if err := f.ts.Set(acme.tenant(t)); err != nil {
		t.Errorf("replacing acme with itself: %v", err)
	}
	// Set fails once the Tenants are closed, and leaves no hub running.
	if err := f.ts.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.ts.Set(fresh.tenant(t)); !errors.Is(err, ErrClosed) {
		t.Errorf("Set after Close: %v", err)
	}
	if f.ts.Hub("fresh") != nil {
		t.Error("a hub was added after Close")
	}
	if err := f.ts.SetHosts("acme", []string{"x.test"}); !errors.Is(err, ErrClosed) {
		t.Errorf("SetHosts after Close: %v", err)
	}
	if err := f.ts.Remove(context.Background(), "acme"); !errors.Is(err, ErrClosed) {
		t.Errorf("Remove after Close: %v", err)
	}
}

// TestValidateTenantsStartsNothing: ValidateTenants checks a set of tenants with keys of every kind without starting
// a goroutine.
func TestValidateTenantsStartsNothing(t *testing.T) {
	var tenants []Tenant
	for _, d := range newTNTenants(t, false) {
		tenants = append(tenants, d.tenant(t))
	}
	n := runtime.NumGoroutine() // earlier tests' stragglers only lower it
	for range 20 {
		if err := ValidateTenants(tenants); err != nil {
			t.Fatal(err)
		}
	}
	if got := runtime.NumGoroutine(); got > n {
		t.Errorf("%d goroutines, %d before", got, n)
	}
}

// TestTenantsLiveConcurrent: tenants are added, changed and removed in a loop while requests are served, updates are
// applied and the Tenants are inspected; a steady tenant's subscriber receives exactly its tenant's updates, and
// closing the Tenants in the middle of it all leaves nothing running.
func TestTenantsLiveConcurrent(t *testing.T) {
	baseline := runtime.NumGoroutine() // earlier tests' stragglers only lower it
	func() {
		steady := tnLive("steady", "steady.test", "1")
		tn, err := NewTenants([]Tenant{steady.tenant(t)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(tn)
		defer srv.Close()
		tr := &http.Transport{MaxIdleConnsPerHost: 64}
		defer tr.CloseIdleConnections()
		f := &tnFixture{t: t, ts: tn, srv: srv, tenants: []*tnTenant{steady}, client: &http.Client{Transport: tr}, tr: tr}
		sub := f.tnSubscribeAll(steady, nil)
		defer sub.close()

		churn := []*tnTenant{tnLive("churn", "churn-a.test", "a"), tnLive("churn", "churn-b.test", "b")}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var changes atomic.Int64
		wg.Go(func() { // the admin: every kind of change, until the Tenants close
			for i := 0; ; i++ {
				d := churn[i%2]
				var err error
				switch i % 4 {
				case 0, 1:
					err = tn.Set(d.tenant(t))
				case 2:
					err = tn.SetHosts("churn", []string{fmt.Sprintf("churn-%d.test", i), "churn-a.test"})
				default:
					err = tn.Remove(context.Background(), "churn")
				}
				if errors.Is(err, ErrClosed) {
					return
				}
				if err != nil {
					t.Errorf("change %d: %v", i, err)
					return
				}
				changes.Add(1)
			}
		})
		for i := range 2 { // subscribers and publishers on the churning tenant's hosts: any answer will do
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					d := churn[i]
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
					if resp, err := f.client.Do(f.newRequest(ctx, tnReq{d: d, tok: d.draft(t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"*"}}})); err == nil {
						resp.Body.Close()
					}
					cancel()
					form := url.Values{"topic": {tnB1}, "data": {"churn"}}
					if resp, err := f.client.Do(f.newRequest(context.Background(), tnReq{d: d, method: http.MethodPost, q: form, tok: d.draft(t, rolePublisher, []string{"*"}, nil)})); err == nil {
						resp.Body.Close()
					}
				}
			})
		}
		wg.Go(func() { // updates from other nodes, and the transport's view of the Tenants
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				u := &Update{ID: fmt.Sprintf("urn:remote:%d", i), Topics: []string{tnB1}, Data: "remote-churn", Stamp: uint64(time.Now().UnixMicro()) << 16, Origin: "other", Tenant: "churn"}
				if i%2 == 0 {
					tn.Apply(u)
				} else {
					tn.Restore(u)
				}
				_ = tn.LocalSubscriptions()
				_ = tn.Stats()
				for _, name := range tn.Names() {
					_ = tn.Hub(name)
				}
				time.Sleep(100 * time.Microsecond)
			}
		})
		const msgs = 200
		var want []string
		for i := range msgs {
			want = append(want, fmt.Sprintf("steady-%d", i))
			f.tnPublish(steady, tnB1, want[i])
		}
		eventually(t, "a few hundred changes", func() bool { return changes.Load() > 200 })
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		if err := tn.Close(ctx); err != nil { // while the admin goes on changing
			t.Fatal(err)
		}
		wg.Wait()
		var got []string
		for _, ev := range sub.receivedEvents() {
			got = append(got, ev.Data)
		}
		if !slices.Equal(got, want) {
			t.Errorf("steady received %d updates, want %d (%q...)", len(got), len(want), got[:min(len(got), 5)])
		}
		if err := tn.Set(churn[0].tenant(t)); !errors.Is(err, ErrClosed) {
			t.Errorf("Set after Close: %v", err)
		}
		tr.CloseIdleConnections()
		srv.CloseClientConnections()
	}()
	if n := settleGoroutines(baseline); n > baseline {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("%d goroutines remain, %d before:\n%s", n, baseline, buf)
	}
}
