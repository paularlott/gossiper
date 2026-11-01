package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---- the tenants file ----------------------------------------------------------------------------------------

func TestParseTenants(t *testing.T) {
	ok := `{"tenants":[{"name":"acme","hosts":["acme.example"],"mercure":{"publisher_key":"k"}},
		{"name":"b.c_d-1","hosts":["b.example"],"mercure":{"publisher_key":"k2"}}]}`
	for name, tc := range map[string]struct {
		json string
		ok   bool
	}{
		"valid":                  {ok, true},
		"no tenants":             {`{"tenants":[]}`, true},
		"empty object":           {`{}`, true},
		"duplicate names":        {`{"tenants":[{"name":"a","hosts":["a.test"],"mercure":{}},{"name":"a","hosts":["b.test"],"mercure":{}}]}`, false},
		"mercure without hosts":  {`{"tenants":[{"name":"a","mercure":{"publisher_key":"k"}}]}`, false},
		"mercure, empty hosts":   {`{"tenants":[{"name":"a","hosts":[],"mercure":{"publisher_key":"k"}}]}`, false},
		"one without hosts":      {`{"tenants":[{"name":"a","hosts":["a.test"],"mercure":{}},{"name":"b","mercure":{}}]}`, false},
		"mercure with hosts":     {`{"tenants":[{"name":"a","hosts":["a.test"],"mercure":{"publisher_key":"k"}}]}`, true},
		"empty name":             {`{"tenants":[{"name":"","mercure":{}}]}`, false},
		"space in name":          {`{"tenants":[{"name":"a b","mercure":{}}]}`, false},
		"slash in name":          {`{"tenants":[{"name":"a/b","mercure":{}}]}`, false},
		"unicode name":           {`{"tenants":[{"name":"é","mercure":{}}]}`, false},
		"long name":              {`{"tenants":[{"name":"` + strings.Repeat("a", 129) + `","mercure":{}}]}`, false},
		"no settings":            {`{"tenants":[{"name":"a"}]}`, false},
		"hosts without mercure":  {`{"tenants":[{"name":"a","hosts":["a.example"]}]}`, false},
		"nats is gone":           {`{"tenants":[{"name":"a","hosts":["a.test"],"mercure":{},"nats":{"users":[]}}]}`, false},
		"unknown tenant field":   {`{"tenants":[{"name":"a","mercure":{},"account":"b"}]}`, false},
		"unknown mercure field":  {`{"tenants":[{"name":"a","mercure":{"publisher_secret":"x"}}]}`, false},
		"unknown top-level":      {`{"tenants":[],"default":{}}`, false},
		"trailing data":          {`{"tenants":[]} {"tenants":[]}`, false},
		"not json":               {`tenants:`, false},
		"wrong type":             {`{"tenants":{"name":"a"}}`, false},
		"default is not allowed": {`{"tenants":[{"name":"","mercure":{}}]}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseTenants([]byte(tc.json))
			if (err == nil) != tc.ok {
				t.Fatalf("parseTenants: %v, want ok %v", err, tc.ok)
			}
		})
	}
}

// writeTenants writes a tenants file.
func writeTenants(t testing.TB, specs ...tenantSpec) string {
	t.Helper()
	b, err := json.Marshal(tenantsFile{Tenants: specs})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "tenants.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTenantsSettingsErrors(t *testing.T) {
	mk := func(specs ...tenantSpec) func(*Settings) {
		return func(s *Settings) { s.TenantsFile = writeTenants(t, specs...) }
	}
	for name, mod := range map[string]func(*Settings){
		"missing file": func(s *Settings) { s.TenantsFile = filepath.Join(t.TempDir(), "nope.json") },
		"shared key": mk(tenantSpec{Name: "a", Hosts: []string{"a.test"}, Mercure: &tenantMercure{PublisherKey: "k1"}},
			tenantSpec{Name: "b", Hosts: []string{"b.test"}, Mercure: &tenantMercure{PublisherKey: "k1"}}),
		"mercure tenant without hosts":    mk(tenantSpec{Name: "a", Mercure: &tenantMercure{PublisherKey: "k1"}}),
		"one mercure tenant without host": mk(tenantSpec{Name: "a", Hosts: []string{"a.test"}, Mercure: &tenantMercure{PublisherKey: "k1"}}, tenantSpec{Name: "b", Mercure: &tenantMercure{PublisherKey: "k2"}}),
		"hosts without mercure":           mk(tenantSpec{Name: "a", Hosts: []string{"a.test"}}),
		"host with a port":                mk(tenantSpec{Name: "a", Hosts: []string{"a.test:8080"}, Mercure: &tenantMercure{PublisherKey: "k1"}}),
		"subscriber key is the other's publisher key": mk(tenantSpec{Name: "a", Hosts: []string{"a.test"}, Mercure: &tenantMercure{PublisherKey: "k1"}},
			tenantSpec{Name: "b", Hosts: []string{"b.test"}, Mercure: &tenantMercure{PublisherKey: "k2", SubscriberKey: "k1"}}),
		"shared host": mk(tenantSpec{Name: "a", Hosts: []string{"h.test"}, Mercure: &tenantMercure{PublisherKey: "k1"}},
			tenantSpec{Name: "b", Hosts: []string{"H.test"}, Mercure: &tenantMercure{PublisherKey: "k2"}}),
	} {
		t.Run(name, func(t *testing.T) {
			s := settings()
			s.PublisherKey, s.Anonymous = "", false // the tenants', or New refuses them for that alone
			mod(&s)
			srv, err := New(s, nil)
			if err == nil {
				srv.Close(context.Background())
				t.Fatal("New accepted the tenants")
			}
		})
	}
}

// TestTenantsRefuseServerMercureSettings: with tenants the server's own Mercure keys and anonymous access
// belong to no hub, so they are refused; each tenant has its own in the tenants file. Without them the server runs
// tenants only (no hub of its own).
func TestTenantsRefuseServerMercureSettings(t *testing.T) {
	file := writeTenants(t, tenantSpec{Name: "a", Hosts: []string{"a.test"}, Mercure: &tenantMercure{PublisherKey: "tenant-a-secret-0123456789abcdef0123"}})
	base := func() Settings {
		s := Defaults()
		s.TenantsFile = file
		return s
	}
	srv, err := New(base(), nil)
	if err != nil {
		t.Fatalf("tenants alone: %v", err)
	}
	if srv.Hub != nil || srv.Tenants == nil {
		t.Errorf("Hub %v, Tenants %v: want only the tenants", srv.Hub, srv.Tenants)
	}
	srv.Close(context.Background())
	for name, mod := range map[string]func(*Settings){
		"publisher-key":        func(s *Settings) { s.PublisherKey = secret },
		"publisher-jwks-url":   func(s *Settings) { s.PublisherJWKS = "https://idp.example/jwks" },
		"subscriber-key":       func(s *Settings) { s.SubscriberKey = secret },
		"subscriber-jwks-url":  func(s *Settings) { s.SubscriberJWKS = "https://idp.example/jwks" },
		"authorization-server": func(s *Settings) { s.AuthServers = []string{"https://idp.example"} },
		"resource-identifier":  func(s *Settings) { s.ResourceID = "https://hub.example/.well-known/mercure" },
		"hub-url":              func(s *Settings) { s.HubURL = "https://hub.example/.well-known/mercure" },
		"anonymous":            func(s *Settings) { s.Anonymous = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := base()
			mod(&s)
			srv, err := New(s, nil)
			if err == nil {
				srv.Close(context.Background())
				t.Fatal("New accepted the server's own Mercure setting alongside tenants")
			}
		})
	}
}

// ---- helpers ---------------------------------------------------------------------------------------------------

// tn describes a tenant of the end-to-end tests.
type tn struct {
	name      string
	host      string
	secret    string // draft-07 key of the tenant's Mercure hub
	anonymous bool
	subs      bool
}

func (d tn) label() string { return d.name }

func (d tn) spec(t testing.TB) tenantSpec {
	t.Helper()
	return tenantSpec{Name: d.name, Hosts: []string{d.host}, Mercure: &tenantMercure{PublisherKey: d.secret, Anonymous: d.anonymous, Subscriptions: d.subs}}
}

// newTN is a tenant whose host is its name under .test.
func newTN(t testing.TB, name string, anonymous, subs bool) tn {
	return tn{name: name, host: name + ".test", secret: "tenant-secret-" + name + "-0123456789abcdef0123456789", anonymous: anonymous, subs: subs}
}

// tenantToken is a draft-07 token with the grants.
func tenantToken(t testing.TB, secret string, pub, sub []string) string {
	t.Helper()
	m := map[string]any{}
	if pub != nil {
		m["publish"] = pub
	}
	if sub != nil {
		m["subscribe"] = sub
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": m, "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (d tn) token(t testing.TB, pub, sub []string) string { return tenantToken(t, d.secret, pub, sub) }

// tnStream is an SSE stream of a node, collecting its events.
type tnStream struct {
	mu     sync.Mutex
	events []string
	ids    []string
	closed chan struct{}
	cancel context.CancelFunc
}

// openStream subscribes at base; host overrides the Host header, tok is a bearer token, lastID a Last-Event-ID.
func openStream(t testing.TB, base, host, tok string, q url.Values, lastID string) *tnStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/mercure?"+q.Encode(), nil)
	if host != "" {
		req.Host = host
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		cancel()
		t.Fatalf("subscribe %s host=%q: %d", base, host, resp.StatusCode)
	}
	s := &tnStream{closed: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(s.closed)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if d, ok := strings.CutPrefix(line, "data: "); ok {
				s.mu.Lock()
				s.events = append(s.events, d)
				s.mu.Unlock()
			} else if id, ok := strings.CutPrefix(line, "id: "); ok {
				s.mu.Lock()
				s.ids = append(s.ids, id)
				s.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-s.closed })
	return s
}

func (s *tnStream) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

// real returns the events that are neither probes nor subscription events.
func (s *tnStream) real() []string {
	var out []string
	for _, e := range s.got() {
		if !strings.HasPrefix(e, "probe|") && !strings.Contains(e, `"subscriber":`) {
			out = append(out, e)
		}
	}
	return out
}

// subscriptionEvents returns the subscription events the stream received.
func (s *tnStream) subscriptionEvents() []string {
	var out []string
	for _, e := range s.got() {
		if strings.Contains(e, `"subscriber":`) {
			out = append(out, e)
		}
	}
	return out
}

// postForm publishes at base with a token; host overrides the Host header.
func postForm(t testing.TB, base, host, tok string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/.well-known/mercure", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if host != "" {
		req.Host = host
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err) // callable from any goroutine
		return -1, ""
	}
	defer resp.Body.Close()
	b := new(strings.Builder)
	_, _ = bufio.NewReader(resp.Body).WriteTo(b)
	return resp.StatusCode, b.String()
}

func mustPost(t testing.TB, base, host, tok string, form url.Values) string {
	t.Helper()
	code, body := postForm(t, base, host, tok, form)
	if code != 200 {
		t.Fatalf("publish at %s (host %q): %d %s", base, host, code, body)
	}
	return body
}

func getWith(t testing.TB, base, host, path, tok string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if host != "" {
		req.Host = host
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := new(strings.Builder)
	_, _ = bufio.NewReader(resp.Body).WriteTo(b)
	return resp.StatusCode, b.String()
}

// tenantSettings are the settings of a node of the tenants tests. The server has no Mercure keys of its own (every
// hub is a tenant's).
func tenantSettings(t testing.TB, file string) Settings {
	return tenantSettingsFrom(settings(), file)
}

const sharedTopic = "https://shared.example/doc"

// ---- single node -----------------------------------------------------------------------------------------------

func TestTenantsSingleNode(t *testing.T) {
	tenants := []tn{newTN(t, "umbra", true, false), newTN(t, "acme", false, false), newTN(t, "globex", true, false),
		newTN(t, "initech", false, false)}
	var specs []tenantSpec
	for _, d := range tenants {
		specs = append(specs, d.spec(t))
	}
	n := startNode(t, tenantSettings(t, writeTenants(t, specs...)))

	// Mercure: every tenant has an anonymous (where it allows) and a token subscriber, and publishes the same topic
	// publicly and privately.
	type watch struct {
		d    tn
		name string
		s    *tnStream
		want []string
	}
	var watches []watch
	for _, d := range tenants {
		pub, priv := d.label()+"|public", d.label()+"|private"
		wide := d.token(t, nil, []string{"*"})
		narrow := d.token(t, nil, []string{"https://shared.example/other"})
		watches = append(watches,
			watch{d, "token *", openStream(t, n.base, d.host, wide, url.Values{"topic": {sharedTopic}}, ""), []string{pub, priv}},
			watch{d, "token elsewhere", openStream(t, n.base, d.host, narrow, url.Values{"topic": {"*"}}, ""), []string{pub}})
		if d.anonymous {
			watches = append(watches, watch{d, "anonymous", openStream(t, n.base, d.host, "", url.Values{"topic": {sharedTopic}}, ""), []string{pub}})
		}
	}
	for _, d := range tenants {
		tok := d.token(t, []string{"*"}, nil)
		mustPost(t, n.base, d.host, tok, url.Values{"topic": {sharedTopic}, "data": {d.label() + "|public"}})
		mustPost(t, n.base, d.host, tok, url.Values{"topic": {sharedTopic}, "data": {d.label() + "|private"}, "private": {"on"}})
	}
	// A tenant's token with every grant, presented on another tenant's host, publishes nowhere.
	acmeTok := tenants[1].token(t, []string{"*"}, nil)
	for _, host := range []string{"globex.test", "umbra.test", "initech.test"} {
		if code, _ := postForm(t, n.base, host, acmeTok, url.Values{"topic": {sharedTopic}, "data": {"acme|leak"}}); code != 401 {
			t.Errorf("acme token on %s: %d", host, code)
		}
	}
	// No tenant has the host: 404, with any token (a tenant's own included), for publishing and subscribing alike.
	for _, host := range []string{"", "unknown.test", "acme.example", "acme.test.evil"} {
		for _, tok := range []string{"", acmeTok, tenants[1].token(t, nil, []string{"*"})} {
			if code, _ := postForm(t, n.base, host, tok, url.Values{"topic": {sharedTopic}, "data": {"acme|leak"}}); code != 404 {
				t.Errorf("publish on host %q: %d, want 404", host, code)
			}
			if code, _ := getWith(t, n.base, host, "/.well-known/mercure?topic=*", tok); code != 404 {
				t.Errorf("subscribe on host %q: %d, want 404", host, code)
			}
		}
	}
	time.Sleep(400 * time.Millisecond)
	for _, w := range watches {
		if got := w.s.got(); !slices.Equal(got, w.want) {
			t.Errorf("%s %s received %q, want %q", w.d.label(), w.name, got, w.want)
		}
	}

	// The counters add up over the tenants (metrics are the node's).
	if v, _ := metricValue(metricsText(t, n.base), "gossiper_published_total"); v != fmt.Sprint(2*len(tenants)) {
		t.Errorf("published_total = %q, want %d", v, 2*len(tenants))
	}
}

// TestTenantsSubscriptionsOnOneNode: the subscriptions API lists a tenant's subscribers only.
func TestTenantsSubscriptionsOnOneNode(t *testing.T) {
	a, b, c := newTN(t, "acme", false, true), newTN(t, "globex", false, true), newTN(t, "initech", false, true)
	s := tenantSettings(t, writeTenants(t, a.spec(t), b.spec(t), c.spec(t)))
	s.Subscriptions = true
	n := startNode(t, s)
	for _, d := range []tn{a, b, c} {
		openStream(t, n.base, d.host, d.token(t, nil, []string{"*"}), url.Values{"topic": {"https://shared.example/" + d.name + "-only"}}, "")
	}
	for _, d := range []tn{a, b, c} {
		code, body := getWith(t, n.base, d.host, "/.well-known/mercure/subscriptions", d.token(t, nil, []string{"*"}))
		if code != 200 {
			t.Fatalf("%s: %d %s", d.label(), code, body)
		}
		for _, other := range []string{"acme", "globex", "initech"} {
			has := strings.Contains(body, other+"-only")
			if has != (other == d.label()) {
				t.Errorf("%s's subscriptions list %s: %v\n%s", d.label(), other, has, body)
			}
		}
	}
	// A tenant's token on another's host, or on a host no tenant has, lists nothing.
	if code, body := getWith(t, n.base, b.host, "/.well-known/mercure/subscriptions", a.token(t, nil, []string{"*"})); code != 401 {
		t.Errorf("acme's token on globex's host: %d %s", code, body)
	}
	if code, body := getWith(t, n.base, "", "/.well-known/mercure/subscriptions", a.token(t, nil, []string{"*"})); code != 404 {
		t.Errorf("acme's token on no tenant's host: %d %s", code, body)
	}
}

// ---- clusters -----------------------------------------------------------------------------------------------

// waitMeshed waits until an update published on node 0 for the tenant reaches the tenant's streams on the others.
func waitMeshed(t *testing.T, d tn, nodes []*node, topic string, streams []*tnStream) {
	t.Helper()
	tok := d.token(t, []string{"*"}, nil)
	eventually(t, 20*time.Second, "tenant "+d.label()+" to mesh", func() bool {
		mustPost(t, nodes[0].base, d.host, tok, url.Values{"topic": {topic}, "data": {"probe|" + d.label()}})
		time.Sleep(100 * time.Millisecond)
		for _, s := range streams {
			if len(s.got()) == 0 {
				return false
			}
		}
		return true
	})
}

func fileWithout(t testing.TB, drop string, tenants []tn) string {
	var specs []tenantSpec
	for _, d := range tenants {
		if d.name != drop {
			specs = append(specs, d.spec(t))
		}
	}
	return writeTenants(t, specs...)
}

// TestTenantsFastCluster: three nodes with the tenants file, one of which lacks a tenant. Mercure updates published
// on one node reach the tenant's subscribers on the others, and nobody else's; the subscriptions API of a node lists
// the tenant's subscribers of every node and no other tenant's.
func TestTenantsFastCluster(t *testing.T) {
	tenants := []tn{newTN(t, "umbra", true, true), newTN(t, "acme", false, true), newTN(t, "globex", true, true),
		newTN(t, "initech", false, true)}
	full, short := fileWithout(t, "", tenants), fileWithout(t, "initech", tenants)
	nodes := clusterNodes(t, 3, func(i int, s *Settings) {
		*s = tenantSettingsFrom(*s, full)
		if i == 2 {
			s.TenantsFile = short // this node does not have initech yet
		}
	})
	if nodes[2].Tenants.Hub("initech") != nil || nodes[0].Tenants.Hub("initech") == nil {
		t.Fatal("tenants of the nodes")
	}
	// One subscriber per tenant on every node that has it, with a wide token.
	streams := map[string][]*tnStream{}
	for ni, nd := range nodes {
		for _, d := range tenants {
			if d.name == "initech" && ni == 2 {
				continue
			}
			streams[d.name] = append(streams[d.name], openStream(t, nd.base, d.host, d.token(t, nil, []string{"*"}), url.Values{"topic": {"*"}}, ""))
		}
	}
	for _, d := range tenants {
		waitMeshed(t, d, nodes, "https://probe.example/p", streams[d.name][1:])
	}
	// Publish on node 1 (and on others), each tenant, the same topic; public and private.
	for i, d := range tenants {
		nd := nodes[i%3]
		if d.name == "initech" && i%3 == 2 {
			nd = nodes[0]
		}
		tok := d.token(t, []string{"*"}, nil)
		mustPost(t, nd.base, d.host, tok, url.Values{"topic": {sharedTopic}, "data": {d.label() + "|public"}})
		mustPost(t, nd.base, d.host, tok, url.Values{"topic": {sharedTopic}, "data": {d.label() + "|private"}, "private": {"on"}})
	}
	time.Sleep(time.Second)
	for _, d := range tenants {
		for i, s := range streams[d.name] {
			want := []string{d.label() + "|public", d.label() + "|private"}
			got := s.real()
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s subscriber %d received %q, want %q", d.label(), i, got, want)
			}
			// It can be told of the subscribers of its own tenant that connected after it (itself included), on every
			// node, and of nobody else's. (Those that connected before the nodes met reached nobody: at most.)
			max := len(streams[d.name]) - i
			if d.name == "" { // the default tenant's subscription events are off
				max = 0
			}
			if n := len(s.subscriptionEvents()); n > max {
				t.Errorf("%s subscriber %d received %d subscription events, at most %d are its tenant's", d.label(), i, n, max)
			}
		}
	}
	// The cluster's node without the tenant still serves the others, and has no hub at the missing tenant's host.
	if code, _ := postForm(t, nodes[2].base, "initech.test", tenants[3].token(t, []string{"*"}, nil), url.Values{"topic": {"x"}, "data": {"y"}}); code != 404 {
		t.Errorf("the node without initech, at its host: %d, want 404", code)
	}
	if code, _ := postForm(t, nodes[2].base, "", tenants[3].token(t, []string{"*"}, nil), url.Values{"topic": {"x"}, "data": {"y"}}); code != 404 {
		t.Errorf("the node without initech, with no host: %d, want 404", code)
	}
	// The subscriptions API of node 0 lists each tenant's subscribers of every node, and only its own.
	for _, d := range tenants {
		body := ""
		eventually(t, 10*time.Second, "subscriptions of "+d.label(), func() bool {
			var code int
			code, body = getWith(t, nodes[0].base, d.host, "/.well-known/mercure/subscriptions", d.token(t, nil, []string{"*"}))
			want := 3
			if d.name == "initech" {
				want = 2
			}
			return code == 200 && strings.Count(body, `"topic":"*"`) == want
		})
		var doc struct {
			Subscriptions []map[string]any `json:"subscriptions"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatal(err)
		}
		subscribers := map[string]bool{}
		for _, s := range doc.Subscriptions {
			subscribers[fmt.Sprint(s["subscriber"])] = true
		}
		if len(subscribers) != len(streams[d.name]) {
			t.Errorf("%s: %d subscribers listed, want %d", d.label(), len(subscribers), len(streams[d.name]))
		}
	}

}

// tenantSettingsFrom adds the tenants test settings to s (a node of clusterNodes).
func tenantSettingsFrom(s Settings, file string) Settings {
	s.PublisherKey, s.Anonymous = "", false
	s.TenantsFile = file
	return s
}

// ---- history database -----------------------------------------------------------------------------------------

// TestTenantsHistoryDBRestart: a node with a history database that restarts replays each tenant's history to that
// tenant only.
func TestTenantsHistoryDBRestart(t *testing.T) {
	tenants := []tn{newTN(t, "umbra", true, false), newTN(t, "acme", false, false), newTN(t, "globex", true, false),
		newTN(t, "initech", false, false)}
	file := fileWithout(t, "", tenants)
	s := tenantSettings(t, file)
	s.NodeID = "5b2f1a64-37c2-4c3c-8d2e-0e4f4f3e5a11"
	s.HistoryDB = filepath.Join(t.TempDir(), "history.db")
	waitReady := func(n *node) {
		eventually(t, 15*time.Second, "readyz", func() bool { code, _ := get(t, n.base+"/readyz"); return code == 200 })
	}
	n := startNode(t, s)
	waitReady(n)
	ids := map[string][]string{}
	for _, d := range tenants {
		tok := d.token(t, []string{"*"}, nil)
		for i := range 3 {
			ids[d.name] = append(ids[d.name], mustPost(t, n.base, d.host, tok, url.Values{"topic": {sharedTopic}, "data": {fmt.Sprintf("%s|%d", d.label(), i)}}))
		}
		ids[d.name] = append(ids[d.name], mustPost(t, n.base, d.host, tok, url.Values{"topic": {sharedTopic}, "data": {d.label() + "|private"}, "private": {"on"}}))
	}
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}
	n = startNode(t, s)
	waitReady(n)
	for _, d := range tenants {
		want := []string{d.label() + "|0", d.label() + "|1", d.label() + "|2"}
		wantAll := append(slices.Clone(want), d.label()+"|private")
		wide := d.token(t, nil, []string{"*"})
		var anon *tnStream
		if d.anonymous {
			anon = openStream(t, n.base, d.host, "", url.Values{"topic": {"*"}}, "earliest")
		}
		all := openStream(t, n.base, d.host, wide, url.Values{"topic": {"*"}}, "earliest")
		fromFirst := openStream(t, n.base, d.host, wide, url.Values{"topic": {"*"}}, ids[d.name][0])
		var foreign []*tnStream
		for _, o := range tenants {
			if o.name != d.name {
				// Another tenant's cursor, with this tenant's token: nothing replays.
				foreign = append(foreign, openStream(t, n.base, d.host, wide, url.Values{"topic": {"*"}}, ids[o.name][1]))
			}
		}
		time.Sleep(400 * time.Millisecond)
		if got := all.got(); !slices.Equal(got, wantAll) {
			t.Errorf("%s from earliest: %q, want %q", d.label(), got, wantAll)
		}
		if got := fromFirst.got(); !slices.Equal(got, wantAll[1:]) {
			t.Errorf("%s from its first event: %q, want %q", d.label(), got, wantAll[1:])
		}
		if anon != nil {
			if got := anon.got(); !slices.Equal(got, want) {
				t.Errorf("%s anonymous from earliest: %q, want %q", d.label(), got, want)
			}
		}
		for i, f := range foreign {
			if got := f.got(); len(got) != 0 {
				t.Errorf("%s with another tenant's cursor (%d): %q", d.label(), i, got)
			}
		}
	}
}

// ---- mixed load -----------------------------------------------------------------------------------------------

// TestTenantsMixedLoad: many tenants publish at once on a cluster; nothing crosses.
func TestTenantsMixedLoad(t *testing.T) {
	const tenantCount, msgs = 6, 25
	var tenants []tn
	var specs []tenantSpec
	for i := range tenantCount {
		d := newTN(t, fmt.Sprintf("t%d", i), i%2 == 0, false)
		tenants = append(tenants, d)
		specs = append(specs, d.spec(t))
	}
	nodes := clusterNodes(t, 3, func(i int, s *Settings) { *s = tenantSettingsFrom(*s, writeTenants(t, specs...)) })
	// A subscriber of every tenant on every node.
	type mw struct {
		d tn
		s *tnStream
	}
	var ms []mw
	for _, nd := range nodes {
		for _, d := range tenants {
			ms = append(ms, mw{d, openStream(t, nd.base, d.host, d.token(t, nil, []string{"*"}), url.Values{"topic": {"https://load.example/{id}"}}, "")})
		}
	}
	// Let the cluster mesh (probes are filtered out by their marker).
	for _, d := range tenants {
		var others []*tnStream
		for _, w := range ms[len(tenants):] { // the streams of the nodes after the first
			if w.d.name == d.name {
				others = append(others, w.s)
			}
		}
		waitMeshed(t, d, nodes, "https://load.example/probe", others)
	}
	type publisher struct {
		d   tn
		pi  int
		tok string
	}
	var pubs []*publisher
	for _, d := range tenants {
		for pi := range 3 {
			pubs = append(pubs, &publisher{d: d, pi: pi, tok: d.token(t, []string{"*"}, nil)})
		}
	}
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var errs []string
	for _, p := range pubs {
		wg.Go(func() {
			for i := range msgs {
				code, body := postForm(t, nodes[(p.pi+i)%3].base, p.d.host, p.tok, url.Values{"topic": {fmt.Sprintf("https://load.example/%d", i%4)},
					"data": {fmt.Sprintf("%s|%d|%d", p.d.label(), p.pi, i)}, "private": {[]string{"", "on"}[i%2]}})
				if code != 200 {
					errMu.Lock()
					errs = append(errs, fmt.Sprintf("publish %s: %d %s", p.d.label(), code, body))
					errMu.Unlock()
					return
				}
			}
		})
	}
	wg.Wait()
	for _, e := range errs {
		t.Error(e)
	}
	want := 3 * msgs
	eventually(t, 30*time.Second, "all deliveries", func() bool {
		for _, w := range ms {
			if len(w.s.real()) < want {
				return false
			}
		}
		return true
	})
	time.Sleep(time.Second)
	for _, w := range ms {
		got := w.s.real()
		if len(got) != want {
			t.Errorf("subscriber of %s got %d, want %d", w.d.label(), len(got), want)
		}
		for _, g := range got {
			if !strings.HasPrefix(g, w.d.label()+"|") {
				t.Errorf("subscriber of %s got %q", w.d.label(), g)
			}
		}
	}

}

// TestTenantsMixedWithPlainNode: a node that runs no tenants (its tenants file is missing, say) in a cluster with
// nodes that do shows its subscribers its own hub's updates only, never a tenant's, and the tenant nodes show their
// subscribers their tenant's updates only, never the plain node's.
func TestTenantsMixedWithPlainNode(t *testing.T) {
	tenants := []tn{newTN(t, "acme", true, false), newTN(t, "globex", true, false)}
	file := fileWithout(t, "", tenants)
	nodes := clusterNodes(t, 3, func(i int, s *Settings) {
		if i < 2 {
			*s = tenantSettingsFrom(*s, file)
		}
	})
	if nodes[2].Tenants != nil || nodes[2].Hub == nil {
		t.Fatal("node 3 runs tenants")
	}
	plain := openStream(t, nodes[2].base, "", "", url.Values{"topic": {"*"}}, "")
	plainAsAcme := openStream(t, nodes[2].base, "acme.test", "", url.Values{"topic": {"*"}}, "") // the host means nothing to it
	acme0 := openStream(t, nodes[0].base, "acme.test", "", url.Values{"topic": {"*"}}, "")
	acme1 := openStream(t, nodes[1].base, "acme.test", "", url.Values{"topic": {"*"}}, "")
	globex1 := openStream(t, nodes[1].base, "globex.test", "", url.Values{"topic": {"*"}}, "")
	acmeTok, globexTok, plainTok := tenants[0].token(t, []string{"*"}, nil), tenants[1].token(t, []string{"*"}, nil), tenantToken(t, secret, []string{"*"}, nil)
	eventually(t, 20*time.Second, "the nodes to mesh", func() bool {
		mustPost(t, nodes[0].base, "acme.test", acmeTok, url.Values{"topic": {"https://probe.example/p"}, "data": {"probe|a"}})
		time.Sleep(100 * time.Millisecond)
		return len(acme1.got()) > 0
	})
	time.Sleep(500 * time.Millisecond)
	mustPost(t, nodes[0].base, "acme.test", acmeTok, url.Values{"topic": {sharedTopic}, "data": {"acme|secret"}})
	mustPost(t, nodes[1].base, "acme.test", acmeTok, url.Values{"topic": {sharedTopic}, "data": {"acme|secret2"}})
	mustPost(t, nodes[0].base, "globex.test", globexTok, url.Values{"topic": {sharedTopic}, "data": {"globex|public"}})
	mustPost(t, nodes[2].base, "", plainTok, url.Values{"topic": {sharedTopic}, "data": {"plain|from-plain"}})
	mustPost(t, nodes[2].base, "acme.test", plainTok, url.Values{"topic": {sharedTopic}, "data": {"plain|from-plain2"}}) // its host means nothing
	time.Sleep(time.Second)
	for name, s := range map[string]*tnStream{"plain": plain, "plain via the acme host": plainAsAcme} {
		got := s.real()
		slices.Sort(got)
		if !slices.Equal(got, []string{"plain|from-plain", "plain|from-plain2"}) {
			t.Errorf("%s subscriber received %q", name, got)
		}
	}
	for name, s := range map[string]*tnStream{"acme on node 0": acme0, "acme on node 1": acme1} {
		got := s.real()
		slices.Sort(got)
		if !slices.Equal(got, []string{"acme|secret", "acme|secret2"}) {
			t.Errorf("%s subscriber received %q, want its two updates", name, got)
		}
	}
	if got := globex1.real(); !slices.Equal(got, []string{"globex|public"}) {
		t.Errorf("globex subscriber received %q", got)
	}

}

// Each tenant's browser origins are its own: a page of one tenant gets no CORS grant from another tenant's hub.
func TestTenantsCORSOrigins(t *testing.T) {
	a, b := newTN(t, "acme", true, false), newTN(t, "globex", true, false)
	sa, sb := a.spec(t), b.spec(t)
	sa.Mercure.CORSOrigins = []string{"https://app.acme.example"}
	sb.Mercure.CORSOrigins, sb.Mercure.CookieName = []string{"https://app.globex.example"}, "globexAuth"
	n := startNode(t, tenantSettings(t, writeTenants(t, sa, sb)))
	allowed := func(host, origin string) string {
		req, _ := http.NewRequest(http.MethodGet, n.base+"/.well-known/mercure?topic=x", nil)
		req.Host = host
		req.Header.Set("Origin", origin)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		resp, err := http.DefaultClient.Do(req.WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("Access-Control-Allow-Origin")
	}
	if got := allowed(a.host, "https://app.acme.example"); got != "https://app.acme.example" {
		t.Errorf("acme's own origin: %q", got)
	}
	if got := allowed(a.host, "https://app.globex.example"); got != "" {
		t.Errorf("globex's origin on acme's hub: %q", got)
	}
	if got := allowed(b.host, "https://app.globex.example"); got != "https://app.globex.example" {
		t.Errorf("globex's own origin: %q", got)
	}
	if n.Tenants.Hub("globex") == nil {
		t.Fatal("no globex hub")
	}
}
