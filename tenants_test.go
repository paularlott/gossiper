package gossiper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
)

// settle is how long a test waits before it concludes that something it expects not to arrive never will.
const tnSettle = 400 * time.Millisecond

// tnPublication is one update every tenant publishes.
type tnPublication struct {
	topic   string
	private bool
	tag     string
}

var tnPublications = []tnPublication{
	{tnB1, false, "pub-b1"}, {tnB1, true, "priv-b1"}, {tnB2, false, "pub-b2"}, {tnB2, true, "priv-b2"}, {tnNews, false, "pub-news"},
}

// tnData is the data of a tenant's publication: it names the tenant, so a delivery to another tenant shows.
func tnData(tenant string, p tnPublication) string {
	return tenant + "|" + p.tag
}

// tnSelector is a way of subscribing and the topics it selects.
type tnSelector struct {
	name   string
	method string
	q      url.Values
	topics []string
}

var tnAll = []string{tnB1, tnB2, tnNews}

var tnSelectors = []tnSelector{
	{"topic=*", "GET", url.Values{"topic": {"*"}}, tnAll},
	{"topic exact", "GET", url.Values{"topic": {tnB1}}, []string{tnB1}},
	{"topic template", "GET", url.Values{"topic": {"https://shared.example/books/{id}"}}, []string{tnB1, tnB2}},
	{"match", "GET", url.Values{"match": {tnB1}}, []string{tnB1}},
	{"match_exact", "GET", url.Values{"match_exact": {tnB1}}, []string{tnB1}},
	{"match_urlpattern", "GET", url.Values{"match_urlpattern": {"https://shared.example/books/:id"}}, []string{tnB1, tnB2}},
	{"match=*", "GET", url.Values{"match": {"*"}}, tnAll},
	{"QUERY topic=*", methodQuery, url.Values{"topic": {"*"}}, tnAll},
	{"QUERY template", methodQuery, url.Values{"topic": {"https://shared.example/books/{id}"}}, []string{tnB1, tnB2}},
	{"QUERY match_urlpattern", methodQuery, url.Values{"match_urlpattern": {"https://shared.example/*"}}, tnAll},
}

// tnExpected is the data a subscriber of tenant, with the selector and grant ("" anonymous, "all", "b1"), is sent
// for the tnPublications.
func tnExpected(tenant string, sel tnSelector, grant string) []string {
	var out []string
	for _, p := range tnPublications {
		if !slices.Contains(sel.topics, p.topic) {
			continue
		}
		if p.private && !(grant == "all" || grant == "b1" && p.topic == tnB1) {
			continue
		}
		out = append(out, tnData(tenant, p))
	}
	return out
}

var tnVias = []string{"header", "query", "cookie", "cookie2"}

// tnStream is an open subscription and what it must receive.
type tnStream struct {
	desc string
	c    *sseClient
	want []string
}

// openStreams opens the subscribers of tenant d: draft-07 and Mercure 1.0 tokens, with a wide and a narrow
// subscribe grant, every selector and each token presentation in turn, all addressed to the tenant's host.
func (f *tnFixture) openStreams(d *tnTenant) []tnStream {
	f.t.Helper()
	var out []tnStream
	n := 0
	for ki, kind := range []string{"draft", "modern"} {
		for gi, grant := range []string{"all", "b1"} {
			var tok string
			switch {
			case kind == "draft" && grant == "all":
				tok = d.draft(f.t, roleSubscriber, nil, []string{"*"})
			case kind == "draft":
				tok = d.draft(f.t, roleSubscriber, nil, []string{tnB1})
			case grant == "all":
				tok = d.modern(f.t, roleSubscriber, f.srv.URL, subOnly, "*")
			default:
				tok = d.modern(f.t, roleSubscriber, f.srv.URL, subOnly, tnB1)
			}
			sels := tnSelectors
			if grant == "b1" {
				sels = tnSelectors[:5]
			}
			for si, sel := range sels {
				n++
				r := tnReq{d: d, method: sel.method, tok: tok, via: tnVias[(si+ki+gi)%len(tnVias)], q: sel.q}
				desc := fmt.Sprintf("%s/%s/%s/%s/%s host=%q", d.name, kind, grant, sel.name, r.via, r.host)
				out = append(out, tnStream{desc, f.open(r), tnExpected(d.name, sel, grant)})
			}
		}
	}
	return out
}

// publishAll publishes tnPublications as tenant d, with its publishers in turn: draft-07 and Mercure 1.0 tokens,
// and each presentation.
func (f *tnFixture) publishAll(d *tnTenant) {
	f.t.Helper()
	for i, p := range tnPublications {
		var r tnReq
		switch i % 4 {
		case 0:
			r.tok = d.draft(f.t, rolePublisher, []string{"*"}, nil)
		case 1:
			r.tok = d.modern(f.t, rolePublisher, f.srv.URL, pubOnly, "*")
		case 2:
			r.tok, r.via = d.draft(f.t, rolePublisher, []string{tnB1, tnB2, tnNews}, nil), "query"
		default:
			r.tok, r.via = d.modern(f.t, rolePublisher, f.srv.URL, pubOnly, tnB1, tnB2, tnNews), "cookie2"
		}
		r.d = d
		form := url.Values{"topic": {p.topic}, "data": {tnData(d.name, p)}}
		if p.private {
			form.Set("private", "on")
		}
		if res := f.do(r, form); res.code != 200 {
			f.t.Fatalf("publish %s %s: %d %s", d.name, p.tag, res.code, res.body)
		}
	}
}

// checkStreams waits for the settle time and compares what every stream holds with what it must.
func checkStreams(t *testing.T, streams []tnStream) {
	t.Helper()
	time.Sleep(tnSettle)
	for _, s := range streams {
		got := s.c.received()
		if !slices.Equal(got, s.want) {
			t.Errorf("%s: received %q, want %q", s.desc, got, s.want)
		}
	}
}

// TestTenantsMercureIsolation: every tenant has subscribers of every kind (draft-07 and Mercure 1.0 tokens,
// wide and narrow grants, GET and QUERY, every selector, every token presentation, with and without the tenant's
// host) and publishes updates to the same topic URLs as the others; each subscriber receives exactly its own
// tenant's updates that its selector and grant allow.
func TestTenantsMercureIsolation(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	var streams []tnStream
	for _, d := range f.tenants {
		streams = append(streams, f.openStreams(d)...)
	}
	// Anonymous subscribers: umbra's and globex's through their hosts; acme refuses them.
	for _, sel := range tnSelectors {
		streams = append(streams,
			tnStream{"anonymous umbra " + sel.name, f.open(tnReq{method: sel.method, q: sel.q, host: "umbra.test"}), tnExpected("umbra", sel, "")},
			tnStream{"anonymous globex " + sel.name, f.open(tnReq{method: sel.method, q: sel.q, host: "globex.test"}), tnExpected("globex", sel, "")})
		if c, res := f.tryOpen(tnReq{method: sel.method, q: sel.q, host: "acme.test"}); c != nil || res.code != 401 {
			t.Errorf("anonymous subscriber of acme (%s): %d, want 401", sel.name, res.code)
		}
	}
	for _, d := range f.tenants {
		f.publishAll(d)
	}
	checkStreams(t, streams)
	if len(streams) < 150 {
		t.Fatalf("only %d streams", len(streams))
	}
	for _, d := range f.tenants {
		h := f.ts.Hub(d.name)
		if got := h.Stats().Applied; got != uint64(len(tnPublications)) {
			t.Errorf("tenant %q applied %d updates, want %d", d.name, got, len(tnPublications))
		}
	}
}

// TestTenantsPublishCannotCrossTenants: a publisher token with every grant, of one tenant, reaches that tenant's
// subscribers only, whatever it is presented with, and a token for another tenant is refused on any tenant's host.
func TestTenantsPublishCannotCrossTenants(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	var streams []tnStream
	for _, d := range f.tenants {
		sub := d.draft(t, roleSubscriber, nil, []string{"*"})
		streams = append(streams, tnStream{d.name, f.open(tnReq{d: d, tok: sub, q: url.Values{"topic": {"*"}}}), nil})
	}
	acme := f.byName("acme")
	tok := acme.draft(t, rolePublisher, []string{"*"}, nil)
	modern := acme.modern(t, rolePublisher, f.srv.URL, pubOnly, "*")
	form := func(data string) url.Values { return url.Values{"topic": {tnB1}, "data": {data}} }
	for _, host := range []string{"acme.test", "ACME.test:8080"} {
		for _, tk := range []string{tok, modern} {
			if res := f.do(tnReq{tok: tk, host: host}, form("from-acme")); res.code != 200 {
				t.Fatalf("acme publish (host %q): %d %s", host, res.code, res.body)
			}
		}
	}
	for _, host := range []string{"globex.test", "umbra.test", "initech.test", "hooli.test"} {
		for _, tk := range []string{tok, modern} {
			if res := f.do(tnReq{tok: tk, host: host}, form("acme-token-elsewhere")); res.code != 401 {
				t.Errorf("acme token on %s: %d, want 401", host, res.code)
			}
		}
		for _, via := range []string{"header", "query", "cookie"} {
			if res := f.do(tnReq{tok: tok, host: host, via: via}, form("acme-token-elsewhere")); res.code != 401 {
				t.Errorf("acme token on %s (%s): %d, want 401", host, via, res.code)
			}
		}
	}
	time.Sleep(tnSettle)
	for _, s := range streams {
		got := s.c.received()
		if s.desc == "acme" {
			if !slices.Equal(got, []string{"from-acme", "from-acme", "from-acme", "from-acme"}) {
				t.Errorf("acme subscriber received %q", got)
			}
		} else if len(got) != 0 {
			t.Errorf("%s subscriber received %q", s.desc, got)
		}
	}
}

// TestTenantsHostRouting: a request for a tenant's host belongs to that tenant, with or without a token; a
// token of another tenant, or none the tenant accepts, is refused there rather than served by another tenant. A
// host no tenant has is refused with 404, whatever token comes with it.
func TestTenantsHostRouting(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	acme, globex, initech, umbra := f.byName("acme"), f.byName("globex"), f.byName("initech"), f.byName("umbra")
	tokens := map[string]string{
		"acme":     acme.draft(t, roleSubscriber, nil, []string{"*"}),
		"acme-m":   acme.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"),
		"globex":   globex.draft(t, roleSubscriber, nil, []string{"*"}),
		"globex-m": globex.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"),
		"initech":  initech.draft(t, roleSubscriber, nil, []string{"*"}),
		"umbra":    umbra.draft(t, roleSubscriber, nil, []string{"*"}),
	}
	q := url.Values{"topic": {"*"}}
	cases := []struct {
		host, token string
		want        int
	}{
		{"acme.test", "acme", 200}, {"acme.test", "acme-m", 200}, {"acme.test", "globex", 401}, {"acme.test", "globex-m", 401},
		{"acme.test", "initech", 401}, {"acme.test", "umbra", 401}, {"acme.test", "", 401},
		{"globex.test", "globex", 200}, {"globex.test", "globex-m", 200}, {"globex.test", "acme", 401},
		{"globex.test", "acme-m", 401}, {"globex.test", "umbra", 401}, {"globex.test", "", 200}, // globex is anonymous
		{"initech.test", "initech", 200}, {"initech.test", "acme", 401}, {"initech.test", "", 401},
		{"umbra.test", "umbra", 200}, {"umbra.test", "initech", 401}, {"umbra.test", "", 200},
		{"GLOBEX.test", "", 200}, {"globex.test:8443", "", 200}, {"acme.test:9", "acme", 200}, {"acme.test:9", "globex", 401},
		{"acme.test.", "acme", 200}, {"ACME.TEST.:80", "acme", 200}, {"acme.test.", "globex", 401}, {"globex.test.", "", 200},
		// No tenant has the host: the token does not matter (it would be good for a tenant, and it is not asked).
		{"", "acme", 404}, {"", "globex", 404}, {"", "initech", 404}, {"", "umbra", 404}, {"", "", 404},
		{"other.test", "acme", 404}, {"other.test", "acme-m", 404}, {"other.test", "", 404},
		{"acme.test.evil", "acme", 404}, {"xacme.test", "acme", 404}, {"test", "acme", 404},
	}
	for _, tc := range cases {
		for _, via := range []string{"header", "query", "cookie"} {
			c, res := f.tryOpen(tnReq{tok: tokens[tc.token], via: via, host: tc.host, q: q})
			if res.code != tc.want {
				t.Errorf("host %q token %q via %s: %d, want %d", tc.host, tc.token, via, res.code, tc.want)
			}
			if c != nil {
				c.close()
			}
		}
	}
	// A refused request is a 404 with the hub's error body and the security headers, for every method.
	for _, r := range []tnReq{{}, {method: methodQuery, q: q}, {method: http.MethodPost, q: q}, {path: subscriptionsPath, tok: tokens["acme"]}, {path: "/anything"}} {
		res := f.do(r, nil)
		if res.code != 404 || !strings.Contains(res.body, "no hub at this host") {
			t.Errorf("unknown host, %+v: %d %q", r, res.code, res.body)
		}
		if res.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("unknown host, %+v: no security headers: %v", r, res.header)
		}
	}
}

// TestTenantsWhichTenantServes: the tenant that serves each request is the one whose host it is addressed to, whatever
// token it carries.
func TestTenantsWhichTenantServes(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	cases := []struct {
		tenant, host string
		tok          func(d *tnTenant) string
		serves       string // the tenant whose hub gets the subscriber
	}{
		{"acme", "", func(d *tnTenant) string { return d.draft(t, roleSubscriber, nil, []string{"*"}) }, "acme"},
		{"acme", "globex.test", func(d *tnTenant) string { return "" }, "globex"},
		{"acme", "umbra.test", func(d *tnTenant) string { return "" }, "umbra"},
		{"initech", "", func(d *tnTenant) string { return d.modern(t, roleSubscriber, f.srv.URL, subOnly, "*") }, "initech"},
		{"hooli", "", func(d *tnTenant) string { return d.modern(t, roleSubscriber, f.srv.URL, subOnly, "*") }, "hooli"},
		{"hooli", "", func(d *tnTenant) string { return d.draft(t, roleSubscriber, nil, []string{"*"}) }, "hooli"},
		{"umbra", "", func(d *tnTenant) string { return "" }, "umbra"},
		{"umbra", "", func(d *tnTenant) string { return d.draft(t, roleSubscriber, nil, []string{"*"}) }, "umbra"},
		{"umbra", "UMBRA.test.", func(d *tnTenant) string { return "" }, "umbra"},
	}
	for i, tc := range cases {
		before := map[string]int64{}
		for _, d := range f.tenants {
			before[d.name] = f.ts.Hub(d.name).stats.Subscribers.Load()
		}
		d := f.byName(tc.tenant)
		c := f.open(tnReq{d: d, tok: tc.tok(d), host: tc.host, q: url.Values{"topic": {"*"}}})
		for _, d := range f.tenants {
			got := f.ts.Hub(d.name).stats.Subscribers.Load() - before[d.name]
			want := int64(0)
			if d.name == tc.serves {
				want = 1
			}
			if got != want {
				t.Errorf("case %d: tenant %q gained %d subscribers, want %d", i, d.name, got, want)
			}
		}
		c.close()
		eventually(t, "streams closed", func() bool {
			for _, d := range f.tenants {
				if f.ts.Hub(d.name).stats.Subscribers.Load() != before[d.name] {
					return false
				}
			}
			return true
		})
	}
}

// TestTenantsTokensAreNotInterchangeable: forged, expired, wrongly signed, wrongly issued and wrongly addressed
// tokens never reach a tenant that did not issue them, even on the hosts of the anonymous tenants.
func TestTenantsTokensAreNotInterchangeable(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	acme, globex, initech, def := f.byName("acme"), f.byName("globex"), f.byName("initech"), f.byName("umbra")
	other := tnHS("some-other-secret-0123456789abcdef0123")
	expired := func(k tnKey) string {
		c := mercureClaims(nil, []string{"*"})
		c["exp"] = time.Now().Add(-time.Hour).Unix()
		return k.sign(t, c, "")
	}
	modernClaims := func(iss, aud string) jwt.MapClaims {
		c := accessClaims(aud, time.Hour, mDetail(subOnly, mBare("*")))
		c["iss"] = iss
		return c
	}
	cases := map[string]string{
		"forged draft-07":                    other.sign(t, mercureClaims(nil, []string{"*"}), ""),
		"forged modern, acme's issuer":       other.sign(t, modernClaims(acme.iss, acme.aud), "at+jwt"),
		"forged modern, default's issuer":    other.sign(t, modernClaims(def.iss, f.srv.URL+hubPath), "at+jwt"),
		"unsigned (alg none)":                strings.Join([]string{"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", "eyJtZXJjdXJlIjp7InN1YnNjcmliZSI6WyIqIl19fQ", ""}, "."),
		"expired acme draft-07":              expired(acme.pubKey),
		"expired default draft-07":           expired(def.pubKey),
		"acme key, globex issuer":            acme.pubKey.sign(t, modernClaims(globex.iss, globex.aud), "at+jwt"),
		"acme key, initech issuer":           acme.pubKey.sign(t, modernClaims(initech.iss, f.srv.URL+hubPath), "at+jwt"),
		"globex key, acme issuer":            globex.subKey.sign(t, modernClaims(acme.iss, acme.aud), "at+jwt"),
		"initech key, default issuer":        initech.pubKey.sign(t, modernClaims(def.iss, f.srv.URL+hubPath), "at+jwt"),
		"default key, acme issuer":           def.pubKey.sign(t, modernClaims(acme.iss, acme.aud), "at+jwt"),
		"acme token for globex's resource":   acme.modernIss(t, roleSubscriber, acme.iss, globex.aud, subOnly, "*"),
		"acme token, default's resource":     acme.modernIss(t, roleSubscriber, acme.iss, f.srv.URL+hubPath, subOnly, "*"),
		"initech token, acme's resource":     initech.modernIss(t, roleSubscriber, initech.iss, acme.aud, subOnly, "*"),
		"initech token, wrong resource":      initech.modernIss(t, roleSubscriber, initech.iss, "https://elsewhere.test"+hubPath, subOnly, "*"),
		"acme's publisher key as subscriber": acme.pubKey.sign(t, mercureClaims(nil, []string{"*"}), ""),
	}
	for name, tok := range cases {
		for _, host := range []string{"acme.test", "globex.test", "initech.test", "umbra.test", "hooli.test"} {
			for _, via := range []string{"header", "query", "cookie", "cookie2"} {
				c, res := f.tryOpen(tnReq{tok: tok, host: host, via: via, q: url.Values{"topic": {"*"}}})
				if c != nil {
					c.close()
					t.Errorf("%s (host %q, %s): accepted", name, host, via)
				} else if res.code != 401 && res.code != 400 {
					t.Errorf("%s (host %q, %s): %d, want 401", name, host, via, res.code)
				}
			}
		}
	}
	// And as publishers.
	for name, tok := range cases {
		for _, host := range []string{"acme.test", "umbra.test", "initech.test"} {
			res := f.do(tnReq{tok: tok, host: host}, url.Values{"topic": {tnB1}, "data": {"forged"}})
			if res.code == 200 {
				t.Errorf("publish with %s (host %q): accepted", name, host)
			}
		}
	}
	for _, d := range f.tenants {
		if n := f.ts.Hub(d.name).Stats().Applied; n != 0 {
			t.Errorf("tenant %q applied %d updates", d.name, n)
		}
	}
}

// TestTenantsUnknownHost: there is no default tenant: a request whose host no tenant has is refused with 404, with no
// token, with a bad one, and with a good token of a tenant, and nothing is published or subscribed.
func TestTenantsUnknownHost(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	q := url.Values{"topic": {"*"}}
	acme, initech := f.byName("acme"), f.byName("initech")
	valid := []string{acme.draft(t, roleSubscriber, nil, []string{"*"}), acme.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"),
		initech.draft(t, roleSubscriber, nil, []string{"*"})}
	for _, host := range []string{"", "unknown.test", "acme.example", "acme"} {
		for _, tok := range append([]string{"", "garbage"}, valid...) {
			if c, res := f.tryOpen(tnReq{q: q, host: host, tok: tok}); c != nil || res.code != 404 {
				t.Errorf("subscribe, host %q token %.12q: %d, want 404", host, tok, res.code)
			}
			if res := f.do(tnReq{host: host, tok: tok}, url.Values{"topic": {"x"}}); res.code != 404 {
				t.Errorf("publish, host %q token %.12q: %d, want 404", host, tok, res.code)
			}
		}
	}
	// A valid publisher token with no matching host publishes nothing.
	pub := acme.draft(t, rolePublisher, []string{"*"}, nil)
	if res := f.do(tnReq{host: "unknown.test", tok: pub}, url.Values{"topic": {tnB1}, "data": {"x"}}); res.code != 404 {
		t.Errorf("publisher token on an unknown host: %d", res.code)
	}
	for _, d := range f.tenants {
		if n := f.ts.Hub(d.name).Stats(); n.Applied != 0 || n.Subscribers != 0 || n.Refused != 0 {
			t.Errorf("tenant %q was reached: %+v", d.name, n)
		}
	}
	// The tenants' own hosts work.
	if c, res := f.tryOpen(tnReq{d: initech, q: q, tok: valid[2]}); c == nil {
		t.Errorf("initech token on its host: %d", res.code)
	}
	if c, res := f.tryOpen(tnReq{q: q, host: "globex.test"}); c == nil { // globex is anonymous on its host
		t.Errorf("globex anonymous: %d", res.code)
	}
	if res := f.do(tnReq{d: acme}, url.Values{"topic": {"x"}}); res.code != 401 {
		t.Errorf("anonymous publish on acme's host: %d", res.code)
	}
}

// TestTenantsInvalidTokenIsNotDowngradedToAnonymous: a bad token on a request to a tenant that accepts anonymous
// subscribers is refused, not served as anonymous.
func TestTenantsInvalidTokenIsNotDowngradedToAnonymous(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	acme := f.byName("acme")
	exp := mercureClaims(nil, []string{"*"})
	exp["exp"] = time.Now().Add(-time.Minute).Unix()
	for name, tok := range map[string]string{"expired": acme.pubKey.sign(t, exp, ""), "garbage": "not.a.jwt", "empty segments": ".."} {
		for _, host := range []string{"globex.test", "umbra.test"} {
			for _, via := range []string{"header", "query", "cookie"} {
				c, res := f.tryOpen(tnReq{tok: tok, via: via, host: host, q: url.Values{"topic": {"*"}}})
				if c != nil {
					c.close()
					t.Errorf("%s via %s on %s: served", name, via, host)
				} else if res.code != 401 && res.code != 400 {
					t.Errorf("%s via %s on %s: %d", name, via, host, res.code)
				}
			}
		}
	}
}

// TestTenantsLastEventID: a subscriber replays its own tenant's history only, whatever cursor it holds, a cursor
// from another tenant (an unknown one) included.
func TestTenantsLastEventID(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	acme, globex := f.byName("acme"), f.byName("globex")
	pub := func(d *tnTenant, data string) string {
		res := f.do(tnReq{d: d, tok: d.draft(t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {tnB1}, "data": {data}})
		if res.code != 200 {
			t.Fatalf("publish: %d %s", res.code, res.body)
		}
		return res.body
	}
	a1, a2 := pub(acme, "acme-1"), pub(acme, "acme-2")
	g1, g2 := pub(globex, "globex-1"), pub(globex, "globex-2")
	sub := func(d *tnTenant, q url.Values, hdr http.Header) []string {
		q.Set("topic", "*")
		c := f.open(tnReq{d: d, tok: d.draft(t, roleSubscriber, nil, []string{"*"}), q: q, hdr: hdr})
		time.Sleep(tnSettle / 2)
		return c.received()
	}
	// The cursor of the tenant's own history.
	if got := sub(acme, url.Values{}, http.Header{"Last-Event-ID": {a1}}); !slices.Equal(got, []string{"acme-2"}) {
		t.Errorf("acme from its own %s: %q", a1, got)
	}
	// A cursor the tenant does not hold replays nothing: never the other tenant's history.
	for _, cursor := range []string{g1, g2} {
		if got := sub(acme, url.Values{}, http.Header{"Last-Event-ID": {cursor}}); len(got) != 0 {
			t.Errorf("acme with globex's cursor %s: %q", cursor, got)
		}
		if got := sub(acme, url.Values{"lastEventID": {cursor}}, nil); len(got) != 0 {
			t.Errorf("acme with globex's cursor %s (query): %q", cursor, got)
		}
		if got := sub(acme, url.Values{"last_event_id": {cursor}}, nil); len(got) != 0 {
			t.Errorf("acme with globex's cursor %s (modern query): %q", cursor, got)
		}
	}
	if got := sub(globex, url.Values{}, http.Header{"Last-Event-ID": {a2}}); len(got) != 0 {
		t.Errorf("globex with acme's cursor: %q", got)
	}
	// "earliest" is every update the tenant holds.
	if got := sub(acme, url.Values{}, http.Header{"Last-Event-ID": {"earliest"}}); !slices.Equal(got, []string{"acme-1", "acme-2"}) {
		t.Errorf("acme from earliest: %q", got)
	}
	if got := sub(globex, url.Values{}, http.Header{"Last-Event-ID": {"earliest"}}); !slices.Equal(got, []string{"globex-1", "globex-2"}) {
		t.Errorf("globex from earliest: %q", got)
	}
	// The same publisher-chosen event ID in two tenants names each tenant's own update.
	for _, d := range []*tnTenant{acme, globex} {
		res := f.do(tnReq{d: d, tok: d.draft(t, rolePublisher, []string{"*"}, nil)}, url.Values{"topic": {tnB1}, "data": {d.name + "-same-id"}, "id": {"urn:same"}})
		if res.code != 200 {
			t.Fatalf("publish: %d %s", res.code, res.body)
		}
		pub(d, d.name+"-after")
	}
	for _, d := range []*tnTenant{acme, globex} {
		if got := sub(d, url.Values{}, http.Header{"Last-Event-ID": {"urn:same"}}); !slices.Equal(got, []string{d.name + "-after"}) {
			t.Errorf("%s from the shared id: %q", d.name, got)
		}
	}
	// A tenant that published nothing holds none of it.
	c := f.open(tnReq{d: f.byName("umbra"), q: url.Values{"topic": {"*"}}, hdr: http.Header{"Last-Event-ID": {"earliest"}}})
	time.Sleep(tnSettle / 2)
	if got := c.received(); len(got) != 0 {
		t.Errorf("umbra replayed %q", got)
	}
}

// tnMarker is the part of a subscription's topic that names its tenant.
func tnMarker(tenant string) string {
	return "shared.example/" + tenant + "-"
}

// TestTenantsSubscriptions: the subscriptions API and the subscription events show a tenant's own subscribers only,
// in both formats.
func TestTenantsSubscriptions(t *testing.T) {
	f := startTenants(t, newTNTenants(t, true), nil)
	// A monitor of every tenant's subscription events (private: its token grants everything), draft-07 and Mercure 1.0.
	monitors := map[*tnTenant][]*sseClient{}
	for _, d := range f.tenants {
		monitors[d] = []*sseClient{
			f.open(tnReq{d: d, tok: d.draft(t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"*"}}}),
			f.open(tnReq{d: d, tok: d.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"), q: url.Values{"match": {"*"}}}),
		}
	}
	time.Sleep(tnSettle / 2)
	for _, cs := range monitors {
		for _, c := range cs {
			c.received() // the monitors' own subscription events
		}
	}
	// Each tenant's subscribers: topics with the tenant's marker, draft-07 and Mercure 1.0, with several selectors.
	for _, d := range f.tenants {
		for i := range 3 {
			topic := fmt.Sprintf("https://%s%d", tnMarker(d.name), i)
			tok, q := d.draft(t, roleSubscriber, nil, []string{"*"}), url.Values{"topic": {topic}}
			if i == 1 {
				tok, q = d.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"), url.Values{"match": {topic}}
			}
			f.open(tnReq{d: d, tok: tok, q: q})
		}
	}
	time.Sleep(tnSettle)
	for d, cs := range monitors {
		for i, c := range cs {
			mine := 0
			for _, ev := range c.receivedEvents() {
				for _, other := range f.tenants {
					if other != d && strings.Contains(ev.Data, tnMarker(other.name)) {
						t.Errorf("tenant %q's monitor %d saw an event of %q: %s", d.name, i, other.name, ev.Data)
					}
				}
				if strings.Contains(ev.Data, tnMarker(d.name)) {
					mine++
				}
			}
			if mine != 3 {
				t.Errorf("tenant %q's monitor %d saw %d of its 3 subscription events", d.name, i, mine)
			}
		}
	}
	// The API, in both formats, on each of the tenant's hosts.
	for _, d := range f.tenants {
		for _, tok := range []string{d.draft(t, roleSubscriber, nil, []string{"*"}), d.modern(t, roleSubscriber, f.srv.URL, subOnly, "*")} {
			for _, host := range d.hosts {
				res := f.do(tnReq{tok: tok, host: host, path: subscriptionsPath}, nil)
				if res.code != 200 {
					t.Fatalf("subscriptions of %q: %d %s", d.name, res.code, res.body)
				}
				var doc struct {
					Subscriptions []Subscription `json:"subscriptions"`
				}
				if err := json.Unmarshal([]byte(res.body), &doc); err != nil {
					t.Fatal(err)
				}
				own := 0
				for _, s := range doc.Subscriptions {
					desc := s.Topic + s.Match
					switch {
					case strings.Contains(desc, tnMarker(d.name)):
						own++
					case strings.Contains(desc, "shared.example/"):
						t.Errorf("tenant %q lists %q", d.name, desc)
					}
				}
				if own != 3 {
					t.Errorf("tenant %q lists %d of its 3 subscriptions: %s", d.name, own, res.body)
				}
			}
		}
	}
	// A tenant's token asks for another tenant's subscriptions through its host; no host asks for nothing.
	acme := f.byName("acme")
	res := f.do(tnReq{tok: acme.draft(t, roleSubscriber, nil, []string{"*"}), host: "globex.test", path: subscriptionsPath}, nil)
	if res.code != 401 {
		t.Errorf("acme token listing globex's subscriptions: %d %s", res.code, res.body)
	}
	if res := f.do(tnReq{tok: acme.draft(t, roleSubscriber, nil, []string{"*"}), path: subscriptionsPath}, nil); res.code != 404 {
		t.Errorf("subscriptions on no tenant's host: %d %s", res.code, res.body)
	}
}

// TestTenantsGoAPI: Hub.Publish on a tenant's hub reaches that tenant's subscribers only.
func TestTenantsGoAPI(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	var streams []tnStream
	for _, d := range f.tenants {
		streams = append(streams,
			tnStream{d.name + " all", f.open(tnReq{d: d, tok: d.draft(t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"*"}}}), []string{d.name + "-public", d.name + "-private"}},
			// A grant for book 2 only: the private update is on book 1.
			tnStream{d.name + " limited", f.open(tnReq{d: d, tok: d.draft(t, roleSubscriber, nil, []string{tnB2}), q: url.Values{"topic": {"*"}}}), []string{d.name + "-public"}})
		if d.anonymous {
			streams = append(streams, tnStream{d.name + " anonymous", f.open(tnReq{d: d, q: url.Values{"topic": {"*"}}}), []string{d.name + "-public"}})
		}
	}
	for _, d := range f.tenants {
		h := f.ts.Hub(d.name)
		if _, err := h.Publish(context.Background(), &Update{Topics: []string{tnB1}, Data: d.name + "-public"}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Publish(context.Background(), &Update{Topics: []string{tnB1}, Data: d.name + "-private", Private: true}); err != nil {
			t.Fatal(err)
		}
	}
	checkStreams(t, streams)
	if f.ts.Hub("nobody") != nil {
		t.Error("Hub returns a hub for an unknown tenant")
	}
}

// TestTenantsNewValidation: tenants without a name or hosts, and tenants that would not be isolated, are refused.
func TestTenantsNewValidation(t *testing.T) {
	k1, k2, k3 := "key-one-0123456789abcdef0123456789", "key-two-0123456789abcdef0123456789", "key-three-0123456789abcdef012345678"
	cfg := func(pub, sub string) Config {
		c := Config{PublisherKey: auth.KeyConfig{Key: pub}}
		if sub != "" {
			c.SubscriberKey = auth.KeyConfig{Key: sub}
		}
		return c
	}
	as := newTNAuthServer(t, tnRSA(t))
	pemA, pemB := tnRSA(t).config(t).Key, tnRSA(t).config(t).Key
	viaAS := func(resource string) Config {
		return Config{Issuers: []auth.Issuer{{Issuer: as.URL, Discover: true}}, ResourceIdentifier: resource, AllowInsecureKeyURLs: true}
	}
	jwks := func(u string) Config {
		return Config{PublisherKey: auth.KeyConfig{JWKSURL: u}, AllowInsecureKeyURLs: true}
	}
	tests := []struct {
		name    string
		tenants []Tenant
		ok      bool
	}{
		{"distinct", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: cfg(k1, "")}, {Name: "b", Hosts: []string{"b.test"}, Config: cfg(k2, "")}}, true},
		{"duplicate names", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: cfg(k1, "")}, {Name: "a", Hosts: []string{"a.test"}, Config: cfg(k2, "")}}, false},
		{"shared publisher key", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: cfg(k1, "")}, {Name: "b", Hosts: []string{"b.test"}, Config: cfg(k1, "")}}, false},
		{"publisher key is the other's subscriber key", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: cfg(k1, "")}, {Name: "b", Hosts: []string{"b.test"}, Config: cfg(k2, k1)}}, false},
		{"shared subscriber key", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: cfg(k1, k3)}, {Name: "b", Hosts: []string{"b.test"}, Config: cfg(k2, k3)}}, false},
		{"one tenant uses its key twice", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: cfg(k1, k1)}, {Name: "b", Hosts: []string{"b.test"}, Config: cfg(k2, "")}}, true},
		{"shared JWKS URL", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: jwks("http://jwks.example/k")}, {Name: "b", Hosts: []string{"b.test"}, Config: jwks("http://jwks.example/k")}}, false},
		{"duplicate hosts", []Tenant{{Name: "a", Hosts: []string{"h.test"}, Config: cfg(k1, "")}, {Name: "b", Hosts: []string{"h.test"}, Config: cfg(k2, "")}}, false},
		{"duplicate hosts, case", []Tenant{{Name: "a", Hosts: []string{"H.test"}, Config: cfg(k1, "")}, {Name: "b", Hosts: []string{"h.TEST"}, Config: cfg(k2, "")}}, false},
		{"a tenant lists a host twice", []Tenant{{Name: "a", Hosts: []string{"h.test", "h.test"}, Config: cfg(k1, "")}}, false},
		{"host with a port", []Tenant{{Name: "a", Hosts: []string{"h.test:8080"}, Config: cfg(k1, "")}}, false},
		{"host with a path", []Tenant{{Name: "a", Hosts: []string{"h.test/x"}, Config: cfg(k1, "")}}, false},
		{"empty host", []Tenant{{Name: "a", Hosts: []string{""}, Config: cfg(k1, "")}}, false},
		{"hosts differing by the root dot", []Tenant{{Name: "a", Hosts: []string{"h.test"}, Config: cfg(k1, "")}, {Name: "b", Hosts: []string{"h.test."}, Config: cfg(k2, "")}}, false},
		{"one PEM key written twice", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: pemA, Algorithm: "RS256"}}},
			{Name: "b", Hosts: []string{"b.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: "\n" + strings.ReplaceAll(pemA, "\n", "\r\n") + "\n\n", Algorithm: "RS256"}}}}, false},
		{"two PEM keys", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: pemA, Algorithm: "RS256"}}},
			{Name: "b", Hosts: []string{"b.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: pemB, Algorithm: "RS256"}}}}, true},
		{"bad config", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: k1}, MaxConnectionLifetime: -1}}}, false},
		{"bad key", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: k1, Algorithm: "RS256"}}}}, false},
		{"no tenants", nil, true},
		{"transport set on a tenant", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: k1}, Transport: &local{}}}}, false},
		{"shared authorization server, no resources (each defaults to its host)", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: viaAS("")}, {Name: "b", Hosts: []string{"b.test"}, Config: viaAS("")}}, true},
		{"shared authorization server, one resource", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: viaAS("https://a.test" + hubPath)}, {Name: "b", Hosts: []string{"b.test"}, Config: viaAS("https://a.test" + hubPath)}}, false},
		{"shared authorization server, one resource unset", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: viaAS("https://a.test" + hubPath)}, {Name: "b", Hosts: []string{"b.test"}, Config: viaAS("")}}, true},
		{"shared authorization server, distinct resources", []Tenant{{Name: "a", Hosts: []string{"a.test"}, Config: viaAS("https://a.test" + hubPath)}, {Name: "b", Hosts: []string{"b.test"}, Config: viaAS("https://b.test" + hubPath)}}, true},
		{"issuer with the key of another tenant", []Tenant{
			{Name: "a", Hosts: []string{"a.test"}, Config: Config{PublisherKey: auth.KeyConfig{Key: k1}}},
			{Name: "b", Hosts: []string{"b.test"}, Config: Config{Issuers: []auth.Issuer{{Issuer: "https://as.example", Key: k1}}}}}, false},
		{"issuers with their own keys share a name", []Tenant{
			{Name: "a", Hosts: []string{"a.test"}, Config: Config{Issuers: []auth.Issuer{{Issuer: "https://as.example", Key: k1}}}},
			{Name: "b", Hosts: []string{"b.test"}, Config: Config{Issuers: []auth.Issuer{{Issuer: "https://as.example", Key: k2}}}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateTenants(tc.tenants); (err == nil) != tc.ok {
				t.Errorf("ValidateTenants: %v, want ok %v", err, tc.ok)
			}
			ts, err := NewTenants(tc.tenants, nil)
			if (err == nil) != tc.ok {
				t.Fatalf("NewTenants: %v, want ok %v", err, tc.ok)
			}
			if ts != nil {
				ts.Close(context.Background())
			}
		})
	}
}

// TestTenantsCORSPreflight: a preflight is routed by its host like any request and answered with the policy of that
// tenant: never with the policy of another tenant. A host no tenant has is refused.
func TestTenantsCORSPreflight(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	preflightReq := func(host, origin string) *http.Response {
		req := f.newRequest(context.Background(), tnReq{method: http.MethodOptions, host: host, hdr: http.Header{
			"Origin": {origin}, "Access-Control-Request-Method": {"GET"}, "Access-Control-Request-Headers": {"authorization"},
		}})
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	preflight := func(host, origin string) string {
		resp := preflightReq(host, origin)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("preflight %q %q: %d", host, origin, resp.StatusCode)
		}
		return resp.Header.Get("Access-Control-Allow-Origin")
	}
	if got := preflight("acme.test", "https://acme.example"); got != "https://acme.example" {
		t.Errorf("acme's origin on acme's host: %q", got)
	}
	if got := preflight("ACME.test.:8443", "https://acme.example"); got != "https://acme.example" {
		t.Errorf("acme's origin on acme's host, spelt another way: %q", got)
	}
	for _, o := range []string{"https://globex.example", "https://umbra.example", "https://evil.example"} {
		if got := preflight("acme.test", o); got != "" {
			t.Errorf("origin %s allowed on acme's host: %q", o, got)
		}
	}
	if got := preflight("globex.test", "https://acme.example"); got != "" {
		t.Errorf("acme's origin allowed on globex's host: %q", got)
	}
	if got := preflight("globex.test", "https://globex.example"); got != "https://globex.example" {
		t.Errorf("globex's origin on globex's host: %q", got)
	}
	// No tenant has the host: the preflight is refused, even for an origin a tenant allows.
	for _, host := range []string{"", "unknown.test"} {
		for _, o := range []string{"https://acme.example", "https://evil.example"} {
			resp := preflightReq(host, o)
			if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("preflight on host %q from %s: %d, allow-origin %q", host, o, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
			}
		}
	}
	// A data request is answered with the policy of the tenant that serves it.
	globex := f.byName("globex")
	c := f.open(tnReq{d: globex, q: url.Values{"topic": {"x"}}, hdr: http.Header{"Origin": {"https://acme.example"}}})
	if got := c.resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("acme's origin on a globex stream: %q", got)
	}
	c = f.open(tnReq{d: globex, q: url.Values{"topic": {"x"}}, hdr: http.Header{"Origin": {"https://globex.example"}}})
	if got := c.resp.Header.Get("Access-Control-Allow-Origin"); got != "https://globex.example" {
		t.Errorf("globex's origin on a globex stream: %q", got)
	}
}

// TestTenantsMixedLoad: many tenants with several users each publish and subscribe at once; nothing crosses.
func TestTenantsMixedLoad(t *testing.T) {
	const tenants, perTenant, msgs = 8, 3, 40
	var descs []*tnTenant
	for i := range tenants {
		d := &tnTenant{name: fmt.Sprintf("t%d", i), hosts: []string{fmt.Sprintf("t%d.test", i)}, pubKey: tnHS(fmt.Sprintf("load-secret-%d-0123456789abcdef0123456", i)),
			iss: fmt.Sprintf("https://iss.t%d", i), aud: fmt.Sprintf("https://t%d.test%s", i, hubPath), anonymous: i%2 == 0}
		descs = append(descs, d)
	}
	f := startTenants(t, descs, nil)
	type sub struct {
		d *tnTenant
		c *sseClient
	}
	var subs []sub
	for _, d := range descs {
		for u := range perTenant {
			var r tnReq
			switch u % 3 {
			case 0:
				r = tnReq{tok: d.draft(t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"https://load.example/{x}"}}}
			case 1:
				r = tnReq{tok: d.modern(t, roleSubscriber, f.srv.URL, subOnly, "*"), q: url.Values{"match_urlpattern": {"https://load.example/*"}}, via: "cookie2"}
			default:
				r = tnReq{tok: d.draft(t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"*"}}, via: "query", method: methodQuery}
			}
			r.d = d
			subs = append(subs, sub{d, f.open(r)})
		}
	}
	var wg sync.WaitGroup
	for _, d := range descs {
		for u := range perTenant {
			wg.Go(func() {
				for i := range msgs {
					topic := fmt.Sprintf("https://load.example/%d", i%5)
					form := url.Values{"topic": {topic}, "data": {fmt.Sprintf("%s|%d|%d", d.name, u, i)}}
					if i%4 == 0 {
						form.Set("private", "on")
					}
					var r tnReq
					if u%2 == 0 {
						r.tok = d.draft(t, rolePublisher, []string{"*"}, nil)
					} else {
						r.tok = d.modern(t, rolePublisher, f.srv.URL, pubOnly, "*")
					}
					r.d = d
					if res := f.do(r, form); res.code != 200 {
						t.Errorf("publish %s: %d %s", d.name, res.code, res.body)
						return
					}
				}
			})
		}
	}
	wg.Wait()
	time.Sleep(tnSettle)
	for _, s := range subs {
		got := s.c.received()
		if len(got) != perTenant*msgs {
			t.Errorf("tenant %q subscriber received %d, want %d", s.d.name, len(got), perTenant*msgs)
		}
		for _, g := range got {
			if !strings.HasPrefix(g, s.d.name+"|") {
				t.Errorf("tenant %q subscriber received %q", s.d.name, g)
				break
			}
		}
	}
}

// TestHubDropsOtherTenantsUpdates: a hub applies the updates of its own tenant only. A plain hub on a node of a
// cluster whose other nodes run tenants must not show the tenants' updates to its subscribers.
func TestHubDropsOtherTenantsUpdates(t *testing.T) {
	apply := func(h *Hub, tenant, data string, restore bool) {
		u := &Update{ID: "urn:" + data, Topics: []string{"t"}, Data: data, Stamp: uint64(h.clock.Now()), Origin: "other-node", Tenant: tenant}
		if restore {
			h.Restore(u)
		} else {
			h.Apply(u)
		}
	}
	e := newEnv(t, Config{Anonymous: true})
	c := e.subscribe(t, "", "t")
	apply(e.hub, "acme", "from-acme", false)
	apply(e.hub, "acme", "restored-from-acme", true)
	apply(e.hub, "", "plain", false)
	if got := c.drain("plain"); len(got) != 0 {
		t.Errorf("a plain hub delivered %q", got)
	}
	if n := e.hub.Stats().HistoryLen; n != 1 {
		t.Errorf("history holds %d updates, want 1", n)
	}

	// A tenant's hub, applied to directly with another tenant's update, and Tenants given updates of tenants it lacks.
	f := startTenants(t, newTNTenants(t, false), nil)
	acme, globex := f.byName("acme"), f.byName("globex")
	sa := f.open(tnReq{d: acme, tok: acme.draft(t, roleSubscriber, nil, []string{"*"}), q: url.Values{"topic": {"t"}}})
	sg := f.open(tnReq{d: globex, q: url.Values{"topic": {"t"}}})
	apply(f.ts.Hub("acme"), "globex", "to-acme-hub", false)
	apply(f.ts.Hub("globex"), "acme", "to-globex-hub", false)
	apply(f.ts.Hub("globex"), "", "plain-to-globex-hub", false)
	f.ts.Apply(&Update{ID: "urn:ghost", Topics: []string{"t"}, Stamp: uint64(f.ts.Hub("acme").clock.Now()), Origin: "other", Tenant: "ghost"})
	f.ts.Restore(&Update{ID: "urn:ghost2", Topics: []string{"t"}, Stamp: uint64(f.ts.Hub("acme").clock.Now()), Origin: "other", Tenant: "ghost"})
	f.ts.Apply(&Update{ID: "urn:acme", Topics: []string{"t"}, Data: "routed", Stamp: uint64(f.ts.Hub("acme").clock.Now()), Origin: "other", Tenant: "acme"})
	time.Sleep(tnSettle)
	if got := sa.received(); !slices.Equal(got, []string{"routed"}) {
		t.Errorf("acme received %q", got)
	}
	if got := sg.received(); len(got) != 0 {
		t.Errorf("globex received %q", got)
	}
}

// TestTenantsAuthorizationHeaderBeatsCookie: the tenant is the host's; a valid token in a cookie does not make up for a
// bad Authorization header, and a stale cookie of another tenant next to a valid header does not decide.
func TestTenantsAuthorizationHeaderBeatsCookie(t *testing.T) {
	f := startTenants(t, newTNTenants(t, false), nil)
	acme, initech := f.byName("acme"), f.byName("initech")
	acmeTok := acme.draft(t, roleSubscriber, nil, []string{"*"})
	initTok := initech.draft(t, roleSubscriber, nil, []string{"*"})
	q := url.Values{"topic": {"*"}}
	// On acme's host: the header names acme and the cookie initech: the header wins, and acme serves it.
	req := f.newRequest(context.Background(), tnReq{d: acme, tok: initTok, via: "cookie", q: q, hdr: http.Header{"Authorization": {"Bearer " + acmeTok}}})
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := f.ts.Hub("acme").stats.Subscribers.Load(); got != 1 {
		t.Errorf("acme has %d subscribers", got)
	}
	// The header names initech and the cookie acme, on acme's host: the header wins and acme refuses it.
	req = f.newRequest(context.Background(), tnReq{d: acme, tok: acmeTok, via: "cookie", q: q, hdr: http.Header{"Authorization": {"Bearer " + initTok}}})
	resp2, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Errorf("a foreign header with an acme cookie on acme's host: %d, want 401", resp2.StatusCode)
	}
	if got := f.ts.Hub("initech").stats.Subscribers.Load(); got != 0 {
		t.Errorf("initech has %d subscribers", got)
	}

}
