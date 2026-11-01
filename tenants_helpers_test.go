package gossiper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
)

// tnKey is a signing key of a test tenant: an HMAC secret, or an RSA or ECDSA key pair.
type tnKey struct {
	alg    string
	method jwt.SigningMethod
	secret string // HS256
	priv   any    // RS256, ES256
	pub    any
}

func tnHS(secret string) tnKey {
	return tnKey{alg: "HS256", method: jwt.SigningMethodHS256, secret: secret}
}

func tnRSA(t testing.TB) tnKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return tnKey{alg: "RS256", method: jwt.SigningMethodRS256, priv: k, pub: &k.PublicKey}
}

func tnEC(t testing.TB) tnKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return tnKey{alg: "ES256", method: jwt.SigningMethodES256, priv: k, pub: &k.PublicKey}
}

// config is the hub's verification key.
func (k tnKey) config(t testing.TB) auth.KeyConfig {
	t.Helper()
	if k.secret != "" {
		return auth.KeyConfig{Key: k.secret, Algorithm: k.alg}
	}
	der, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		t.Fatal(err)
	}
	return auth.KeyConfig{Key: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Algorithm: k.alg}
}

func (k tnKey) sign(t testing.TB, claims jwt.MapClaims, typ string) string {
	t.Helper()
	tok := jwt.NewWithClaims(k.method, claims)
	if typ != "" {
		tok.Header["typ"] = typ
	}
	var key any = k.priv
	if k.secret != "" {
		key = []byte(k.secret)
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// jwk is the key's public half as a JWK.
func (k tnKey) jwk(kid string) map[string]any {
	enc := base64.RawURLEncoding.EncodeToString
	m := map[string]any{"kid": kid, "alg": k.alg, "use": "sig"}
	switch p := k.pub.(type) {
	case *rsa.PublicKey:
		m["kty"], m["n"], m["e"] = "RSA", enc(p.N.Bytes()), enc(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PublicKey:
		pt, err := p.Bytes() // 0x04, then X and Y
		if err != nil {
			panic(err)
		}
		m["kty"], m["crv"] = "EC", "P-256"
		m["x"], m["y"] = enc(pt[1:33]), enc(pt[33:])
	}
	return m
}

// tnAuthServer is an OAuth authorization server (plain HTTP): metadata with a jwks_uri, and the JWK Set.
type tnAuthServer struct {
	*httptest.Server
	key tnKey
}

func newTNAuthServer(t testing.TB, key tnKey) *tnAuthServer {
	t.Helper()
	as := &tnAuthServer{key: key}
	as.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": as.URL, "jwks_uri": as.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key.jwk("as1")}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(as.Close)
	return as
}

// tnTenant describes one test tenant and mints its users' tokens.
type tnTenant struct {
	name          string
	hosts         []string
	pubKey        tnKey
	subKey        tnKey // zero: the subscriber key is the publisher key
	hasSubKey     bool
	iss           string // issuer of Mercure 1.0 tokens signed with the keys; the authorization server's URL for as
	as            *tnAuthServer
	aud           string // resource identifier; "" derives it from the request
	anonymous     bool
	subscriptions bool
	cors          []string
}

// The topics the tests publish to; every tenant uses these same URLs.
const (
	tnB1   = "https://shared.example/books/1"
	tnB2   = "https://shared.example/books/2"
	tnNews = "https://shared.example/news"
)

func (d *tnTenant) config(t testing.TB) Config {
	t.Helper()
	cfg := Config{
		Protocol: ProtocolBoth, PublisherKey: d.pubKey.config(t), ResourceIdentifier: d.aud, Anonymous: d.anonymous,
		Subscriptions: d.subscriptions, CORSOrigins: d.cors, PublishOrigins: []string{"*"}, AllowInsecureKeyURLs: true,
		Heartbeat: -1,
	}
	if d.hasSubKey {
		cfg.SubscriberKey = d.subKey.config(t)
	}
	if d.as != nil {
		cfg.Issuers = []auth.Issuer{{Issuer: d.as.URL, Discover: true}}
	} else {
		cfg.TrustedIssuers = []string{d.iss}
	}
	return cfg
}

func (d *tnTenant) tenant(t testing.TB) Tenant {
	return Tenant{Name: d.name, Hosts: d.hosts, Config: d.config(t)}
}

// audience is the resource identifier tokens for a request to the tenant's host must name (srv, the test server's
// address, is not it: requests are addressed by the Host header).
func (d *tnTenant) audience(srv string) string {
	if d.aud != "" {
		return d.aud
	}
	return "http://" + d.hosts[0] + hubPath
}

// draft returns a draft-07 token: pub for the publisher role (the publisher key), sub for the subscriber role.
func (d *tnTenant) draft(t testing.TB, role role, pub, sub []string) string {
	t.Helper()
	k := d.pubKey
	if role == roleSubscriber {
		if d.hasSubKey {
			k = d.subKey
		}
		if d.as != nil { // an authorization server's tenant keeps HMAC draft-07 keys
			k = d.pubKey
		}
	}
	return k.sign(t, mercureClaims(pub, sub), "")
}

// modern returns a Mercure 1.0 access token for a request to srv, granting actions on the exact topics.
func (d *tnTenant) modern(t testing.TB, role role, srv string, actions []string, topics ...string) string {
	t.Helper()
	return d.modernIss(t, role, d.iss, d.audience(srv), actions, topics...)
}

func (d *tnTenant) modernIss(t testing.TB, role role, iss, aud string, actions []string, topics ...string) string {
	t.Helper()
	k := d.pubKey
	if role == roleSubscriber && d.hasSubKey {
		k = d.subKey
	}
	if d.as != nil {
		k, iss = d.as.key, d.as.URL
	}
	var ms []map[string]any
	for _, tp := range topics {
		ms = append(ms, mBare(tp))
	}
	claims := accessClaims(aud, time.Hour, mDetail(actions, ms...))
	claims["iss"] = iss
	return k.sign(t, claims, "at+jwt")
}

// tnFixture is Tenants served over HTTP.
type tnFixture struct {
	t       testing.TB
	ts      *Tenants
	srv     *httptest.Server
	tenants []*tnTenant
	client  *http.Client
	tr      *http.Transport
}

func (f *tnFixture) byName(name string) *tnTenant {
	for _, d := range f.tenants {
		if d.name == name {
			return d
		}
	}
	f.t.Fatalf("no tenant %q", name)
	return nil
}

// startTenants runs Tenants for the descriptions behind an httptest server, over transport (nil: alone).
func startTenants(t testing.TB, descs []*tnTenant, transport Transport) *tnFixture {
	t.Helper()
	var ts []Tenant
	for _, d := range descs {
		ts = append(ts, d.tenant(t))
	}
	tn, err := NewTenants(ts, transport)
	if err != nil {
		t.Fatal(err)
	}
	return serveTenants(t, tn, descs)
}

func serveTenants(t testing.TB, tn *Tenants, descs []*tnTenant) *tnFixture {
	t.Helper()
	srv := httptest.NewServer(tn)
	tr := &http.Transport{MaxIdleConnsPerHost: 64}
	f := &tnFixture{t: t, ts: tn, srv: srv, tenants: descs, client: &http.Client{Transport: tr}, tr: tr}
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() {
			f.tr.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), wait)
			defer cancel()
			if err := tn.Close(ctx); err != nil {
				t.Errorf("tenants close: %v", err)
			}
			srv.CloseClientConnections()
			srv.Close()
		})
	})
	return f
}

// newTNTenants returns the standard test tenants: umbra, acme, globex, initech and hooli, each with its own host and
// keys of another kind. umbra and globex accept anonymous subscribers.
func newTNTenants(t testing.TB, subscriptions bool) []*tnTenant {
	t.Helper()
	as := newTNAuthServer(t, tnRSA(t))
	return []*tnTenant{
		{name: "umbra", hosts: []string{"umbra.test"}, pubKey: tnHS("umbra-secret-0123456789abcdef0123456"), iss: "https://iss.umbra",
			anonymous: true, subscriptions: subscriptions, cors: []string{"https://umbra.example"}},
		{name: "acme", hosts: []string{"acme.test"}, pubKey: tnHS("acme-pub-secret-0123456789abcdef01234"),
			subKey: tnHS("acme-sub-secret-0123456789abcdef01234"), hasSubKey: true, iss: "https://iss.acme",
			aud: "https://acme.test" + hubPath, subscriptions: subscriptions, cors: []string{"https://acme.example"}},
		{name: "globex", hosts: []string{"globex.test"}, pubKey: tnRSA(t), subKey: tnRSA(t), hasSubKey: true,
			iss: "https://iss.globex", aud: "https://globex.test" + hubPath, anonymous: true, subscriptions: subscriptions,
			cors: []string{"https://globex.example"}},
		{name: "initech", hosts: []string{"initech.test"}, pubKey: tnEC(t), iss: "https://iss.initech", anonymous: false, subscriptions: subscriptions},
		{name: "hooli", hosts: []string{"hooli.test"}, pubKey: tnHS("hooli-secret-0123456789abcdef0123456"), as: as, iss: as.URL,
			aud: "https://hooli.test" + hubPath, subscriptions: subscriptions},
	}
}

// tnReq is one client request to the fixture's server.
type tnReq struct {
	method string    // GET, QUERY, POST, ...
	d      *tnTenant // the tenant addressed: its first host is the Host header unless host is set
	host   string    // the Host header; "" for the tenant's, or the server's own address (no tenant's) without d
	tok    string
	via    string // "header" (default), "query", "cookie" (draft-07), "cookie2" (Mercure 1.0)
	q      url.Values
	hdr    http.Header
	path   string // default the hub URL
}

func (f *tnFixture) newRequest(ctx context.Context, r tnReq) *http.Request {
	f.t.Helper()
	method := r.method
	if method == "" {
		method = http.MethodGet
	}
	path := r.path
	if path == "" {
		path = hubPath
	}
	target := f.srv.URL + path
	q := url.Values{}
	for k, v := range r.q {
		q[k] = v
	}
	var body io.Reader
	switch method {
	case methodQuery, http.MethodPost:
		body = strings.NewReader(q.Encode())
		q = url.Values{}
	}
	if r.via == "query" && r.tok != "" {
		q.Set("authorization", r.tok)
	}
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		f.t.Fatal(err)
	}
	for k, vs := range r.hdr {
		req.Header[k] = vs
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	switch {
	case r.host != "":
		req.Host = r.host
	case r.d != nil:
		req.Host = r.d.hosts[0]
	}
	switch r.via {
	case "", "header":
		if r.tok != "" {
			req.Header.Set("Authorization", "Bearer "+r.tok)
		}
	case "cookie":
		req.AddCookie(&http.Cookie{Name: "mercureAuthorization", Value: r.tok})
	case "cookie2":
		req.AddCookie(&http.Cookie{Name: "__Secure-mercure_access_token", Value: r.tok})
	}
	if method == http.MethodPost && (r.via == "cookie" || r.via == "cookie2") {
		req.Header.Set("Origin", "https://app.example")
	}
	return req
}

// do sends the request and reads the response.
func (f *tnFixture) do(r tnReq, form url.Values) result {
	f.t.Helper()
	if form != nil {
		r.q = form
		r.method = http.MethodPost
	}
	req := f.newRequest(context.Background(), r)
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, string(b), resp.Header}
}

// open opens a stream and waits for its first comment; ok is false (and the stream nil) when the hub refuses it.
func (f *tnFixture) tryOpen(r tnReq) (*sseClient, result) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := f.client.Do(f.newRequest(ctx, r))
	if err != nil {
		cancel()
		f.t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		return nil, result{resp.StatusCode, string(b), resp.Header}
	}
	c := &sseClient{t: f.t, resp: resp, cancel: cancel, events: make(chan sseEvent, 1<<14), closed: make(chan struct{})}
	go c.read()
	f.t.Cleanup(c.close)
	eventually(f.t, "the stream's first comment", func() bool { return c.comments.Load() > 0 })
	return c, result{code: 200}
}

func (f *tnFixture) open(r tnReq) *sseClient {
	f.t.Helper()
	c, res := f.tryOpen(r)
	if c == nil {
		f.t.Fatalf("subscribe %+v: %d %s", r, res.code, res.body)
	}
	return c
}

// received returns the data of the events the stream holds now, without waiting.
func (c *sseClient) received() []string {
	var out []string
	for {
		select {
		case ev := <-c.events:
			out = append(out, ev.Data)
		default:
			return out
		}
	}
}

// receivedEvents is received with the whole events.
func (c *sseClient) receivedEvents() []sseEvent {
	var out []sseEvent
	for {
		select {
		case ev := <-c.events:
			out = append(out, ev)
		default:
			return out
		}
	}
}
