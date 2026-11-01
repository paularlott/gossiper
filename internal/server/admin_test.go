package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const apiToken = "admin-token-0123456789"

// call makes an admin API request with the token tok and returns the status and the decoded body (nil when empty).
func call(t testing.TB, base, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: %d, not JSON: %s", method, path, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, out
}

// api is call with the API token, failing the test on an unexpected status.
func api(t testing.TB, base, method, path string, body any, want int) map[string]any {
	t.Helper()
	code, out := call(t, base, method, path, apiToken, body)
	if code != want {
		t.Fatalf("%s %s: %d (want %d) %v", method, path, code, want, out)
	}
	return out
}

// adminSettings are tenantSettings with a database and the API on, and no tenants file unless given.
func adminSettings(t testing.TB, file string) Settings {
	s := tenantSettings(t, file)
	s.Database = filepath.Join(t.TempDir(), "gossiper.db")
	s.APIToken = apiToken
	return s
}

// hubStatus opens a subscription at the host's hub with tok and returns the status, without reading the stream.
func hubStatus(t testing.TB, base, host, tok string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/.well-known/mercure?topic=x", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAdminAPIAuthentication(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	if code, _ := call(t, n.base, "GET", "/api/tenants", "", nil); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := call(t, n.base, "GET", "/api/tenants", "wrong", nil); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	api(t, n.base, "GET", "/api/tenants", nil, 200)
	// The OpenAPI document needs no token (404 in a build without the web assets).
	if code, _ := call(t, n.base, "GET", "/api/openapi.json", "", nil); code != 200 && code != 404 {
		t.Errorf("openapi.json: %d", code)
	}
	if code, _ := call(t, n.base, "GET", "/api/nothing", apiToken, nil); code != 404 {
		t.Errorf("unknown endpoint: %d", code)
	}
	// Failures are limited per address: 60 a minute, then 429 even with the right token.
	for range 58 {
		call(t, n.base, "GET", "/api/tenants", "wrong", nil)
	}
	req, _ := http.NewRequest("GET", n.base+"/api/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("after 60 failures: %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}

	// A bcrypt hash as the setting.
	hash, _ := bcrypt.GenerateFromPassword([]byte("hashed-token"), bcrypt.MinCost)
	s := adminSettings(t, "")
	s.APIToken = string(hash)
	h := startNode(t, s)
	for range 3 {
		if code, _ := call(t, h.base, "GET", "/api/tenants", "hashed-token", nil); code != 200 {
			t.Errorf("bcrypt token: %d", code)
		}
	}
	if code, _ := call(t, h.base, "GET", "/api/tenants", string(hash), nil); code != 401 {
		t.Errorf("the hash itself as the token: %d", code)
	}

	// Without a token the API is off; a token without a database is an error.
	s = adminSettings(t, "")
	s.APIToken = ""
	off := startNode(t, s)
	if code, _ := get(t, off.base+"/api/tenants"); code != 404 {
		t.Errorf("API without a token: %d", code)
	}
	s = tenantSettings(t, "")
	s.APIToken = apiToken
	if _, err := New(s, nil); err == nil || !strings.Contains(err.Error(), "database") {
		t.Errorf("token without database: %v", err)
	}
}

func TestAdminAPITenantLifecycle(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a, b := newTN(t, "alpha", false, false), newTN(t, "bravo", false, false)

	out := api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	if out["source"] != "database" || out["name"] != "alpha" {
		t.Fatalf("created: %v", out)
	}
	m := out["mercure"].(map[string]any)
	if m["publisher_key"] != nil || m["publisher_key_set"] != true {
		t.Errorf("the HMAC key is shown: %v", m)
	}
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 409) // exists
	api(t, n.base, "PUT", "/api/tenants/bravo", b.spec(t), 201)
	if l := api(t, n.base, "GET", "/api/tenants", nil, 200)["tenants"].([]any); len(l) != 2 {
		t.Fatalf("list: %v", l)
	}

	// Both serve their hubs on their hosts, isolated.
	eventually(t, 5*time.Second, "the hubs to start", func() bool {
		code := hubStatus(t, n.base, b.host, b.token(t, nil, []string{"*"}))
		return code == 200
	})
	sa := openStream(t, n.base, a.host, a.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	sb := openStream(t, n.base, b.host, b.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	time.Sleep(100 * time.Millisecond)
	mustPost(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"for-a"}})
	mustPost(t, n.base, b.host, b.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"for-b"}})
	eventually(t, 5*time.Second, "both updates", func() bool { return len(sa.real()) == 1 && len(sb.real()) == 1 })
	if sa.real()[0] != "for-a" || sb.real()[0] != "for-b" {
		t.Fatalf("crossed tenants: %v %v", sa.real(), sb.real())
	}
	if code, _ := postForm(t, n.base, b.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"x"}}); code != 401 && code != 403 {
		t.Errorf("tenant a's token on b's host: %d", code)
	}
	// New keys: the hub starts over (its streams end), the old key's tokens are refused, the new key's accepted;
	// tenant b is untouched.
	a2 := a
	a2.secret = "rotated-secret-alpha-0123456789abcdef0123"
	api(t, n.base, "PUT", "/api/tenants/alpha", map[string]any{"hosts": []string{a.host},
		"mercure": map[string]any{"publisher_key": a2.secret}}, 200)
	select {
	case <-sa.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream of the changed hub did not end")
	}
	eventually(t, 5*time.Second, "the new key", func() bool {
		code, _ := postForm(t, n.base, a.host, a2.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"y"}})
		return code == 200
	})
	if code, _ := postForm(t, n.base, a.host, a.token(t, []string{"*"}, nil), url.Values{"topic": {sharedTopic}, "data": {"z"}}); code == 200 {
		t.Error("the old key still publishes")
	}
	select {
	case <-sb.closed:
		t.Fatal("tenant b's stream ended")
	default:
	}
	// Hosts only: streams stay open.
	sb2 := openStream(t, n.base, b.host, b.token(t, nil, []string{"*"}), url.Values{"topic": {sharedTopic}}, "")
	spec := b.spec(t)
	spec.Hosts = []string{b.host, "bravo2.test"}
	api(t, n.base, "PUT", "/api/tenants/bravo", spec, 200)
	eventually(t, 5*time.Second, "the new host", func() bool {
		code := hubStatus(t, n.base, "bravo2.test", b.token(t, nil, []string{"*"}))
		return code == 200
	})
	select {
	case <-sb2.closed:
		t.Fatal("a host change ended the stream")
	default:
	}

	// Deleted: the host answers 404.
	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 204)
	api(t, n.base, "DELETE", "/api/tenants/alpha", nil, 404)
	api(t, n.base, "GET", "/api/tenants/alpha", nil, 404)
	eventually(t, 5*time.Second, "the host to go", func() bool {
		code := hubStatus(t, n.base, a.host, a2.token(t, nil, []string{"*"}))
		return code == 404
	})
	st := api(t, n.base, "GET", "/api/status", nil, 200)
	if st["tenants"].(map[string]any)["database"] != float64(1) {
		t.Errorf("status: %v", st)
	}
}

func TestAdminAPIRefusesClashes(t *testing.T) {
	file := newTN(t, "filed", false, false)
	n := startNode(t, adminSettings(t, writeTenants(t, file.spec(t))))
	a, b := newTN(t, "alpha", false, false), newTN(t, "bravo", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)

	clash := b.spec(t)
	clash.Hosts = []string{a.host}
	api(t, n.base, "POST", "/api/tenants", clash, 409) // a's host
	clash = b.spec(t)
	clash.Mercure.PublisherKey = a.secret
	api(t, n.base, "POST", "/api/tenants", clash, 409) // a's key
	clash = b.spec(t)
	clash.Hosts = []string{file.host}
	api(t, n.base, "POST", "/api/tenants", clash, 409) // the file's host
	api(t, n.base, "PUT", "/api/tenants/filed", file.spec(t), 409)
	api(t, n.base, "DELETE", "/api/tenants/filed", nil, 409)
	api(t, n.base, "PUT", "/api/tenants/alpha", map[string]any{"name": "alpha"}, 400) // no mercure settings

	// Malformed: 400.
	api(t, n.base, "POST", "/api/tenants", `{"name":"x","hosts":["x.test"],"mercure":{"publisher_key":"k"},"bogus":1}`, 400)
	api(t, n.base, "POST", "/api/tenants", `{"name":"x"`, 400)
	api(t, n.base, "POST", "/api/tenants", map[string]any{"name": "bad name", "hosts": []string{"b.test"}, "mercure": map[string]any{}}, 400)
	api(t, n.base, "POST", "/api/tenants", map[string]any{"name": "nohosts", "mercure": map[string]any{"publisher_key": "k"}}, 400)
	api(t, n.base, "POST", "/api/tenants", map[string]any{"name": "empty"}, 400)
	api(t, n.base, "PUT", "/api/tenants/x", map[string]any{"name": "y", "hosts": []string{"y.test"}, "mercure": map[string]any{}}, 400)
	api(t, n.base, "POST", "/api/tenants", map[string]any{"name": "n", "hosts": []string{"n.test"}, "mercure": map[string]any{}, "nats": map[string]any{}}, 400)

	// Nothing of the refused changes was kept: bravo is free to create, and the list is the file's and alpha.
	api(t, n.base, "POST", "/api/tenants", b.spec(t), 201)
	list := api(t, n.base, "GET", "/api/tenants", nil, 200)["tenants"].([]any)
	src := map[string]string{}
	for _, x := range list {
		src[x.(map[string]any)["name"].(string)] = x.(map[string]any)["source"].(string)
	}
	if len(src) != 3 || src["filed"] != "file" || src["alpha"] != "database" || src["bravo"] != "database" {
		t.Errorf("tenants: %v", src)
	}
}

func TestAdminAPIPersistsAcrossRestart(t *testing.T) {
	s := adminSettings(t, "")
	n := startNode(t, s)
	a := newTN(t, "alpha", false, false)
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}
	n = startNode(t, s)
	code := hubStatus(t, n.base, a.host, a.token(t, nil, []string{"*"}))
	if code != 200 {
		t.Fatalf("after a restart the tenant's hub answers %d", code)
	}
}

func TestAPIDocs(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	code, body := get(t, n.base+"/api-docs/")
	if code == 404 {
		t.Skip("the web assets are not built (task webassets)")
	}
	if code != 200 || !strings.Contains(body, "<div id=\"redoc\">") {
		t.Fatalf("/api-docs/: %d", code)
	}
	resp, err := http.Get(n.base + "/api-docs/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP %q", csp)
	}
	if strings.Contains(body, "https://") {
		t.Errorf("the page references another origin")
	}
	i := strings.Index(body, "/api-docs/assets/")
	if i < 0 {
		t.Fatal("no asset in the page")
	}
	asset := body[i:]
	asset = asset[:strings.IndexByte(asset, '"')]
	// A browser gets it gzipped; a client without gzip gets it plain.
	req, _ := http.NewRequest("GET", n.base+asset, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	tr := &http.Transport{DisableCompression: true}
	resp, err = (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || len(gz) < 2 || gz[0] != 0x1f {
		t.Errorf("gzip asset: %d %q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	req, _ = http.NewRequest("GET", n.base+asset, nil)
	resp, err = (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" || len(plain) <= len(gz) {
		t.Errorf("plain asset: %d %q %d bytes", resp.StatusCode, resp.Header.Get("Content-Encoding"), len(plain))
	}
	if code, _ := get(t, n.base+"/api-docs/assets/nothing.js"); code != 404 {
		t.Errorf("missing asset: %d", code)
	}
	code, body = get(t, n.base+"/api/openapi.json")
	var doc map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &doc) != nil || doc["openapi"] != "3.1.0" {
		t.Errorf("openapi.json: %d", code)
	}
}

// Short HMAC secrets are refused, the server's and the tenants', unless allow-weak-keys accepts them.
func TestWeakKeysRefused(t *testing.T) {
	s := settings()
	s.PublisherKey = "short"
	if _, err := New(s, nil); err == nil || !strings.Contains(err.Error(), "publisher-key") {
		t.Fatalf("a weak server key: %v", err)
	}
	s.AllowWeakKeys = true
	srv, err := New(s, nil)
	if err != nil {
		t.Fatalf("allow-weak-keys: %v", err)
	}
	srv.Close(context.Background())

	n := startNode(t, adminSettings(t, ""))
	weak := map[string]any{"hosts": []string{"weak.test"}, "mercure": map[string]any{"publisher_key": "short"}}
	if out := api(t, n.base, "PUT", "/api/tenants/weak", weak, 400); !strings.Contains(fmt.Sprint(out["error"]), "HMAC") {
		t.Errorf("weak tenant key: %v", out)
	}
	if _, err := New(tenantSettings(t, writeTenants(t, tenantSpec{Name: "w", Hosts: []string{"w.test"}, Mercure: &tenantMercure{PublisherKey: "short"}})), nil); err == nil {
		t.Error("a weak key in the tenants file was accepted")
	}
}

// A tenant whose own settings are invalid is the request's fault (400); a clash with another tenant is 409.
func TestAdminAPIInvalidSettings(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	bad := map[string]any{"hosts": []string{"bad.test"}, "mercure": map[string]any{"publisher_key": strings.Repeat("k", 32), "publisher_alg": "none"}}
	api(t, n.base, "PUT", "/api/tenants/bad", bad, 400)
}
