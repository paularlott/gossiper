package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// accessToken is a Mercure 1.0 token for the hub at host, signed with secret by https://localhost (the default trusted
// issuer), allowing action ("publish" or "subscribe") on every topic.
func accessToken(t testing.TB, secret, host, action string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://localhost", "aud": "http://" + host + "/.well-known/mercure", "sub": "s", "client_id": "c",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": uuid.NewString(),
		"authorization_details": []any{map[string]any{
			"type": "https://mercure.rocks/authorization-detail", "actions": []string{action},
			"topics": []any{map[string]any{"match": "*"}},
		}},
	})
	tok.Header["typ"] = "at+jwt"
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// publishWith publishes to the tenant at host on base with a token signed with secret, and returns the status.
func publishWith(t testing.TB, base, host, secret string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/.well-known/mercure", strings.NewReader("topic=x&data=y"))
	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken(t, secret, host, "publish"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// subscribeWith opens a stream on the tenant at host with a token signed with secret, and returns the status.
func subscribeWith(t testing.TB, base, host, secret string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/mercure?match=x", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+accessToken(t, secret, host, "subscribe"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

const (
	keyA = "rotation-key-a-0123456789abcdef0123456789abcdef"
	keyB = "rotation-key-b-0123456789abcdef0123456789abcdef"
	keyC = "rotation-key-c-0123456789abcdef0123456789abcdef"
)

// rotationTenant creates the tenant "alpha" with publisher key keyA on n and waits for it to be served.
func rotationTenant(t *testing.T, n *node) tn {
	t.Helper()
	a := tn{name: "alpha", host: "alpha.test", secret: keyA}
	api(t, n.base, "POST", "/api/tenants", a.spec(t), 201)
	eventually(t, 5*time.Second, "alpha served", func() bool { return serves(t, n, a) })
	return a
}

// expect waits for the statuses of publishes with each key to be as wanted (a change applies asynchronously).
func expect(t *testing.T, base, host string, want map[string]int) {
	t.Helper()
	eventually(t, 5*time.Second, fmt.Sprintf("publish statuses %v", want), func() bool {
		for k, code := range want {
			if publishWith(t, base, host, k) != code {
				return false
			}
		}
		return true
	})
}

// A rotation keeps the replaced key accepted for its grace period, alongside the new one; ending the grace period
// refuses it at once. Nothing restarts.
func TestRotateKeepsOldKeyForGrace(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := rotationTenant(t, n)
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 401})

	out := api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "1h"}, 200)
	m, _ := out["mercure"].(map[string]any)
	if until, ok := m["publisher_previous_key_until"].(string); !ok || until == "" {
		t.Errorf("the view does not say until when the previous key is accepted: %v", m)
	}
	if _, shown := m["publisher_key"]; shown {
		t.Errorf("the view shows the new secret: %v", m)
	}
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 200, keyC: 401})

	call(t, n.base, "DELETE", "/api/tenants/alpha/previous-keys", apiToken, nil)
	expect(t, n.base, a.host, map[string]int{keyA: 401, keyB: 200})
	got := api(t, n.base, "GET", "/api/tenants/alpha", nil, 200)
	if m, _ := got["mercure"].(map[string]any); m["publisher_previous_key_until"] != nil {
		t.Errorf("a previous key is still shown after its grace period ended: %v", m)
	}
}

// A grace period ends by itself: the previous key is refused once its time passes, with nothing applied again.
func TestRotateGraceExpires(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := rotationTenant(t, n)
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "2s"}, 200)
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 200})
	time.Sleep(2500 * time.Millisecond)
	if code := publishWith(t, n.base, a.host, keyA); code != 401 {
		t.Errorf("the previous key after its grace period: %d, want 401", code)
	}
	if code := publishWith(t, n.base, a.host, keyB); code != 200 {
		t.Errorf("the new key: %d, want 200", code)
	}
}

// grace 0s replaces the key at once, as a PUT does.
func TestRotateNoGrace(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := rotationTenant(t, n)
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "0s"}, 200)
	expect(t, n.base, a.host, map[string]int{keyA: 401, keyB: 200})
}

// A PUT that keeps the key keeps its previous key; one that changes the key replaces it at once.
func TestPutAndPreviousKeys(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := rotationTenant(t, n)
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 200})

	b := a
	b.secret, b.anonymous = keyB, true // another setting changes, the key stays
	api(t, n.base, "PUT", "/api/tenants/alpha", b.spec(t), 200)
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 200})

	c := a
	c.secret = keyC
	api(t, n.base, "PUT", "/api/tenants/alpha", c.spec(t), 200)
	expect(t, n.base, a.host, map[string]int{keyA: 401, keyB: 401, keyC: 200})
}

// A tenant without a subscriber key signs its subscribers' tokens with the publisher key: rotating the publisher key
// keeps their tokens good, and giving it a subscriber key keeps the publisher key good for subscribers meanwhile.
func TestRotateSubscribers(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := rotationTenant(t, n)
	if code := subscribeWith(t, n.base, a.host, keyA); code != 200 {
		t.Fatalf("subscribe with the publisher key: %d", code)
	}
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	eventually(t, 5*time.Second, "subscribers take both keys", func() bool {
		return subscribeWith(t, n.base, a.host, keyA) == 200 && subscribeWith(t, n.base, a.host, keyB) == 200
	})
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"subscriber_key": keyC}, 200)
	eventually(t, 5*time.Second, "subscribers take the new subscriber key and the replaced publisher key", func() bool {
		return subscribeWith(t, n.base, a.host, keyC) == 200 && subscribeWith(t, n.base, a.host, keyB) == 200
	})
	if code := publishWith(t, n.base, a.host, keyB); code != 200 {
		t.Errorf("publish with the publisher key after a subscriber rotation: %d", code)
	}
}

// Rotations the API refuses.
func TestRotateRefused(t *testing.T) {
	file := tn{name: "filed", host: "filed.test", secret: "file-tenant-secret-0123456789abcdef0123456789"}
	n := startNode(t, adminSettings(t, writeTenants(t, file.spec(t))))
	rotationTenant(t, n)
	other := tn{name: "bravo", host: "bravo.test", secret: keyC}
	api(t, n.base, "POST", "/api/tenants", other.spec(t), 201)
	jw := tenantSpec{Name: "jwks", Hosts: []string{"jwks.test"}, Mercure: &tenantMercure{PublisherJWKSURL: "https://idp.example/jwks"}}
	call(t, n.base, "POST", "/api/tenants", apiToken, jw)

	for name, tc := range map[string]struct {
		path string
		body any
		want int
	}{
		"no key":            {"/api/tenants/alpha/rotate", map[string]any{"grace": "1h"}, 400},
		"same key":          {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyA}, 400},
		"weak key":          {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": "short"}, 400},
		"bad grace":         {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "forever"}, 400},
		"negative grace":    {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "-1h"}, 400},
		"grace over a week": {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "169h"}, 400},
		"unknown field":     {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "keep": true}, 400},
		"another's key":     {"/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyC}, 409},
		"no such tenant":    {"/api/tenants/nobody/rotate", map[string]any{"publisher_key": keyB}, 404},
		"tenants file":      {"/api/tenants/filed/rotate", map[string]any{"publisher_key": keyB}, 409},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out := call(t, n.base, "POST", tc.path, apiToken, tc.body); code != tc.want {
				t.Errorf("%d %v, want %d", code, out, tc.want)
			}
		})
	}
	if code, _ := call(t, n.base, "DELETE", "/api/tenants/nobody/previous-keys", apiToken, nil); code != 404 {
		t.Errorf("drop previous keys of no tenant: %d, want 404", code)
	}
	if code, _ := call(t, n.base, "DELETE", "/api/tenants/filed/previous-keys", apiToken, nil); code != 409 {
		t.Errorf("drop previous keys of a file tenant: %d, want 409", code)
	}
}

// A previous key is still the tenant's: another tenant cannot take it until the grace period ends.
func TestPreviousKeyStaysTheTenants(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	rotationTenant(t, n)
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	taker := tn{name: "bravo", host: "bravo.test", secret: keyA}
	if code, out := call(t, n.base, "POST", "/api/tenants", apiToken, taker.spec(t)); code != 409 {
		t.Fatalf("a tenant with another's previous key: %d %v, want 409", code, out)
	}
	call(t, n.base, "DELETE", "/api/tenants/alpha/previous-keys", apiToken, nil)
	api(t, n.base, "POST", "/api/tenants", taker.spec(t), 201)
}

// Once a grace period has passed, the previous key is free again, though the record still holds it.
func TestExpiredPreviousKeyIsFree(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	rotationTenant(t, n)
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB, "grace": "1s"}, 200)
	time.Sleep(1500 * time.Millisecond)
	taker := tn{name: "bravo", host: "bravo.test", secret: keyA}
	api(t, n.base, "POST", "/api/tenants", taker.spec(t), 201)
	eventually(t, 5*time.Second, "bravo served", func() bool { return serves(t, n, taker) })
}

// Every node of a cluster applies a rotation and the end of its grace period.
func TestRotateAcrossCluster(t *testing.T) {
	binds := []string{freePort(t, "both"), freePort(t, "both")}
	var nodes []*node
	for i := range 2 {
		s := adminSettings(t, "")
		s.NodeID = uuid.NewString()
		s.Database = filepath.Join(t.TempDir(), fmt.Sprintf("node%d.db", i))
		s.ClusterBind = binds[i]
		s.ClusterKey = testClusterKey
		s.ClusterPeers = []string{binds[1-i]}
		nodes = append(nodes, startNode(t, s))
	}
	eventually(t, 15*time.Second, "the nodes to meet", func() bool {
		return nodes[0].gossip.NumAliveNodes() == 2 && nodes[1].gossip.NumAliveNodes() == 2
	})
	a := rotationTenant(t, nodes[0])
	expect(t, nodes[1].base, a.host, map[string]int{keyA: 200, keyB: 401})
	api(t, nodes[0].base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	expect(t, nodes[1].base, a.host, map[string]int{keyA: 200, keyB: 200})
	call(t, nodes[0].base, "DELETE", "/api/tenants/alpha/previous-keys", apiToken, nil)
	expect(t, nodes[1].base, a.host, map[string]int{keyA: 401, keyB: 200})
}

// A rotation restarts the tenant's hub: a subscriber that reconnects with its old token (still accepted) and its last
// event ID misses nothing published meanwhile, whichever key published it.
func TestRotateLosesNoUpdates(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	a := rotationTenant(t, n)
	q := url.Values{"match": {"https://example.com/r"}}
	sub := accessToken(t, keyA, a.host, "subscribe")
	first := openStream(t, n.base, a.host, sub, q, "")
	time.Sleep(100 * time.Millisecond)
	mustPost(t, n.base, a.host, accessToken(t, keyA, a.host, "publish"), url.Values{"topic": {"https://example.com/r"}, "data": {"before"}})
	eventually(t, 5*time.Second, "the first event", func() bool { return len(first.real()) == 1 })

	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	select { // the hub starts over: the stream ends, as with any change of keys
	case <-first.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end when the tenant's hub started over")
	}
	mustPost(t, n.base, a.host, accessToken(t, keyB, a.host, "publish"), url.Values{"topic": {"https://example.com/r"}, "data": {"with-new"}})
	mustPost(t, n.base, a.host, accessToken(t, keyA, a.host, "publish"), url.Values{"topic": {"https://example.com/r"}, "data": {"with-old"}})

	first.mu.Lock()
	last := first.ids[len(first.ids)-1]
	first.mu.Unlock()
	again := openStream(t, n.base, a.host, sub, q, last) // the old token, which the grace period still accepts
	eventually(t, 5*time.Second, "the updates published while it was away", func() bool {
		return slices.Equal(again.real(), []string{"with-new", "with-old"})
	})
}

// With --protocol both, draft-07 tokens signed with the previous key are accepted too.
func TestRotateDraft07Tokens(t *testing.T) {
	s := adminSettings(t, "")
	s.Protocol = "both"
	n := startNode(t, s)
	a := rotationTenant(t, n)
	draft := func(secret string) int {
		code, _ := postForm(t, n.base, a.host, tenantToken(t, secret, []string{"*"}, nil), url.Values{"topic": {"x"}, "data": {"y"}})
		return code
	}
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	eventually(t, 5*time.Second, "draft-07 tokens of both keys", func() bool { return draft(keyA) == 200 && draft(keyB) == 200 })
	if code := draft(keyC); code != 401 {
		t.Errorf("draft-07 token of another key: %d, want 401", code)
	}
	call(t, n.base, "DELETE", "/api/tenants/alpha/previous-keys", apiToken, nil)
	eventually(t, 5*time.Second, "the previous key refused", func() bool { return draft(keyA) == 401 && draft(keyB) == 200 })
}

// Previous keys are in the database: a node that restarts during a grace period still accepts them.
func TestPreviousKeysSurviveRestart(t *testing.T) {
	s := adminSettings(t, "")
	n := startNode(t, s)
	a := rotationTenant(t, n)
	api(t, n.base, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200)
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 200})
	if err := n.stop(); err != nil {
		t.Fatal(err)
	}
	n = startNode(t, s)
	eventually(t, 5*time.Second, "alpha served again", func() bool { return serves(t, n, tn{name: "alpha", host: a.host, secret: keyB}) })
	expect(t, n.base, a.host, map[string]int{keyA: 200, keyB: 200, keyC: 401})
}

// An identity provider's token rotates only the tenants it may write.
func TestRotateNeedsWriteOnTheTenant(t *testing.T) {
	p := newFakeIDP(t)
	n := startNode(t, idpSettings(t, p))
	rotationTenant(t, n)
	b := tn{name: "bravo", host: "bravo.test", secret: keyC}
	api(t, n.base, "POST", "/api/tenants", b.spec(t), 201)

	alphaOnly := p.token(t, details(map[string]any{"actions": []string{"write"}, "tenants": []string{"alpha"}}))
	readAll := p.token(t, details(map[string]any{"actions": []string{"read"}}))
	// In order: the refusals, then what the token may do.
	for _, tc := range []struct {
		name, tok, method, path string
		body                    any
		want                    int
	}{
		{"other tenant", alphaOnly, "POST", "/api/tenants/bravo/rotate", map[string]any{"publisher_key": keyB}, 403},
		{"other's previous keys", alphaOnly, "DELETE", "/api/tenants/bravo/previous-keys", nil, 403},
		{"read only", readAll, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 403},
		{"read only previous keys", readAll, "DELETE", "/api/tenants/alpha/previous-keys", nil, 403},
		{"its tenant", alphaOnly, "POST", "/api/tenants/alpha/rotate", map[string]any{"publisher_key": keyB}, 200},
		{"its previous keys", alphaOnly, "DELETE", "/api/tenants/alpha/previous-keys", nil, 204},
	} {
		if code, out := call(t, n.base, tc.method, tc.path, tc.tok, tc.body); code != tc.want {
			t.Errorf("%s: %d %v, want %d", tc.name, code, out, tc.want)
		}
	}
}
