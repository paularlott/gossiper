package gossiper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A publish asking for more copies than there are nodes is refused, and not delivered; one asking for copies is
// idempotent by its ID, and one that does not ask is not (the spec delivers a reused ID again).
func TestCopiesSingleNode(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.subscribe(t, "", "https://c.test/a")
	tok := tokenFor(t, all, nil)
	post := func(d, id, replicas string) result {
		hdr := bearer(tok)
		if replicas != "" {
			hdr.Set(replicasHeader, replicas)
		}
		form := url.Values{"topic": {"https://c.test/a"}, "data": {d}}
		if id != "" {
			form.Set("id", id)
		}
		return e.do(t, http.MethodPost, e.hubURL(), hdr, form.Encode())
	}
	if r := post("two", "", "2"); r.code != 503 || !strings.Contains(r.body, "Too few nodes: 1 of 2") {
		t.Fatalf("2 copies on one node: %d %q", r.code, r.body)
	}
	for _, bad := range []string{"x", "-1", fmt.Sprint(MaxReplicas + 1)} {
		if r := post("bad", "", bad); r.code != 400 {
			t.Fatalf("replicas %q: %d %q", bad, r.code, r.body)
		}
	}
	for range 2 { // the second is the first published again
		if r := post("once", "urn:once", "1"); r.code != 200 || r.body != "urn:once" {
			t.Fatalf("idempotent publish: %d %q", r.code, r.body)
		}
	}
	for range 2 {
		if r := post("twice", "urn:twice", ""); r.code != 200 {
			t.Fatalf("plain publish: %d %q", r.code, r.body)
		}
	}
	sub.expect("once", "twice", "twice")
	if n := e.hub.Stats().Duplicates; n != 1 {
		t.Errorf("%d duplicates, want 1", n)
	}
}

// On a stream, "replicas" asks for copies: too many is a refused line; an update published again with its ID is
// answered as the first, and not delivered again.
func TestCopiesStream(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.subscribe(t, "", "https://c.test/s")
	c := e.stream(t, tokenFor(t, all, nil))
	c.send(t, `{"topic":["https://c.test/s"],"data":"x","replicas":3}`)
	if a := c.answer(t); a.ID != "" || a.Line != 1 || a.Status != 503 || a.Error != "Too few nodes: 1 of 3" {
		t.Fatalf("3 copies on one node: %+v", a)
	}
	for range 2 {
		c.send(t, `{"topic":["https://c.test/s"],"data":"once","id":"urn:s","replicas":1}`)
		if a := c.answer(t); a.ID != "urn:s" || a.Status != 0 {
			t.Fatalf("idempotent line: %+v", a)
		}
	}
	c.send(t, `{"topic":["https://c.test/s"],"data":"after"}`)
	if a := c.answer(t); a.ID == "" {
		t.Fatalf("plain line: %+v", a)
	}
	sub.expect("once", "after")
}

// Hub.Publish takes the copies asked for too.
func TestCopiesHubPublish(t *testing.T) {
	h := newModernHub(t, Config{})
	_, err := h.Publish(context.Background(), &Update{Topics: []string{"https://c.test/p"}, Replicas: 2})
	if !errors.Is(err, ErrTooFewNodes) {
		t.Fatalf("2 copies on one node: %v", err)
	}
	for range 2 {
		if id, err := h.Publish(context.Background(), &Update{ID: "urn:p", Topics: []string{"https://c.test/p"}, Replicas: 1}); err != nil || id != "urn:p" {
			t.Fatalf("idempotent publish: %q %v", id, err)
		}
	}
	if h.hist.len() != 1 {
		t.Fatalf("the history holds %d updates, want 1", h.hist.len())
	}
}

// The idempotency set remembers an ID for at least half its window, and stays bounded.
func TestIdempotencySet(t *testing.T) {
	var s idempotency
	now := time.Now()
	if !s.first("a", now) || s.first("a", now) {
		t.Fatal("a repeated ID was not caught")
	}
	if s.first("a", now.Add(idempotencyWindow/2)) { // rotated: still in the older generation
		t.Fatal("an ID was forgotten within the window")
	}
	if !s.first("a", now.Add(2*idempotencyWindow)) {
		t.Fatal("an ID was remembered past the window")
	}
	for i := range idempotencyMax + 10 {
		s.first(fmt.Sprint(i), now)
	}
	if n := len(s.cur) + len(s.old); n > idempotencyMax {
		t.Errorf("the set holds %d IDs", n)
	}
}
