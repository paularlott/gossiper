package gossiper

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// msDoc is a Mercure 1.0 (and draft-07) subscription document.
type msDoc struct {
	Context    string          `json:"@context"`
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	MatchType  string          `json:"match_type"`
	Match      string          `json:"match"`
	Topic      string          `json:"topic"`
	Subscriber string          `json:"subscriber"`
	Active     bool            `json:"active"`
	Payload    json.RawMessage `json:"payload"`
}

func rawKeys(t testing.TB, data string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		t.Fatalf("not a JSON object: %q: %v", data, err)
	}
	return m
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nextDoc reads events until one whose subscription document satisfies pred.
func nextDoc(t testing.TB, c *sseClient, pred func(msDoc) bool) (msDoc, sseEvent) {
	t.Helper()
	for {
		ev := c.mustNext()
		var d msDoc
		if err := json.Unmarshal([]byte(ev.Data), &d); err != nil {
			t.Fatalf("event data %q: %v", ev.Data, err)
		}
		if pred(d) {
			return d, ev
		}
	}
}

func withMatch(match string, active bool) func(msDoc) bool {
	return func(d msDoc) bool { return d.Match == match && d.Active == active }
}

var regexpLastEventID = regexp.MustCompile(`last-event-id="([^"]*)"`)

// collectDocs reads events until a subscription document of every wanted match has been seen (as active or not),
// skipping the others, and returns the documents by match.
func collectDocs(t testing.TB, c *sseClient, active bool, wanted ...string) (map[string]msDoc, map[string]sseEvent) {
	t.Helper()
	docs, frames := map[string]msDoc{}, map[string]sseEvent{}
	want := map[string]bool{}
	for _, m := range wanted {
		want[m] = true
	}
	for len(docs) < len(want) {
		d, ev := nextDoc(t, c, func(d msDoc) bool { return want[d.Match] && d.Active == active })
		if _, dup := docs[d.Match]; !dup {
			docs[d.Match], frames[d.Match] = d, ev
		}
	}
	return docs, frames
}

const subsGlob = "/.well-known/mercure/subscriptions/*"

// monitor subscribes to every subscription event; its token grants them by a relative URL pattern.
func (e *env) monitor(t testing.TB) *sseClient {
	t.Helper()
	return e.matchStream(t, e.access(t, mDetail(subOnly, mPattern(subsGlob))), "match_urlpattern", subsGlob)
}

func subID(matchType, match, subscriber string) string {
	return subsBase + "/" + matchType + "/" + escapeSegment(match) + "/" + escapeSegment(subscriber)
}

// TestSubscriptionEventsMercure1: §8.1.
func TestSubscriptionEventsMercure1(t *testing.T) {
	const (
		foo = "https://example.com/foo"
		bar = "https://example.com/bar/:id"
		oth = "https://example.com/other"
	)
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		mon := e.monitor(t)

		// The token of §6.8: the payload of the first matching detail is the subscription's.
		tok := e.access(t,
			mPayload(mDetail(subOnly, mBare(foo)), map[string]any{"custom1": "data only available for this topic"}),
			mPayload(mDetail(subOnly, mPattern(bar)), map[string]any{"custom2": "data available for matching subscriptions"}),
			mPayload(mDetail(subOnly, mBare("*")), map[string]any{"custom3": "default data for all other subscriptions"}),
		)
		c := e.matchStream(t, tok, "match", foo, "match_urlpattern", bar, "match", oth)

		got, frames := collectDocs(t, mon, true, foo, bar, oth)
		subscriber := got[foo].Subscriber
		if !uuidV4.MatchString(subscriber) {
			t.Fatalf("subscriber %q", subscriber)
		}
		wantPayload := map[string]string{
			foo: `{"custom1":"data only available for this topic"}`,
			bar: `{"custom2":"data available for matching subscriptions"}`,
			oth: `{"custom3":"default data for all other subscriptions"}`,
		}
		wantType := map[string]string{foo: "exact", bar: "urlpattern", oth: "exact"}
		for match, d := range got {
			if d.ID != subID(wantType[match], match, subscriber) {
				t.Errorf("%s: id %q, want %q", match, d.ID, subID(wantType[match], match, subscriber))
			}
			if d.Type != "subscription" || d.MatchType != wantType[match] || d.Match != match || d.Subscriber != subscriber || !d.Active {
				t.Errorf("%s: %+v", match, d)
			}
			if d.Context != "" || d.Topic != "" {
				t.Errorf("%s: draft-07 members in a Mercure 1.0 document: %+v", match, d)
			}
			if string(d.Payload) != wantPayload[match] {
				t.Errorf("%s: payload %s, want %s", match, d.Payload, wantPayload[match])
			}
			ev := frames[match]
			if ev.Type != "mercure" {
				t.Errorf("%s: SSE event type %q, want mercure", match, ev.Type)
			}
			if keys := keysOf(rawKeys(t, ev.Data)); !reflect.DeepEqual(keys, []string{"active", "id", "match", "match_type", "payload", "subscriber", "type"}) {
				t.Errorf("%s: members %v", match, keys)
			}
		}

		// It ends: inactive events with the same ids.
		c.close()
		ended, endedFrames := collectDocs(t, mon, false, foo, bar, oth)
		for match, d := range ended {
			ev := endedFrames[match]
			if d.ID != got[match].ID || d.Subscriber != subscriber || ev.Type != "mercure" || string(d.Payload) != wantPayload[match] {
				t.Errorf("%s: inactive event %+v (%s)", match, d, ev.Type)
			}
		}
	})
}

func TestSubscriptionEventPayloadSelection(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		mon := e.monitor(t)
		first := map[string]any{"which": "first"}
		second := map[string]any{"which": "second"}
		tok := e.access(t,
			mPayload(mDetail(subOnly, mExact("https://example.com/a")), first),
			mPayload(mDetail(subOnly, mPattern("https://example.com/*")), second),
			mDetail(subOnly, mPattern("https://nowhere.example/*")),
			mPayload(mDetail(pubOnly, mBare("*")), map[string]any{"which": "publish detail"}),
		)
		e.matchStream(t, tok,
			"match", "https://example.com/a", // the first detail, though the second matches too
			"match", "https://example.com/b", // the second
			"match_urlpattern", "https://example.com/c/*", // the second: the pattern string is matched as a topic
			"match", "urn:no-detail", // none: no payload
			"match", "https://nowhere.example/x", // a detail without a payload
		)
		want := map[string]string{
			"https://example.com/a":     `{"which":"first"}`,
			"https://example.com/b":     `{"which":"second"}`,
			"https://example.com/c/*":   `{"which":"second"}`,
			"urn:no-detail":             "",
			"https://nowhere.example/x": "",
		}
		var matches []string
		for m := range want {
			matches = append(matches, m)
		}
		docs, frames := collectDocs(t, mon, true, matches...)
		for _, d := range docs {
			ev := frames[d.Match]
			if string(d.Payload) != want[d.Match] {
				t.Errorf("%s: payload %q, want %q", d.Match, d.Payload, want[d.Match])
			}
			if want[d.Match] == "" {
				if _, ok := rawKeys(t, ev.Data)["payload"]; ok {
					t.Errorf("%s: payload member in %s", d.Match, ev.Data)
				}
			}
		}
	})
}

func TestSubscriptionEventIDs(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		mon := e.monitor(t)
		tok := e.access(t, mDetail(subOnly, mBare("*")))
		const odd = "https://example.com/a b?x=1&y=%20#f"
		const oddEscaped = "https%3A%2F%2Fexample.com%2Fa%20b%3Fx%3D1%26y%3D%2520%23f"

		e.matchStream(t, tok, "match", odd, "match_urlpattern", "https://example.com/:id")
		e.matchStream(t, tok, "match", odd)
		odds := map[string]bool{}
		var pattern msDoc
		for len(odds) < 2 || pattern.Subscriber == "" {
			d, _ := nextDoc(t, mon, func(d msDoc) bool { return d.Active && (d.Match == odd || d.Match == "https://example.com/:id") })
			if d.Match != odd {
				pattern = d
				continue
			}
			if !odds[d.Subscriber] {
				odds[d.Subscriber] = true
				if want := subsBase + "/exact/" + oddEscaped + "/" + escapeSegment(d.Subscriber); d.ID != want {
					t.Errorf("id %q, want %q", d.ID, want)
				}
				if dec, err := url.PathUnescape(strings.Split(strings.TrimPrefix(d.ID, subsBase+"/exact/"), "/")[0]); err != nil || dec != odd {
					t.Errorf("the match in the id is encoded more than once: %q (%v)", dec, err)
				}
				if !uuidV4.MatchString(d.Subscriber) {
					t.Errorf("subscriber %q is not a random identifier", d.Subscriber)
				}
			}
		}
		// One connection, one identifier across its subscriptions; two connections of one token, two identifiers.
		if !odds[pattern.Subscriber] {
			t.Errorf("subscriber %q of the second matcher is not one of %v", pattern.Subscriber, odds)
		}
	})
}

// TestSubscriptionEventsArePrivateMercure1: only subscribers granted the event's topic receive it.
func TestSubscriptionEventsArePrivateMercure1(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		cfg.Anonymous = true
		e := newEnv(t, cfg)
		route := []string{"match", "sentinel", "match_urlpattern", subsGlob}

		anon := e.matchStream(t, "", route...)
		unrelated := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("https://example.com/*"))), route...)
		exactOnly := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern(subsBase+"/exact/*"))), route...)
		patternOnly := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern(subsBase+"/urlpattern/*"))), route...)
		absolute := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("https://localhost"+subsBase+"/*"))), route...)
		otherHost := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("https://other.example"+subsBase+"/*"))), route...)
		exactGrant := e.matchStream(t, e.access(t, mDetail(subOnly, mExact(subsBase+"/*"))), route...)
		everything := e.monitor(t)
		wildcard := e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), route...)
		publishOnly := e.matchStream(t, e.access(t, mDetail(pubOnly, mBare("*"))), route...)

		waitSubscribers(t, e.hub, 10)
		e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match", "https://example.com/x", "match_urlpattern", "https://example.com/:y")
		collectDocs(t, everything, true, "https://example.com/x", "https://example.com/:y")

		onlyType := func(c *sseClient, allowed ...string) {
			t.Helper()
			e.publishA(t, "end", "sentinel")
			for {
				ev := c.mustNext()
				if ev.Data == "end" {
					return
				}
				var d msDoc
				if err := json.Unmarshal([]byte(ev.Data), &d); err != nil {
					t.Fatal(err)
				}
				if d.Match != "https://example.com/x" && d.Match != "https://example.com/:y" {
					continue // another stream's own announcement
				}
				if !slices.Contains(allowed, d.MatchType) {
					t.Fatalf("a subscriber granted %v received %s", allowed, ev.Data)
				}
			}
		}
		onlyType(anon)
		onlyType(unrelated)
		onlyType(otherHost)
		onlyType(exactGrant)
		onlyType(publishOnly)
		onlyType(exactOnly, "exact")
		onlyType(patternOnly, "urlpattern")
		onlyType(absolute, "exact", "urlpattern")
		onlyType(wildcard, "exact", "urlpattern")
	})
}

// TestSubscriptionEventsGrantedByType checks that the grants above actually deliver.
func TestSubscriptionEventsGrantedByType(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		route := []string{"match_urlpattern", subsGlob}
		exactOnly := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern(subsBase+"/exact/*"))), route...)
		patternOnly := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern(subsBase+"/urlpattern/*"))), route...)
		absolute := e.matchStream(t, e.access(t, mDetail(subOnly, mPattern("https://localhost"+subsBase+"/*"))), route...)
		wildcard := e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), route...)
		e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match", "https://example.com/x", "match_urlpattern", "https://example.com/:y")
		for _, tc := range []struct {
			name string
			c    *sseClient
			want []string
		}{
			{"exact grant by pattern", exactOnly, []string{"https://example.com/x"}},
			{"urlpattern grant by pattern", patternOnly, []string{"https://example.com/:y"}},
			{"absolute pattern grant", absolute, []string{"https://example.com/x", "https://example.com/:y"}},
			{"wildcard", wildcard, []string{"https://example.com/x", "https://example.com/:y"}},
		} {
			collectDocs(t, tc.c, true, tc.want...)
		}
	})
}

// TestSubscriptionEventsKeepDraft07: in a hub that speaks both revisions, draft-07 subscriptions keep their format.
func TestSubscriptionEventsKeepDraft07(t *testing.T) {
	e := newEnv(t, Config{Protocol: ProtocolBoth, TrustedIssuers: []string{testIssuer}, Subscriptions: true})
	mon := e.monitor(t)
	legacyMonitor := e.subscribe(t, tokenFor(t, nil, all), "*")

	claims := mercureClaims(nil, all)
	claims["mercure"].(map[string]any)["payload"] = map[string]any{"user": "paul"}
	e.subscribe(t, signJWT(t, testSecret, claims), "https://example.com/legacy")
	e.matchStream(t, e.access(t, mPayload(mDetail(subOnly, mBare("*")), map[string]any{"user": "modern"})), "match", "https://example.com/modern")

	legacyDoc, legacyEv := nextDoc(t, mon, func(d msDoc) bool { return d.Topic == "https://example.com/legacy" && d.Active })
	modernDoc, modernEv := nextDoc(t, mon, func(d msDoc) bool { return d.Match == "https://example.com/modern" && d.Active })

	if legacyEv.Type != "" || legacyDoc.Type != "Subscription" || legacyDoc.Context != "https://mercure.rocks/" || legacyDoc.MatchType != "" || legacyDoc.Match != "" {
		t.Errorf("draft-07 subscription event: type %q, %+v", legacyEv.Type, legacyDoc)
	}
	if want := subsBase + "/" + escapeSegment("https://example.com/legacy") + "/" + escapeSegment(legacyDoc.Subscriber); legacyDoc.ID != want {
		t.Errorf("draft-07 id %q, want %q", legacyDoc.ID, want)
	}
	if string(legacyDoc.Payload) != `{"user":"paul"}` {
		t.Errorf("draft-07 payload %s", legacyDoc.Payload)
	}
	if modernEv.Type != "mercure" || modernDoc.Type != "subscription" || modernDoc.MatchType != "exact" || modernDoc.Context != "" || modernDoc.Topic != "" {
		t.Errorf("Mercure 1.0 subscription event: type %q, %+v", modernEv.Type, modernDoc)
	}
	if string(modernDoc.Payload) != `{"user":"modern"}` {
		t.Errorf("Mercure 1.0 payload %s", modernDoc.Payload)
	}

	// A draft-07 token's mercure.payload serves a subscription made with Mercure 1.0 parameters.
	e.matchStream(t, signJWT(t, testSecret, claims), "match", "https://example.com/legacy-token-modern-params")
	d, ev := nextDoc(t, mon, withMatch("https://example.com/legacy-token-modern-params", true))
	if ev.Type != "mercure" || d.MatchType != "exact" || string(d.Payload) != `{"user":"paul"}` {
		t.Errorf("%s %+v", ev.Type, d)
	}
	// The draft-07 monitor, which has a draft-07 token, sees both (its token allows everything).
	if _, ev = nextDoc(t, legacyMonitor, func(d msDoc) bool { return d.Match == "https://example.com/modern" }); ev.Type != "mercure" {
		t.Errorf("event type %q", ev.Type)
	}
}

// ---- the subscriptions API ----

const (
	subsA = "https://example.com/a"
	subsB = "https://example.com/b"
	subsP = "https://example.com/:selector"
)

// apiFixture is a hub with two subscribers: S1 on A and P (with payloads), S2 on B and P.
type apiFixture struct {
	e      *env
	aud    string // the audience of its tokens
	s1, s2 string // subscriber ids
	c1, c2 *sseClient
}

func newAPIFixture(t *testing.T, cfg Config) *apiFixture {
	t.Helper()
	cfg.Subscriptions = true
	e := newEnv(t, cfg)
	f := &apiFixture{e: e, aud: e.hubURL()}
	if cfg.ResourceIdentifier != "" {
		f.aud = cfg.ResourceIdentifier
	}
	t1 := f.token(t, mPayload(mDetail(subOnly, mBare("*")), map[string]any{"foo": "bar"}))
	t2 := f.token(t, mPayload(mDetail(subOnly, mBare("*")), map[string]any{"foo": "bap"}))
	f.c1 = e.matchStream(t, t1, "match", subsA, "match_urlpattern", subsP)
	f.c2 = e.matchStream(t, t2, "match", subsB, "match_urlpattern", subsP)
	for _, s := range e.hub.LocalSubscriptions() {
		switch {
		case s.Match == subsA:
			f.s1 = s.Subscriber
		case s.Match == subsB:
			f.s2 = s.Subscriber
		}
	}
	if f.s1 == "" || f.s2 == "" {
		t.Fatalf("subscribers %v", e.hub.LocalSubscriptions())
	}
	return f
}

func (f *apiFixture) token(t testing.TB, details ...any) string {
	return accessFor(t, f.aud, details...)
}

func (f *apiFixture) all(t testing.TB) string {
	return f.token(t, mDetail(subOnly, mPattern(subsBase+"{/*}?")))
}

func (f *apiFixture) get(t testing.TB, path, tok string) result {
	t.Helper()
	return f.e.get(t, f.e.srv.URL+path, bearer(tok))
}

func escPath(matchType, match string, rest ...string) string {
	p := subsBase + "/" + matchType + "/" + escapeSegment(match)
	for _, r := range rest {
		p += "/" + escapeSegment(r)
	}
	return p
}

type apiCollection struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	Context       string          `json:"@context"`
	LastEventID   string          `json:"lastEventID"`
	Subscriptions json.RawMessage `json:"subscriptions"`
}

func decodeCollection(t testing.TB, body string) (apiCollection, []msDoc) {
	t.Helper()
	var c apiCollection
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("%q: %v", body, err)
	}
	var docs []msDoc
	if err := json.Unmarshal(c.Subscriptions, &docs); err != nil {
		t.Fatalf("subscriptions %s: %v", c.Subscriptions, err)
	}
	return c, docs
}

// TestSubscriptionsAPIMercure1: §8.2.
func TestSubscriptionsAPIMercure1(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.HubURL = "https://hub.example/.well-known/mercure"
		cfg.ResourceIdentifier = "https://hub.example/.well-known/mercure"
		f := newAPIFixture(t, cfg)
		e := f.e
		full := f.all(t) // its tokens name the configured resource identifier, not the test server
		last := e.hub.hist.last()
		if last == "" {
			t.Fatal("no events after two subscribers connected")
		}
		wantLink := `<https://hub.example/.well-known/mercure>; rel="mercure"; last-event-id="` + last + `"; type="mercure"; content-type="application/json"`
		checkHeaders := func(t *testing.T, r result) {
			t.Helper()
			if r.header.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type %q", r.header.Get("Content-Type"))
			}
			if r.header.Get("Link") != wantLink {
				t.Errorf("Link %q, want %q", r.header.Get("Link"), wantLink)
			}
			if r.header.Get("ETag") != `"`+last+`"` {
				t.Errorf("ETag %q", r.header.Get("ETag"))
			}
			if r.header.Get("Cache-Control") != "private, must-revalidate" {
				t.Errorf("Cache-Control %q", r.header.Get("Cache-Control"))
			}
		}

		t.Run("the collection", func(t *testing.T) {
			r := f.get(t, subsBase, full)
			if r.code != 200 {
				t.Fatalf("%d %s", r.code, r.body)
			}
			checkHeaders(t, r)
			col, docs := decodeCollection(t, r.body)
			if col.ID != subsBase || col.Type != "subscriptions" || col.Context != "" || col.LastEventID != "" {
				t.Errorf("collection %+v", col)
			}
			want := map[string]string{
				subID("exact", subsA, f.s1):      `{"foo":"bar"}`,
				subID("urlpattern", subsP, f.s1): `{"foo":"bar"}`,
				subID("exact", subsB, f.s2):      `{"foo":"bap"}`,
				subID("urlpattern", subsP, f.s2): `{"foo":"bap"}`,
			}
			if len(docs) != len(want) {
				t.Fatalf("%d documents: %s", len(docs), r.body)
			}
			var ids []string
			for _, d := range docs {
				ids = append(ids, d.ID)
				pl, ok := want[d.ID]
				if !ok || d.Type != "subscription" || !d.Active || string(d.Payload) != pl || d.Context != "" || d.Topic != "" {
					t.Errorf("document %+v", d)
				}
			}
			if !sort.StringsAreSorted(ids) {
				t.Errorf("documents are not in a stable order: %v", ids)
			}
		})
		t.Run("a matcher's collection", func(t *testing.T) {
			path := escPath("urlpattern", subsP)
			if path != subsBase+"/urlpattern/https%3A%2F%2Fexample.com%2F%3Aselector" {
				t.Fatalf("path %s", path)
			}
			r := f.get(t, path, full)
			if r.code != 200 {
				t.Fatalf("%d %s", r.code, r.body)
			}
			checkHeaders(t, r)
			col, docs := decodeCollection(t, r.body)
			if col.ID != path || col.Type != "subscriptions" || len(docs) != 2 {
				t.Fatalf("%+v %v", col, docs)
			}
			for _, d := range docs {
				if d.MatchType != "urlpattern" || d.Match != subsP {
					t.Errorf("%+v", d)
				}
			}
			r = f.get(t, escPath("exact", subsA), full)
			if _, docs = decodeCollection(t, r.body); len(docs) != 1 || docs[0].Subscriber != f.s1 {
				t.Errorf("exact A: %s", r.body)
			}
			// A matcher nobody uses: an empty list, not null.
			r = f.get(t, escPath("exact", "https://example.com/nobody"), full)
			if r.code != 200 || !strings.Contains(r.body, `"subscriptions":[]`) {
				t.Errorf("%d %s", r.code, r.body)
			}
			// The type is part of the key.
			r = f.get(t, escPath("exact", subsP), full)
			if _, docs = decodeCollection(t, r.body); len(docs) != 0 {
				t.Errorf("exact pattern string: %s", r.body)
			}
		})
		t.Run("a subscription", func(t *testing.T) {
			path := escPath("urlpattern", subsP, f.s1)
			r := f.get(t, path, full)
			if r.code != 200 {
				t.Fatalf("%d %s", r.code, r.body)
			}
			checkHeaders(t, r)
			var d msDoc
			if err := json.Unmarshal([]byte(r.body), &d); err != nil {
				t.Fatal(err)
			}
			if d.ID != path || d.Type != "subscription" || d.MatchType != "urlpattern" || d.Match != subsP || d.Subscriber != f.s1 || !d.Active || string(d.Payload) != `{"foo":"bar"}` {
				t.Errorf("%+v", d)
			}
			if keys := keysOf(rawKeys(t, r.body)); !reflect.DeepEqual(keys, []string{"active", "id", "match", "match_type", "payload", "subscriber", "type"}) {
				t.Errorf("members %v (the cursor belongs in the Link header)", keys)
			}
		})
		t.Run("HEAD", func(t *testing.T) {
			r := e.do(t, http.MethodHead, e.srv.URL+subsBase, bearer(full), "")
			if r.code != 200 || r.body != "" {
				t.Fatalf("%d %q", r.code, r.body)
			}
			checkHeaders(t, r)
		})
		t.Run("not found", func(t *testing.T) {
			for _, path := range []string{
				escPath("exact", subsA, "urn:uuid:unknown"),
				escPath("exact", subsA, f.s2), // S2 has no subscription to A
				escPath("urlpattern", subsA, f.s1),
				subsBase + "/regex/" + escapeSegment(subsA),
				subsBase + "/regex/" + escapeSegment(subsA) + "/" + escapeSegment(f.s1),
				subsBase + "/Exact/" + escapeSegment(subsA),
				subsBase + "/exact",
				subsBase + "/exact/",
				subsBase + "/",
				subsBase + "/exact/a/b/c",
				subsBase + "/x/y/z/w",
			} {
				r := f.get(t, path, full)
				if r.code != 404 {
					t.Errorf("%s: %d %s", path, r.code, r.body)
				}
			}
		})
		t.Run("methods", func(t *testing.T) {
			r := e.do(t, http.MethodPost, e.srv.URL+subsBase, bearer(full), "x=1")
			if r.code != 405 || r.header.Get("Allow") != "GET, HEAD, OPTIONS" {
				t.Fatalf("%d %v", r.code, r.header)
			}
		})
		t.Run("a subscription that ended is gone", func(t *testing.T) {
			f.c2.close()
			eventually(t, "S2 to go", func() bool {
				return f.get(t, escPath("exact", subsB, f.s2), full).code == 404
			})
			r := f.get(t, subsBase, full)
			if _, docs := decodeCollection(t, r.body); len(docs) != 2 {
				t.Errorf("%s", r.body)
			}
		})
	})
}

// TestSubscriptionsAPIAuthorization: the grant is matched against the request's path.
func TestSubscriptionsAPIAuthorization(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		f := newAPIFixture(t, mcfg(p))
		e := f.e
		coll := subsBase
		matcher := escPath("exact", subsA)
		single := escPath("exact", subsA, f.s1)
		type tc struct {
			name  string
			token string
			want  [3]int // collection, matcher collection, subscription
		}
		ok, no := 200, 403
		for _, c := range []tc{
			{"wildcard", f.token(t, mDetail(subOnly, mBare("*"))), [3]int{ok, ok, ok}},
			{"wildcard urlpattern", f.token(t, mDetail(subOnly, mPattern("*"))), [3]int{ok, ok, ok}},
			{"everything under the path", f.token(t, mDetail(subOnly, mPattern(subsBase+"{/*}?"))), [3]int{ok, ok, ok}},
			{"star under the path needs a segment", f.token(t, mDetail(subOnly, mPattern(subsGlob))), [3]int{no, ok, ok}},
			{"absolute pattern", f.token(t, mDetail(subOnly, mPattern("https://localhost"+subsBase+"{/*}?"))), [3]int{ok, ok, ok}},
			{"pattern of another host", f.token(t, mDetail(subOnly, mPattern("https://elsewhere.example"+subsBase+"{/*}?"))), [3]int{no, no, no}},
			{"exact collection path", f.token(t, mDetail(subOnly, mExact(coll))), [3]int{ok, no, no}},
			{"exact matcher path", f.token(t, mDetail(subOnly, mExact(matcher))), [3]int{no, ok, no}},
			{"exact subscription path", f.token(t, mDetail(subOnly, mExact(single))), [3]int{no, no, ok}},
			{"exact with the unescaped match", f.token(t, mDetail(subOnly, mExact(subsBase+"/exact/"+subsA))), [3]int{no, no, no}},
			{"exact is not a pattern", f.token(t, mDetail(subOnly, mExact(subsGlob))), [3]int{no, no, no}},
			{"pattern by matcher type", f.token(t, mDetail(subOnly, mPattern(subsBase+"/exact/:match"))), [3]int{no, ok, no}},
			{"pattern by matcher type and subscriber", f.token(t, mDetail(subOnly, mPattern(subsBase+"/exact/:match/:subscriber"))), [3]int{no, no, ok}},
			{"pattern for the other type", f.token(t, mDetail(subOnly, mPattern(subsBase+"/urlpattern/*"))), [3]int{no, no, no}},
			{"this subscriber only", f.token(t, mDetail(subOnly, mPattern(subsBase+"/*/*/"+escapeSegment(f.s1)))), [3]int{no, no, ok}},
			{"publish only", f.token(t, mDetail(pubOnly, mBare("*"))), [3]int{no, no, no}},
			{"publish and a narrow subscribe", f.token(t, mDetail(pubOnly, mBare("*")), mDetail(subOnly, mExact(coll))), [3]int{ok, no, no}},
			{"no details", f.token(t), [3]int{no, no, no}},
		} {
			t.Run(c.name, func(t *testing.T) {
				for i, path := range []string{coll, matcher, single} {
					r := f.get(t, path, c.token)
					if r.code != c.want[i] {
						t.Errorf("%s: %d, want %d (%s)", path, r.code, c.want[i], strings.TrimSpace(r.body))
					}
					if r.code == 403 {
						wantChallenge(t, r.header, "insufficient_scope", e.metadataURL())
					}
				}
			})
		}
		t.Run("no token", func(t *testing.T) {
			r := f.get(t, coll, "")
			if r.code != 401 {
				t.Fatalf("%d", r.code)
			}
			wantChallenge(t, r.header, "", e.metadataURL())
		})
		t.Run("bad token", func(t *testing.T) {
			bad := signAccess(t, accessClaims("https://other.example", time.Hour, mDetail(subOnly, mBare("*"))))
			r := f.get(t, coll, bad)
			if r.code != 401 {
				t.Fatalf("%d", r.code)
			}
			wantChallenge(t, r.header, "invalid_token", e.metadataURL())
		})
		t.Run("a unknown path is not authorized before it is found", func(t *testing.T) {
			// A token that cannot read the path is told so, not that it does not exist.
			r := f.get(t, subsBase+"/regex/x", f.token(t, mDetail(subOnly, mExact(coll))))
			if r.code != 403 {
				t.Fatalf("%d", r.code)
			}
		})
		t.Run("draft-07 token", func(t *testing.T) {
			legacy := tokenFor(t, nil, all)
			r := f.get(t, matcher, legacy)
			if !p.legacy() {
				if r.code != 401 {
					t.Fatalf("%d", r.code)
				}
				return
			}
			// Both: the selectors authorize, and a Mercure 1.0 path gets Mercure 1.0 documents.
			if r.code != 200 || r.header.Get("Content-Type") != "application/json" {
				t.Fatalf("%d %v", r.code, r.header)
			}
			col, _ := decodeCollection(t, r.body)
			if col.Type != "subscriptions" || col.Context != "" {
				t.Errorf("%+v", col)
			}
			// The collection URL has no revision: the token's revision decides.
			r = f.get(t, subsBase, legacy)
			col, _ = decodeCollection(t, r.body)
			if r.code != 200 || r.header.Get("Content-Type") != "application/ld+json" || col.Type != "Subscriptions" || col.Context != "https://mercure.rocks/" || col.LastEventID == "" {
				t.Errorf("draft-07 collection: %d %v %s", r.code, r.header, r.body)
			}
			if got := r.header.Get("Link"); got != `</.well-known/mercure>; rel="mercure"` {
				t.Errorf("draft-07 Link %q", got)
			}
			r = f.get(t, subsBase, f.all(t))
			if r.code != 200 || r.header.Get("Content-Type") != "application/json" {
				t.Errorf("Mercure 1.0 collection: %d %v", r.code, r.header)
			}
		})
	})
}

// TestSubscriptionsAPIDocumentsMatchEvents: §8.2: a single-subscription response is the event's document.
func TestSubscriptionsAPIDocumentsMatchEvents(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		mon := e.monitor(t)
		tok := e.access(t, mPayload(mDetail(subOnly, mBare("*")), map[string]any{"n": 1, "s": "x y"}))
		e.matchStream(t, tok, "match", subsA, "match_urlpattern", subsP)
		api := e.access(t, mDetail(subOnly, mPattern(subsBase+"{/*}?")))
		docs, frames := collectDocs(t, mon, true, subsA, subsP) // the two events come in any order
		for _, m := range []struct{ typ, match string }{{"exact", subsA}, {"urlpattern", subsP}} {
			d, ev := docs[m.match], frames[m.match]
			r := e.get(t, e.srv.URL+escPath(m.typ, m.match, d.Subscriber), bearer(api))
			if r.code != 200 {
				t.Fatalf("%d %s", r.code, r.body)
			}
			var fromEvent, fromAPI map[string]any
			if err := json.Unmarshal([]byte(ev.Data), &fromEvent); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(r.body), &fromAPI); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fromEvent, fromAPI) {
				t.Errorf("event %s\nAPI   %s", ev.Data, r.body)
			}
		}
	})
}

// TestSubscriptionsAPICursor: the Link header's last-event-id is the hub's last event, and reconciles with the stream.
func TestSubscriptionsAPICursor(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		cfg := mcfg(p)
		cfg.Subscriptions = true
		e := newEnv(t, cfg)
		api := e.access(t, mDetail(subOnly, mPattern(subsBase+"{/*}?")))
		cursor := func(r result) string {
			t.Helper()
			m := regexpLastEventID.FindStringSubmatch(r.header.Get("Link"))
			if m == nil {
				t.Fatalf("Link %q has no last-event-id", r.header.Get("Link"))
			}
			if r.header.Get("ETag") != `"`+m[1]+`"` {
				t.Fatalf("ETag %q for cursor %q", r.header.Get("ETag"), m[1])
			}
			return m[1]
		}
		// Nothing has happened yet.
		r := e.get(t, e.srv.URL+subsBase, bearer(api))
		if r.code != 200 || cursor(r) != "earliest" {
			t.Fatalf("%d %q", r.code, r.header.Get("Link"))
		}
		if _, docs := decodeCollection(t, r.body); len(docs) != 0 {
			t.Fatalf("%s", r.body)
		}
		if !strings.Contains(r.header.Get("Link"), `type="mercure"`) || !strings.Contains(r.header.Get("Link"), `content-type="application/json"`) || !strings.Contains(r.header.Get("Link"), `rel="mercure"`) {
			t.Fatalf("Link %q", r.header.Get("Link"))
		}
		// A publication moves it.
		id := e.publishA(t, "x", "t")
		if got := cursor(e.get(t, e.srv.URL+subsBase, bearer(api))); got != id {
			t.Fatalf("cursor %q, want %q", got, id)
		}
		// Reconcile: read the list, then subscribe to the events from its cursor.
		e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match", "https://example.com/first")
		r = e.get(t, e.srv.URL+subsBase, bearer(api))
		from := cursor(r)
		_, docs := decodeCollection(t, r.body)
		if len(docs) != 1 || docs[0].Match != "https://example.com/first" {
			t.Fatalf("%s", r.body)
		}
		e.matchStream(t, e.access(t, mDetail(subOnly, mBare("*"))), "match", "https://example.com/second")
		mon := e.matchStream(t, api, "match_urlpattern", subsGlob, "last_event_id", from)
		d, _ := nextDoc(t, mon, func(d msDoc) bool { return d.Active && strings.HasPrefix(d.Match, "https://example.com/") })
		if d.Match != "https://example.com/second" {
			t.Fatalf("the event stream from the cursor began with %+v, want the subscription made after the list", d)
		}
	})
}

// TestSubscriptionsAPIOffAndLegacy: without Subscriptions there is no API; draft-07 hubs have their paths only.
func TestSubscriptionsAPIOffAndLegacy(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		e := newEnv(t, mcfg(p))
		tok := e.access(t, mDetail(subOnly, mBare("*")))
		for _, path := range []string{subsBase, subsBase + "/exact/a", subsBase + "/exact/a/b"} {
			if r := e.get(t, e.srv.URL+path, bearer(tok)); r.code != 404 {
				t.Errorf("%s: %d", path, r.code)
			}
		}
		// No subscription events either.
		mon := e.matchStream(t, tok, "match_urlpattern", "*")
		e.matchStream(t, tok, "match", "x")
		e.publishA(t, "end", "sentinel")
		for _, d := range mon.drain("end") {
			t.Errorf("event %s", d)
		}
	})
	t.Run("draft-07 hub", func(t *testing.T) {
		e := newEnv(t, Config{Protocol: ProtocolLegacy, Subscriptions: true})
		tok := tokenFor(t, nil, all)
		e.subscribe(t, tok, "https://example.com/a")
		var sub string
		for _, s := range e.hub.LocalSubscriptions() {
			sub = s.Subscriber
		}
		r := e.get(t, e.srv.URL+subsBase+"/"+escapeSegment("https://example.com/a")+"/"+escapeSegment(sub), bearer(tok))
		if r.code != 200 || r.header.Get("Content-Type") != "application/ld+json" {
			t.Fatalf("%d %v", r.code, r.header)
		}
		var d msDoc
		if err := json.Unmarshal([]byte(r.body), &d); err != nil || d.Type != "Subscription" || d.Topic != "https://example.com/a" || d.Context == "" {
			t.Fatalf("%v %+v", err, d)
		}
		// A Mercure 1.0 path is a draft-07 path with odd segments: nothing is there.
		if r = e.get(t, e.srv.URL+subsBase+"/exact/"+escapeSegment("https://example.com/a")+"/"+escapeSegment(sub), bearer(tok)); r.code != 404 {
			t.Fatalf("%d", r.code)
		}
	})
}

// TestSubscriptionsAPIRemoteNodes: subscriptions of other nodes appear in the Mercure 1.0 collections too.
func TestSubscriptionsAPIRemoteNodes(t *testing.T) {
	ft := newFakeTransport("node-a")
	ft.remote = []Subscription{{
		ID: subID("exact", "https://example.com/remote", "urn:uuid:remote-1"), MatchType: "exact", Match: "https://example.com/remote",
		Subscriber: "urn:uuid:remote-1", Active: true, Payload: json.RawMessage(`{"node":"b"}`),
	}}
	cfg := mcfg(ProtocolBoth)
	cfg.Subscriptions = true
	cfg.Transport = ft
	e := newEnv(t, cfg)
	api := e.access(t, mDetail(subOnly, mPattern(subsBase+"{/*}?")))
	r := e.get(t, e.srv.URL+subsBase, bearer(api))
	if _, docs := decodeCollection(t, r.body); r.code != 200 || len(docs) != 1 || docs[0].Type != "subscription" || docs[0].Subscriber != "urn:uuid:remote-1" || string(docs[0].Payload) != `{"node":"b"}` {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if r.header.Get("Warning") != "" {
		t.Fatalf("Warning %q though every node answered", r.header.Get("Warning"))
	}
	r = e.get(t, e.srv.URL+escPath("exact", "https://example.com/remote", "urn:uuid:remote-1"), bearer(api))
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	ft.mu.Lock()
	ft.complete = false
	ft.mu.Unlock()
	r = e.get(t, e.srv.URL+subsBase, bearer(api))
	if r.code != 200 || r.header.Get("Warning") == "" {
		t.Fatalf("%d, Warning %q: an incomplete answer must say so", r.code, r.header.Get("Warning"))
	}
}
