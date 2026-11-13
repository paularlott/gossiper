package gossiper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper/auth"
)

// streamClient is a streaming publish: lines written to in, answers read from out.
type streamClient struct {
	in   *io.PipeWriter
	out  *bufio.Scanner
	resp *http.Response
}

func (e *env) stream(t *testing.T, tok string) *streamClient {
	t.Helper()
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, e.hubURL(), pr)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	t.Cleanup(func() { pw.Close(); resp.Body.Close() })
	return &streamClient{in: pw, out: bufio.NewScanner(resp.Body), resp: resp}
}

func (c *streamClient) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		t.Fatal(err)
	}
}

func (c *streamClient) answer(t *testing.T) streamAck {
	t.Helper()
	got := make(chan streamAck, 1)
	go func() {
		var a streamAck
		if c.out.Scan() {
			_ = json.Unmarshal(c.out.Bytes(), &a)
		} else {
			a.Error = "stream ended"
		}
		got <- a
	}()
	select {
	case a := <-got:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return streamAck{}
	}
}

// A streaming publish answers each line as it is published, while the body stays open; a refused line is answered
// with its error and the stream goes on.
func TestStreamPublish(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.openStream(t, http.MethodGet, url.Values{"topic": {"https://s.test/a"}}, nil, "")
	c := e.stream(t, tokenFor(t, []string{"https://s.test/a"}, nil))
	c.send(t, `{"topic":["https://s.test/a"],"data":"one"}`)
	if a := c.answer(t); a.ID == "" || a.Status != 0 {
		t.Fatalf("first answer: %+v", a)
	}
	sub.expect("one") // published before the body ends
	c.send(t, `{nope`)
	if a := c.answer(t); a.Line != 2 || a.Status != 400 {
		t.Fatalf("invalid line: %+v", a)
	}
	c.send(t, `{"topic":["https://s.test/b"],"data":"x"}`)
	if a := c.answer(t); a.Line != 3 || a.Status != 403 {
		t.Fatalf("forbidden line: %+v", a)
	}
	c.send(t, `{"topic":["https://s.test/a"],"data":"two","id":"urn:two"}`)
	if a := c.answer(t); a.ID != "urn:two" {
		t.Fatalf("after the refused lines: %+v", a)
	}
	sub.expect("two")
	c.in.Close()
	if a := c.answer(t); a.Error != "stream ended" {
		t.Fatalf("after the body closed: %+v", a)
	}
}

// A stream ends when its token expires.
func TestStreamPublishTokenExpiry(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	claims := mercureClaims(all, nil)
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(1500 * time.Millisecond))
	c := e.stream(t, signJWT(t, testSecret, claims))
	c.send(t, `{"topic":["https://s.test/a"],"data":"one"}`)
	if a := c.answer(t); a.ID == "" {
		t.Fatalf("before expiry: %+v", a)
	}
	time.Sleep(2 * time.Second)
	c.send(t, `{"topic":["https://s.test/a"],"data":"late"}`)
	if a := c.answer(t); a.Status != 401 {
		t.Fatalf("after expiry: %+v", a)
	}
	if a := c.answer(t); a.Error != "stream ended" {
		t.Fatalf("the stream went on: %+v", a)
	}
}

// finite posts body, NDJSON updates, as a whole (a stream that ends) and returns the answers, one a line.
func (e *env) finite(t testing.TB, tok, body string) []streamAck {
	t.Helper()
	r := e.do(t, http.MethodPost, e.hubURL(), http.Header{"Authorization": {"Bearer " + tok}, "Content-Type": {"application/x-ndjson"}}, body)
	if r.code != 200 || r.header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("finite stream: %d %s %q", r.code, r.header.Get("Content-Type"), r.body)
	}
	var out []streamAck
	for _, line := range strings.Split(strings.TrimSpace(r.body), "\n") {
		if line == "" {
			continue
		}
		var a streamAck
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("answer %q: %v", line, err)
		}
		out = append(out, a)
	}
	return out
}

// A stream that ends is a batch: each line is published in order or refused with its own error, and answered.
func TestFiniteStream(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true, MaxPublishBytes: 4096})
	c := e.openStream(t, http.MethodGet, url.Values{"topic": {"https://b.test/a"}}, nil, "")
	body := `{"topic":["https://b.test/a"],"data":"one"}

{nope
{"topic":["https://b.test/b"],"data":"forbidden"}
{"data":"no topic"}
{"topic":["https://b.test/a"],"bogus":1}
{"topic":[" /.well-known/mercure/subscriptions/exact/a/b"],"data":"forged"}
{"topic":["https://b.test/a"],"data":"` + strings.Repeat("x", 5000) + `"}
{"topic":["https://b.test/a"],"data":"two","id":"urn:two","type":"t","retry":5}`
	got := e.finite(t, tokenFor(t, []string{"https://b.test/a"}, nil), body)
	want := []streamAck{{}, {Line: 3, Status: 400}, {Line: 4, Status: 403}, {Line: 5, Status: 400}, {Line: 6, Status: 400}, {Line: 7, Status: 400}, {Line: 8, Status: 413},
		{Status: 413}} // and the stream ends, saying why
	if len(got) != len(want) {
		t.Fatalf("answers: %+v", got)
	}
	for i, w := range want {
		if i == 0 {
			if got[0].ID == "" {
				t.Errorf("first: %+v", got[0])
			}
			continue
		}
		if got[i].Line != w.Line || got[i].Status != w.Status {
			t.Errorf("answer %d: %+v, want line %d status %d", i, got[i], w.Line, w.Status)
		}
	}
	// A line over the limit ends the stream (what follows it cannot be read reliably): "two" is not published.
	c.expect("one")
	if got := e.hub.Stats().Published; got != 1 {
		t.Errorf("published %d, want 1", got)
	}
	// Without the line over the limit, the rest goes through.
	got = e.finite(t, tokenFor(t, all, nil), `{"topic":["https://b.test/a"],"data":"two","id":"urn:two"}`+"\n"+`{"topic":["https://b.test/a"],"data":"three"}`)
	if len(got) != 2 || got[0].ID != "urn:two" || got[1].ID == "" {
		t.Fatalf("answers: %+v", got)
	}
	c.expect("two", "three")
	// A stream needs a publisher token like any publish.
	if r := e.do(t, http.MethodPost, e.hubURL(), http.Header{"Content-Type": {"application/x-ndjson"}}, `{"topic":["t"]}`); r.code != 401 {
		t.Errorf("without a token: %d", r.code)
	}
}

// A line is one JSON object and nothing else: one followed by garbage, or by a second object, is refused as a whole
// and published neither in part nor whole; space around it is fine.
func TestStreamLineIsOneObject(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.openStream(t, http.MethodGet, url.Values{"topic": {"https://s.test/o"}}, nil, "")
	c := e.stream(t, tokenFor(t, all, nil))
	for i, line := range []string{
		`{"topic":["https://s.test/o"],"data":"first"} garbage`,
		`{"topic":["https://s.test/o"],"data":"one"}{"topic":["https://s.test/o"],"data":"two"}`,
		`{"topic":["https://s.test/o"],"data":"x"},`,
	} {
		c.send(t, line)
		if a := c.answer(t); a.Line != i+1 || a.Status != 400 || a.ID != "" {
			t.Fatalf("line %d %q: %+v", i+1, line, a)
		}
	}
	c.send(t, "  "+`{"topic":["https://s.test/o"],"data":"ok"}`+"\t ")
	if a := c.answer(t); a.ID == "" || a.Status != 0 {
		t.Fatalf("a line with space around it: %+v", a)
	}
	sub.expect("ok") // nothing of the refused lines
}

// Lines that arrive in a row are published together (a run): each subscriber still gets its updates in the order
// published, whatever mix of topics the run holds, and each line is answered in order, a refused one with its own
// line.
func TestStreamRun(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	both := e.subscribe(t, "", "https://r.test/a", "https://r.test/b")
	onlyA := e.subscribe(t, "", "https://r.test/a")
	pattern := e.subscribe(t, "", "https://r.test/{x}")
	waitSubscribers(t, e.hub, 3)
	var body strings.Builder
	var wantBoth, wantA []string
	const n = 300 // several runs (runMax)
	for i := range n {
		switch {
		case i == 100:
			body.WriteString("{nope\n")
		case i == 200:
			body.WriteString(`{"topic":["https://r.test/c"],"data":"forbidden"}` + "\n")
		default:
			topic := "https://r.test/a"
			if i%3 == 0 {
				topic = "https://r.test/b"
			} else {
				wantA = append(wantA, strconv.Itoa(i))
			}
			wantBoth = append(wantBoth, strconv.Itoa(i))
			fmt.Fprintf(&body, `{"topic":[%q],"data":"%d"}`+"\n", topic, i)
		}
	}
	got := e.finite(t, tokenFor(t, []string{"https://r.test/a", "https://r.test/b"}, nil), body.String())
	if len(got) != n {
		t.Fatalf("%d answers, want %d", len(got), n)
	}
	for i, a := range got {
		switch i {
		case 100:
			if a.Line != 101 || a.Status != 400 {
				t.Errorf("answer %d: %+v", i, a)
			}
		case 200:
			if a.Line != 201 || a.Status != 403 {
				t.Errorf("answer %d: %+v", i, a)
			}
		default:
			if a.ID == "" || a.Status != 0 {
				t.Errorf("answer %d: %+v", i, a)
			}
		}
	}
	both.expect(wantBoth...)
	onlyA.expect(wantA...)
	pattern.expect(wantBoth...)
	if p := e.hub.Stats().Published; p != uint64(len(wantBoth)) {
		t.Errorf("published %d, want %d", p, len(wantBoth))
	}
}

// Updates on one topic published in a row (the run's fast path: every update has the same subscribers) reach a
// subscriber in order.
func TestStreamRunSameTopic(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.subscribe(t, "", "https://r.test/a")
	waitSubscribers(t, e.hub, 1)
	var body strings.Builder
	var want []string
	for i := range 200 {
		want = append(want, strconv.Itoa(i))
		fmt.Fprintf(&body, `{"topic":["https://r.test/a"],"data":"%d"}`+"\n", i)
	}
	if got := e.finite(t, tokenFor(t, all, nil), body.String()); len(got) != 200 {
		t.Fatalf("%d answers", len(got))
	}
	sub.expect(want...)
}

// A line that asks for copies is not part of a run: the run before it is published first, so the order holds.
func TestStreamRunAroundCopies(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.subscribe(t, "", "https://r.test/a")
	waitSubscribers(t, e.hub, 1)
	var body strings.Builder
	var want []string
	for i := range 100 {
		replicas := 0
		if i == 50 {
			replicas = 1 // one copy, this node's: published alone
		}
		want = append(want, strconv.Itoa(i))
		fmt.Fprintf(&body, `{"topic":["https://r.test/a"],"data":"%d","replicas":%d}`+"\n", i, replicas)
	}
	for i, a := range e.finite(t, tokenFor(t, all, nil), body.String()) {
		if a.ID == "" || a.Status != 0 {
			t.Errorf("answer %d: %+v", i, a)
		}
	}
	sub.expect(want...)
}

// runTransport is a transport that takes runs, applying them on this node only; it records the length
// of each run and fails the updates whose data is fail.
type runTransport struct {
	*fakeTransport
	fail string

	mu   sync.Mutex
	runs []int
}

func (r *runTransport) PublishRun(_ context.Context, us []*Update) []error {
	r.mu.Lock()
	r.runs = append(r.runs, len(us))
	r.mu.Unlock()
	var errs []error
	var ok []*Update
	for i, u := range us {
		if r.fail != "" && u.Data == r.fail {
			if errs == nil {
				errs = make([]error, len(us))
			}
			errs[i] = fmt.Errorf("%w: test", ErrUpdateTooLarge)
			continue
		}
		ok = append(ok, u)
	}
	r.fakeTransport.mu.Lock()
	h := r.fakeTransport.hub
	r.fakeTransport.mu.Unlock()
	h.ApplyRun(ok)
	return errs
}

func (r *runTransport) longest() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Max(append([]int{0}, r.runs...))
}

// A transport that takes runs is handed them: an update it fails is answered with its own line, the others of its run
// are published, and nothing is reordered.
func TestStreamRunTransport(t *testing.T) {
	rt := &runTransport{fakeTransport: newFakeTransport("n1"), fail: "fail"}
	e := newEnv(t, Config{Anonymous: true, Transport: rt})
	sub := e.subscribe(t, "", "https://r.test/a")
	waitSubscribers(t, e.hub, 1)
	var body strings.Builder
	var want []string
	for i := range 200 {
		data := strconv.Itoa(i)
		if i == 70 {
			data = "fail"
		} else {
			want = append(want, data)
		}
		fmt.Fprintf(&body, `{"topic":["https://r.test/a"],"data":%q}`+"\n", data)
	}
	got := e.finite(t, tokenFor(t, all, nil), body.String())
	if len(got) != 200 {
		t.Fatalf("%d answers", len(got))
	}
	for i, a := range got {
		if i == 70 {
			if a.Line != 71 || a.Status != http.StatusRequestEntityTooLarge || a.ID != "" {
				t.Errorf("answer %d: %+v", i, a)
			}
		} else if a.ID == "" || a.Status != 0 {
			t.Errorf("answer %d: %+v", i, a)
		}
	}
	sub.expect(want...)
	if n := rt.longest(); n < 2 || n > runMax {
		t.Errorf("longest run %d, want 2 to %d", n, runMax)
	}
	if p := e.hub.Stats().Published; p != 199 {
		t.Errorf("published %d, want 199", p)
	}
}

// A run applied twice (a peer's batch sent again) is applied once: the updates applied before are dropped, by
// stamp and origin or, for the idempotent ones, by ID, and a subscriber receives each once, in order.
func TestApplyRunDuplicates(t *testing.T) {
	e := newEnv(t, Config{Anonymous: true})
	sub := e.subscribe(t, "", "https://r.test/a", "https://r.test/b")
	waitSubscribers(t, e.hub, 1)
	var run []*Update
	var want []string
	for i := range 150 {
		topic := "https://r.test/a"
		if i%2 == 0 {
			topic = "https://r.test/b"
		}
		u := &Update{ID: fmt.Sprintf("d-%d", i), Topics: []string{topic}, Data: strconv.Itoa(i), Stamp: uint64(hlc.Now()), Origin: "peer"}
		u.Idempotent = i%5 == 0
		run = append(run, u)
		want = append(want, u.Data)
	}
	again := make([]*Update, len(run)) // a copy of each, as a peer's batch sent again is decoded afresh
	for i, u := range run {
		c := *u
		c.encoded = nil
		again[i] = &c
	}
	e.hub.ApplyRun(run)
	e.hub.ApplyRun(again)
	sub.expect(want...)
	if ev, ok := sub.next(100 * time.Millisecond); ok {
		t.Errorf("received again: %+v", ev)
	}
	if s := e.hub.Stats(); s.Applied != 150 || s.Duplicates != 150 {
		t.Errorf("applied %d, duplicates %d, want 150 and 150", s.Applied, s.Duplicates)
	}
}

// A run is at most a quarter of a subscriber's queue: it never takes a subscriber from below half full (where the
// publisher waits for it) to full (where it is disconnected).
func TestRunLen(t *testing.T) {
	for _, c := range []struct{ buffer, want int }{{1, 1}, {8, 2}, {100, 25}, {1000, runMax}, {8192, runMax}} {
		h := &Hub{cfg: Config{DispatchBuffer: c.buffer}}
		if got := h.runLen(); got != c.want {
			t.Errorf("DispatchBuffer %d: run of %d, want %d", c.buffer, got, c.want)
		}
	}
}

// Tenants take runs over any transport: a stream to a tenant's hub is published in runs through the shared transport,
// and a run that mixes tenants (a peer's batch) reaches each tenant's hub with its own updates, in order.
func TestStreamRunTenants(t *testing.T) {
	rt := &runTransport{fakeTransport: newFakeTransport("n1")}
	tenant := func(name, key string) Tenant {
		return Tenant{Name: name, Hosts: []string{name + ".test"}, Config: Config{
			Protocol: ProtocolBoth, PublisherKey: auth.KeyConfig{Key: key}, Anonymous: true, Heartbeat: -1}}
	}
	ts, err := NewTenants([]Tenant{tenant("a", testSecret), tenant("b", testSecret+"-b")}, rt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		_ = ts.Close(ctx)
	})
	envOf := func(h *Hub) *env {
		srv := httptest.NewServer(h)
		tr := &http.Transport{MaxIdleConnsPerHost: 64}
		t.Cleanup(func() { tr.CloseIdleConnections(); srv.CloseClientConnections(); srv.Close() })
		return &env{hub: h, srv: srv, client: &http.Client{Transport: tr}, tr: tr}
	}
	a, b := envOf(ts.Hub("a")), envOf(ts.Hub("b"))
	subA := a.subscribe(t, "", "https://r.test/a")
	subB := b.subscribe(t, "", "https://r.test/a")
	waitSubscribers(t, a.hub, 1)
	waitSubscribers(t, b.hub, 1)

	var body strings.Builder
	var want []string
	for i := range 200 {
		want = append(want, strconv.Itoa(i))
		fmt.Fprintf(&body, `{"topic":["https://r.test/a"],"data":"%d"}`+"\n", i)
	}
	if got := a.finite(t, tokenFor(t, all, nil), body.String()); len(got) != 200 {
		t.Fatalf("%d answers", len(got))
	}
	subA.expect(want...)
	if n := rt.longest(); n < 2 {
		t.Errorf("longest run %d: the tenant's stream was not published in runs", n)
	}

	// A peer's batch: both tenants' updates, interleaved, and one of a tenant this node does not have.
	var run []*Update
	var wantA, wantB []string
	for i := range 99 {
		name := []string{"a", "b", "gone"}[i%3]
		data := fmt.Sprintf("%s%d", name, i)
		run = append(run, &Update{ID: fmt.Sprintf("p-%d", i), Topics: []string{"https://r.test/a"}, Data: data,
			Stamp: uint64(hlc.Now()), Origin: "peer", Tenant: name})
		switch name {
		case "a":
			wantA = append(wantA, data)
		case "b":
			wantB = append(wantB, data)
		}
	}
	ts.ApplyRun(run)
	subA.expect(wantA...)
	subB.expect(wantB...)
}
