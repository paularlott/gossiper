package gossiper

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
{"topic":["https://b.test/a"],"data":"` + strings.Repeat("x", 5000) + `"}
{"topic":["https://b.test/a"],"data":"two","id":"urn:two","type":"t","retry":5}`
	got := e.finite(t, tokenFor(t, []string{"https://b.test/a"}, nil), body)
	want := []streamAck{{}, {Line: 3, Status: 400}, {Line: 4, Status: 403}, {Line: 5, Status: 400}, {Line: 6, Status: 400}, {Line: 7, Status: 413},
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
