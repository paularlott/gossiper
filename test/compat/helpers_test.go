//go:build compat

package compat

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	secret        = "compat-secret-compat-secret-0123456789"
	allowedOrigin = "http://example.com"
	badOrigin     = "http://evil.example.org"
	hubPath       = "/.well-known/mercure"
)

// hub is one hub under test, addressed from the host.
type hub struct{ name, base string }

var (
	hubSC     = hub{"gossiper", envOr("COMPAT_GOSSIPER_URL", "http://localhost:13000")}
	hubModern = hub{"gossiper-modern", envOr("COMPAT_MODERN_URL", "http://localhost:13001")}
	hubRef    = hub{"reference", envOr("COMPAT_REFERENCE_URL", "http://localhost:13003")}
	// appSC is the PHP app wired to Gossiper; the reference container serves the same app next to its hub.
	appSC  = envOr("COMPAT_APP_URL", "http://localhost:13002")
	appRef = hubRef.base

	runID = randHex(4)
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var client = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{DisableCompression: true, DisableKeepAlives: true},
}

// ---------------------------------------------------------------------------------------------------------
// Tokens

func mintWith(key string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t := jwt.NewWithClaims(method, claims)
	var k any = []byte(key)
	if method == jwt.SigningMethodNone {
		k = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := t.SignedString(k)
	if err != nil {
		panic(err)
	}
	return s
}

func mint(claims jwt.MapClaims) string { return mintWith(secret, jwt.SigningMethodHS256, claims) }

func mercureClaims(publish, subscribe []string) jwt.MapClaims {
	m := map[string]any{}
	if publish != nil {
		m["publish"] = publish
	}
	if subscribe != nil {
		m["subscribe"] = subscribe
	}
	return jwt.MapClaims{"mercure": m}
}

func pubToken(publish ...string) string { return mint(mercureClaims(publish, nil)) }

func subToken(subscribe ...string) string { return mint(mercureClaims(nil, subscribe)) }

// ---------------------------------------------------------------------------------------------------------
// Raw requests

type req struct {
	Method string
	Path   string // path and query, relative to the hub's base URL
	Header map[string]string
	Body   string
}

type resp struct {
	Status int
	Header http.Header
	Body   string
	Stream bool // an event stream: Body is only the first bytes
}

func (h hub) do(r req) resp {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, h.base+r.Path, body)
	if err != nil {
		return resp{Status: -1, Body: err.Error()}
	}
	for k, v := range r.Header {
		if strings.EqualFold(k, "Host") {
			hr.Host = v
			continue
		}
		hr.Header.Set(k, v)
	}
	res, err := client.Do(hr)
	if err != nil {
		return resp{Status: -1, Body: err.Error()}
	}
	defer res.Body.Close()
	out := resp{Status: res.StatusCode, Header: res.Header}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") && method != http.MethodHead {
		out.Stream = true
		buf := make([]byte, 4096)
		done := make(chan int, 1)
		go func() { n, _ := res.Body.Read(buf); done <- n }()
		select {
		case n := <-done:
			out.Body = string(buf[:n])
		case <-time.After(200 * time.Millisecond):
		}
		return out
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	out.Body = string(b)
	return out
}

// publishReq is a POST of an update with the given Authorization header value (empty: none).
func publishReq(v url.Values, authz string, extra map[string]string) req {
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if authz != "" {
		h["Authorization"] = authz
	}
	for k, val := range extra {
		h[k] = val
	}
	return req{Method: http.MethodPost, Path: hubPath, Header: h, Body: v.Encode()}
}

func bearer(tok string) string { return "Bearer " + tok }

var (
	uuidRe         = regexp.MustCompile(`urn(:|%3A|%3a)uuid(:|%3A|%3a)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	runIDRe        = regexp.MustCompile(`https?(:|%3A|%3a)(//|%2F%2F|%2f%2f)compat\.test(/|%2F|%2f)[0-9a-f]{8}`)
	listHdrs       = map[string]bool{"Vary": true, "Access-Control-Expose-Headers": true, "Access-Control-Allow-Methods": true, "Access-Control-Allow-Headers": true, "Allow": true}
	hardHdrs       = []string{"Content-Type", "WWW-Authenticate", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Last-Event-ID", "Mercure-Last-Event-ID", "Link", "Allow"}
	softHdrs       = []string{"Vary", "Cache-Control", "Access-Control-Max-Age", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "ETag"}
	resourceMetaRe = regexp.MustCompile(`,?\s*resource_metadata="[^"]*"`)
	whitespRe      = regexp.MustCompile(`\s+`)
)

func normText(s string) string {
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = runIDRe.ReplaceAllString(s, "https://compat.test/<run>")
	return s
}

func normHeaderBase(name string, vals []string, base string, modern bool) string {
	if len(vals) == 0 {
		return "<absent>"
	}
	if base != "" {
		nv := make([]string, len(vals))
		for i, v := range vals {
			nv[i] = strings.ReplaceAll(v, base, "<hub>")
		}
		vals = nv
	}
	if name == "WWW-Authenticate" && !modern {
		// The reference appends an OAuth "resource_metadata" parameter; the error code is what clients act on.
		v := resourceMetaRe.ReplaceAllString(strings.Join(vals, ", "), "")
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ","))
	}
	if name == "Content-Type" {
		return whitespRe.ReplaceAllString(strings.ToLower(strings.Join(vals, ",")), "")
	}
	if listHdrs[name] {
		var parts []string
		for _, v := range vals {
			for _, p := range strings.Split(v, ",") {
				if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
					parts = append(parts, p)
				}
			}
		}
		sort.Strings(parts)
		return strings.Join(parts, ", ")
	}
	return normText(strings.Join(vals, ", "))
}

// ---------------------------------------------------------------------------------------------------------
// Differences

type diff struct {
	Test, Field, Hub, Ref, Got, Class, Reason string
}

var (
	reportMu sync.Mutex
	report   []diff
)

func record(d diff) {
	reportMu.Lock()
	defer reportMu.Unlock()
	report = append(report, d)
}

// known maps a field (e.g. "status", "header:Vary", "body", "frame.event") to why Gossiper differs. A known
// difference is logged and reported, not failed. Key "*" matches every field.
type known map[string]string

// globalKnown are differences that hold on every response.
var globalKnown = known{
	"header:Access-Control-Expose-Headers": "Gossiper exposes \"Link, Last-Event-ID, Mercure-Last-Event-ID\"; the reference exposes \"Accept-Query, Link, Mercure-Last-Event-ID\". Browsers read Last-Event-ID from the response of a replayed stream only if exposed; nothing in the Mercure client flow depends on Accept-Query.",
}

func (k known) reason(field string) (string, bool) {
	if r, ok := k[field]; ok {
		return r, true
	}
	if r, ok := k["*"]; ok {
		return r, true
	}
	r, ok := globalKnown[field]
	return r, ok
}

func (c *cmp) add(field, display, ref, got string, soft bool) {
	d := diff{Test: c.t.Name(), Field: display, Hub: c.hubName, Ref: ref, Got: got}
	if r, ok := c.known.reason(field); ok {
		d.Class, d.Reason = "known", r
		c.t.Logf("KNOWN DIFFERENCE %s: reference=%q %s=%q (%s)", display, ref, c.hubName, got, r)
	} else if soft {
		d.Class = "info"
		c.t.Logf("info: %s differs: reference=%q %s=%q", display, ref, c.hubName, got)
	} else {
		d.Class = "FAIL"
		c.t.Errorf("DIFFERENCE %s: reference=%q %s=%q", display, ref, c.hubName, got)
	}
	record(d)
}

type cmp struct {
	t       *testing.T
	hubName string
	known   known
	// modern compares Mercure 1.0 responses: the WWW-Authenticate resource_metadata URL is compared too, with each
	// hub's own base URL replaced by <hub>.
	modern           bool
	gotBase, refBase string
}

func (c *cmp) resp(got, ref resp, compareBody bool) {
	if got.Status != ref.Status {
		c.add("status", "status", fmt.Sprint(ref.Status), fmt.Sprint(got.Status), false)
	}
	for _, name := range hardHdrs {
		if g, r := normHeaderBase(name, got.Header[http.CanonicalHeaderKey(name)], c.gotBase, c.modern), normHeaderBase(name, ref.Header[http.CanonicalHeaderKey(name)], c.refBase, c.modern); g != r {
			c.add("header:"+name, "header "+name, r, g, false)
		}
	}
	for _, name := range softHdrs {
		if g, r := normHeaderBase(name, got.Header[http.CanonicalHeaderKey(name)], c.gotBase, c.modern), normHeaderBase(name, ref.Header[http.CanonicalHeaderKey(name)], c.refBase, c.modern); g != r {
			c.add("header:"+name, "header "+name, r, g, true)
		}
	}
	if compareBody && !got.Stream && !ref.Stream {
		if g, r := strings.TrimSpace(normText(strings.ReplaceAll(got.Body, orEmpty(c.gotBase), "<hub>"))), strings.TrimSpace(normText(strings.ReplaceAll(ref.Body, orEmpty(c.refBase), "<hub>"))); g != r {
			c.add("body", "body", r, g, true)
		}
	}
}

// bothHubs sends r to the hub under test and to the reference and compares the responses.
func bothHubs(t *testing.T, h hub, r req, k known, compareBody bool) (resp, resp) {
	t.Helper()
	got, ref := h.do(r), hubRef.do(r)
	t.Logf("%s %s -> reference %d, %s %d", r.Method, r.Path, ref.Status, h.name, got.Status)
	(&cmp{t: t, hubName: h.name, known: k}).resp(got, ref, compareBody)
	return got, ref
}

func writeReport() {
	reportMu.Lock()
	defer reportMu.Unlock()
	type key struct{ Test, Field, Hub, Class string }
	seen := map[key]bool{}
	var b strings.Builder
	fmt.Fprintf(&b, "Differences recorded by the last run (reference = FrankenPHP built-in hub)\n\n")
	for _, d := range report {
		k := key{d.Test, d.Field, d.Hub, d.Class}
		if seen[k] {
			continue
		}
		seen[k] = true
		fmt.Fprintf(&b, "[%s] %s | %s | %s\n    reference: %q\n    %s: %q\n", d.Class, d.Test, d.Hub, d.Field, d.Ref, d.Hub, d.Got)
		if d.Reason != "" {
			fmt.Fprintf(&b, "    why: %s\n", d.Reason)
		}
	}
	_ = os.WriteFile("last-run-differences.txt", []byte(b.String()), 0o644)
}

// ---------------------------------------------------------------------------------------------------------
// SSE client

type frame struct {
	ID, Event, Data, Retry string
	HasID, HasEvent        bool
	Raw                    string
}

func (f frame) String() string {
	return fmt.Sprintf("{id=%q event=%q retry=%q data=%q}", f.ID, f.Event, f.Retry, f.Data)
}

type sseStream struct {
	Status   int
	Header   http.Header
	Frames   chan frame
	Comments chan string
	cancel   context.CancelFunc
	Body     string // the error body of a refused stream
}

func (s *sseStream) Close() { s.cancel() }

// stream opens an event stream and returns once the response headers arrived.
func (h hub) stream(path string, hdr map[string]string) (*sseStream, error) {
	return h.streamReq(http.MethodGet, path, hdr, "")
}

func (h hub) streamReq(method, path string, hdr map[string]string, body string) (*sseStream, error) {
	ctx, cancel := context.WithCancel(context.Background())
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, h.base+path, rd)
	if err != nil {
		cancel()
		return nil, err
	}
	hr.Header.Set("Accept", "text/event-stream")
	for k, v := range hdr {
		hr.Header.Set(k, v)
	}
	type result struct {
		res *http.Response
		err error
	}
	ch := make(chan result, 1)
	go func() { r, e := client.Do(hr); ch <- result{r, e} }()
	var res *http.Response
	select {
	case r := <-ch:
		if r.err != nil {
			cancel()
			return nil, r.err
		}
		res = r.res
	case <-time.After(10 * time.Second):
		cancel()
		return nil, fmt.Errorf("%s: timeout waiting for response headers of %s", h.name, path)
	}
	s := &sseStream{Status: res.StatusCode, Header: res.Header, Frames: make(chan frame, 1024), Comments: make(chan string, 1024), cancel: cancel}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		s.Body = string(b)
		res.Body.Close()
		return s, nil
	}
	go func() {
		defer res.Body.Close()
		defer close(s.Frames)
		rd := bufio.NewReader(res.Body)
		var cur frame
		var data []string
		var raw []string
		dirty := false
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if line == "" {
				if dirty {
					cur.Data = strings.Join(data, "\n")
					cur.Raw = strings.Join(raw, "\n")
					s.Frames <- cur
				}
				cur, data, raw, dirty = frame{}, nil, nil, false
				continue
			}
			if strings.HasPrefix(line, ":") {
				select {
				case s.Comments <- line:
				default:
				}
				continue
			}
			name, val, _ := strings.Cut(line, ":")
			val = strings.TrimPrefix(val, " ")
			raw = append(raw, line)
			dirty = true
			switch name {
			case "id":
				cur.ID, cur.HasID = val, true
			case "event":
				cur.Event, cur.HasEvent = val, true
			case "data":
				data = append(data, val)
			case "retry":
				cur.Retry = val
			}
		}
	}()
	return s, nil
}

func (s *sseStream) next(d time.Duration) (frame, bool) {
	select {
	case f, ok := <-s.Frames:
		return f, ok
	case <-time.After(d):
		return frame{}, false
	}
}

// collect reads frames until one with data "END" (not included) or the timeout.
func (s *sseStream) collect(d time.Duration) ([]frame, bool) {
	var out []frame
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-s.Frames:
			if !ok {
				return out, false
			}
			if f.Data == "END" {
				return out, true
			}
			out = append(out, f)
		case <-deadline:
			return out, false
		}
	}
}

// ---------------------------------------------------------------------------------------------------------
// Scenarios: publish and subscribe on one hub, then compare the hub's frames with the reference's.

type pub struct {
	Topics          []string
	Data            string
	ID, Type, Retry string
	Private         bool
	Token           string // overrides the default publisher token
	NoData          bool
}

type auth struct {
	Subscribe []string // exact topics
	Patterns  []string // Mercure 1.0: URL patterns
	Payload   any
	Via       string // "header" (default), "query" or "cookie"
}

type scenario struct {
	Name     string
	Pre      []pub // published before subscribing
	Topics   []string
	Query    string // extra raw query, e.g. "lastEventID={{id:0}}"
	Header   map[string]string
	Auth     *auth
	Post     []pub  // published after subscribing; a final public "END" update is added
	Sentinel string // topic of the END update; default: the first subscription topic
	WantData []string
	Known    known
	NoWait   bool

	// Mercure 1.0: at+jwt tokens, "match" (or Param) instead of "topic", Params as extra raw query parameters.
	Modern   bool
	Param    string   // subscription parameter name for Topics (default "match")
	Params   []string // raw "name=value" pairs added to the query (expanded)
	QueryM   bool     // subscribe with the QUERY method and a form body instead of GET
	PubGrant []match  // publisher token topics (default: URL pattern "*")
	// RefHub overrides the reference (default hubRef; Modern: hubRefModern)
	RefHub *hub
}

type expander struct {
	ns, rid string
	ids     []string
}

func (e *expander) x(s string) string {
	s = strings.ReplaceAll(s, "{{ns}}", e.ns)
	s = strings.ReplaceAll(s, "{{rid}}", e.rid)
	for i := range e.ids {
		s = strings.ReplaceAll(s, fmt.Sprintf("{{id:%d}}", i), e.ids[i])
	}
	return s
}

func (e *expander) xs(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = e.x(s)
	}
	return out
}

type outcome struct {
	Status   int
	Header   http.Header
	Frames   []frame
	END      bool
	Explicit map[string]bool
	IDs      []string
	PubFail  []string
}

func (h hub) runScenario(t *testing.T, sc scenario, rid string) outcome {
	t.Helper()
	e := &expander{ns: "https://compat.test/" + runID + "/" + sc.Name + "/" + randHex(3), rid: rid}
	out := outcome{Explicit: map[string]bool{}}
	doPub := func(p pub) {
		v := url.Values{}
		for _, tp := range p.Topics {
			v.Add("topic", e.x(tp))
		}
		if !p.NoData {
			v.Set("data", e.x(p.Data))
		}
		if p.ID != "" {
			v.Set("id", e.x(p.ID))
			out.Explicit[e.x(p.ID)] = true
		}
		if p.Type != "" {
			v.Set("type", e.x(p.Type))
		}
		if p.Retry != "" {
			v.Set("retry", p.Retry)
		}
		if p.Private {
			v.Set("private", "on")
		}
		tok := p.Token
		if tok == "" && sc.Modern {
			g := sc.PubGrant
			if g == nil {
				g = []match{up("*")}
			}
			tok = newAT(h, pubDetail(g...)).String()
		}
		if tok == "" {
			tok = pubToken("*")
		}
		r := h.do(publishReq(v, bearer(tok), nil))
		if r.Status != 200 {
			out.PubFail = append(out.PubFail, fmt.Sprintf("%d %s", r.Status, strings.TrimSpace(r.Body)))
		}
		out.IDs = append(out.IDs, strings.TrimSpace(r.Body))
		e.ids = out.IDs
	}
	for _, p := range sc.Pre {
		doPub(p)
	}

	q := url.Values{}
	param := "topic"
	if sc.Modern {
		param = "match"
		if sc.Param != "" {
			param = sc.Param
		}
	}
	for _, tp := range sc.Topics {
		q.Add(param, e.x(tp))
	}
	for _, kv := range sc.Params {
		k, v, _ := strings.Cut(e.x(kv), "=")
		q.Add(k, v)
	}
	path := hubPath + "?" + q.Encode()
	if sc.Query != "" {
		path += "&" + e.x(sc.Query)
	}
	hdr := map[string]string{}
	for k, v := range sc.Header {
		hdr[k] = e.x(v)
	}
	if a := sc.Auth; a != nil && sc.Modern {
		var ms []match
		for _, x := range e.xs(a.Subscribe) {
			ms = append(ms, ex(x))
		}
		for _, x := range e.xs(a.Patterns) {
			ms = append(ms, up(x))
		}
		tok := newAT(h, subDetail(a.Payload, ms...)).String()
		switch a.Via {
		case "query":
			path += "&authorization=" + url.QueryEscape(tok)
		case "cookie":
			hdr["Cookie"] = modernCookie + "=" + tok
		default:
			hdr["Authorization"] = bearer(tok)
		}
	} else if a != nil {
		var claims jwt.MapClaims
		m := map[string]any{"subscribe": e.xs(a.Subscribe)}
		if a.Payload != nil {
			m["payload"] = a.Payload
		}
		claims = jwt.MapClaims{"mercure": m}
		tok := mint(claims)
		switch a.Via {
		case "query":
			path += "&authorization=" + url.QueryEscape(tok)
		case "cookie":
			hdr["Cookie"] = "mercureAuthorization=" + tok
		default:
			hdr["Authorization"] = bearer(tok)
		}
	}
	var s *sseStream
	var err error
	if sc.QueryM {
		pth, qs, _ := strings.Cut(path, "?")
		hdr["Content-Type"] = "application/x-www-form-urlencoded"
		s, err = h.streamReq("QUERY", pth, hdr, qs)
	} else {
		s, err = h.stream(path, hdr)
	}
	if err != nil {
		t.Fatalf("%s: %v", h.name, err)
	}
	defer s.Close()
	out.Status, out.Header = s.Status, s.Header
	if s.Status != 200 {
		return out
	}
	if !sc.NoWait {
		time.Sleep(250 * time.Millisecond)
	}
	for _, p := range sc.Post {
		doPub(p)
	}
	sentinel := sc.Sentinel
	if sentinel == "" {
		sentinel = sc.Topics[0]
	}
	doPub(pub{Topics: []string{sentinel}, Data: "END"})
	out.Frames, out.END = s.collect(8 * time.Second)
	return out
}

// normFrames replaces the generated IDs of the published updates by their position.
func (o outcome) normFrames() []frame {
	out := make([]frame, len(o.Frames))
	for i, f := range o.Frames {
		for n, id := range o.IDs {
			if id != "" && !o.Explicit[id] && f.ID == id {
				f.ID = fmt.Sprintf("<id:%d>", n)
				f.Raw = strings.ReplaceAll(f.Raw, id, f.ID)
			}
		}
		f.ID, f.Data, f.Raw = normText(f.ID), normText(f.Data), normText(f.Raw)
		f.Data = canonJSON(f.Data)
		f.Raw = canonRawJSON(f.Raw)
		out[i] = f
	}
	return out
}

// canonJSON re-marshals JSON data with sorted keys; other data is returned as is.
func canonJSON(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func canonRawJSON(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "data: ") {
			lines[i] = "data: " + canonJSON(strings.TrimPrefix(l, "data: "))
		}
	}
	return strings.Join(lines, "\n")
}

func (c *cmp) frames(got, ref []frame) {
	if len(got) != len(ref) {
		c.add("frames.count", "frame count", fmt.Sprint(framesString(ref)), fmt.Sprint(framesString(got)), false)
	}
	n := min(len(got), len(ref))
	for i := 0; i < n; i++ {
		g, r := got[i], ref[i]
		chk := func(field, gv, rv string) {
			if gv != rv {
				c.add("frame."+field, fmt.Sprintf("frame[%d].%s", i, field), rv, gv, false)
			}
		}
		chk("id", g.ID, r.ID)
		chk("event", g.Event, r.Event)
		chk("retry", g.Retry, r.Retry)
		chk("data", g.Data, r.Data)
		if g.Raw != r.Raw && g.ID == r.ID && g.Event == r.Event && g.Retry == r.Retry && g.Data == r.Data {
			c.add("frame.raw", fmt.Sprintf("frame[%d] wire format", i), r.Raw, g.Raw, true)
		}
	}
}

func framesString(fs []frame) string {
	var parts []string
	for _, f := range fs {
		parts = append(parts, f.String())
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// runDifferential runs sc on h and on the reference and compares them, plus the scenario's own expectation.
func runDifferential(t *testing.T, h hub, sc scenario) {
	t.Helper()
	rid := randHex(4) // shared so that client-chosen ids and data are identical on both hubs
	refHub := hubRef
	if sc.Modern {
		refHub = hubRefModern
	}
	if sc.RefHub != nil {
		refHub = *sc.RefHub
	}
	got := h.runScenario(t, sc, rid)
	ref := refHub.runScenario(t, sc, rid)
	c := &cmp{t: t, hubName: h.name, known: sc.Known, modern: sc.Modern, gotBase: h.base, refBase: refHub.base}
	for who, o := range map[string]outcome{h.name: got, "reference": ref} {
		if len(o.PubFail) > 0 && !strings.Contains(sc.Name, "pubfail") {
			t.Errorf("%s: publish failed: %v", who, o.PubFail)
		}
	}
	c.resp(resp{Status: got.Status, Header: got.Header}, resp{Status: ref.Status, Header: ref.Header}, false)
	if got.Status != 200 || ref.Status != 200 {
		return
	}
	for who, o := range map[string]outcome{h.name: got, "reference": ref} {
		if !o.END {
			t.Errorf("%s: END not received; frames: %s", who, framesString(o.Frames))
		}
	}
	if sc.WantData != nil {
		for who, o := range map[string]outcome{h.name: got, "reference": ref} {
			var data []string
			for _, f := range o.Frames {
				data = append(data, f.Data)
			}
			want := make([]string, len(sc.WantData))
			for i, w := range sc.WantData {
				want[i] = strings.ReplaceAll(w, "{{rid}}", rid)
			}
			if fmt.Sprint(data) != fmt.Sprint(want) {
				t.Errorf("%s: data of the frames = %q, want %q", who, data, want)
			}
		}
	}
	c.frames(got.normFrames(), ref.normFrames())
	t.Logf("%s frames: %s", h.name, framesString(got.normFrames()))
	t.Logf("reference frames: %s", framesString(ref.normFrames()))
}

func orEmpty(s string) string {
	if s == "" {
		return "\x00"
	}
	return s
}
