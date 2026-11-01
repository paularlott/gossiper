package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ndjson = "application/x-ndjson"

// resendTimeout bounds how long the publishes of a stream the hub ended wait for a new one.
const resendTimeout = 30 * time.Second

// line is an update as a line of a publish stream.
type line struct {
	Topic    []string `json:"topic"`
	Data     string   `json:"data,omitempty"`
	ID       string   `json:"id,omitempty"`
	Type     string   `json:"type,omitempty"`
	Private  bool     `json:"private,omitempty"`
	Retry    uint64   `json:"retry,omitempty"`
	Replicas int      `json:"replicas,omitempty"`
}

// answer is a line of the hub's answer: an update's event ID, or an error (with the line it refuses, or for the
// stream as a whole when it ends), or both (published, not stored).
type answer struct {
	ID     string `json:"id"`
	Line   int    `json:"line"`
	Status int    `json:"status"`
	Error  string `json:"error"`
}

// pubStream is an open publish stream: updates are written as lines into the request body, answers read from the
// response in the same order.
type pubStream struct {
	c      *Client
	body   *io.PipeWriter
	cancel context.CancelFunc // ends the request

	mu      sync.Mutex
	out     out           // lines not yet written to the body
	enc     *json.Encoder // encodes lines straight into out
	line    line          // the line being encoded
	pending []pending     // the publishes awaiting an answer, in order
	since   time.Time     // when the hub last answered, or publishes started awaiting an answer
	err     error         // why the stream ended; nil while it is open
	wake    chan struct{} // tells the writer there are lines
	done    chan struct{} // closed when the stream ended
}

// out is lines to write; the encoder appends to it.
type out []byte

func (o *out) Write(b []byte) (int, error) {
	*o = append(*o, b...)
	return len(b), nil
}

// pending is a publish awaiting its answer, kept to send it again on another stream should the hub end this one
// before reading it.
type pending struct {
	u    Update
	done func(string, error)
}

// refusal is why a hub refused a publish stream: it offers none (another Mercure hub).
type refusal struct{ err error }

func (r *refusal) Error() string { return r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

// openStream opens a publish stream; a *refusal says the hub does not offer them.
func (c *Client) openStream(ctx context.Context) (*pubStream, error) {
	h, err := c.header(ctx)
	if err != nil {
		return nil, err
	}
	if c.opts.Transport == Auto { // ask first with an empty stream: a hub that has none answers it at once
		pctx, cancel := context.WithTimeout(ctx, c.openTimeout)
		resp, err := c.post(pctx, h.Clone(), http.NoBody)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
		cancel()
		if err != nil {
			return nil, err
		}
	}
	pr, pw := io.Pipe()
	sctx, cancel := context.WithCancel(c.ctx)
	type reply struct {
		resp *http.Response
		err  error
	}
	replied := make(chan reply, 1)
	go func() { resp, err := c.post(sctx, h, pr); replied <- reply{resp, err} }()
	giveUp := func(err error) error {
		cancel()
		pw.CloseWithError(err)
		go func() {
			if r := <-replied; r.resp != nil {
				r.resp.Body.Close()
			}
		}()
		return err
	}
	var r reply
	select {
	case r = <-replied:
	case <-time.After(c.openTimeout):
		err := giveUp(fmt.Errorf("mercure: no answer to the publish stream within %s", c.openTimeout))
		if c.opts.Transport == Auto { // the probe passed: something on the way holds streams back (a proxy that buffers request bodies)
			err = &refusal{err}
		}
		return nil, err
	case <-ctx.Done():
		return nil, giveUp(ctx.Err())
	}
	if r.err != nil {
		cancel()
		pw.Close()
		return nil, r.err
	}
	p := &pubStream{c: c, body: pw, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
	p.enc = json.NewEncoder(&p.out)
	p.enc.SetEscapeHTML(false)
	go p.write()
	go p.read(r.resp.Body)
	go p.watch()
	return p, nil
}

// post posts body as a publish stream (an empty one probes) and returns the answer once the hub took it as one. A
// hub that clearly does not offer streams is a *refusal; one that fails (5xx, 429) or refuses the client (401, 403)
// is an *Error.
func (c *Client) post(ctx context.Context, h http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.hub.String(), body)
	if err != nil {
		return nil, err
	}
	c.setHeader(req, h)
	req.Header.Set("Content-Type", ndjson)
	req.Header.Set("Accept", ndjson)
	resp, err := c.stream.Do(req)
	if err != nil {
		return nil, err
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode == http.StatusOK && mt == ndjson {
		return resp, nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	err = &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(msg))}
	switch s := resp.StatusCode; {
	case s >= 200 && s < 300, s == http.StatusBadRequest, s == http.StatusNotFound, s == http.StatusMethodNotAllowed,
		s == http.StatusUnsupportedMediaType:
		return nil, &refusal{err}
	}
	return nil, err
}

// send queues a publish, reporting false when the stream has ended (the caller opens another).
func (p *pubStream) send(q pending) bool {
	p.mu.Lock()
	if p.err != nil {
		p.mu.Unlock()
		return false
	}
	u := &q.u
	p.line = line{Topic: u.Topics, Data: u.Data, ID: u.ID, Type: u.Type, Private: u.Private, Retry: retryMillis(u.Retry),
		Replicas: u.Replicas}
	_ = p.enc.Encode(&p.line) // cannot fail: strings, a bool, a number
	p.line = line{}
	if len(p.pending) == 0 {
		p.since = time.Now()
	}
	p.pending = append(p.pending, q)
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return true
}

// write writes the queued lines into the body, many at a time, until the stream ends.
func (p *pubStream) write() {
	var buf out
	for {
		select {
		case <-p.wake:
		case <-p.done:
			return
		}
		p.mu.Lock()
		buf, p.out = p.out, buf[:0]
		p.mu.Unlock()
		if len(buf) == 0 {
			continue
		}
		if _, err := p.body.Write(buf); err != nil {
			// The request side closes as the hub ends the stream, often before its last answer is read: the reader
			// tells how the stream ended, unless it tells nothing soon.
			select {
			case <-p.done:
			case <-time.After(writeGrace):
				p.end(fmt.Errorf("%w: %v", ErrDisconnected, err))
			}
			return
		}
	}
}

// writeGrace is how long a stream whose writes fail waits for its answers to tell how it ended.
const writeGrace = 2 * time.Second

// read takes the answers, in order, until the stream ends.
func (p *pubStream) read(body io.ReadCloser) {
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var a answer
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			p.end(fmt.Errorf("mercure: undecodable answer %q", sc.Text()))
			return
		}
		if a.ID == "" && a.Line == 0 { // the stream's end, with why (its token expired, the hub is closing, idle)
			p.end(&Error{Status: a.Status, Message: a.Error})
			return
		}
		p.mu.Lock()
		if len(p.pending) == 0 {
			p.mu.Unlock()
			p.end(errors.New("mercure: an answer to no publish"))
			return
		}
		done := p.pending[0].done
		p.pending[0] = pending{}
		p.pending = p.pending[1:]
		p.since = time.Now()
		p.mu.Unlock()
		if a.Status == 0 {
			done(a.ID, nil)
		} else { // refused, or published but not stored (with its ID): not to be sent again either way
			done(a.ID, &Error{Status: a.Status, Message: a.Error})
		}
	}
	err := sc.Err()
	if err == nil {
		err = io.EOF
	}
	p.end(fmt.Errorf("%w: %v", ErrDisconnected, err))
}

// watch ends the stream when publishes await an answer that does not come: its connection is gone without a word
// (half-open), which HTTP/1.1 does not notice.
func (p *pubStream) watch() {
	t := time.NewTicker(p.c.answerTimeout / 4)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-p.done:
			return
		}
		p.mu.Lock()
		stale := len(p.pending) > 0 && time.Since(p.since) > p.c.answerTimeout
		p.mu.Unlock()
		if stale {
			p.end(fmt.Errorf("%w: no answer within %s", ErrDisconnected, p.c.answerTimeout))
			return
		}
	}
}

// end ends the stream. The publishes still awaiting an answer fail with err (the hub may or may not have published
// them), unless the hub ended the stream itself (its token expired, the hub is closing, the stream was idle): it
// answers every line it published before it ends (a line published but not stored too, with an error), so those it
// did not answer were not published, and they go first on the next stream.
func (p *pubStream) end(err error) {
	c := p.c
	c.mu.Lock() // with the client's lock: no new stream takes publishes before the carried ones
	p.mu.Lock()
	if p.err != nil {
		p.mu.Unlock()
		c.mu.Unlock()
		return
	}
	p.err = err
	waiting := p.pending
	p.pending = nil
	p.mu.Unlock()
	close(p.done)
	var hubs *Error
	byHub := errors.As(err, &hubs)
	failErr := err
	switch {
	case c.closed():
		failErr = ErrClosed
	case byHub && len(waiting) > 0:
		c.carry = append(c.carry, waiting...)
		waiting = nil
	case errors.Is(err, ErrDisconnected):
		// The connection is lost: the hub may or may not have published what it did not answer. A publish that
		// asked for copies is idempotent, so it is sent again; the others fail.
		var lost []pending
		for _, q := range waiting {
			if q.u.Replicas > 0 {
				c.carry = append(c.carry, q)
			} else {
				lost = append(lost, q)
			}
		}
		waiting = lost
	}
	if len(c.carry) > 0 && !c.resending && !c.closed() {
		c.resending = true
		go c.resend()
	}
	c.mu.Unlock()
	p.cancel()
	p.body.CloseWithError(err)
	fail(waiting, failErr)
	if !errors.Is(failErr, ErrClosed) && (!byHub || hubs.Status != http.StatusRequestTimeout) { // idle: a quiet close
		c.report(fmt.Errorf("mercure: publish stream ended: %w", err))
	}
}

func fail(ps []pending, err error) {
	for _, q := range ps {
		q.done("", err)
	}
}

// resend sees the carried publishes onto a new stream (or to POSTs), in order; they fail if none takes them within
// resendTimeout.
func (c *Client) resend() {
	ctx, cancel := context.WithTimeout(c.ctx, resendTimeout)
	defer cancel()
	for {
		_, err := c.publisher(ctx)
		c.mu.Lock()
		ps := c.carry
		if len(ps) == 0 || err != nil && (permanent(err) || ctx.Err() != nil) {
			switch {
			case c.closed():
				err = ErrClosed
			case err == ctx.Err() && c.openErr != nil: // gave up: why the last open failed
				err = c.openErr
			}
			c.carry, c.resending = nil, false
			c.mu.Unlock()
			fail(ps, err)
			return
		}
		wait := time.Until(c.retryAt) // the open failed: try again once it may
		c.mu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}
}

// postCarry publishes the carried publishes with POSTs, in order, the client having fallen back to them. With c.mu.
func (c *Client) postCarry() {
	if len(c.carry) == 0 {
		return
	}
	ps := c.carry
	c.carry = nil
	go func() {
		for _, q := range ps {
			id, err := c.httpPublish(c.ctx, q.u)
			q.done(id, c.closedErr(err))
		}
	}()
}

func (p *pubStream) ended() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
