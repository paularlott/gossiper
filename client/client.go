// Package client is a Go client for Mercure hubs: it publishes updates and subscribes to topics.
//
// By default it publishes with a POST per update, as Mercure's HTTP protocol does, which any Mercure hub takes. With
// Transport Stream (or Auto) it publishes to a gossiper hub over one streaming publish instead (a long POST of NDJSON,
// a line an update, answered a line each): it publishes as fast as it writes, without waiting for each answer, many
// times faster than a POST per update; Auto falls back to a POST per update with any other Mercure hub. Either way it
// subscribes with Server-Sent Events, a stream a subscription that reconnects by itself, resuming from its last event
// ID. With HTTP/2 (https, or CleartextHTTP2 for a gossiper hub over http) the publish stream and every subscription
// share one connection.
//
//	c, _ := client.New(client.Options{URL: "https://example.com/.well-known/mercure", Token: jwt})
//	defer c.Close()
//	id, err := c.Publish(ctx, client.Update{Topics: []string{"https://example.com/books/1"}, Data: "{}"})
//	sub, err := c.Subscribe(ctx, client.Subscribe{Topics: []string{"https://example.com/books/{id}"}})
//	for ev := range sub.Events() { … }
//
// A service inside the cluster can bypass the proxy and reach a node directly: URL is the node's address and Host the
// host name the hub (a tenant's) is reached at, as the proxy would have asked for it.
//
// The client is a module of its own (github.com/paularlott/gossiper/client), needing nothing beyond the standard
// library, so a program that only publishes and subscribes does not depend on the hub. Its tests run the hub from
// this repository as a process.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
	"unicode/utf8"
)

// Transport selects how the client publishes.
type Transport int

const (
	// HTTP publishes with a POST per update, one request a publish, as Mercure's HTTP protocol does: the default,
	// which any Mercure hub takes.
	HTTP Transport = iota
	// Stream publishes over a stream only: one long streaming publish to a gossiper hub carries every update.
	Stream
	// Auto publishes over a stream when the hub offers it (a gossiper hub), and with a POST per update otherwise.
	Auto
)

func (t Transport) String() string {
	switch t {
	case Stream:
		return "stream"
	case Auto:
		return "auto"
	}
	return "http"
}

// Options configure a Client.
type Options struct {
	// URL is the hub's URL, such as https://example.com/.well-known/mercure, or a node's address
	// (http://10.0.0.5:8080/.well-known/mercure) with Host.
	URL string
	// Host is the host name to ask for, when it is not URL's: the hub's (a tenant's) public host name, when URL is a
	// node's address that bypasses the proxy.
	Host string
	// Token is the JWT the client presents, to publish and to subscribe.
	Token string
	// TokenFunc, when set, supplies the token instead, each time the client opens a stream or makes a request: a
	// token that expires is replaced without a new client.
	TokenFunc func(ctx context.Context) (string, error)
	// Transport selects how the client publishes. Default HTTP: a POST per update.
	Transport Transport
	// HTTPClient makes the requests. Default: a client of its own, with a 30s timeout for a POST per update.
	// Streams (the publish stream, the subscriptions) last as long as they need, whatever its Timeout. Redirects are
	// not followed (the token goes to the hub's URL only), unless it has a CheckRedirect of its own.
	HTTPClient *http.Client
	// CleartextHTTP2 makes the default HTTP client speak HTTP/2 to an http:// URL (h2c, prior knowledge): a gossiper
	// hub, reached directly, speaks it, and the publish stream and the subscriptions then share one connection. A hub
	// (or proxy) that speaks only HTTP/1.1 refuses it. With https, HTTP/2 is used when the hub offers it, whatever
	// this says.
	CleartextHTTP2 bool
	// TLSConfig configures TLS for the default HTTP client.
	TLSConfig *tls.Config
	// CAFile names PEM certificates the default HTTP client trusts for the hub's, as well as the system's: a private
	// CA, or a gossiper hub's self-signed certificate (the self-signed.crt of its tls-dir).
	CAFile string
	// InsecureSkipVerify makes the default HTTP client take any certificate from the hub, unverified: development
	// only, as anyone between the client and the hub can then read and change what passes.
	InsecureSkipVerify bool
	// Header is added to every request.
	Header http.Header
	// MaxInFlight bounds the publishes awaiting the hub's answer; PublishAsync waits for room beyond it. Default 4096.
	MaxInFlight int
	// RetryStream is how long Auto publishes with a POST per update after a hub refused a stream, before it tries
	// again. Default one minute.
	RetryStream time.Duration
	// MaxEventSize bounds an event a subscription takes, in bytes (its data, and any one line of it): a stream with a
	// larger one ends and reconnects, with the error told to OnError, rather than hold what the hub sends without
	// limit. Default 8 MiB, well over a gossiper hub's default --max-publish-size (1 MiB); raise it with that.
	MaxEventSize int
	// OnError, when set, is told of errors the client recovers from by itself: a publish stream lost, a subscription
	// that reconnects.
	OnError func(error)
}

// Update is an update to publish.
type Update struct {
	Topics  []string // the canonical topic, then its alternates
	Data    string
	ID      string // default: the hub makes one
	Type    string
	Private bool
	Retry   time.Duration // the reconnection time subscribers are given; 0: none
	// Replicas asks a gossiper hub for that many copies, on as many nodes, before the publish is answered: an error
	// (Status 503) when fewer nodes can take it, or when it does not reach them in time. Such a publish is
	// idempotent by its ID: published again (a retry, through any node), the hub answers as it did the first and
	// does not deliver it again. Without an ID the client makes one, so its own resends are safe: it sends such a
	// publish again when a hub ends its stream or the connection is lost (to another node, through a load balancer).
	// Give an ID to make your own retries safe too. Other Mercure hubs ignore it.
	Replicas int
}

// Event is an event a subscription receives.
type Event struct {
	ID    string
	Type  string
	Data  string
	Retry time.Duration // 0: none
}

// Error is an error the hub answered, with the HTTP status of its kind (in a publish stream too).
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("mercure: %d %s", e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("mercure: %d %s", e.Status, e.Message)
}

// permanent reports whether retrying the same request cannot help.
func permanent(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status >= 400 && e.Status < 500 && e.Status != http.StatusTooManyRequests &&
		e.Status != http.StatusRequestTimeout
}

var (
	// ErrClosed is returned once the client is closed.
	ErrClosed = errors.New("mercure: client closed")
	// ErrDisconnected fails a publish whose connection was lost before the hub answered: it may or may not have
	// been published.
	ErrDisconnected = errors.New("mercure: connection lost before the hub answered")
)

// Client publishes to and subscribes at one hub. It is safe for concurrent use.
type Client struct {
	opts   Options
	hub    *url.URL
	http   *http.Client
	stream *http.Client    // for streams: no timeout
	own    *http.Transport // the transport New made, closed with the client
	slots  chan struct{}
	ctx    context.Context // ended by Close
	cancel context.CancelFunc
	done   <-chan struct{} // ctx.Done()
	once   sync.Once
	subsWG sync.WaitGroup

	openTimeout   time.Duration // how long opening a publish stream waits for the hub's answer
	answerTimeout time.Duration // how long publishes await an answer before their stream is deemed lost

	mu        sync.Mutex
	pub       *pubStream
	opening   chan struct{} // closed when the stream being opened is open (or failed); nil when none is
	carry     []pending     // publishes of a stream the hub ended, unanswered: they go first on the next one
	resending bool          // a goroutine sees carry onto a new stream
	openErr   error         // why the last stream failed to open: publishes fail with it until retryAt
	openFails int           // streams that failed to open in a row
	retryAt   time.Time
	httpUntil time.Time // Auto: publish with POSTs until then (the hub refused a stream)
	subs      map[*Subscription]struct{}
}

// New returns a client. It connects when first used.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("mercure: URL must be an http or https URL")
	}
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = 4096
	}
	if o.RetryStream <= 0 {
		o.RetryStream = time.Minute
	}
	if o.MaxEventSize <= 0 {
		o.MaxEventSize = 8 << 20
	}
	c := &Client{opts: o, hub: u, http: o.HTTPClient, slots: make(chan struct{}, o.MaxInFlight),
		openTimeout: 10 * time.Second, answerTimeout: 30 * time.Second, subs: map[*Subscription]struct{}{}}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.done = c.ctx.Done()
	if c.http != nil && c.http.CheckRedirect == nil {
		hc := *c.http
		hc.CheckRedirect = noRedirect
		c.http = &hc
	}
	if c.http == nil {
		tlsConfig, err := clientTLS(o)
		if err != nil {
			c.cancel()
			return nil, err
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		tr.MaxIdleConnsPerHost = 64
		tr.ResponseHeaderTimeout = 30 * time.Second
		// A connection gone without a word (half-open) is noticed: HTTP/2 pings it once quiet.
		tr.HTTP2 = &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 15 * time.Second}
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(true)
		tr.Protocols.SetHTTP2(true)
		if o.CleartextHTTP2 && u.Scheme == "http" {
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetUnencryptedHTTP2(true)
		}
		c.http = &http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: noRedirect}
		c.own = tr
	}
	sc := *c.http
	sc.Timeout = 0
	c.stream = &sc
	return c, nil
}

// noRedirect refuses a redirect: the answer is the hub's, and is not followed. Every request carries the token, which
// goes to the hub's URL and nowhere else (Go would send it on to another port or a subdomain of the hub's host, and
// from https to http).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// clientTLS is the default HTTP client's TLS configuration: TLSConfig, with CAFile and InsecureSkipVerify.
func clientTLS(o Options) (*tls.Config, error) {
	if o.CAFile == "" && !o.InsecureSkipVerify {
		return o.TLSConfig, nil
	}
	cfg := &tls.Config{}
	if o.TLSConfig != nil {
		cfg = o.TLSConfig.Clone()
	}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("mercure: CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("mercure: CA file %s: no PEM certificate", o.CAFile)
		}
		cfg.RootCAs = pool
	}
	if o.InsecureSkipVerify {
		cfg.InsecureSkipVerify = true //nolint:gosec // asked for, and only then
	}
	return cfg, nil
}

// Close closes the client's subscriptions and publish stream. Publishes awaiting their answer fail.
func (c *Client) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		pub, carry := c.pub, c.carry
		c.carry = nil
		subs := make([]*Subscription, 0, len(c.subs))
		for s := range c.subs {
			subs = append(subs, s)
		}
		c.mu.Unlock()
		for _, s := range subs {
			s.Close()
		}
		if pub != nil {
			pub.end(ErrClosed)
		}
		fail(carry, ErrClosed)
		if c.own != nil { // once the subscriptions let go of their connections (not here: OnError may be closing it)
			go func() {
				c.subsWG.Wait()
				c.own.CloseIdleConnections()
			}()
		}
	})
	return nil
}

// Transport reports how the client publishes now: Stream or HTTP (Auto, with Transport Auto, before it first
// publishes).
func (c *Client) Transport() Transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.opts.Transport != Auto:
		return c.opts.Transport
	case c.pub != nil:
		return Stream
	case !c.httpUntil.IsZero() && time.Now().Before(c.httpUntil):
		return HTTP
	}
	return Auto
}

func (c *Client) token(ctx context.Context) (string, error) {
	if c.opts.TokenFunc != nil {
		return c.opts.TokenFunc(ctx)
	}
	return c.opts.Token, nil
}

func (c *Client) report(err error) {
	if c.opts.OnError != nil && err != nil {
		c.opts.OnError(err)
	}
}

// closedErr is err, or ErrClosed once the client is closed (which cancelled what err comes from).
func (c *Client) closedErr(err error) error {
	if err != nil && c.closed() {
		return ErrClosed
	}
	return err
}

// detached is ctx without its cancellation: Close cancels it instead.
func (c *Client) detached(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(c.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

// backoff is how long publishes wait after fails streams failed to open in a row before one is opened again.
func backoff(fails int) time.Duration {
	return jitter(min(100*time.Millisecond<<min(fails-1, 7), 10*time.Second))
}

func (c *Client) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// publisher returns the publish stream to use, opening one if need be, or nil to publish with POSTs.
func (c *Client) publisher(ctx context.Context) (*pubStream, error) {
	for {
		if c.closed() {
			return nil, ErrClosed
		}
		c.mu.Lock()
		switch {
		case c.opts.Transport == HTTP:
			c.mu.Unlock()
			return nil, nil
		case c.pub != nil && !c.pub.ended():
			p := c.pub
			c.mu.Unlock()
			return p, nil
		case c.opts.Transport == Auto && time.Now().Before(c.httpUntil):
			c.postCarry()
			c.mu.Unlock()
			return nil, nil
		case c.opening != nil:
			wait := c.opening
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.done:
				return nil, ErrClosed
			}
		case time.Now().Before(c.retryAt): // the last open failed: not again so soon
			err := c.openErr
			c.mu.Unlock()
			return nil, err
		}
		wait := make(chan struct{})
		c.opening = wait
		c.mu.Unlock()
		p, err := c.openStream(ctx)
		c.mu.Lock()
		c.opening = nil
		close(wait)
		var r *refusal
		switch {
		case errors.As(err, &r) && c.opts.Transport == Auto: // another Mercure hub: POSTs for a while
			c.httpUntil, c.openFails, c.retryAt, err = time.Now().Add(c.opts.RetryStream), 0, time.Time{}, nil
			c.postCarry()
		case err == nil: // the carried publishes go first, before the stream is anyone's
			for _, q := range c.carry {
				p.send(q)
			}
			c.carry, c.pub, c.openFails, c.retryAt = nil, p, 0, time.Time{}
		case ctx.Err() == nil: // the hub failed, not the caller: those waiting for it hear why, and wait longer each time
			c.openFails++
			c.openErr, c.retryAt = err, time.Now().Add(backoff(c.openFails))
		}
		c.mu.Unlock()
		if err != nil {
			if r != nil {
				err = r.err
			}
			return nil, err
		}
		if p == nil {
			return nil, nil
		}
		if c.closed() { // closed while opening: Close did not see it
			p.end(ErrClosed)
			return nil, ErrClosed
		}
		return p, nil
	}
}

// Publish publishes u and returns its event ID once the hub has it.
func (c *Client) Publish(ctx context.Context, u Update) (string, error) {
	type result struct {
		id  string
		err error
	}
	ch := make(chan result, 1)
	if err := c.publish(ctx, u, func(id string, err error) { ch <- result{id, err} }); err != nil {
		return "", err
	}
	select {
	case r := <-ch:
		return r.id, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// PublishAsync publishes u without waiting for the hub: done, if not nil, is called with the event ID or the error
// once the hub answers. Over a stream it runs on the goroutine that reads the answers, so it must be quick and must
// not wait for the client (no Publish in it): until it returns, no other answer is read. Over a stream the publishes
// of a client keep their order; with a POST per update (Transport HTTP, the default) each is a request of its own,
// and they may reach the hub in any order. It waits only when MaxInFlight publishes are awaiting their answer.
func (c *Client) PublishAsync(ctx context.Context, u Update, done func(id string, err error)) error {
	if done == nil {
		done = func(string, error) {}
	}
	return c.publish(ctx, u, done)
}

func (c *Client) publish(ctx context.Context, u Update, done func(string, error)) error {
	if err := u.check(); err != nil {
		return err
	}
	if u.Replicas > 0 && u.ID == "" {
		u.ID = newID()
	}
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return ErrClosed
	}
	release := func(id string, err error) { <-c.slots; done(id, err) }
	for {
		p, err := c.publisher(ctx)
		if err != nil {
			<-c.slots
			return err
		}
		if p == nil {
			// As over a stream, the publish no longer depends on ctx once it is on its way; Close cancels it.
			hctx, cancel := c.detached(ctx)
			go func() {
				defer cancel()
				id, err := c.httpPublish(hctx, u)
				release(id, c.closedErr(err))
			}()
			return nil
		}
		if p.send(pending{u, release}) {
			return nil
		}
		// the stream ended just now: the next one takes it
	}
}

// Subscribe opens a subscription. It returns once the hub accepted it, or with the hub's error; from then on the
// subscription reconnects by itself, resuming from its last event ID, until it is closed or ctx ends.
func (c *Client) Subscribe(ctx context.Context, s Subscribe) (*Subscription, error) {
	if len(s.Topics) == 0 && len(s.Match) == 0 && len(s.MatchURLPattern) == 0 {
		return nil, errors.New("mercure: subscribe to at least one topic")
	}
	if s.Buffer <= 0 {
		s.Buffer = 1024
	}
	sub := &Subscription{c: c, spec: s, events: make(chan Event, s.Buffer), stop: make(chan struct{}),
		lastID: s.LastEventID}
	c.mu.Lock()
	if c.closed() {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	c.subs[sub] = struct{}{}
	c.subsWG.Add(1)
	c.mu.Unlock()
	first := make(chan error, 1)
	go sub.run(ctx, first)
	select {
	case err := <-first:
		if err != nil {
			sub.Close()
			return nil, err
		}
		return sub, nil
	case <-ctx.Done():
		sub.Close()
		return nil, ctx.Err()
	}
}

// Subscribe describes a subscription.
type Subscribe struct {
	// Topics are topic selectors: topics, URI templates, or * (draft-07 "topic" parameters).
	Topics []string
	// Match and MatchURLPattern are Mercure 1.0 matchers: exact topics and URL patterns.
	Match           []string
	MatchURLPattern []string
	// LastEventID resumes after that event (or "earliest" for the whole history).
	LastEventID string
	// Buffer is the capacity of the Events channel. Default 1024. A reader that falls a full buffer behind holds up
	// the stream; the hub drops a stream that stays behind (dispatch buffer), and the subscription then resumes from
	// its last event (Mercure's history keeps what it missed, within its limits).
	Buffer int
}

// Subscription is an open subscription.
type Subscription struct {
	c      *Client
	spec   Subscribe
	events chan Event
	stop   chan struct{}
	once   sync.Once

	mu     sync.Mutex
	lastID string
	err    error
}

// Events returns the subscription's events. It is closed when the subscription ends.
func (s *Subscription) Events() <-chan Event { return s.events }

// LastEventID returns the ID of the last event delivered, which the subscription resumes from should it reconnect.
func (s *Subscription) LastEventID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastID
}

// Err returns why the subscription ended, once Events is closed: nil when it was closed (or its ctx ended), the
// hub's error when it refused the subscription for good (its token was refused, say).
func (s *Subscription) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close ends the subscription.
func (s *Subscription) Close() {
	s.once.Do(func() { close(s.stop) })
}

func (s *Subscription) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// run keeps the subscription open until it ends: closed, or refused for good once reconnecting. first gets the
// outcome of the first attempt.
func (s *Subscription) run(ctx context.Context, first chan<- error) {
	c := s.c
	var endErr error
	defer func() {
		c.mu.Lock()
		delete(c.subs, s)
		c.mu.Unlock()
		s.mu.Lock()
		s.err = endErr
		close(s.events)
		s.mu.Unlock()
		c.subsWG.Done()
	}()
	delay := 100 * time.Millisecond
	reauth := false // retried once already with a new token after a 401
	for {
		if s.stopped() || ctx.Err() != nil || c.closed() {
			return
		}
		established := false
		onOpen := func() {
			established = true
			if first != nil {
				first <- nil
				first = nil
			}
		}
		err := s.followSSE(ctx, onOpen)
		if s.stopped() || ctx.Err() != nil || c.closed() {
			return
		}
		if first != nil { // the first attempt failed: the caller hears why
			if err == nil {
				err = ErrDisconnected
			}
			first <- err
			endErr = err
			return
		}
		if established {
			delay, reauth = 100*time.Millisecond, false
		}
		if permanent(err) {
			var e *Error
			if errors.As(err, &e) && e.Status == http.StatusUnauthorized && c.opts.TokenFunc != nil && !reauth {
				reauth = true // its token expired, say: once more at once, with a new one
				c.report(fmt.Errorf("mercure: subscription reconnecting: %w", err))
				continue
			}
			endErr = err
			return
		}
		if err != nil {
			c.report(fmt.Errorf("mercure: subscription reconnecting: %w", err))
		}
		select {
		case <-time.After(jitter(delay)):
		case <-s.stop:
			return
		case <-ctx.Done():
			return
		case <-c.done:
			return
		}
		delay = min(delay*2, 5*time.Second)
	}
}

// jitter spreads reconnections over half the delay to all of it, so clients do not all return at once when a node
// goes away.
func jitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d/2+1)
}

func (c *Client) header(ctx context.Context) (http.Header, error) {
	h := http.Header{}
	for k, v := range c.opts.Header {
		h[k] = append([]string(nil), v...)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("mercure: token: %w", err)
	}
	if tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h, nil
}

// check refuses an update the hub would refuse for its text, as the hub does over HTTP: JSON would otherwise
// replace invalid UTF-8 and send something else.
func (u Update) check() error {
	if len(u.Topics) == 0 {
		return &Error{Status: http.StatusBadRequest, Message: `Missing "topic" parameter`}
	}
	if u.Replicas < 0 {
		return &Error{Status: http.StatusBadRequest, Message: `Invalid "replicas"`}
	}
	ok := utf8.ValidString(u.Data) && utf8.ValidString(u.ID) && utf8.ValidString(u.Type)
	for _, t := range u.Topics {
		ok = ok && utf8.ValidString(t)
	}
	if !ok {
		return &Error{Status: http.StatusBadRequest, Message: "invalid UTF-8"}
	}
	return nil
}

// newID returns a random (version 4) UUID URN, for an update that asks for copies without an ID.
func newID() string {
	var b [16]byte // unique, not secret: the runtime's generator does
	binary.BigEndian.PutUint64(b[:8], rand.Uint64())
	binary.BigEndian.PutUint64(b[8:], rand.Uint64())
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// retryMillis is d in milliseconds; 0: none.
func retryMillis(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d / time.Millisecond)
}
