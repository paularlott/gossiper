package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	maxJWKSSize    = 1 << 20          // bound on a JWK Set response body
	fetchTimeout   = 10 * time.Second // bound on one fetch
	minRefetch     = 30 * time.Second // minimum spacing of unknown-kid refetches
	notReadyRetry  = 30 * time.Second // background retry interval until a set is loaded
	maxJWKSEntries = 1000
)

var (
	errRateLimited = errors.New("refetch rate limited")
	errClosed      = errors.New("verifier closed")
)

// keyError is a key lookup failure raised from inside the jwt key function.
type keyError struct {
	msg   string
	cause error
}

func (e *keyError) Error() string {
	if e.cause != nil {
		return e.msg + ": " + e.cause.Error()
	}
	return e.msg
}
func (e *keyError) Unwrap() error { return e.cause }

type jwk struct {
	kid string
	alg string // from the JWK; empty when unset
	key any    // []byte, *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
}

func (k *jwk) supports(alg string) bool {
	return (k.alg == "" || k.alg == alg) && keyMatchesAlg(k.key, alg)
}

// keySet is an immutable parsed JWK Set.
type keySet struct {
	all   []*jwk
	byKid map[string][]*jwk
}

// pick returns the key (or a jwt.VerificationKeySet when several qualify) from
// list that can verify alg, or nil.
func pick(list []*jwk, alg string) any {
	var first *jwk
	var many []jwt.VerificationKey
	for _, k := range list {
		if !k.supports(alg) {
			continue
		}
		if first == nil {
			first = k
			continue
		}
		if many == nil {
			many = []jwt.VerificationKey{first.key}
		}
		many = append(many, k.key)
	}
	switch {
	case many != nil:
		return jwt.VerificationKeySet{Keys: many}
	case first != nil:
		return first.key
	}
	return nil
}

type fetchCall struct {
	done chan struct{}
	err  error
}

type jwksSource struct {
	url        string
	discover   func(context.Context) (string, error) // resolves url when it is empty
	client     *http.Client
	refresh    time.Duration
	now        func() time.Time
	minRefetch time.Duration

	set atomic.Pointer[keySet]

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	inflight *fetchCall
	last     time.Time // start of the most recent fetch
	lastErr  error
	closed   bool
}

func newJWKSSource(cfg KeyConfig, o internalOpts) *jwksSource {
	return newJWKSSourceFor(jwksTarget{url: cfg.JWKSURL, client: cfg.HTTPClient, refresh: cfg.JWKSRefresh}, o)
}

// jwksTarget says where a jwksSource gets its keys: a fixed url, or discover,
// which resolves the URL (and is called again after a failed fetch).
type jwksTarget struct {
	url      string
	discover func(context.Context) (string, error)
	client   *http.Client
	refresh  time.Duration
}

func newJWKSSourceFor(t jwksTarget, o internalOpts) *jwksSource {
	s := &jwksSource{
		url:        t.url,
		discover:   t.discover,
		client:     t.client,
		refresh:    t.refresh,
		now:        o.now,
		minRefetch: o.minRefetch,
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if s.refresh <= 0 {
		s.refresh = defaultJWKSRefresh
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.minRefetch == 0 {
		s.minRefetch = minRefetch
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	_ = s.refetch(context.Background(), true) // best effort; Ready reports the outcome

	s.wg.Add(1)
	go s.loop()
	return s
}

func (s *jwksSource) ready() bool { return s.set.Load() != nil }

func (s *jwksSource) lastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

func (s *jwksSource) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

func (s *jwksSource) loop() {
	defer s.wg.Done()
	timer := time.NewTimer(s.nextDelay())
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
			_ = s.refetch(s.ctx, true)
			timer.Reset(s.nextDelay())
		}
	}
}

func (s *jwksSource) nextDelay() time.Duration {
	if !s.ready() && s.refresh > notReadyRetry {
		return notReadyRetry
	}
	return s.refresh
}

// refetch fetches the key set. Concurrent callers share one fetch. Unless
// force is set it is skipped (errRateLimited) when a fetch started less than
// minRefetch ago. The caller's ctx only bounds how long it waits; the fetch
// itself is bounded by fetchTimeout and by Close.
func (s *jwksSource) refetch(ctx context.Context, force bool) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errClosed
	}
	call := s.inflight
	if call == nil {
		if !force && !s.last.IsZero() && s.now().Sub(s.last) < s.minRefetch {
			s.mu.Unlock()
			return errRateLimited
		}
		call = &fetchCall{done: make(chan struct{})}
		s.inflight = call
		s.last = s.now()
		s.wg.Add(1)
		go s.run(call)
	}
	s.mu.Unlock()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *jwksSource) run(call *fetchCall) {
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(s.ctx, fetchTimeout)
	set, err := s.fetch(ctx)
	cancel()
	if err == nil {
		s.set.Store(set)
	}
	s.mu.Lock()
	s.lastErr = err
	s.inflight = nil
	s.mu.Unlock()
	call.err = err
	close(call.done)
}

func (s *jwksSource) fetch(ctx context.Context) (*keySet, error) {
	if s.url == "" && s.discover != nil {
		u, err := s.discover(ctx)
		if err != nil {
			return nil, err
		}
		s.url = u
	}
	set, err := s.fetchSet(ctx)
	if err != nil && s.discover != nil {
		s.url = "" // the metadata may have moved: rediscover next time
	}
	return set, err
}

func (s *jwksSource) fetchSet(ctx context.Context) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: unexpected status %s", resp.Status)
	}
	if resp.ContentLength > maxJWKSSize {
		return nil, errors.New("jwks: response too large")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSSize {
		return nil, errors.New("jwks: response too large")
	}
	return parseJWKS(body)
}

// keyFor is the jwt key function for JWKS mode.
func (s *jwksSource) keyFor(ctx context.Context, t *jwt.Token) (any, error) {
	if _, ok := t.Header["crit"]; ok {
		return nil, &keyError{msg: "unsupported crit header"}
	}
	alg := t.Method.Alg()
	kid := ""
	if v, ok := t.Header["kid"]; ok {
		str, ok := v.(string)
		if !ok {
			return nil, &keyError{msg: "kid header is not a string"}
		}
		kid = str
	}

	set := s.set.Load()
	if set == nil {
		// Nothing loaded yet (initial fetch failed): try again, rate limited.
		if err := s.refetch(ctx, false); isCtxErr(err) {
			return nil, &keyError{msg: "key set not loaded", cause: err}
		}
		if set = s.set.Load(); set == nil {
			return nil, &keyError{msg: "key set not loaded", cause: s.lastError()}
		}
	}

	if kid == "" {
		if key := pick(set.all, alg); key != nil {
			return key, nil
		}
		return nil, &keyError{msg: "no key usable with " + alg}
	}

	list, known := set.byKid[kid]
	if !known {
		// Unknown kid: the issuer may have rotated keys.
		if err := s.refetch(ctx, false); isCtxErr(err) {
			return nil, &keyError{msg: "unknown kid", cause: err}
		}
		list, known = s.set.Load().byKid[kid]
	}
	if !known {
		return nil, &keyError{msg: "unknown kid"}
	}
	if key := pick(list, alg); key != nil {
		return key, nil
	}
	return nil, &keyError{msg: "no key for kid usable with " + alg}
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// --- JWK parsing ----------------------------------------------------------

type jwkJSON struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	K   string `json:"k"`
}

// parseJWKS parses a JWK Set. Keys that are unsupported, not for signature
// verification, or invalid are skipped; a set with no usable key is an error.
func parseJWKS(body []byte) (*keySet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	if len(doc.Keys) > maxJWKSEntries {
		return nil, errors.New("jwks: too many keys")
	}
	set := &keySet{byKid: make(map[string][]*jwk)}
	for _, raw := range doc.Keys {
		var j jwkJSON
		if json.Unmarshal(raw, &j) != nil {
			continue
		}
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		key, err := j.publicKey()
		if err != nil {
			continue
		}
		if j.Alg != "" {
			if _, ok := algs[j.Alg]; !ok || !keyMatchesAlg(key, j.Alg) {
				continue
			}
		}
		k := &jwk{kid: j.Kid, alg: j.Alg, key: key}
		set.all = append(set.all, k)
		if k.kid != "" {
			set.byKid[k.kid] = append(set.byKid[k.kid], k)
		}
	}
	if len(set.all) == 0 {
		return nil, errors.New("jwks: no usable keys")
	}
	return set, nil
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (j *jwkJSON) publicKey() (any, error) {
	switch j.Kty {
	case "RSA":
		nb, err := b64(j.N)
		if err != nil || len(nb) == 0 {
			return nil, errors.New("bad n")
		}
		eb, err := b64(j.E)
		if err != nil || len(eb) == 0 || len(eb) > 4 {
			return nil, errors.New("bad e")
		}
		e := 0
		for _, c := range eb {
			e = e<<8 | int(c)
		}
		n := new(big.Int).SetBytes(nb)
		if e < 3 || e&1 == 0 || e > 1<<31-1 || n.BitLen() < minRSABits {
			return nil, errors.New("bad RSA key")
		}
		return &rsa.PublicKey{N: n, E: e}, nil

	case "EC":
		curve := curveByName(j.Crv)
		if curve == nil {
			return nil, errors.New("unsupported curve")
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err1 := b64(j.X)
		y, err2 := b64(j.Y)
		if err1 != nil || err2 != nil || len(x) == 0 || len(y) == 0 || len(x) > size || len(y) > size {
			return nil, errors.New("bad EC coordinates")
		}
		pt := make([]byte, 1+2*size)
		pt[0] = 4
		copy(pt[1+size-len(x):], x)
		copy(pt[1+2*size-len(y):], y)
		return ecdsa.ParseUncompressedPublicKey(curve, pt)

	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, errors.New("unsupported OKP curve")
		}
		x, err := b64(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil

	case "oct":
		k, err := b64(j.K)
		if err != nil || len(k) == 0 {
			return nil, errors.New("bad oct key")
		}
		return k, nil
	}
	return nil, errors.New("unsupported kty")
}
