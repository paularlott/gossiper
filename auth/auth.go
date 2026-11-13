// Package auth verifies the JSON Web Signatures (compact JWTs) presented by
// publishers and subscribers to a Mercure-compatible hub and extracts the
// "mercure" claim from them.
//
// A [Verifier] is configured with either a static key (an HMAC secret or a
// PEM encoded public key / certificate) or the URL of a JWK Set. It is safe
// for concurrent use.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrMalformed is returned (wrapped) for tokens that are not a parseable
	// compact JWS: wrong number of segments, bad base64 or bad JSON, or a token
	// that is too long. The hub answers 400.
	ErrMalformed = errors.New("auth: malformed token")

	// ErrInvalid is returned (wrapped) for tokens that parse but are rejected:
	// bad signature, wrong or disallowed algorithm, expired, not yet valid,
	// unknown key id, or a missing or ill-typed "mercure" claim. The hub
	// answers 401.
	ErrInvalid = errors.New("auth: invalid token")
)

const (
	// MaxTokenSize is the longest token, in bytes, that Verify will parse.
	MaxTokenSize = 16 << 10

	defaultJWKSRefresh = 10 * time.Minute
	defaultHTTPTimeout = 10 * time.Second
)

// Claims is the information extracted from a verified token.
type Claims struct {
	Publish      []string        // mercure.publish (nil if absent)
	HasPublish   bool            // the publish key is present (possibly an empty array)
	Subscribe    []string        // mercure.subscribe (nil if absent)
	HasSubscribe bool            // the subscribe key is present (possibly an empty array)
	Payload      json.RawMessage // mercure.payload verbatim; nil when absent
	Subject      string          // "sub", if any
	Expiry       time.Time       // zero when the token has no exp
}

// KeyConfig describes how tokens are verified. Exactly one of Key and JWKSURL
// must be set.
type KeyConfig struct {
	// Key is an HMAC secret (the raw bytes of the string) or, for asymmetric
	// algorithms, a PEM encoded public key (RSA, ECDSA or Ed25519; PKIX
	// "PUBLIC KEY", PKCS#1 "RSA PUBLIC KEY", or a "CERTIFICATE").
	Key string
	// Algorithm is one of HS256 (default), HS384, HS512, RS256, RS384, RS512,
	// PS256, PS384, PS512, ES256, ES384, ES512 or EdDSA. With JWKSURL it
	// restricts the tokens to that algorithm; empty there allows every
	// public-key algorithm, but no HMAC one: a remote "oct" key is used only
	// when Algorithm names its HMAC algorithm.
	Algorithm string
	// JWKSURL is an alternative to Key: keys are fetched from this JWK Set URL.
	JWKSURL string
	// PreviousKey is a key Key replaced (an HMAC secret or a PEM public key, as Key), still accepted until
	// PreviousUntil: tokens signed with either verify while clients move to the new key. Only with Key; ignored once
	// PreviousUntil has passed (zero: never accepted).
	PreviousKey string
	// PreviousUntil is when PreviousKey stops being accepted.
	PreviousUntil time.Time
	// JWKSRefresh is the background refresh interval. Default 10 minutes.
	JWKSRefresh time.Duration
	// HTTPClient is used to fetch the JWK Set. Default: a client with a 10s timeout.
	HTTPClient *http.Client
	// Leeway is the clock skew tolerated when checking exp and nbf. Default 0.
	Leeway time.Duration
	// AllowInsecureHTTP lets JWKSURL use plain HTTP, or https with a certificate that does not verify (with the default
	// HTTPClient), for tests and development: over HTTP anyone on the path
	// can substitute keys. Default: https only.
	AllowInsecureHTTP bool
}

// WeakSecret reports whether k is an HMAC secret shorter than its algorithm's hash size (32 bytes for HS256, 48 for
// HS384, 64 for HS512): short enough to guess.
func WeakSecret(k KeyConfig) bool {
	alg := k.Algorithm
	if alg == "" {
		alg, _ = DefaultAlgorithm(k.Key)
	}
	info, ok := algs[alg]
	return ok && k.Key != "" && info.kind == kindHMAC && len(k.Key) < info.minSecret
}

// DefaultAlgorithm is the algorithm a static key verifies with when none is given: a PEM public key's own (RS256 for
// RSA, ES256, ES384 or ES512 by the ECDSA curve, EdDSA for Ed25519), HS256 for a secret. A public key is never taken
// as an HMAC secret: anyone who has it could sign tokens with it.
func DefaultAlgorithm(key string) (string, error) {
	if !isPEM(key) {
		return "HS256", nil
	}
	pub, err := parsePublicKeyPEM(key)
	if err != nil {
		return "", err
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RS256", nil
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "ES256", nil
		case 384:
			return "ES384", nil
		case 521:
			return "ES512", nil
		}
	case ed25519.PublicKey:
		return "EdDSA", nil
	}
	return "", fmt.Errorf("auth: no algorithm for a %s key", describeKey(pub))
}

// isPEM reports whether key is PEM-encoded: a public key, never an HMAC secret.
func isPEM(key string) bool { return strings.Contains(key, "-----BEGIN") }

// errPEMSecret refuses an HMAC algorithm with a PEM key: the public key would be the secret.
func errPEMSecret(alg string) error {
	return fmt.Errorf("auth: %s takes a secret, not a PEM public key (anyone with the key could sign tokens): set the key's own algorithm, such as RS256, or leave the algorithm out", alg)
}

// Verifier verifies tokens against a configured key or key set.
type Verifier struct {
	parser *jwt.Parser
	keyfn  jwt.Keyfunc // static mode only
	jwks   *jwksSource // nil in static mode
	weak   bool        // WeakSecret of the static key
}

// NewVerifier validates cfg and returns a Verifier. With JWKSURL the first
// fetch is attempted before returning (bounded by a 10s timeout); if it fails
// the Verifier is still returned and rejects tokens with ErrInvalid until a
// key set has been loaded (see Ready). Callers must call Close when finished.
func NewVerifier(cfg KeyConfig) (*Verifier, error) {
	return newVerifier(cfg, internalOpts{})
}

// internalOpts lets tests inject a clock and rate-limit interval.
type internalOpts struct {
	now        func() time.Time
	minRefetch time.Duration
}

// CheckKey validates cfg as NewVerifier does, without fetching a key set or holding anything to close: for a key a
// hub holds though it verifies no draft-07 tokens with it. weak is WeakSecret's answer for a static key.
func CheckKey(cfg KeyConfig) (weak bool, err error) {
	if err := checkConfig(cfg); err != nil {
		return false, err
	}
	if cfg.JWKSURL != "" {
		_, err := jwksMethods(cfg)
		return false, err
	}
	if _, _, err := verifierKey(cfg); err != nil {
		return false, err
	}
	if cfg.PreviousKey != "" {
		if _, _, err := verifierKey(previousConfig(cfg)); err != nil {
			return false, fmt.Errorf("previous key: %w", err)
		}
	}
	return WeakSecret(cfg), nil
}

func checkConfig(cfg KeyConfig) error {
	if (cfg.Key == "") == (cfg.JWKSURL == "") {
		return errors.New("auth: exactly one of Key and JWKSURL must be set")
	}
	if cfg.PreviousKey != "" && cfg.Key == "" {
		return errors.New("auth: PreviousKey needs Key")
	}
	if cfg.Leeway < 0 {
		return errors.New("auth: negative Leeway")
	}
	return nil
}

// jwksMethods checks a key set's URL and returns the algorithms its keys may sign with.
func jwksMethods(cfg KeyConfig) ([]string, error) {
	if _, err := checkURL(cfg.JWKSURL, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("auth: JWKSURL: %w", err)
	}
	if cfg.Algorithm == "" {
		return remoteAlgs, nil
	}
	if _, ok := algs[cfg.Algorithm]; !ok {
		return nil, fmt.Errorf("auth: unsupported algorithm %q", cfg.Algorithm)
	}
	return []string{cfg.Algorithm}, nil
}

// previousConfig is cfg with its PreviousKey as the key, for verifierKey: the algorithm is Algorithm when set, or
// the previous key's own.
func previousConfig(cfg KeyConfig) KeyConfig {
	cfg.Key, cfg.PreviousKey = cfg.PreviousKey, ""
	return cfg
}

// verifierKey returns a static key's algorithm and the key to verify with: the secret, or the parsed public key.
func verifierKey(cfg KeyConfig) (string, any, error) {
	alg := cfg.Algorithm
	if alg == "" {
		var err error
		if alg, err = DefaultAlgorithm(cfg.Key); err != nil {
			return "", nil, err
		}
	}
	info, ok := algs[alg]
	if !ok {
		return "", nil, fmt.Errorf("auth: unsupported algorithm %q", alg)
	}
	if info.kind == kindHMAC {
		if isPEM(cfg.Key) {
			return "", nil, errPEMSecret(alg)
		}
		return alg, []byte(cfg.Key), nil
	}
	pub, err := parsePublicKeyPEM(cfg.Key)
	if err != nil {
		return "", nil, err
	}
	if !keyMatchesAlg(pub, alg) {
		return "", nil, fmt.Errorf("auth: %s key does not match algorithm %s", describeKey(pub), alg)
	}
	return alg, pub, nil
}

func newVerifier(cfg KeyConfig, o internalOpts) (*Verifier, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.JWKSURL != "" {
		methods, err := jwksMethods(cfg)
		if err != nil {
			return nil, err
		}
		v := &Verifier{
			parser: jwt.NewParser(jwt.WithValidMethods(methods), jwt.WithLeeway(cfg.Leeway)),
		}
		cfg.HTTPClient = secureClient(cfg.HTTPClient, cfg.AllowInsecureHTTP)
		v.jwks = newJWKSSource(cfg, o)
		return v, nil
	}
	alg, key, err := verifierKey(cfg)
	if err != nil {
		return nil, err
	}
	methods := []string{alg}
	var prev any
	if cfg.PreviousKey != "" {
		palg, pkey, err := verifierKey(previousConfig(cfg))
		if err != nil {
			return nil, fmt.Errorf("auth: previous key: %w", err)
		}
		prev = pkey
		if palg != alg {
			methods = append(methods, palg)
		}
	}
	now := o.now
	if now == nil {
		now = time.Now
	}
	until := cfg.PreviousUntil
	v := &Verifier{
		parser: jwt.NewParser(jwt.WithValidMethods(methods), jwt.WithLeeway(cfg.Leeway)),
		weak:   WeakSecret(cfg),
		keyfn: func(t *jwt.Token) (any, error) {
			if _, ok := t.Header["crit"]; ok {
				return nil, &keyError{msg: "unsupported crit header"}
			}
			if prev != nil && now().Before(until) { // rotating: the replaced key still verifies
				return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{key, prev}}, nil
			}
			return key, nil
		},
	}
	return v, nil
}

// Weak reports whether the configured HMAC secret is shorter than the hash
// size of the algorithm (32 bytes for HS256, 48 for HS384, 64 for HS512).
func (v *Verifier) Weak() bool { return v.weak }

// Ready reports whether the verifier has keys to verify with. It is always
// true for a static key and, for a JWK Set, true once a set has been fetched.
func (v *Verifier) Ready() bool {
	if v.jwks == nil {
		return true
	}
	return v.jwks.ready()
}

// JWKSError returns the error from the most recent JWK Set fetch, or nil if it
// succeeded or the verifier uses a static key.
func (v *Verifier) JWKSError() error {
	if v.jwks == nil {
		return nil
	}
	return v.jwks.lastError()
}

// Close stops the JWK Set refresh goroutine, if any, and waits for it and any
// in-flight fetch to finish. It is safe to call more than once. Verify keeps
// working after Close using the last key set.
func (v *Verifier) Close() {
	if v.jwks != nil {
		v.jwks.close()
	}
}

// tokenClaims decodes just what the hub needs from the JWT payload.
type tokenClaims struct {
	Exp     *jwt.NumericDate `json:"exp"`
	Nbf     *jwt.NumericDate `json:"nbf"`
	Sub     json.RawMessage  `json:"sub"`
	Mercure json.RawMessage  `json:"mercure"`
}

func (c *tokenClaims) GetExpirationTime() (*jwt.NumericDate, error) { return c.Exp, nil }
func (c *tokenClaims) GetNotBefore() (*jwt.NumericDate, error)      { return c.Nbf, nil }
func (c *tokenClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (c *tokenClaims) GetIssuer() (string, error)                   { return "", nil }
func (c *tokenClaims) GetSubject() (string, error)                  { return "", nil }
func (c *tokenClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}

// Verify checks the signature and the exp / nbf times of a compact JWS and
// returns the Mercure claims it carries. Errors wrap exactly one of
// ErrMalformed or ErrInvalid.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if token == "" {
		return nil, fail(ErrMalformed, "empty token")
	}
	if len(token) > MaxTokenSize {
		return nil, fail(ErrMalformed, "token longer than %d bytes", MaxTokenSize)
	}

	keyfn := v.keyfn
	if v.jwks != nil {
		keyfn = func(t *jwt.Token) (any, error) { return v.jwks.keyFor(ctx, t) }
	}

	var tc tokenClaims
	if _, err := v.parser.ParseWithClaims(token, &tc, keyfn); err != nil {
		return nil, classify(err)
	}
	return buildClaims(&tc)
}

// classify maps a jwt library error to one of the package sentinels.
func classify(err error) error {
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return fail(ErrMalformed, "%s", shortReason(err))
	}
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fail(ErrInvalid, "token expired")
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fail(ErrInvalid, "token not yet valid")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		if r := shortReason(err); r != "" {
			return fail(ErrInvalid, "%s", r)
		}
		return fail(ErrInvalid, "signature invalid")
	}
	// Key lookup failures keep their cause (including context errors).
	var ke *keyError
	if errors.As(err, &ke) {
		if ke.cause != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalid, ke.msg, ke.cause)
		}
		return fail(ErrInvalid, "%s", ke.msg)
	}
	return fail(ErrInvalid, "%s", shortReason(err))
}

// shortReason returns the outermost message of a jwt error, without the
// library's error chain.
func shortReason(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i > 0 {
		// jwt formats "token is malformed: <detail>"; keep the detail.
		return s[i+2:]
	}
	return s
}

func buildClaims(tc *tokenClaims) (*Claims, error) {
	if len(tc.Mercure) == 0 {
		return nil, fail(ErrInvalid, "missing mercure claim")
	}
	if first := firstNonSpace(tc.Mercure); first != '{' {
		return nil, fail(ErrInvalid, "mercure claim is not an object")
	}
	var m struct {
		Publish   json.RawMessage `json:"publish"`
		Subscribe json.RawMessage `json:"subscribe"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(tc.Mercure, &m); err != nil {
		return nil, fail(ErrInvalid, "mercure claim: %v", err)
	}

	out := &Claims{}
	var err error
	if out.Publish, out.HasPublish, err = selectors(m.Publish); err != nil {
		return nil, fail(ErrInvalid, "mercure.publish: %v", err)
	}
	if out.Subscribe, out.HasSubscribe, err = selectors(m.Subscribe); err != nil {
		return nil, fail(ErrInvalid, "mercure.subscribe: %v", err)
	}
	if len(m.Payload) > 0 {
		out.Payload = m.Payload
	}
	if len(tc.Sub) > 0 {
		var s string
		if json.Unmarshal(tc.Sub, &s) == nil {
			out.Subject = s
		}
	}
	if tc.Exp != nil {
		out.Expiry = tc.Exp.Time
	}
	return out, nil
}

func firstNonSpace(b []byte) byte {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			return c
		}
	}
	return 0
}

// selectors decodes an optional JSON array of strings. An absent key or a
// JSON null count as not present.
func selectors(raw json.RawMessage) (list []string, present bool, err error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	if firstNonSpace(raw) != '[' {
		return nil, false, errors.New("not an array of strings")
	}
	var ptrs []*string
	if err := json.Unmarshal(raw, &ptrs); err != nil {
		return nil, false, errors.New("not an array of strings")
	}
	list = make([]string, len(ptrs))
	for i, p := range ptrs {
		if p == nil {
			return nil, false, errors.New("not an array of strings")
		}
		list[i] = *p
	}
	return list, true, nil
}

// --- algorithms -----------------------------------------------------------

type keyKind int

const (
	kindHMAC keyKind = iota
	kindRSA
	kindEC
	kindEd
)

type algInfo struct {
	kind      keyKind
	bits      int // EC curve size
	minSecret int // HMAC hash size
}

var algs = map[string]algInfo{
	"HS256": {kind: kindHMAC, minSecret: 32},
	"HS384": {kind: kindHMAC, minSecret: 48},
	"HS512": {kind: kindHMAC, minSecret: 64},
	"RS256": {kind: kindRSA},
	"RS384": {kind: kindRSA},
	"RS512": {kind: kindRSA},
	"PS256": {kind: kindRSA},
	"PS384": {kind: kindRSA},
	"PS512": {kind: kindRSA},
	"ES256": {kind: kindEC, bits: 256},
	"ES384": {kind: kindEC, bits: 384},
	"ES512": {kind: kindEC, bits: 521},
	"EdDSA": {kind: kindEd},
}

// remoteAlgs are the algorithms a JWK Set is used with by default: not HMAC, whose "oct" keys a key set should not
// publish (anyone who can read it could sign).
var remoteAlgs = []string{
	"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
}

// minRSABits is the smallest RSA modulus accepted, from a PEM key or a JWK Set.
const minRSABits = 2048

// keyMatchesAlg reports whether key (a []byte, *rsa.PublicKey,
// *ecdsa.PublicKey or ed25519.PublicKey) can verify signatures of alg.
func keyMatchesAlg(key any, alg string) bool {
	info, ok := algs[alg]
	if !ok {
		return false
	}
	switch info.kind {
	case kindHMAC:
		_, ok := key.([]byte)
		return ok
	case kindRSA:
		_, ok := key.(*rsa.PublicKey)
		return ok
	case kindEC:
		k, ok := key.(*ecdsa.PublicKey)
		return ok && k.Curve != nil && k.Curve.Params().BitSize == info.bits
	case kindEd:
		_, ok := key.(ed25519.PublicKey)
		return ok
	}
	return false
}

func describeKey(key any) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", key)
}
