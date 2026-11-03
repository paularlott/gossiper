package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims is the information extracted from a verified draft-08 access
// token.
type AccessClaims struct {
	Issuer   string
	Subject  string // "sub"; identifies the subscriber
	ClientID string
	JTI      string
	Audience []string  // all of "aud"; it contains the configured resource identifier
	IssuedAt time.Time // zero when absent
	Expiry   time.Time // always set
	Details  []Detail  // Mercure authorization details only, in token order
	// Scope is the "scope" claim (space-separated); RawDetails the whole authorization_details claim, details of
	// every type, for an API that defines its own (nil when absent).
	Scope      string
	RawDetails json.RawMessage
}

// Issuer is a trusted token issuer. Exactly one of Key, JWKSURL and Discover
// must be set; only the keys so bound to Issuer verify its tokens.
type Issuer struct {
	// Issuer is the identifier the token's iss must equal exactly.
	Issuer string
	// Key is an HMAC secret (the raw bytes of the string) or a PEM encoded
	// public key or certificate (RSA, ECDSA or Ed25519).
	Key string
	// Algorithms is the allowlist of algorithms accepted from this issuer. It
	// defaults to the algorithms usable with Key (EdDSA, ES*, RS*, PS* for a
	// public key, HS* for a secret) or, for JWKSURL and Discover, to every
	// asymmetric algorithm: add HS* explicitly to accept symmetric keys from a
	// key set. "none" and unknown algorithms are refused.
	Algorithms []string
	// JWKSURL is the issuer's JWK Set URL.
	JWKSURL string
	// Discover finds the JWK Set URL through the issuer's metadata (RFC 8414,
	// then OpenID Connect discovery); the metadata's issuer must equal Issuer.
	Discover bool
}

// AccessConfig describes how draft-08 access tokens are verified.
type AccessConfig struct {
	// Issuers are the trusted issuers (at least one).
	Issuers []Issuer
	// Audience is the hub's resource identifier; the token's aud must contain it. Empty: the caller gives it with
	// every token (VerifyAudience), for a hub whose identifier is the URL each client contacted.
	Audience string
	// Leeway is the clock skew tolerated when checking exp and nbf. Default 0.
	Leeway time.Duration
	// JWKSRefresh is the background refresh interval. Default 10 minutes.
	JWKSRefresh time.Duration
	// HTTPClient fetches metadata and JWK Sets. Default: a client with a 10s
	// timeout. Redirects off https are refused.
	HTTPClient *http.Client
	// AllowInsecureHTTP permits http:// JWKS and issuer URLs, and https ones whose certificate does not verify (a
	// self-signed one), with the default HTTPClient: for tests and development. Otherwise they are refused as an
	// SSRF/MITM hazard.
	AllowInsecureHTTP bool
	// MatcherTypes are the supported match_type values. Default exact, urlpattern.
	MatcherTypes []string
	// ValidateMatcher, if set, is called for every non-wildcard topic matcher
	// (match_type already defaulted); an error invalidates the token.
	ValidateMatcher func(matchType, pattern string) error
	// MaxDetails, MaxTopics (per detail) and MaxPatternLength (bytes) bound the
	// Mercure authorization details. Defaults 64, 256 and 4096.
	MaxDetails, MaxTopics, MaxPatternLength int
	// MaxTokenSize is the longest token, in bytes, that is parsed. Default
	// [MaxTokenSize].
	MaxTokenSize int
	// SkipMercureDetails leaves the Mercure authorization details unread (AccessClaims.Details stays empty), for an
	// API that is not a hub and reads its own type from AccessClaims.RawDetails.
	SkipMercureDetails bool
}

// defaultAccessAlgs is the default allowlist.
var defaultAccessAlgs = []string{
	"EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512", "HS256", "HS384", "HS512",
}

type accessIssuer struct {
	id     string
	algs   map[string]struct{}
	static any         // []byte or public key; nil with jwks
	jwks   *jwksSource // nil with a static key
	target *jwksTarget // how to create jwks; consumed by start
	opts   internalOpts
}

// AccessVerifier verifies draft-08 access tokens (RFC 9068 JWTs carrying
// RFC 9396 authorization_details). It is safe for concurrent use.
type AccessVerifier struct {
	issuers  map[string]*accessIssuer
	audience string
	leeway   time.Duration
	maxToken int
	parser   *jwt.Parser
	details  detailParser
	skip     bool // SkipMercureDetails
	now      func() time.Time
}

// NewAccessVerifier validates cfg and returns an AccessVerifier. The first
// fetch of every remote key set is attempted before returning (in parallel,
// each bounded by a 10s timeout); if one fails the verifier is still returned
// and rejects that issuer's tokens until its keys are loaded (see Ready).
// Callers must call Close when finished.
func NewAccessVerifier(cfg AccessConfig) (*AccessVerifier, error) {
	return newAccessVerifier(cfg, internalOpts{})
}

func newAccessVerifier(cfg AccessConfig, o internalOpts) (*AccessVerifier, error) {
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("auth: no Issuers")
	}
	if cfg.Leeway < 0 {
		return nil, errors.New("auth: negative Leeway")
	}
	if cfg.MaxDetails < 0 || cfg.MaxTopics < 0 || cfg.MaxPatternLength < 0 || cfg.MaxTokenSize < 0 {
		return nil, errors.New("auth: negative limit")
	}
	v := &AccessVerifier{
		issuers:  make(map[string]*accessIssuer, len(cfg.Issuers)),
		audience: cfg.Audience,
		leeway:   cfg.Leeway,
		skip:     cfg.SkipMercureDetails,
		maxToken: orDefault(cfg.MaxTokenSize, MaxTokenSize),
		now:      o.now,
		details: detailParser{
			validate:   cfg.ValidateMatcher,
			maxDetails: orDefault(cfg.MaxDetails, DefaultMaxDetails),
			maxTopics:  orDefault(cfg.MaxTopics, DefaultMaxTopics),
			maxPattern: orDefault(cfg.MaxPatternLength, DefaultMaxPatternLength),
		},
	}
	if v.now == nil {
		v.now = time.Now
	}

	types := cfg.MatcherTypes
	if len(types) == 0 {
		types = []string{"exact", "urlpattern"}
	}
	v.details.types = make(map[string]struct{}, len(types))
	for _, t := range types {
		if t == "" {
			return nil, errors.New("auth: empty matcher type")
		}
		v.details.types[t] = struct{}{}
	}

	client := secureClient(cfg.HTTPClient, cfg.AllowInsecureHTTP)
	union := map[string]struct{}{}
	for _, is := range cfg.Issuers {
		if _, dup := v.issuers[is.Issuer]; dup {
			return nil, fmt.Errorf("auth: duplicate issuer %q", is.Issuer)
		}
		ai, err := buildIssuer(cfg, is, client, o)
		if err != nil {
			return nil, err
		}
		v.issuers[is.Issuer] = ai
		for a := range ai.algs {
			union[a] = struct{}{}
		}
	}
	v.start()

	all := make([]string, 0, len(union))
	for a := range union {
		all = append(all, a)
	}
	v.parser = jwt.NewParser(jwt.WithValidMethods(all), jwt.WithoutClaimsValidation())
	return v, nil
}

func orDefault(n, def int) int {
	if n == 0 {
		return def
	}
	return n
}

// buildIssuer validates one issuer. Remote sources are only described here
// (see start) so that all the initial fetches can run in parallel.
func buildIssuer(cfg AccessConfig, is Issuer, client *http.Client, o internalOpts) (*accessIssuer, error) {
	if is.Issuer == "" {
		return nil, errors.New("auth: empty issuer identifier")
	}
	n := 0
	for _, set := range []bool{is.Key != "", is.JWKSURL != "", is.Discover} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("auth: issuer %q: exactly one of Key, JWKSURL and Discover must be set", is.Issuer)
	}
	ai := &accessIssuer{id: is.Issuer}

	explicit := map[string]struct{}{}
	for _, a := range is.Algorithms {
		if _, ok := algs[a]; !ok {
			return nil, fmt.Errorf("auth: issuer %q: unsupported algorithm %q", is.Issuer, a)
		}
		explicit[a] = struct{}{}
	}

	switch {
	case is.Key != "":
		key, err := staticKey(is, explicit)
		if err != nil {
			return nil, fmt.Errorf("auth: issuer %q: %w", is.Issuer, err)
		}
		ai.static = key
		ai.algs = map[string]struct{}{}
		for _, a := range defaultAccessAlgs {
			if _, ok := explicit[a]; (len(explicit) == 0 || ok) && keyMatchesAlg(key, a) {
				ai.algs[a] = struct{}{}
			}
		}
		for a := range explicit {
			if _, ok := ai.algs[a]; !ok {
				return nil, fmt.Errorf("auth: issuer %q: %s key does not match algorithm %s", is.Issuer, describeKey(key), a)
			}
		}
	default:
		ai.algs = explicit
		if len(ai.algs) == 0 {
			for _, a := range defaultAccessAlgs {
				if algs[a].kind != kindHMAC {
					ai.algs[a] = struct{}{}
				}
			}
		}
		t := jwksTarget{client: client, refresh: cfg.JWKSRefresh}
		if is.JWKSURL != "" {
			if _, err := checkURL(is.JWKSURL, cfg.AllowInsecureHTTP); err != nil {
				return nil, fmt.Errorf("auth: issuer %q: JWKSURL: %w", is.Issuer, err)
			}
			t.url = is.JWKSURL
		} else {
			u, err := checkURL(is.Issuer, cfg.AllowInsecureHTTP)
			if err != nil || u.RawQuery != "" {
				return nil, fmt.Errorf("auth: issuer %q: Discover needs an https issuer URL without query", is.Issuer)
			}
			id, allow := is.Issuer, cfg.AllowInsecureHTTP
			t.discover = func(ctx context.Context) (string, error) {
				return discoverJWKSURI(ctx, client, id, allow)
			}
		}
		ai.target = &t
		ai.opts = o
	}
	return ai, nil
}

// staticKey parses is.Key: a PEM public key when explicit names no HMAC
// algorithm and the key looks like PEM, otherwise an HMAC secret.
func staticKey(is Issuer, explicit map[string]struct{}) (any, error) {
	hmacAlg, otherAlg := false, false
	for a := range explicit {
		if algs[a].kind == kindHMAC {
			hmacAlg = true
		} else {
			otherAlg = true
		}
	}
	switch {
	case hmacAlg && otherAlg:
		return nil, errors.New("algorithms mix HMAC and public-key algorithms")
	case hmacAlg && isPEM(is.Key):
		return nil, errPEMSecret("HMAC")
	case hmacAlg:
		return []byte(is.Key), nil
	case otherAlg || isPEM(is.Key):
		return parsePublicKeyPEM(is.Key)
	}
	return []byte(is.Key), nil
}

// start creates the remote key sources, fetching in parallel.
func (v *AccessVerifier) start() {
	var wg sync.WaitGroup
	for _, ai := range v.issuers {
		if ai.target == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ai.jwks = newJWKSSourceFor(*ai.target, ai.opts)
		}()
	}
	wg.Wait()
}

// Ready reports whether every issuer has keys to verify with: always true for
// a static key, and for a remote key set once it has been fetched.
func (v *AccessVerifier) Ready() bool {
	for _, ai := range v.issuers {
		if ai.jwks != nil && !ai.jwks.ready() {
			return false
		}
	}
	return true
}

// JWKSError returns the error of the most recent key set fetch that failed, of
// any issuer with a remote key set, or nil when the latest fetches succeeded.
func (v *AccessVerifier) JWKSError() error {
	for _, ai := range v.issuers {
		if ai.jwks != nil {
			if err := ai.jwks.lastError(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close stops the key refresh goroutines and waits for them and any in-flight
// fetch. It is safe to call more than once. Verify keeps working afterwards
// with the last key sets.
func (v *AccessVerifier) Close() {
	for _, ai := range v.issuers {
		if ai.jwks != nil {
			ai.jwks.close()
		}
	}
}

// accessTokenClaims is the raw JWT payload: only the exact claim names count.
type accessTokenClaims struct{ m map[string]json.RawMessage }

func (c *accessTokenClaims) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &c.m) }

func (c *accessTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (c *accessTokenClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (c *accessTokenClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (c *accessTokenClaims) GetIssuer() (string, error)                   { return "", nil }
func (c *accessTokenClaims) GetSubject() (string, error)                  { return "", nil }
func (c *accessTokenClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

// str reads an optional string claim; a present claim of another type is an error.
func (c *accessTokenClaims) str(name string) (string, error) {
	raw := c.m[name]
	if !present(raw) {
		return "", nil
	}
	s, ok := jsonString(raw)
	if !ok {
		return "", fmt.Errorf("%s is not a string", name)
	}
	return s, nil
}

// date reads an optional NumericDate claim.
func (c *accessTokenClaims) date(name string) (t time.Time, ok bool, err error) {
	raw := c.m[name]
	if !present(raw) {
		return t, false, nil
	}
	var f float64
	if c := raw[0]; (c < '0' || c > '9') && c != '-' || json.Unmarshal(raw, &f) != nil ||
		f < 0 || f > 253402300799 || math.IsNaN(f) {
		return t, false, fmt.Errorf("%s is not a valid date", name)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true, nil
}

// isAccessType reports whether a typ header value names the JWT access token
// media type: at+jwt, with or without application/, case-insensitively.
func isAccessType(typ string) bool {
	if len(typ) > len("application/") && strings.EqualFold(typ[:len("application/")], "application/") {
		typ = typ[len("application/"):]
	}
	return strings.EqualFold(typ, "at+jwt")
}

// Verify checks the signature and claims of a compact JWT access token and
// returns what it carries. Errors wrap exactly one of ErrMalformed (not a
// parseable compact JWS) or ErrInvalid (every other failure; the kind never
// says which check failed, the message is for logs only).
func (v *AccessVerifier) Verify(ctx context.Context, token string) (*AccessClaims, error) {
	return v.VerifyAudience(ctx, token, v.audience)
}

// VerifyAudience is Verify with the resource identifier the token's aud must contain given for this token; ""
// takes the configured one, and with none configured every token is refused.
func (v *AccessVerifier) VerifyAudience(ctx context.Context, token, audience string) (*AccessClaims, error) {
	if audience == "" {
		audience = v.audience
	}
	if audience == "" {
		return nil, fail(ErrInvalid, "no resource identifier to check the audience against")
	}
	if token == "" {
		return nil, fail(ErrMalformed, "empty token")
	}
	if len(token) > v.maxToken {
		return nil, fail(ErrMalformed, "token longer than %d bytes", v.maxToken)
	}

	var tc accessTokenClaims
	_, err := v.parser.ParseWithClaims(token, &tc, func(t *jwt.Token) (any, error) {
		return v.keyFor(ctx, t, &tc)
	})
	if err != nil {
		return nil, classify(err)
	}
	return v.claims(&tc, audience)
}

// keyFor is the jwt key function: it checks the header, picks the issuer from
// iss and returns only that issuer's key.
func (v *AccessVerifier) keyFor(ctx context.Context, t *jwt.Token, tc *accessTokenClaims) (any, error) {
	if _, ok := t.Header["crit"]; ok {
		return nil, &keyError{msg: "unsupported crit header"}
	}
	typ, _ := t.Header["typ"].(string)
	if !isAccessType(typ) {
		return nil, &keyError{msg: "typ is not at+jwt"}
	}
	iss, err := tc.str("iss")
	if err != nil || iss == "" {
		return nil, &keyError{msg: "missing or invalid iss"}
	}
	ai := v.issuers[iss]
	if ai == nil {
		return nil, &keyError{msg: "untrusted issuer"}
	}
	alg := t.Method.Alg()
	if _, ok := ai.algs[alg]; !ok {
		return nil, &keyError{msg: "algorithm " + alg + " not allowed for issuer"}
	}
	if ai.jwks != nil {
		return ai.jwks.keyFor(ctx, t)
	}
	return ai.static, nil
}

// claims validates the registered claims of a token whose signature has been
// verified and builds the result.
func (v *AccessVerifier) claims(tc *accessTokenClaims, aud string) (*AccessClaims, error) {
	bad := func(err error) (*AccessClaims, error) { return nil, fail(ErrInvalid, "%v", err) }
	out := &AccessClaims{}
	var err error

	exp, ok, err := tc.date("exp")
	if err != nil {
		return bad(err)
	}
	if !ok {
		return bad(errors.New("missing exp"))
	}
	now := v.now()
	if !now.Before(exp.Add(v.leeway)) {
		return nil, fail(ErrInvalid, "token expired")
	}
	out.Expiry = exp

	nbf, ok, err := tc.date("nbf")
	if err != nil {
		return bad(err)
	}
	if ok && now.Before(nbf.Add(-v.leeway)) {
		return nil, fail(ErrInvalid, "token not yet valid")
	}
	if out.IssuedAt, _, err = tc.date("iat"); err != nil {
		return bad(err)
	}

	if out.Issuer, err = tc.str("iss"); err != nil {
		return bad(err)
	}
	if out.Subject, err = tc.str("sub"); err != nil {
		return bad(err)
	}
	if out.ClientID, err = tc.str("client_id"); err != nil {
		return bad(err)
	}
	if out.JTI, err = tc.str("jti"); err != nil {
		return bad(err)
	}

	if out.Audience, err = audience(tc.m["aud"]); err != nil {
		return bad(err)
	}
	found := false
	for _, a := range out.Audience {
		if a == aud {
			found = true
			break
		}
	}
	if !found {
		return nil, fail(ErrInvalid, "audience does not include this resource")
	}

	if !v.skip {
		if out.Details, err = v.details.parse(tc.m["authorization_details"]); err != nil {
			return bad(err)
		}
	}
	if out.Scope, err = tc.str("scope"); err != nil {
		return bad(err)
	}
	if raw := tc.m["authorization_details"]; present(raw) {
		out.RawDetails = raw
	}
	return out, nil
}

// audience decodes aud: a string or an array of strings.
func audience(raw json.RawMessage) ([]string, error) {
	if !present(raw) {
		return nil, errors.New("missing aud")
	}
	if s, ok := jsonString(raw); ok {
		return []string{s}, nil
	}
	if firstNonSpace(raw) != '[' {
		return nil, errors.New("aud is not a string or array of strings")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, errors.New("aud is not a string or array of strings")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := jsonString(it)
		if !ok {
			return nil, errors.New("aud is not a string or array of strings")
		}
		out = append(out, s)
	}
	return out, nil
}

// IsAccessToken reports, without verifying anything, whether a compact JWT
// looks like a draft-08 access token: its typ header is at+jwt, or its payload
// has an authorization_details claim. The hub uses it to choose a verifier
// when both protocols are enabled. Tokens that do not parse are not.
func IsAccessToken(token string) bool {
	const maxLen = 1 << 20
	if len(token) > maxLen {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	var hdr map[string]json.RawMessage
	if !decodeSegment(parts[0], &hdr) {
		return false
	}
	if typ, ok := jsonString(hdr["typ"]); ok && isAccessType(typ) {
		return true
	}
	var claims map[string]json.RawMessage
	if !decodeSegment(parts[1], &claims) {
		return false
	}
	_, ok := claims["authorization_details"]
	return ok
}

func decodeSegment(seg string, v any) bool {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return false
	}
	return json.Unmarshal(bytes.TrimSpace(b), v) == nil
}
