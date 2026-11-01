// Package urlpattern implements the WHATWG URL Pattern Living Standard
// (https://urlpattern.spec.whatwg.org/) for use as a URL matcher, such as the
// topic selectors of the Mercure protocol (draft-dunglas-mercure §4.2).
//
// Matching runs in time linear in the input: component regular expressions are
// translated from ECMAScript ("v" flag) syntax to RE2 and executed by Go's
// regexp package. Constructs RE2 cannot express (backreferences, lookahead,
// lookbehind, regexp modifiers) are rejected with ErrInvalidPattern.
//
// URL parsing follows the WHATWG URL Standard (including IDNA host
// processing), not net/url.
package urlpattern

import (
	"errors"
	"fmt"
	"strconv"
)

// Limits. Patterns and inputs beyond them are rejected (Compile) or never
// match (Test, Exec), keeping compile time and memory bounded.
const (
	// MaxPatternLength is the maximum length in bytes of a pattern string,
	// of a base URL, and of each component of an [Init].
	MaxPatternLength = 4096
	// MaxParts is the maximum number of parts in one component pattern.
	MaxParts = 256
	// MaxInputLength is the maximum length in bytes of a URL to be matched (and
	// of a base URL). Longer inputs never match; together with the size bound on
	// compiled expressions it bounds the worst-case cost of one match.
	MaxInputLength = 8192
)

var (
	// ErrInvalidPattern is returned (wrapped) when a pattern cannot be compiled.
	ErrInvalidPattern = errors.New("urlpattern: invalid pattern")
	// ErrTooComplex is returned (wrapped) when a pattern exceeds a limit.
	ErrTooComplex = errors.New("urlpattern: pattern too long or complex")
)

func invalid(err error) error {
	if err == nil || errors.Is(err, ErrTooComplex) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrInvalidPattern, err)
}

// Options configure compilation.
type Options struct {
	// IgnoreCase makes all matching except host case-insensitive. The
	// Mercure matcher never enables it.
	IgnoreCase bool
}

// Pattern is a compiled URL pattern. It is safe for concurrent use.
type Pattern struct {
	protocol, username, password, hostname, port, pathname, search, hash *component
	hasRegexpGroups                                                      bool
}

// ComponentResult is the match result for one URL component. Groups holds the
// matched group values by name; a group that did not participate in the match
// (undefined in JavaScript) is absent from the map.
type ComponentResult struct {
	Input  string
	Groups map[string]string
}

// Result is the result of a successful [Pattern.Exec].
type Result struct {
	Protocol, Username, Password, Hostname, Port, Pathname, Search, Hash ComponentResult
}

// Compile parses a constructor string (like new URLPattern(input, baseURL))
// and compiles it. A relative pattern is resolved against baseURL; with no
// base ("") a relative pattern is an error.
func Compile(pattern, baseURL string) (*Pattern, error) {
	return CompileWithOptions(pattern, baseURL, Options{})
}

// CompileWithOptions is [Compile] with options.
func CompileWithOptions(pattern, baseURL string, opts Options) (*Pattern, error) {
	if len(pattern) > MaxPatternLength || len(baseURL) > MaxPatternLength {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrTooComplex, MaxPatternLength)
	}
	init, err := parseConstructorString(pattern)
	if err != nil {
		return nil, invalid(err)
	}
	if baseURL == "" && init.Protocol == nil {
		return nil, fmt.Errorf("%w: relative pattern without base URL", ErrInvalidPattern)
	}
	// Deviation from the standard: a pattern that carries its own protocol is
	// absolute, so the base URL is not applied to it. (The standard would still
	// resolve a relative-looking opaque pathname such as "urn\\:uuid\\:*"
	// against the base's directory.)
	if baseURL != "" && init.Protocol == nil {
		init.BaseURL = &baseURL
	}
	return create(init, opts)
}

// CompileInit compiles the dictionary form of a pattern (new
// URLPattern({...})). Per the standard, baseURL must be empty: a base is
// given through init.BaseURL.
func CompileInit(init Init, baseURL string) (*Pattern, error) {
	return CompileInitWithOptions(init, baseURL, Options{})
}

// CompileInitWithOptions is [CompileInit] with options.
func CompileInitWithOptions(init Init, baseURL string, opts Options) (*Pattern, error) {
	if baseURL != "" {
		return nil, fmt.Errorf("%w: base URL argument with an init dictionary", ErrInvalidPattern)
	}
	for _, f := range []*string{init.Protocol, init.Username, init.Password, init.Hostname, init.Port,
		init.Pathname, init.Search, init.Hash, init.BaseURL} {
		if f != nil && len(*f) > MaxPatternLength {
			return nil, fmt.Errorf("%w: longer than %d bytes", ErrTooComplex, MaxPatternLength)
		}
	}
	return create(init, opts)
}

// create implements "create a URL pattern" from an init dictionary.
func create(init Init, opts Options) (*Pattern, error) {
	pi, err := processInit(init, true, Init{})
	if err != nil {
		return nil, invalid(err)
	}
	for _, f := range []**string{&pi.Protocol, &pi.Username, &pi.Password, &pi.Hostname, &pi.Port,
		&pi.Pathname, &pi.Search, &pi.Hash} {
		if *f == nil {
			*f = S("*")
		}
	}
	if dp := defaultPort(*pi.Protocol); dp >= 0 && *pi.Port == itoa(dp) {
		pi.Port = S("")
	}
	p := &Pattern{}
	co := defaultOptions
	co.ignoreCase = opts.IgnoreCase
	ho := hostnameOptions
	po := pathnameOptions
	po.ignoreCase = opts.IgnoreCase
	if p.protocol, err = compileComponent(*pi.Protocol, canonProtocol, defaultOptions); err != nil {
		return nil, invalid(err)
	}
	if p.username, err = compileComponent(*pi.Username, canonUsername, defaultOptions); err != nil {
		return nil, invalid(err)
	}
	if p.password, err = compileComponent(*pi.Password, canonPassword, defaultOptions); err != nil {
		return nil, invalid(err)
	}
	if isIPv6HostnamePattern(*pi.Hostname) {
		p.hostname, err = compileComponent(*pi.Hostname, canonIPv6Hostname, ho)
	} else {
		p.hostname, err = compileComponent(*pi.Hostname, canonHostname, ho)
	}
	if err != nil {
		return nil, invalid(err)
	}
	if p.port, err = compileComponent(*pi.Port, canonPort, defaultOptions); err != nil {
		return nil, invalid(err)
	}
	if p.protocol.matchesSpecialScheme() {
		p.pathname, err = compileComponent(*pi.Pathname, canonPathname, po)
	} else {
		p.pathname, err = compileComponent(*pi.Pathname, canonOpaquePathname, co)
	}
	if err != nil {
		return nil, invalid(err)
	}
	if p.search, err = compileComponent(*pi.Search, canonSearch, co); err != nil {
		return nil, invalid(err)
	}
	if p.hash, err = compileComponent(*pi.Hash, canonHash, co); err != nil {
		return nil, invalid(err)
	}
	for _, c := range p.components() {
		if c.hasRegexpGroups {
			p.hasRegexpGroups = true
		}
	}
	return p, nil
}

func (p *Pattern) components() [8]*component {
	return [8]*component{p.protocol, p.username, p.password, p.hostname, p.port, p.pathname, p.search, p.hash}
}

// isIPv6HostnamePattern implements "hostname pattern is an IPv6 address".
func isIPv6HostnamePattern(s string) bool {
	if len(s) < 2 {
		return false
	}
	switch s[0] {
	case '[':
		return true
	case '{', '\\':
		return s[1] == '['
	}
	return false
}

// Protocol returns the normalised protocol pattern string.
func (p *Pattern) Protocol() string { return p.protocol.pattern }

// Username returns the normalised username pattern string.
func (p *Pattern) Username() string { return p.username.pattern }

// Password returns the normalised password pattern string.
func (p *Pattern) Password() string { return p.password.pattern }

// Hostname returns the normalised hostname pattern string.
func (p *Pattern) Hostname() string { return p.hostname.pattern }

// Port returns the normalised port pattern string.
func (p *Pattern) Port() string { return p.port.pattern }

// Pathname returns the normalised pathname pattern string.
func (p *Pattern) Pathname() string { return p.pathname.pattern }

// Search returns the normalised search pattern string.
func (p *Pattern) Search() string { return p.search.pattern }

// Hash returns the normalised hash pattern string.
func (p *Pattern) Hash() string { return p.hash.pattern }

// HasRegexpGroups reports whether any component uses a custom regexp group.
func (p *Pattern) HasRegexpGroups() bool { return p.hasRegexpGroups }

// urlParts are the URL component strings a pattern is matched against.
type urlParts struct {
	protocol, username, password, hostname, port, pathname, search, hash string
}

func partsOf(u *urlRecord) urlParts {
	v := urlParts{protocol: u.scheme, username: u.username, password: u.password, pathname: u.pathString()}
	if u.hasHost {
		v.hostname = u.host
	}
	if u.port >= 0 {
		v.port = strconv.Itoa(u.port)
	}
	if u.hasQuery {
		v.search = u.query
	}
	if u.hasFrag {
		v.hash = u.frag
	}
	return v
}

// parseInput parses input against the optional parsed base.
func parseInput(input string, base *urlRecord) (urlParts, bool) {
	if len(input) > MaxInputLength {
		return urlParts{}, false
	}
	u, ok := parseURL(input, base)
	if !ok {
		return urlParts{}, false
	}
	return partsOf(u), true
}

// parseBase parses a base URL string; "" means no base.
func parseBase(baseURL string) (*urlRecord, bool) {
	if baseURL == "" {
		return nil, true
	}
	if len(baseURL) > MaxInputLength {
		return nil, false
	}
	return parseURL(baseURL, nil)
}

func (p *Pattern) testParts(v *urlParts) bool {
	return p.protocol.match(v.protocol) && p.hostname.match(v.hostname) && p.port.match(v.port) &&
		p.pathname.match(v.pathname) && p.search.match(v.search) && p.hash.match(v.hash) &&
		p.username.match(v.username) && p.password.match(v.password)
}

func (p *Pattern) execParts(v *urlParts) *Result {
	var r Result
	var ok bool
	for _, e := range [...]struct {
		c   *component
		in  string
		out *ComponentResult
	}{
		{p.protocol, v.protocol, &r.Protocol}, {p.username, v.username, &r.Username},
		{p.password, v.password, &r.Password}, {p.hostname, v.hostname, &r.Hostname},
		{p.port, v.port, &r.Port}, {p.pathname, v.pathname, &r.Pathname},
		{p.search, v.search, &r.Search}, {p.hash, v.hash, &r.Hash},
	} {
		e.out.Input = e.in
		if e.out.Groups, ok = e.c.exec(e.in); !ok {
			return nil
		}
	}
	return &r
}

// Test reports whether input, a URL string resolved against baseURL when
// relative ("" = no base), matches the pattern. An unparsable input or base
// never matches.
func (p *Pattern) Test(input, baseURL string) bool {
	base, ok := parseBase(baseURL)
	if !ok {
		return false
	}
	return p.testWith(input, base)
}

func (p *Pattern) testWith(input string, base *urlRecord) bool {
	v, ok := parseInput(input, base)
	return ok && p.testParts(&v)
}

// Exec is like [Pattern.Test] but returns the per-component match groups, or
// nil if there is no match.
func (p *Pattern) Exec(input, baseURL string) *Result {
	base, ok := parseBase(baseURL)
	if !ok {
		return nil
	}
	v, ok := parseInput(input, base)
	if !ok {
		return nil
	}
	return p.execParts(&v)
}

// initParts processes an init dictionary given as a match input.
func initParts(init Init) (urlParts, bool) {
	for _, f := range []*string{init.Protocol, init.Username, init.Password, init.Hostname, init.Port,
		init.Pathname, init.Search, init.Hash, init.BaseURL} {
		if f != nil && len(*f) > MaxInputLength {
			return urlParts{}, false
		}
	}
	r, err := processInit(init, false, Init{Protocol: S(""), Username: S(""), Password: S(""),
		Hostname: S(""), Port: S(""), Pathname: S(""), Search: S(""), Hash: S("")})
	if err != nil {
		return urlParts{}, false
	}
	return urlParts{*r.Protocol, *r.Username, *r.Password, *r.Hostname, *r.Port, *r.Pathname, *r.Search, *r.Hash}, true
}

// TestInit is [Pattern.Test] for an input given as an init dictionary.
func (p *Pattern) TestInit(input Init) bool {
	v, ok := initParts(input)
	return ok && p.testParts(&v)
}

// ExecInit is [Pattern.Exec] for an input given as an init dictionary.
func (p *Pattern) ExecInit(input Init) *Result {
	v, ok := initParts(input)
	if !ok {
		return nil
	}
	return p.execParts(&v)
}
