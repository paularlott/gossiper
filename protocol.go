package gossiper

import (
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/gossiper/topic"
)

// Protocol selects the revisions of the Mercure protocol a hub accepts.
type Protocol int

const (
	// ProtocolBoth accepts both revisions at once: draft-07 tokens, topic selectors and parameters, and Mercure
	// 1.0 (draft-08) access tokens and matchers. Each request, token and subscription is read in its own revision.
	ProtocolBoth Protocol = iota
	// ProtocolLegacy accepts only draft-07: the mercure claim, the topic parameter, the authorization query
	// parameter and the mercureAuthorization cookie.
	ProtocolLegacy
	// ProtocolModern accepts only Mercure 1.0 (draft-08): at+jwt access tokens with authorization_details, the
	// match parameters, last_event_id and the __Secure-mercure_access_token cookie.
	ProtocolModern
)

// ParseProtocol parses "both", "legacy" (or "07") and "modern" (or "1.0", "08").
func ParseProtocol(s string) (Protocol, error) {
	switch strings.ToLower(s) {
	case "", "both":
		return ProtocolBoth, nil
	case "legacy", "07", "draft-07":
		return ProtocolLegacy, nil
	case "modern", "1.0", "1", "08", "draft-08":
		return ProtocolModern, nil
	}
	return 0, errors.New("gossiper: protocol must be both, legacy or modern")
}

func (p Protocol) legacy() bool { return p != ProtocolModern }
func (p Protocol) modern() bool { return p != ProtocolLegacy }

// matchKind is how a topic matcher is read.
type matchKind uint8

const (
	kindSelector   matchKind = iota // draft-07 topic selector: "*", the exact topic, or an RFC 6570 URI template
	kindExact                       // Mercure 1.0 exact matcher
	kindURLPattern                  // Mercure 1.0 URL pattern
)

// String is the matcher type's name in Mercure 1.0 ("" for a draft-07 selector, which has none).
func (k matchKind) String() string {
	switch k {
	case kindExact:
		return "exact"
	case kindURLPattern:
		return "urlpattern"
	}
	return ""
}

func kindOf(matchType string) (matchKind, bool) {
	switch matchType {
	case "", "exact":
		return kindExact, true
	case "urlpattern":
		return kindURLPattern, true
	}
	return 0, false
}

// matcher is one topic matcher: of a subscription, or of a token's grant.
type matcher struct {
	kind    matchKind
	pattern string
}

// isPatterned reports whether the matcher can match more than one topic (it cannot be indexed by topic).
func (m matcher) isPatterned() bool {
	switch m.kind {
	case kindSelector:
		return m.pattern == "*" || topic.IsTemplate(m.pattern)
	case kindURLPattern:
		return true
	}
	return m.pattern == "*"
}

// matches reports whether topic matches m. "*" matches every topic, whatever the kind.
func (h *Hub) matches(m matcher, topic string) bool {
	if m.pattern == "*" {
		return true
	}
	switch m.kind {
	case kindSelector:
		return h.matcher.Match(topic, m.pattern)
	case kindURLPattern:
		return h.urls.Match(topic, m.pattern)
	}
	return topic == m.pattern
}

// matchAny reports whether one of topics matches one of ms.
func (h *Hub) matchAny(ms []matcher, topics []string) bool {
	for _, m := range ms {
		for _, t := range topics {
			if h.matches(m, t) {
				return true
			}
		}
	}
	return false
}

// grants is what a verified token allows, in either revision.
type grants struct {
	modern    bool
	publish   []matcher
	subscribe []matcher
	payload   json.RawMessage // draft-07: mercure.payload, for every subscription
	details   []auth.Detail   // Mercure 1.0: the subscribe details, for payload selection
	expiry    time.Time       // zero: none
}

func grantsFromClaims(c *auth.Claims) *grants {
	g := &grants{payload: c.Payload, expiry: c.Expiry}
	if c.HasPublish {
		for _, s := range c.Publish {
			g.publish = append(g.publish, matcher{kindSelector, s})
		}
	}
	if c.HasSubscribe {
		for _, s := range c.Subscribe {
			g.subscribe = append(g.subscribe, matcher{kindSelector, s})
		}
	}
	return g
}

func grantsFromAccess(c *auth.AccessClaims) *grants {
	g := &grants{modern: true, expiry: c.Expiry}
	for _, d := range c.Details {
		var pub, sub bool
		for _, a := range d.Actions {
			pub = pub || a == "publish"
			sub = sub || a == "subscribe"
		}
		for _, t := range d.Topics {
			k, _ := kindOf(t.MatchType) // the verifier accepted only known types
			if pub {
				g.publish = append(g.publish, matcher{k, t.Match})
			}
			if sub {
				g.subscribe = append(g.subscribe, matcher{k, t.Match})
			}
		}
		if sub {
			g.details = append(g.details, d)
		}
	}
	return g
}

// payloadFor returns the payload a subscription with matcher m carries in subscription events and the
// subscriptions API: draft-07, the token's mercure.payload; Mercure 1.0, the payload of the first subscribe
// detail one of whose topics matches m's own pattern read as a topic.
func (h *Hub) payloadFor(g *grants, m matcher) json.RawMessage {
	if g == nil {
		return nil
	}
	if !g.modern {
		return g.payload
	}
	for _, d := range g.details {
		for _, t := range d.Topics {
			k, _ := kindOf(t.MatchType)
			if h.matches(matcher{k, t.Match}, m.pattern) {
				return d.Payload
			}
		}
	}
	return nil
}

// validText reports whether s may be a topic, matcher, ID or event type: valid UTF-8 with no control characters
// (C0, DEL, C1) and no format characters (general category Cf), which are invisible and allow spoofing.
func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// escapeStrayPercent escapes each "%" of s that does not start a percent-encoded octet.
func escapeStrayPercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && !(i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2])) {
			b.WriteString("%25")
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// errBadMatch is a subscription request's malformed matcher parameter.
type errBadMatch string

func (e errBadMatch) Error() string { return string(e) }

// subscriptionParams reads a subscription request's matchers and cursor from its query component and, for a
// request with a form body (QUERY), its body: the union of both, the query's cursor first. The matchers are counted
// against MaxTopicSelectors, and the ones that match by pattern against MaxPatternSelectors, before any is
// compiled.
func (h *Hub) subscriptionParams(query, body url.Values) (ms []matcher, cursor string, err error) {
	var total, patterns int
	for _, vals := range []url.Values{query, body} {
		for name, values := range vals {
			isMatch := len(name) >= 5 && strings.EqualFold(name[:5], "match")
			if !(name == "topic" && h.cfg.Protocol.legacy()) && !(isMatch && h.cfg.Protocol.modern()) {
				continue
			}
			total += len(values)
			for _, v := range values {
				if v != "*" && (name == "match_urlpattern" || name == "topic" && strings.Contains(v, "{")) {
					patterns++
				}
			}
		}
	}
	if total > h.cfg.MaxTopicSelectors || patterns > h.cfg.MaxPatternSelectors {
		return nil, "", errBadMatch("too many topic matchers")
	}
	add := func(vals url.Values) error {
		for name, values := range vals {
			var k matchKind
			switch {
			case name == "topic":
				if !h.cfg.Protocol.legacy() {
					continue // not a parameter of Mercure 1.0
				}
				k = kindSelector
			case len(name) >= 5 && strings.EqualFold(name[:5], "match"):
				if !h.cfg.Protocol.modern() {
					continue
				}
				var ok bool
				switch name {
				case "match", "match_exact":
					k, ok = kindExact, true
				case "match_urlpattern":
					k, ok = kindURLPattern, true
				}
				if !ok {
					return errBadMatch(`unsupported matcher parameter "` + name + `"`)
				}
			default:
				continue
			}
			for _, v := range values {
				if v == "" || len(v) > MaxTopicLength || !validText(v) {
					return errBadMatch(`invalid "` + name + `" parameter`)
				}
				if k == kindURLPattern && v != "*" {
					if err := h.urls.Valid(v); err != nil {
						return errBadMatch(`invalid URL pattern in "` + name + `"`)
					}
				}
				ms = append(ms, matcher{k, v})
			}
		}
		return nil
	}
	if err := add(query); err != nil {
		return nil, "", err
	}
	if err := add(body); err != nil {
		return nil, "", err
	}
	for _, vals := range []url.Values{query, body} {
		if cursor != "" {
			break
		}
		if h.cfg.Protocol.modern() {
			cursor = vals.Get("last_event_id")
		}
		if cursor == "" && h.cfg.Protocol.legacy() {
			if cursor = vals.Get("lastEventID"); cursor == "" {
				cursor = vals.Get("Last-Event-ID")
			}
		}
	}
	return ms, cursor, nil
}

// dedupeMatchers returns ms without repeats, in order.
func dedupeMatchers(ms []matcher) []matcher {
	if len(ms) < 2 {
		return ms
	}
	seen := make(map[matcher]struct{}, len(ms))
	out := ms[:0:0]
	for _, m := range ms {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	return out
}

// validate checks an update a publisher supplies: its fields, and that none of its topics addresses the hub's
// reserved namespace.
func (h *Hub) validate(u *Update) error {
	if err := u.validate(); err != nil {
		return err
	}
	if u.Replicas < 0 || u.Replicas > MaxReplicas {
		return ErrInvalidReplicas
	}
	for _, t := range u.Topics {
		if h.reserved(t) {
			return ErrReservedTopic
		}
	}
	return nil
}

// reserved reports whether topic, resolved against the hub URL, names the hub's own path or a path under it
// (whatever its scheme and host): those topics are the hub's own (subscription events), and a publisher must not
// forge them. The path is compared decoded and with its dot segments removed, so /.well-known/%6Dercure/... and
// /.well-known/mercure/../mercure/... are caught; a backslash counts as a slash, a stray "%" (not starting an
// escape) as itself, and leading and trailing spaces (the C0 controls and spaces URL parsers trim) are dropped, as
// browsers and the URL Pattern matcher read them: " /.well-known/mercure/..." names the hub's path for a
// match_urlpattern subscriber. A topic that is still not a URL reference names no hub path.
func (h *Hub) reserved(topic string) bool {
	s := strings.ReplaceAll(strings.TrimFunc(topic, func(r rune) bool { return r <= 0x20 }), `\`, "/")
	ref, err := url.Parse(s)
	if err != nil {
		if ref, err = url.Parse(escapeStrayPercent(s)); err != nil {
			return false
		}
	}
	p := h.base.ResolveReference(ref).Path
	if p == "" {
		return false
	}
	p = path.Clean(p)
	if strings.HasPrefix(p, hubPath+"/") {
		return true
	}
	// The hub URL itself too, but not for a name that is only a fragment or a query ("#general", "?x"), which merely
	// resolves to it: nothing of the hub's lives there, and such names are common.
	return p == hubPath && (ref.Scheme != "" || ref.Host != "" || ref.Path != "")
}
