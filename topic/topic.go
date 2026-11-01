// Package topic implements Mercure topic selector matching.
//
// A topic selector is any string. It matches a topic if
//
//  1. the selector is "*", or
//  2. the selector and the topic are identical, or
//  3. the selector is a valid URI Template (RFC 6570) and the topic is the
//     expansion of that template for some assignment of variables, or
//  4. never otherwise.
//
// Rule 3 is implemented by compiling the template to an anchored RE2 regular
// expression, so matching runs in time linear in the length of the topic
// regardless of the template.
//
// # Template semantics
//
// All of RFC 6570 levels 1 to 4 is supported: the operators none, "+", "#",
// ".", "/", ";", "?" and "&"; several variables per expression; prefix (":n")
// and explode ("*") modifiers. A variable may be undefined, in which case it
// contributes nothing to the expansion, and an expression whose variables are
// all undefined expands to the empty string (including its operator prefix).
// A variable may take a string, list or associative array value, whichever the
// modifier allows.
//
// Values are matched against the character set RFC 6570 expansion would
// produce. For the operators none, ".", "/", ";", "?" and "&" a value
// consists of unreserved characters and pct-encoded triplets only, so a
// reserved character such as "/" ends the value. For "+" and "#" a value may
// also contain reserved characters. Literal parts of the template match
// themselves exactly, byte for byte; non-ASCII characters in a literal are
// literal (IRI templates).
//
// A string that is not a valid template, or that exceeds the limits below,
// is not treated as a template and matches by rules 1 and 2 only.
//
// # Limits
//
// Templates longer than 4096 bytes, with more than 64 expressions or 128
// variable specifiers, or whose prefix modifiers sum to more than 512 are not
// compiled. Prefix modifiers count characters (UTF-8 code points of the
// unencoded value), as in RFC 6570.
package topic

import (
	"strings"
)

const (
	// defaultTemplateCache is the template cache size used when the result
	// cache is disabled.
	defaultTemplateCache = 256
	// templateCostBudget bounds the estimated total size, in compiled
	// instructions, of the cached templates (roughly 40 MB).
	templateCostBudget = 1 << 20
	// maxResultKeyLen is the maximum len(selector)+len(topic) for which a
	// match result is cached. It stops large attacker-supplied strings from
	// occupying the result cache.
	maxResultKeyLen = 512
)

// Matcher matches topics against topic selectors. Safe for concurrent use.
// A Matcher must be created with NewMatcher.
type Matcher struct {
	// templates caches compiled templates by selector; a nil *tmpl records
	// that the selector is not a usable template.
	templates *cache[string, *tmpl]
	// results caches match results; nil when disabled.
	results *cache[resultKey, bool]
}

type resultKey struct {
	selector, topic string
}

// NewMatcher returns a matcher caching up to cacheSize compiled templates and
// cacheSize (selector, topic) match results; cacheSize <= 0 disables the
// result cache (templates are still cached with a small default bound).
//
// Caches are bounded: they never hold more than max(cacheSize, 2) entries
// each, and the compiled templates are additionally bounded by total size.
// Selectors longer than the template limit are never cached, and results are
// only cached for short selector and topic pairs.
func NewMatcher(cacheSize int) *Matcher {
	m := &Matcher{}
	if cacheSize > 0 {
		m.templates = newCache[string, *tmpl](cacheSize, templateCostBudget)
		m.results = newCache[resultKey, bool](cacheSize, 0)
	} else {
		m.templates = newCache[string, *tmpl](defaultTemplateCache, templateCostBudget)
	}
	return m
}

// Match reports whether topic matches selector.
func (m *Matcher) Match(topic, selector string) bool {
	if selector == "*" || selector == topic {
		return true
	}
	if !mayBeTemplate(selector) {
		return false
	}
	var key resultKey
	cacheable := m.results != nil && len(selector)+len(topic) <= maxResultKeyLen
	if cacheable {
		key = resultKey{selector, topic}
		if r, ok := m.results.get(key); ok {
			return r
		}
	}
	t := m.template(selector)
	r := t != nil && t.re.MatchString(topic)
	if cacheable {
		// Clone so the cache does not pin larger buffers the strings may
		// be substrings of.
		m.results.set(resultKey{strings.Clone(selector), strings.Clone(topic)}, r, 1)
	}
	return r
}

// MatchAny reports whether any of topics matches any of selectors.
func (m *Matcher) MatchAny(topics, selectors []string) bool {
	if len(topics) == 0 {
		return false
	}
	for _, sel := range selectors {
		if sel == "*" {
			return true
		}
		var t *tmpl
		if mayBeTemplate(sel) {
			t = m.template(sel)
		}
		for _, topic := range topics {
			if topic == sel || t != nil && t.re.MatchString(topic) {
				return true
			}
		}
	}
	return false
}

// IsTemplate reports whether s is a valid URI template containing at least one
// expression. It checks syntax and the template length, expression and
// variable limits; a Matcher additionally declines templates that are
// syntactically valid but too costly to compile (see the package
// documentation). IsTemplate is therefore true for every selector a Matcher
// treats as a template, which makes it safe for deciding whether a selector
// can only ever match by equality.
func IsTemplate(s string) bool {
	if !mayBeTemplate(s) {
		return false
	}
	_, ok := parseTemplate(s)
	return ok
}

// mayBeTemplate is a cheap pre-check: a template contains "{" and is within
// the length limit.
func mayBeTemplate(s string) bool {
	return len(s) <= maxTemplateLen && strings.IndexByte(s, '{') >= 0
}

// template returns the compiled form of selector, or nil if selector is not
// a usable template. The caller has checked mayBeTemplate.
func (m *Matcher) template(selector string) *tmpl {
	if t, ok := m.templates.get(selector); ok {
		return t
	}
	t := compileTemplate(selector)
	cost := 1 + len(selector)/16
	if t != nil {
		cost = t.cost
	}
	m.templates.set(strings.Clone(selector), t, cost)
	return t
}
