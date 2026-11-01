package urlpattern

import (
	"fmt"
	"regexp"
	"strings"
)

type compKind uint8

const (
	compLiteral      compKind = iota // matches exactly one fixed string
	compFullWildcard                 // "*" / "(.*)": matches any input without line terminators
	compRegexp                       // everything else, via RE2
)

// component is a compiled URL pattern component.
type component struct {
	pattern         string // normalised pattern string
	kind            compKind
	literal         string
	wildName        string // group name of the sole group when kind == compFullWildcard
	re              *regexp.Regexp
	names           []string
	dropEmpty       []bool // per name: an empty capture means "undefined"
	hasRegexpGroups bool
}

// compileComponent implements "compile a component".
func compileComponent(input string, enc encodeFunc, o options) (*component, error) {
	parts, err := parsePatternString(input, o, enc)
	if err != nil {
		return nil, err
	}
	if len(parts) > MaxParts {
		return nil, fmt.Errorf("%w: too many parts", ErrTooComplex)
	}
	c := &component{pattern: generatePatternString(parts, o)}
	for _, pt := range parts {
		if pt.typ == ptRegexp {
			c.hasRegexpGroups = true
		}
	}
	if !o.ignoreCase {
		if lit, ok := literalOf(parts); ok {
			c.kind, c.literal = compLiteral, lit
			return c, nil
		}
		if len(parts) == 1 && parts[0].typ == ptFullWildcard && parts[0].mod == modNone &&
			parts[0].prefix == "" && parts[0].suffix == "" {
			c.kind, c.wildName = compFullWildcard, parts[0].name
			c.names = []string{parts[0].name}
			return c, nil
		}
	}
	src, names, dropEmpty := generateRegexp(parts, o)
	goSrc, err := translateRegexp(src, o.ignoreCase)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(goSrc)
	if err != nil {
		return nil, fmt.Errorf("urlpattern: invalid regular expression: %w", err)
	}
	if re.NumSubexp() != len(names) {
		return nil, fmt.Errorf("urlpattern: invalid regular expression: unexpected capture group")
	}
	c.kind, c.re, c.names, c.dropEmpty = compRegexp, re, names, dropEmpty
	return c, nil
}

func literalOf(parts []part) (string, bool) {
	switch len(parts) {
	case 0:
		return "", true
	case 1:
		if parts[0].typ == ptFixedText && parts[0].mod == modNone {
			return parts[0].value, true
		}
		return "", false
	}
	var b strings.Builder
	for _, pt := range parts {
		if pt.typ != ptFixedText || pt.mod != modNone {
			return "", false
		}
		b.WriteString(pt.value)
	}
	return b.String(), true
}

func hasLineTerminator(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n', '\r':
			return true
		case 0xE2:
			if i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xA8 || s[i+2] == 0xA9) {
				return true
			}
		}
	}
	return false
}

// match reports whether input matches the component.
func (c *component) match(input string) bool {
	switch c.kind {
	case compLiteral:
		return input == c.literal
	case compFullWildcard:
		return !hasLineTerminator(input)
	}
	return c.re.MatchString(input)
}

// exec matches input and returns the groups; ok is false on no match.
func (c *component) exec(input string) (groups map[string]string, ok bool) {
	switch c.kind {
	case compLiteral:
		return map[string]string{}, input == c.literal
	case compFullWildcard:
		if hasLineTerminator(input) {
			return nil, false
		}
		return map[string]string{c.wildName: input}, true
	}
	m := c.re.FindStringSubmatchIndex(input)
	if m == nil {
		return nil, false
	}
	groups = make(map[string]string, len(c.names))
	for i, name := range c.names {
		if s, e := m[2*(i+1)], m[2*(i+1)+1]; s >= 0 && !(s == e && c.dropEmpty[i]) {
			groups[name] = input[s:e]
		}
	}
	return groups, true
}

var specialSchemes = [...]string{"ftp", "file", "http", "https", "ws", "wss"}

// matchesSpecialScheme implements "protocol component matches a special scheme".
func (c *component) matchesSpecialScheme() bool {
	for _, s := range specialSchemes {
		if c.match(s) {
			return true
		}
	}
	return false
}
