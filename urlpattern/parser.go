package urlpattern

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
)

// This file implements pattern string tokenizing and parsing (spec §2.1) and
// the conversion of part lists to pattern strings (spec §2.3).

type tokenType uint8

const (
	tkInvalidChar tokenType = iota
	tkOpen
	tkClose
	tkRegexp
	tkName
	tkChar
	tkEscapedChar
	tkOtherModifier
	tkAsterisk
	tkEnd
)

type token struct {
	typ   tokenType
	index int
	value string
}

var errSyntax = errors.New("urlpattern: invalid pattern syntax")

// isValidNameCodePoint reports whether r may appear in a group name
// (ECMAScript IdentifierStart / IdentifierPart).
func isValidNameCodePoint(r rune, first bool) bool {
	if r == '$' || r == '_' {
		return true
	}
	if isIDStart(r) {
		return true
	}
	if first {
		return false
	}
	if r == 0x200C || r == 0x200D {
		return true
	}
	if unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc, unicode.Other_ID_Continue) {
		return !unicode.In(r, unicode.Pattern_Syntax, unicode.Pattern_White_Space)
	}
	return false
}

func isIDStart(r rune) bool {
	if r < 0x80 {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
	}
	if unicode.In(r, unicode.L, unicode.Nl, unicode.Other_ID_Start) {
		return !unicode.In(r, unicode.Pattern_Syntax, unicode.Pattern_White_Space)
	}
	return false
}

// tokenize implements "tokenize"; lenient policy turns errors into
// invalid-char tokens.
func tokenize(input []rune, strict bool) ([]token, error) {
	var tokens []token
	n := len(input)
	index := 0
	nextIndex := 0
	var cp rune
	getNext := func() {
		cp = input[nextIndex]
		nextIndex++
	}
	seek := func(i int) {
		nextIndex = i
		getNext()
	}
	add := func(typ tokenType, nextPos, valuePos, valueLen int) {
		tokens = append(tokens, token{typ: typ, index: index, value: string(input[valuePos : valuePos+valueLen])})
		index = nextPos
	}
	addDefLen := func(typ tokenType, nextPos, valuePos int) { add(typ, nextPos, valuePos, nextPos-valuePos) }
	addDefault := func(typ tokenType) { addDefLen(typ, nextIndex, index) }
	procErr := func(nextPos, valuePos int) error {
		if strict {
			return errSyntax
		}
		addDefLen(tkInvalidChar, nextPos, valuePos)
		return nil
	}
	for index < n {
		seek(index)
		switch cp {
		case '*':
			addDefault(tkAsterisk)
			continue
		case '+', '?':
			addDefault(tkOtherModifier)
			continue
		case '\\':
			if index == n-1 {
				if err := procErr(nextIndex, index); err != nil {
					return nil, err
				}
				continue
			}
			escapedIndex := nextIndex
			getNext()
			addDefLen(tkEscapedChar, nextIndex, escapedIndex)
			continue
		case '{':
			addDefault(tkOpen)
			continue
		case '}':
			addDefault(tkClose)
			continue
		case ':':
			namePos := nextIndex
			nameStart := namePos
			for namePos < n {
				seek(namePos)
				if !isValidNameCodePoint(cp, namePos == nameStart) {
					break
				}
				namePos = nextIndex
			}
			if namePos <= nameStart {
				if err := procErr(nameStart, index); err != nil {
					return nil, err
				}
				continue
			}
			addDefLen(tkName, namePos, nameStart)
			continue
		case '(':
			depth := 1
			regexpPos := nextIndex
			regexpStart := regexpPos
			bad := false
			for regexpPos < n {
				seek(regexpPos)
				if cp >= 0x80 {
					if err := procErr(regexpStart, index); err != nil {
						return nil, err
					}
					bad = true
					break
				}
				if regexpPos == regexpStart && cp == '?' {
					if err := procErr(regexpStart, index); err != nil {
						return nil, err
					}
					bad = true
					break
				}
				if cp == '\\' {
					if regexpPos == n-1 {
						if err := procErr(regexpStart, index); err != nil {
							return nil, err
						}
						bad = true
						break
					}
					getNext()
					if cp >= 0x80 {
						if err := procErr(regexpStart, index); err != nil {
							return nil, err
						}
						bad = true
						break
					}
					regexpPos = nextIndex
					continue
				}
				if cp == ')' {
					depth--
					if depth == 0 {
						regexpPos = nextIndex
						break
					}
				} else if cp == '(' {
					depth++
					if regexpPos == n-1 {
						if err := procErr(regexpStart, index); err != nil {
							return nil, err
						}
						bad = true
						break
					}
					tempPos := nextIndex
					getNext()
					if cp != '?' {
						if err := procErr(regexpStart, index); err != nil {
							return nil, err
						}
						bad = true
						break
					}
					nextIndex = tempPos
				}
				regexpPos = nextIndex
			}
			if bad {
				continue
			}
			if depth != 0 {
				if err := procErr(regexpStart, index); err != nil {
					return nil, err
				}
				continue
			}
			regexpLen := regexpPos - regexpStart - 1
			if regexpLen == 0 {
				if err := procErr(regexpStart, index); err != nil {
					return nil, err
				}
				continue
			}
			add(tkRegexp, regexpPos, regexpStart, regexpLen)
			continue
		}
		addDefault(tkChar)
	}
	addDefLen(tkEnd, index, index)
	return tokens, nil
}

// ---- parts ----

type partType uint8

const (
	ptFixedText partType = iota
	ptRegexp
	ptSegmentWildcard
	ptFullWildcard
)

type modifier uint8

const (
	modNone modifier = iota
	modOptional
	modZeroOrMore
	modOneOrMore
)

func (m modifier) String() string {
	switch m {
	case modZeroOrMore:
		return "*"
	case modOptional:
		return "?"
	case modOneOrMore:
		return "+"
	}
	return ""
}

type part struct {
	typ    partType
	value  string
	mod    modifier
	name   string
	prefix string
	suffix string
}

// options are the pattern-string parsing/compilation options (spec §2.1.4).
type options struct {
	delimiter  string // "" or one ASCII code point
	prefix     string // "" or one ASCII code point
	ignoreCase bool
}

var (
	defaultOptions  = options{}
	hostnameOptions = options{delimiter: "."}
	pathnameOptions = options{delimiter: "/", prefix: "/"}
)

const fullWildcardRegexp = ".*"

func segmentWildcardRegexp(o options) string {
	return "[^" + escapeRegexpString(o.delimiter) + "]+?"
}

type patternParser struct {
	tokens       []token
	enc          encodeFunc
	segWildcard  string
	parts        []part
	pendingFixed string
	index        int
	nextNumeric  int
}

func (p *patternParser) tryConsume(t tokenType) (token, bool) {
	tok := p.tokens[p.index]
	if tok.typ != t {
		return token{}, false
	}
	p.index++
	return tok, true
}

func (p *patternParser) tryConsumeModifier() (token, bool) {
	if t, ok := p.tryConsume(tkOtherModifier); ok {
		return t, true
	}
	return p.tryConsume(tkAsterisk)
}

func (p *patternParser) tryConsumeRegexpOrWildcard(haveName bool) (token, bool) {
	if t, ok := p.tryConsume(tkRegexp); ok {
		return t, true
	}
	if !haveName {
		return p.tryConsume(tkAsterisk)
	}
	return token{}, false
}

func (p *patternParser) consumeRequired(t tokenType) error {
	if _, ok := p.tryConsume(t); !ok {
		return errSyntax
	}
	return nil
}

func (p *patternParser) consumeText() string {
	var b strings.Builder
	for {
		t, ok := p.tryConsume(tkChar)
		if !ok {
			t, ok = p.tryConsume(tkEscapedChar)
		}
		if !ok {
			break
		}
		b.WriteString(t.value)
	}
	return b.String()
}

func (p *patternParser) maybeAddPartFromPendingFixed() error {
	if p.pendingFixed == "" {
		return nil
	}
	enc, err := p.enc(p.pendingFixed)
	if err != nil {
		return err
	}
	p.pendingFixed = ""
	p.parts = append(p.parts, part{typ: ptFixedText, value: enc, mod: modNone})
	return nil
}

func (p *patternParser) addPart(prefix string, nameTok *token, reTok *token, suffix string, modTok *token) error {
	mod := modNone
	if modTok != nil {
		switch modTok.value {
		case "?":
			mod = modOptional
		case "*":
			mod = modZeroOrMore
		case "+":
			mod = modOneOrMore
		}
	}
	if nameTok == nil && reTok == nil && mod == modNone {
		p.pendingFixed += prefix
		return nil
	}
	if err := p.maybeAddPartFromPendingFixed(); err != nil {
		return err
	}
	if nameTok == nil && reTok == nil {
		if prefix == "" {
			return nil
		}
		enc, err := p.enc(prefix)
		if err != nil {
			return err
		}
		p.parts = append(p.parts, part{typ: ptFixedText, value: enc, mod: mod})
		return nil
	}
	var regexpValue string
	switch {
	case reTok == nil:
		regexpValue = p.segWildcard
	case reTok.typ == tkAsterisk:
		regexpValue = fullWildcardRegexp
	default:
		regexpValue = reTok.value
	}
	typ := ptRegexp
	if regexpValue == p.segWildcard {
		typ = ptSegmentWildcard
		regexpValue = ""
	} else if regexpValue == fullWildcardRegexp {
		typ = ptFullWildcard
		regexpValue = ""
	}
	name := ""
	if nameTok != nil {
		name = nameTok.value
	} else if reTok != nil {
		name = strconv.Itoa(p.nextNumeric)
		p.nextNumeric++
	}
	for _, q := range p.parts {
		if q.name == name {
			return errSyntax
		}
	}
	encPrefix, err := p.enc(prefix)
	if err != nil {
		return err
	}
	encSuffix, err := p.enc(suffix)
	if err != nil {
		return err
	}
	p.parts = append(p.parts, part{typ: typ, value: regexpValue, mod: mod, name: name, prefix: encPrefix, suffix: encSuffix})
	return nil
}

// parsePatternString implements "parse a pattern string".
func parsePatternString(input string, o options, enc encodeFunc) ([]part, error) {
	toks, err := tokenize([]rune(input), true)
	if err != nil {
		return nil, err
	}
	p := &patternParser{tokens: toks, enc: enc, segWildcard: segmentWildcardRegexp(o)}
	for p.index < len(p.tokens) {
		charTok, haveChar := p.tryConsume(tkChar)
		nameTok, haveName := p.tryConsume(tkName)
		reTok, haveRe := p.tryConsumeRegexpOrWildcard(haveName)
		if haveName || haveRe {
			prefix := ""
			if haveChar {
				prefix = charTok.value
			}
			if prefix != "" && prefix != o.prefix {
				p.pendingFixed += prefix
				prefix = ""
			}
			if err := p.maybeAddPartFromPendingFixed(); err != nil {
				return nil, err
			}
			modTok, haveMod := p.tryConsumeModifier()
			var np, rp, mp *token
			if haveName {
				np = &nameTok
			}
			if haveRe {
				rp = &reTok
			}
			if haveMod {
				mp = &modTok
			}
			if err := p.addPart(prefix, np, rp, "", mp); err != nil {
				return nil, err
			}
			continue
		}
		var fixed token
		haveFixed := haveChar
		if haveChar {
			fixed = charTok
		} else {
			fixed, haveFixed = p.tryConsume(tkEscapedChar)
		}
		if haveFixed {
			p.pendingFixed += fixed.value
			continue
		}
		if _, ok := p.tryConsume(tkOpen); ok {
			prefix := p.consumeText()
			nameTok, haveName = p.tryConsume(tkName)
			reTok, haveRe = p.tryConsumeRegexpOrWildcard(haveName)
			suffix := p.consumeText()
			if err := p.consumeRequired(tkClose); err != nil {
				return nil, err
			}
			modTok, haveMod := p.tryConsumeModifier()
			var np, rp, mp *token
			if haveName {
				np = &nameTok
			}
			if haveRe {
				rp = &reTok
			}
			if haveMod {
				mp = &modTok
			}
			if err := p.addPart(prefix, np, rp, suffix, mp); err != nil {
				return nil, err
			}
			continue
		}
		if err := p.maybeAddPartFromPendingFixed(); err != nil {
			return nil, err
		}
		if err := p.consumeRequired(tkEnd); err != nil {
			return nil, err
		}
	}
	return p.parts, nil
}

// ---- escaping ----

func escapeRegexpString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '.', '+', '*', '?', '^', '$', '{', '}', '(', ')', '[', ']', '|', '/', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func escapePatternString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '+', '*', '?', ':', '{', '}', '(', ')', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ---- part list -> regular expression ----

// generateRegexp implements "generate a regular expression and name list",
// producing ECMAScript regexp source (without flags).
func generateRegexp(parts []part, o options) (string, []string, []bool) {
	var b strings.Builder
	var names []string
	var dropEmpty []bool
	b.WriteByte('^')
	for _, pt := range parts {
		if pt.typ == ptFixedText {
			if pt.mod == modNone {
				b.WriteString(escapeRegexpString(pt.value))
			} else {
				b.WriteString("(?:")
				b.WriteString(escapeRegexpString(pt.value))
				b.WriteByte(')')
				b.WriteString(pt.mod.String())
			}
			continue
		}
		names = append(names, pt.name)
		// In ECMAScript an empty iteration of a quantified group is rejected, so
		// an optional group without prefix and suffix that matched the empty
		// string is left undefined. RE2 captures "" instead; component.exec
		// drops these captures.
		dropEmpty = append(dropEmpty, pt.mod == modOptional && pt.prefix == "" && pt.suffix == "")
		rv := pt.value
		switch pt.typ {
		case ptSegmentWildcard:
			rv = segmentWildcardRegexp(o)
		case ptFullWildcard:
			rv = fullWildcardRegexp
		}
		if pt.prefix == "" && pt.suffix == "" {
			if pt.mod == modNone || pt.mod == modOptional {
				b.WriteByte('(')
				b.WriteString(rv)
				b.WriteByte(')')
				b.WriteString(pt.mod.String())
			} else {
				b.WriteString("((?:")
				b.WriteString(rv)
				b.WriteByte(')')
				b.WriteString(pt.mod.String())
				b.WriteByte(')')
			}
			continue
		}
		if pt.mod == modNone || pt.mod == modOptional {
			b.WriteString("(?:")
			b.WriteString(escapeRegexpString(pt.prefix))
			b.WriteByte('(')
			b.WriteString(rv)
			b.WriteByte(')')
			b.WriteString(escapeRegexpString(pt.suffix))
			b.WriteByte(')')
			b.WriteString(pt.mod.String())
			continue
		}
		b.WriteString("(?:")
		b.WriteString(escapeRegexpString(pt.prefix))
		b.WriteString("((?:")
		b.WriteString(rv)
		b.WriteString(")(?:")
		b.WriteString(escapeRegexpString(pt.suffix))
		b.WriteString(escapeRegexpString(pt.prefix))
		b.WriteString("(?:")
		b.WriteString(rv)
		b.WriteString("))*)")
		b.WriteString(escapeRegexpString(pt.suffix))
		b.WriteByte(')')
		if pt.mod == modZeroOrMore {
			b.WriteByte('?')
		}
	}
	b.WriteByte('$')
	return b.String(), names, dropEmpty
}

// ---- part list -> pattern string ----

func firstRune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}

func lastRune(s string) rune {
	var last rune
	for _, r := range s {
		last = r
	}
	return last
}

// generatePatternString implements "generate a pattern string".
func generatePatternString(parts []part, o options) string {
	var b strings.Builder
	for i, pt := range parts {
		var prev, next *part
		if i > 0 {
			prev = &parts[i-1]
		}
		if i < len(parts)-1 {
			next = &parts[i+1]
		}
		if pt.typ == ptFixedText {
			if pt.mod == modNone {
				b.WriteString(escapePatternString(pt.value))
				continue
			}
			b.WriteByte('{')
			b.WriteString(escapePatternString(pt.value))
			b.WriteByte('}')
			b.WriteString(pt.mod.String())
			continue
		}
		customName := !(pt.name[0] >= '0' && pt.name[0] <= '9')
		needsGrouping := pt.suffix != "" || (pt.prefix != "" && pt.prefix != o.prefix)
		if !needsGrouping && customName && pt.typ == ptSegmentWildcard && pt.mod == modNone &&
			next != nil && next.prefix == "" && next.suffix == "" {
			if next.typ == ptFixedText {
				needsGrouping = isValidNameCodePoint(firstRune(next.value), false)
			} else {
				needsGrouping = next.name[0] >= '0' && next.name[0] <= '9'
			}
		}
		if !needsGrouping && pt.prefix == "" && prev != nil && prev.typ == ptFixedText &&
			o.prefix != "" && string(lastRune(prev.value)) == o.prefix {
			needsGrouping = true
		}
		if needsGrouping {
			b.WriteByte('{')
		}
		b.WriteString(escapePatternString(pt.prefix))
		if customName {
			b.WriteByte(':')
			b.WriteString(pt.name)
		}
		switch {
		case pt.typ == ptRegexp:
			b.WriteByte('(')
			b.WriteString(pt.value)
			b.WriteByte(')')
		case pt.typ == ptSegmentWildcard && !customName:
			b.WriteByte('(')
			b.WriteString(segmentWildcardRegexp(o))
			b.WriteByte(')')
		case pt.typ == ptFullWildcard:
			if !customName && (prev == nil || prev.typ == ptFixedText || prev.mod != modNone ||
				needsGrouping || pt.prefix != "") {
				b.WriteByte('*')
			} else {
				b.WriteByte('(')
				b.WriteString(fullWildcardRegexp)
				b.WriteByte(')')
			}
		}
		if pt.typ == ptSegmentWildcard && customName && pt.suffix != "" &&
			isValidNameCodePoint(firstRune(pt.suffix), false) {
			b.WriteByte('\\')
		}
		b.WriteString(escapePatternString(pt.suffix))
		if needsGrouping {
			b.WriteByte('}')
		}
		b.WriteString(pt.mod.String())
	}
	return b.String()
}
