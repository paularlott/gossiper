package urlpattern

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// This file translates the ECMAScript regular expressions that URL Pattern
// generates (and that users write inside "(...)" groups) into RE2 syntax so
// they can run on Go's linear-time regexp engine. The source is parsed with
// the syntax of an ECMAScript RegExp created with the "v" flag; constructs
// RE2 cannot express (backreferences, lookaround, regexp modifiers, class
// string literals longer than one code point) are rejected.

// maxProgramSize bounds the estimated size of the compiled program of one
// component, keeping compile time and per-byte matching cost bounded.
const maxProgramSize = 2000

type reError struct{ msg string }

func (e reError) Error() string { return "urlpattern: invalid regular expression: " + e.msg }

type reTranslator struct {
	src        []rune
	pos        int
	out        strings.Builder
	ignoreCase bool
}

// translateRegexp converts ECMAScript (v flag) regexp source to RE2 syntax.
func translateRegexp(src string, ignoreCase bool) (res string, err error) {
	t := &reTranslator{src: []rune(src), ignoreCase: ignoreCase}
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(reError); ok {
				res, err = "", e
				return
			}
			panic(r)
		}
	}()
	if ignoreCase {
		t.out.WriteString("(?i)")
	}
	size := t.disjunction()
	if t.pos < len(t.src) {
		t.fail("unmatched ')'")
	}
	if size > maxProgramSize {
		t.fail("expression too complex")
	}
	return t.out.String(), nil
}

func (t *reTranslator) fail(format string, args ...any) {
	panic(reError{fmt.Sprintf(format, args...)})
}

func (t *reTranslator) peek() rune {
	if t.pos < len(t.src) {
		return t.src[t.pos]
	}
	return -1
}

func (t *reTranslator) peekAt(i int) rune {
	if t.pos+i < len(t.src) {
		return t.src[t.pos+i]
	}
	return -1
}

func (t *reTranslator) next() rune {
	if t.pos >= len(t.src) {
		t.fail("unexpected end of pattern")
	}
	r := t.src[t.pos]
	t.pos++
	return r
}

func (t *reTranslator) eat(r rune) bool {
	if t.peek() == r {
		t.pos++
		return true
	}
	return false
}

func (t *reTranslator) disjunction() int {
	size := t.alternative()
	for t.eat('|') {
		t.out.WriteByte('|')
		size += t.alternative() + 1
	}
	return size
}

func (t *reTranslator) alternative() int {
	size := 0
	for {
		c := t.peek()
		if c == -1 || c == '|' || c == ')' {
			return size
		}
		size += t.term()
		if size > maxProgramSize*4 {
			t.fail("expression too complex")
		}
	}
}

// term parses Term and returns its estimated program size.
func (t *reTranslator) term() int {
	c := t.next()
	size := 1
	quantifiable := true
	switch c {
	case '^':
		t.out.WriteByte('^')
		quantifiable = false
	case '$':
		t.out.WriteByte('$')
		quantifiable = false
	case '(':
		size = t.group() + 2
	case '\\':
		size, quantifiable = t.atomEscape()
	case '.':
		t.out.WriteString(`[^\n\r\x{2028}\x{2029}]`)
	case '[':
		set, neg := t.classBody()
		t.emitClass(set, neg)
	case '*', '+', '?':
		t.fail("nothing to repeat")
	case '{', '}', ']':
		t.fail("lone %q", c)
	default:
		t.emitLiteral(c)
	}
	q := t.peek()
	if q == '*' || q == '+' || q == '?' || q == '{' {
		if !quantifiable {
			t.fail("nothing to repeat")
		}
		size = t.quantifier(size)
	}
	return size
}

func (t *reTranslator) group() int {
	if t.eat('?') {
		switch t.peek() {
		case ':':
			t.pos++
			t.out.WriteString("(?:")
		case '=', '!':
			t.fail("lookahead assertions are not supported")
		case '<':
			t.pos++
			if c := t.peek(); c == '=' || c == '!' {
				t.fail("lookbehind assertions are not supported")
			}
			start := t.pos
			for t.peek() != '>' {
				c := t.next()
				if !isValidNameCodePoint(c, t.pos-1 == start) {
					t.fail("invalid group name")
				}
			}
			if t.pos == start {
				t.fail("empty group name")
			}
			t.pos++
			// Named groups become non-capturing so that the capture
			// numbering matches the generated group name list.
			t.out.WriteString("(?:")
		default:
			t.fail("unsupported group syntax")
		}
	} else {
		t.out.WriteByte('(')
	}
	size := t.disjunction()
	if !t.eat(')') {
		t.fail("missing ')'")
	}
	t.out.WriteByte(')')
	return size
}

func (t *reTranslator) quantifier(atomSize int) int {
	c := t.next()
	var size int
	switch c {
	case '*', '+', '?':
		t.out.WriteRune(c)
		size = atomSize + 1
	case '{':
		lo, ok := t.number()
		if !ok {
			t.fail("invalid quantifier")
		}
		hi := lo
		unbounded := false
		if t.eat(',') {
			if t.peek() == '}' {
				unbounded = true
			} else if hi, ok = t.number(); !ok {
				t.fail("invalid quantifier")
			}
		}
		if !t.eat('}') {
			t.fail("invalid quantifier")
		}
		if !unbounded && hi < lo {
			t.fail("numbers out of order in {} quantifier")
		}
		t.out.WriteString("{" + strconv.Itoa(lo))
		copies := lo
		if unbounded {
			t.out.WriteString(",")
			copies = lo + 1
		} else if hi != lo {
			t.out.WriteString("," + strconv.Itoa(hi))
			copies = hi
		}
		t.out.WriteByte('}')
		if copies < 1 {
			copies = 1
		}
		if atomSize > maxProgramSize || copies > maxProgramSize {
			t.fail("expression too complex")
		}
		size = atomSize * copies
		if size > maxProgramSize {
			t.fail("expression too complex")
		}
	}
	if t.eat('?') {
		t.out.WriteByte('?')
	}
	return size
}

func (t *reTranslator) number() (int, bool) {
	start := t.pos
	v := 0
	for c := t.peek(); c >= '0' && c <= '9'; c = t.peek() {
		if v < 1<<24 {
			v = v*10 + int(c-'0')
		}
		t.pos++
	}
	return v, t.pos > start
}

func (t *reTranslator) emitLiteral(r rune) {
	if r < 0x80 && isASCIIAlnum(r) {
		t.out.WriteRune(r)
		return
	}
	fmt.Fprintf(&t.out, `\x{%X}`, r)
}

// atomEscape parses the escape after a backslash outside a class.
func (t *reTranslator) atomEscape() (size int, quantifiable bool) {
	c := t.next()
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		t.emitClass(classEscapeSet(c), false)
		return 1, true
	case 'p', 'P':
		set := t.propertyEscape(c == 'P')
		t.emitClass(set, false)
		return 1, true
	case 'b':
		t.out.WriteString(`\b`)
		return 1, false
	case 'B':
		t.out.WriteString(`\B`)
		return 1, false
	case 'k':
		t.fail("named backreferences are not supported")
	case '1', '2', '3', '4', '5', '6', '7', '8', '9':
		t.fail("backreferences are not supported")
	case '0':
		if d := t.peek(); d >= '0' && d <= '9' {
			t.fail("invalid decimal escape")
		}
		t.emitLiteral(0)
		return 1, true
	}
	t.pos--
	t.emitLiteral(t.characterEscape(false))
	return 1, true
}

// characterEscape parses CharacterEscape (after the backslash).
func (t *reTranslator) characterEscape(inClass bool) rune {
	c := t.next()
	switch c {
	case 't':
		return '\t'
	case 'n':
		return '\n'
	case 'v':
		return '\v'
	case 'f':
		return '\f'
	case 'r':
		return '\r'
	case 'c':
		l := t.next()
		if !isASCIIAlpha(l) {
			t.fail("invalid control escape")
		}
		return l % 32
	case '0':
		if d := t.peek(); d >= '0' && d <= '9' {
			t.fail("invalid decimal escape")
		}
		return 0
	case 'x':
		return t.hexDigits(2)
	case 'u':
		return t.unicodeEscape()
	}
	if strings.ContainsRune("^$\\.*+?()[]{}|/", c) {
		return c
	}
	if inClass && strings.ContainsRune("&-!#%,:;<=>@`~", c) {
		return c
	}
	t.fail("invalid escape \\%c", c)
	return 0
}

func (t *reTranslator) hexDigits(n int) rune {
	var v rune
	for i := 0; i < n; i++ {
		c := t.next()
		if !isASCIIHex(c) {
			t.fail("invalid hexadecimal escape")
		}
		v = v<<4 | rune(hexVal(c))
	}
	return v
}

func (t *reTranslator) unicodeEscape() rune {
	if t.eat('{') {
		var v rune
		n := 0
		for {
			c := t.next()
			if c == '}' {
				break
			}
			if !isASCIIHex(c) {
				t.fail("invalid unicode escape")
			}
			v = v<<4 | rune(hexVal(c))
			if v > unicode.MaxRune {
				t.fail("unicode escape out of range")
			}
			n++
		}
		if n == 0 {
			t.fail("invalid unicode escape")
		}
		return v
	}
	v := t.hexDigits(4)
	if v >= 0xD800 && v <= 0xDBFF && t.peek() == '\\' && t.peekAt(1) == 'u' {
		save := t.pos
		t.pos += 2
		lo := t.hexDigits(4)
		if lo >= 0xDC00 && lo <= 0xDFFF {
			return (v-0xD800)<<10 + (lo - 0xDC00) + 0x10000
		}
		t.pos = save
	}
	return v
}

// ---- character classes ----

type rng struct{ lo, hi rune }

// charSet is a sorted list of disjoint, non-adjacent ranges.
type charSet []rng

func normalizeSet(rs []rng) charSet {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	out := charSet{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi+1 {
			if r.hi > last.hi {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func (a charSet) union(b charSet) charSet {
	rs := make([]rng, 0, len(a)+len(b))
	rs = append(rs, a...)
	rs = append(rs, b...)
	return normalizeSet(rs)
}

func (a charSet) complement() charSet {
	var out charSet
	next := rune(0)
	for _, r := range a {
		if r.lo > next {
			out = append(out, rng{next, r.lo - 1})
		}
		next = r.hi + 1
	}
	if next <= unicode.MaxRune {
		out = append(out, rng{next, unicode.MaxRune})
	}
	return out
}

func (a charSet) intersect(b charSet) charSet {
	return a.complement().union(b.complement()).complement()
}

func (a charSet) subtract(b charSet) charSet { return a.intersect(b.complement()) }

func oneRune(r rune) charSet { return charSet{{r, r}} }

func classEscapeSet(c rune) charSet {
	var s charSet
	switch c {
	case 'd', 'D':
		s = charSet{{'0', '9'}}
	case 'w', 'W':
		s = charSet{{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}}
	default: // s, S: WhiteSpace and LineTerminator
		s = normalizeSet([]rng{{9, 13}, {0x20, 0x20}, {0xA0, 0xA0}, {0x1680, 0x1680}, {0x2000, 0x200A},
			{0x2028, 0x2029}, {0x202F, 0x202F}, {0x205F, 0x205F}, {0x3000, 0x3000}, {0xFEFF, 0xFEFF}})
	}
	if c == 'D' || c == 'W' || c == 'S' {
		return s.complement()
	}
	return s
}

// classBody parses the rest of a character class after '[' and returns its
// set and whether it is negated.
func (t *reTranslator) classBody() (charSet, bool) {
	neg := t.eat('^')
	return t.classContents(), neg
}

type classOperand struct {
	set    charSet
	ch     rune
	isChar bool
}

func (t *reTranslator) classContents() charSet {
	if t.eat(']') {
		return nil
	}
	first := t.classOperand()
	asSet := func(o classOperand) charSet {
		if o.isChar {
			return oneRune(o.ch)
		}
		return o.set
	}
	switch {
	case t.peek() == '&' && t.peekAt(1) == '&':
		result := asSet(first)
		for t.peek() == '&' && t.peekAt(1) == '&' {
			t.pos += 2
			if t.peek() == '&' {
				t.fail("invalid set operation in character class")
			}
			result = result.intersect(asSet(t.classOperand()))
		}
		if !t.eat(']') {
			t.fail("invalid set operation in character class")
		}
		return result
	case t.peek() == '-' && t.peekAt(1) == '-':
		result := asSet(first)
		for t.peek() == '-' && t.peekAt(1) == '-' {
			t.pos += 2
			result = result.subtract(asSet(t.classOperand()))
		}
		if !t.eat(']') {
			t.fail("invalid set operation in character class")
		}
		return result
	}
	var rs []rng
	add := func(o classOperand) {
		if o.isChar && t.peek() == '-' {
			t.pos++
			hi := t.classOperand()
			if !hi.isChar || hi.ch < o.ch {
				t.fail("invalid character class range")
			}
			rs = append(rs, rng{o.ch, hi.ch})
			return
		}
		rs = append(rs, asSet(o)...)
	}
	add(first)
	for !t.eat(']') {
		if t.peek() == -1 {
			t.fail("unterminated character class")
		}
		add(t.classOperand())
	}
	return normalizeSet(rs)
}

const classSyntaxChars = "()[]{}/-|"
const classDoublePunct = "&!#$%*+,.:;<=>?@^`~"

func (t *reTranslator) classOperand() classOperand {
	c := t.next()
	switch c {
	case '[':
		set, neg := t.classBody()
		if neg {
			set = set.complement()
		}
		return classOperand{set: set}
	case '\\':
		e := t.next()
		switch e {
		case 'd', 'D', 'w', 'W', 's', 'S':
			return classOperand{set: classEscapeSet(e)}
		case 'p', 'P':
			return classOperand{set: t.propertyEscape(e == 'P')}
		case 'q':
			return classOperand{set: t.classStrings()}
		case 'b':
			return classOperand{ch: 8, isChar: true}
		}
		t.pos--
		return classOperand{ch: t.characterEscape(true), isChar: true}
	}
	if strings.ContainsRune(classSyntaxChars, c) {
		t.fail("unescaped %q in character class", c)
	}
	if strings.ContainsRune(classDoublePunct, c) && t.peek() == c {
		t.fail("reserved double punctuator in character class")
	}
	return classOperand{ch: c, isChar: true}
}

// classStrings parses \q{...} (after "\q"); only single code point strings
// are supported.
func (t *reTranslator) classStrings() charSet {
	if !t.eat('{') {
		t.fail("invalid \\q escape")
	}
	var rs []rng
	n := 0
	flush := func() {
		if n != 1 {
			t.fail("class string literals other than single code points are not supported")
		}
		n = 0
	}
	for {
		c := t.next()
		switch c {
		case '}':
			flush()
			return normalizeSet(rs)
		case '|':
			flush()
		case '\\':
			e := t.next()
			var ch rune
			if e == 'b' {
				ch = 8
			} else {
				t.pos--
				ch = t.characterEscape(true)
			}
			rs = append(rs, rng{ch, ch})
			n++
		default:
			if strings.ContainsRune(classSyntaxChars, c) {
				t.fail("unescaped %q in class string", c)
			}
			rs = append(rs, rng{c, c})
			n++
		}
	}
}

func (t *reTranslator) emitClass(set charSet, neg bool) {
	if len(set) == 0 {
		if neg {
			t.out.WriteString(`[\x{0}-\x{10FFFF}]`)
		} else {
			t.out.WriteString(`[^\x{0}-\x{10FFFF}]`)
		}
		return
	}
	t.out.WriteByte('[')
	if neg {
		t.out.WriteByte('^')
	}
	for _, r := range set {
		if r.lo == r.hi {
			fmt.Fprintf(&t.out, `\x{%X}`, r.lo)
		} else {
			fmt.Fprintf(&t.out, `\x{%X}-\x{%X}`, r.lo, r.hi)
		}
	}
	t.out.WriteByte(']')
}

// ---- Unicode property escapes ----

func (t *reTranslator) propertyEscape(negate bool) charSet {
	if !t.eat('{') {
		t.fail("invalid property escape")
	}
	start := t.pos
	for t.peek() != '}' {
		t.next()
	}
	name := string(t.src[start:t.pos])
	t.pos++
	set, ok := lookupProperty(name)
	if !ok {
		t.fail("unsupported Unicode property %q", name)
	}
	if negate {
		return set.complement()
	}
	return set
}

func tableSet(tabs ...*unicode.RangeTable) charSet {
	var rs []rng
	for _, tab := range tabs {
		for _, r := range tab.R16 {
			if r.Stride == 1 {
				rs = append(rs, rng{rune(r.Lo), rune(r.Hi)})
				continue
			}
			for c := rune(r.Lo); c <= rune(r.Hi); c += rune(r.Stride) {
				rs = append(rs, rng{c, c})
			}
		}
		for _, r := range tab.R32 {
			if r.Stride == 1 {
				rs = append(rs, rng{rune(r.Lo), rune(r.Hi)})
				continue
			}
			for c := rune(r.Lo); c <= rune(r.Hi); c += rune(r.Stride) {
				rs = append(rs, rng{c, c})
			}
		}
	}
	return normalizeSet(rs)
}

var categoryLongNames = map[string]string{
	"Letter": "L", "Cased_Letter": "LC", "Uppercase_Letter": "Lu", "Lowercase_Letter": "Ll",
	"Titlecase_Letter": "Lt", "Modifier_Letter": "Lm", "Other_Letter": "Lo",
	"Mark": "M", "Combining_Mark": "M", "Nonspacing_Mark": "Mn", "Spacing_Mark": "Mc", "Enclosing_Mark": "Me",
	"Number": "N", "Decimal_Number": "Nd", "digit": "Nd", "Letter_Number": "Nl", "Other_Number": "No",
	"Punctuation": "P", "punct": "P", "Connector_Punctuation": "Pc", "Dash_Punctuation": "Pd",
	"Open_Punctuation": "Ps", "Close_Punctuation": "Pe", "Initial_Punctuation": "Pi",
	"Final_Punctuation": "Pf", "Other_Punctuation": "Po",
	"Symbol": "S", "Math_Symbol": "Sm", "Currency_Symbol": "Sc", "Modifier_Symbol": "Sk", "Other_Symbol": "So",
	"Separator": "Z", "Space_Separator": "Zs", "Line_Separator": "Zl", "Paragraph_Separator": "Zp",
	"Other": "C", "Control": "Cc", "cntrl": "Cc", "Format": "Cf", "Surrogate": "Cs", "Private_Use": "Co",
	"Unassigned": "Cn",
}

func categorySet(name string) (charSet, bool) {
	if long, ok := categoryLongNames[name]; ok {
		name = long
	}
	switch name {
	case "LC":
		return tableSet(unicode.Lu, unicode.Ll, unicode.Lt), true
	case "Cn":
		assigned := tableSet(unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
			unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
		return assigned.complement(), true
	case "C":
		return tableSet(unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs), true
	}
	if tab, ok := unicode.Categories[name]; ok {
		return tableSet(tab), true
	}
	return nil, false
}

var binaryPropertyAliases = map[string]string{
	"AHex": "ASCII_Hex_Digit", "Hex": "Hex_Digit", "space": "White_Space", "WSpace": "White_Space",
	"Bidi_C": "Bidi_Control", "Dash": "Dash", "Dia": "Diacritic", "Ext": "Extender", "Ideo": "Ideographic",
	"Join_C": "Join_Control", "NChar": "Noncharacter_Code_Point", "Pat_Syn": "Pattern_Syntax",
	"Pat_WS": "Pattern_White_Space", "QMark": "Quotation_Mark", "RI": "Regional_Indicator",
	"SD": "Soft_Dotted", "STerm": "Sentence_Terminal", "Term": "Terminal_Punctuation",
	"UIdeo": "Unified_Ideograph", "VS": "Variation_Selector", "LOE": "Logical_Order_Exception",
	"IDSB": "IDS_Binary_Operator", "IDST": "IDS_Trinary_Operator",
}

func binaryPropertySet(name string) (charSet, bool) {
	switch name {
	case "Any":
		return charSet{{0, unicode.MaxRune}}, true
	case "ASCII":
		return charSet{{0, 0x7F}}, true
	case "Assigned":
		s, _ := categorySet("Cn")
		return s.complement(), true
	case "Alphabetic", "Alpha":
		return tableSet(unicode.L, unicode.Nl, unicode.Other_Alphabetic), true
	case "Lowercase", "Lower":
		return tableSet(unicode.Ll, unicode.Other_Lowercase), true
	case "Uppercase", "Upper":
		return tableSet(unicode.Lu, unicode.Other_Uppercase), true
	}
	if a, ok := binaryPropertyAliases[name]; ok {
		name = a
	}
	if strings.HasPrefix(name, "Other_") || name == "Hyphen" || name == "Deprecated" {
		return nil, false
	}
	if tab, ok := unicode.Properties[name]; ok {
		return tableSet(tab), true
	}
	return nil, false
}

func lookupProperty(name string) (charSet, bool) {
	if k, v, ok := strings.Cut(name, "="); ok {
		switch k {
		case "General_Category", "gc":
			return categorySet(v)
		case "Script", "sc":
			if tab, ok := unicode.Scripts[v]; ok {
				return tableSet(tab), true
			}
		}
		return nil, false
	}
	if s, ok := categorySet(name); ok {
		return s, true
	}
	return binaryPropertySet(name)
}
