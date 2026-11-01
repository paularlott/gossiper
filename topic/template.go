package topic

import (
	"regexp"
	"strconv"
	"strings"
)

// Limits applied to selectors that are interpreted as URI Templates. A
// selector exceeding any of them is not treated as a template: it only
// matches by equality (or "*").
const (
	// maxTemplateLen is the maximum length of a template in bytes.
	maxTemplateLen = 4096
	// maxExpressions is the maximum number of {...} expressions.
	maxExpressions = 64
	// maxVariables is the maximum number of variable specifiers in total.
	maxVariables = 128
	// maxPrefixBudget bounds the sum of all prefix lengths in a template.
	// Prefix bounds are compiled to bounded repetitions, which RE2 expands
	// to one program copy per repetition, so they are the one construct
	// whose compiled size is not proportional to the template length.
	maxPrefixBudget = 512
	// maxPatternLen bounds the generated regular expression source.
	maxPatternLen = 64 << 10
)

// part is either a literal run of the template or an expression.
type part struct {
	lit  string
	expr *expression // non-nil for an expression
}

type expression struct {
	op   byte // 0 or one of + # . / ; ? &
	vars []varSpec
}

type varSpec struct {
	name    string
	prefix  int // 0 when there is no prefix modifier
	explode bool
}

// parseTemplate splits s into literals and expressions. It reports false if
// s is not a valid template, has no expressions, or exceeds the syntactic
// limits above.
func parseTemplate(s string) ([]part, bool) {
	if len(s) > maxTemplateLen {
		return nil, false
	}
	var parts []part
	exprs, vars := 0, 0
	for i := 0; i < len(s); {
		j := strings.IndexAny(s[i:], "{}")
		if j < 0 {
			parts = append(parts, part{lit: s[i:]})
			break
		}
		j += i
		if s[j] == '}' {
			return nil, false
		}
		if j > i {
			parts = append(parts, part{lit: s[i:j]})
		}
		end := strings.IndexByte(s[j+1:], '}')
		if end < 0 {
			return nil, false
		}
		end += j + 1
		body := s[j+1 : end]
		if strings.IndexByte(body, '{') >= 0 {
			return nil, false
		}
		e, ok := parseExpression(body)
		if !ok {
			return nil, false
		}
		exprs++
		vars += len(e.vars)
		if exprs > maxExpressions || vars > maxVariables {
			return nil, false
		}
		parts = append(parts, part{expr: e})
		i = end + 1
	}
	if exprs == 0 {
		return nil, false
	}
	return parts, true
}

// parseExpression parses the text between the braces of an expression.
func parseExpression(body string) (*expression, bool) {
	if body == "" {
		return nil, false
	}
	e := &expression{}
	switch body[0] {
	case '+', '#', '.', '/', ';', '?', '&':
		e.op = body[0]
		body = body[1:]
	case '=', ',', '!', '@', '|': // reserved for future extensions
		return nil, false
	}
	for body != "" || e.vars == nil {
		var spec string
		if i := strings.IndexByte(body, ','); i >= 0 {
			spec, body = body[:i], body[i+1:]
			if body == "" { // trailing comma
				return nil, false
			}
		} else {
			spec, body = body, ""
		}
		v, ok := parseVarSpec(spec)
		if !ok {
			return nil, false
		}
		e.vars = append(e.vars, v)
	}
	return e, true
}

func parseVarSpec(s string) (varSpec, bool) {
	var v varSpec
	if strings.HasSuffix(s, "*") {
		v.explode = true
		s = s[:len(s)-1]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if v.explode {
			return v, false
		}
		n, ok := parsePrefix(s[i+1:])
		if !ok {
			return v, false
		}
		v.prefix = n
		s = s[:i]
	}
	if !validVarName(s) {
		return v, false
	}
	v.name = s
	return v, true
}

// parsePrefix parses max-length = %x31-39 0*3DIGIT, so at most 9999.
func parsePrefix(s string) (int, bool) {
	if len(s) == 0 || len(s) > 4 || s[0] < '1' || s[0] > '9' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// validVarName reports whether n is a valid varname:
// varchar *( ["."] varchar ), varchar = ALPHA / DIGIT / "_" / pct-encoded.
func validVarName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); {
		c := n[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			i++
		case c == '%':
			if i+2 >= len(n) || !isHex(n[i+1]) || !isHex(n[i+2]) {
				return false
			}
			i += 3
		case c == '.':
			if i == 0 || i == len(n)-1 || n[i-1] == '.' {
				return false
			}
			i++
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// opInfo holds the RFC 6570 Appendix A expansion parameters of an operator.
type opInfo struct {
	first    string // prefix emitted once when the expression is not empty
	sep      string // separator between expanded variables
	named    bool   // emits name=value
	semi     bool   // empty named values are emitted without "="
	reserved bool   // values may contain reserved characters
}

func opFor(c byte) opInfo {
	switch c {
	case '+':
		return opInfo{sep: ",", reserved: true}
	case '#':
		return opInfo{first: "#", sep: ",", reserved: true}
	case '.':
		return opInfo{first: ".", sep: "."}
	case '/':
		return opInfo{first: "/", sep: "/"}
	case ';':
		return opInfo{first: ";", sep: ";", named: true, semi: true}
	case '?':
		return opInfo{first: "?", sep: "&", named: true}
	case '&':
		return opInfo{first: "&", sep: "&", named: true}
	}
	return opInfo{sep: ","}
}

// Regular expression building blocks. A value is a sequence of "units": a
// character from the operator's allowed set or a pct-encoded triplet. None of
// these contains a counted repetition, so they may be placed inside one.
const (
	unreservedSet = `A-Za-z0-9._~`
	reservedSet   = `:/?#\[\]@!$&'()*+,;=`
	hexPair       = `%[0-9A-Fa-f][0-9A-Fa-f]`
	// utf8Char matches the pct-encoding of exactly one UTF-8 encoded
	// character, so that prefix lengths count characters, not octets.
	utf8Char = `%[0-7][0-9A-Fa-f]` +
		`|%[CcDd][0-9A-Fa-f]%[89ABab][0-9A-Fa-f]` +
		`|%[Ee][0-9A-Fa-f]%[89ABab][0-9A-Fa-f]%[89ABab][0-9A-Fa-f]` +
		`|%[Ff][0-7]%[89ABab][0-9A-Fa-f]%[89ABab][0-9A-Fa-f]%[89ABab][0-9A-Fa-f]`
	// unitCost is an estimate of the compiled instructions in one prefix unit.
	unitCost = 40
)

// class returns the bracket expression of characters allowed in a value.
// comma additionally allows "," for operators where it is not already
// allowed; it is needed for list and associative array values, which are
// comma-joined unless exploded.
func (o opInfo) class(comma bool) string {
	s := unreservedSet
	if o.reserved {
		s += reservedSet
	} else if comma {
		s += ","
	}
	return "[" + s + "-]"
}

// unit matches one character of a value or one pct-encoded triplet.
func (o opInfo) unit(comma bool) string {
	return "(?:" + o.class(comma) + "|" + hexPair + ")"
}

// charUnit matches exactly one character of a prefix-limited value.
func (o opInfo) charUnit() string {
	u := "(?:" + o.class(false) + "|" + utf8Char
	if o.reserved {
		// Pre-encoded triplets in the value are passed through unchanged.
		u += "|" + hexPair
	}
	return u + ")"
}

type compiler struct {
	prefixTotal int
	cost        int // estimated compiled instruction count of prefix units
}

// item returns a regular expression matching the expansion of one variable
// specifier (excluding the operator's first/sep characters), for every kind
// of value (string, list, associative array) the specifier permits. copies is
// the number of times the item is emitted into the final pattern.
func (c *compiler) item(o opInfo, v varSpec, copies int) string {
	name := regexp.QuoteMeta(v.name)
	sep := regexp.QuoteMeta(o.sep)
	switch {
	case v.prefix > 0:
		c.prefixTotal += v.prefix
		c.cost += unitCost * v.prefix * copies
		u := o.charUnit()
		switch {
		case !o.named:
			return u + "{0," + strconv.Itoa(v.prefix) + "}"
		case o.semi:
			return name + "(?:=" + u + "{1," + strconv.Itoa(v.prefix) + "})?"
		default:
			return name + "=" + u + "{0," + strconv.Itoa(v.prefix) + "}"
		}

	case v.explode:
		u := o.unit(false)
		if o.named {
			// Exploded named values are name=elem pairs for lists and
			// key=value pairs for associative arrays. The former is
			// a special case of the latter (names are unit sequences).
			var pair string
			if o.semi {
				pair = u + "+(?:=" + u + "+)?"
			} else {
				pair = u + "+=" + u + "*"
			}
			return pair + "(?:" + sep + pair + ")*"
		}
		elem := u + "*"
		list := elem + "(?:" + sep + elem + ")*"
		if o.reserved {
			// "=" is an allowed character, so pairs are covered by list.
			return "(?:" + list + ")"
		}
		pair := u + "+=" + u + "*"
		return "(?:" + list + "|" + pair + "(?:" + sep + pair + ")*)"

	default:
		u := o.unit(true)
		switch {
		case !o.named:
			return u + "*"
		case o.semi:
			return name + "(?:=" + u + "+)?"
		default:
			return name + "=" + u + "*"
		}
	}
}

// expr returns a regular expression matching every possible expansion of e,
// including the empty expansion produced when all its variables are undefined.
func (c *compiler) expr(e *expression) string {
	o := opFor(e.op)
	sep := regexp.QuoteMeta(o.sep)
	first := regexp.QuoteMeta(o.first)
	var b strings.Builder

	if o.first == o.sep {
		// Every defined variable is preceded by the separator, which doubles
		// as the operator prefix for the first one.
		for _, v := range e.vars {
			b.WriteString("(?:" + sep + c.item(o, v, 1) + ")?")
		}
		return b.String()
	}

	// Otherwise the first defined variable is preceded by the operator prefix
	// and later ones by the separator. h matches a non-empty selection of
	// variables 0..i whose last member is at most i; extending it by variable
	// i is either "h, separator, item" or, when nothing was selected before,
	// just "item". This keeps the pattern linear in the number of variables.
	var h string
	for i, v := range e.vars {
		if i == 0 {
			h = c.item(o, v, 1)
			continue
		}
		it := c.item(o, v, 2)
		h = "(?:" + h + "(?:" + sep + it + ")?|" + it + ")"
	}
	b.WriteString("(?:" + first + h + ")?")
	return b.String()
}

// tmpl is a compiled URI template.
type tmpl struct {
	re   *regexp.Regexp
	cost int // estimated memory cost in compiled instructions
}

// compileTemplate compiles s. It returns nil if s is not a valid template or
// is too complex to compile within the package limits.
func compileTemplate(s string) *tmpl {
	parts, ok := parseTemplate(s)
	if !ok {
		return nil
	}
	var c compiler
	var b strings.Builder
	b.WriteString(`\A`)
	for _, p := range parts {
		if p.expr != nil {
			b.WriteString(c.expr(p.expr))
		} else {
			b.WriteString(regexp.QuoteMeta(p.lit))
		}
		if c.prefixTotal > maxPrefixBudget || b.Len() > maxPatternLen {
			return nil
		}
	}
	b.WriteString(`\z`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return &tmpl{re: re, cost: 1 + b.Len()/4 + c.cost + len(s)/16}
}
