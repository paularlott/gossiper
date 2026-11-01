package topic

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// A minimal RFC 6570 expander used as an oracle by the tests. It follows the
// algorithm of RFC 6570 section 3.2.1 and is independent of the template
// parser in the package under test.

type kind int

const (
	undef kind = iota
	str
	list
	assoc
)

type kv struct{ k, v string }

type value struct {
	kind kind
	s    string
	l    []string
	m    []kv
}

type vars map[string]value

func S(s string) value    { return value{kind: str, s: s} }
func L(l ...string) value { return value{kind: list, l: l} }
func M(kvs ...string) value {
	v := value{kind: assoc}
	for i := 0; i+1 < len(kvs); i += 2 {
		v.m = append(v.m, kv{kvs[i], kvs[i+1]})
	}
	return v
}

// rfcVars is the variable set of RFC 6570 sections 1.2 and 3.2.
func rfcVars() vars {
	return vars{
		"count":      L("one", "two", "three"),
		"dom":        L("example", "com"),
		"dub":        S("me/too"),
		"hello":      S("Hello World!"),
		"half":       S("50%"),
		"var":        S("value"),
		"who":        S("fred"),
		"base":       S("http://example.com/home/"),
		"path":       S("/foo/bar"),
		"list":       L("red", "green", "blue"),
		"keys":       M("semi", ";", "dot", ".", "comma", ","),
		"v":          S("6"),
		"x":          S("1024"),
		"y":          S("768"),
		"empty":      S(""),
		"empty_keys": M(),
		// "undef" is deliberately absent.
	}
}

type opSpec struct {
	first, sep string
	named      bool
	ifemp      string
	allowR     bool
}

func opSpecFor(op string) opSpec {
	switch op {
	case "+":
		return opSpec{"", ",", false, "", true}
	case "#":
		return opSpec{"#", ",", false, "", true}
	case ".":
		return opSpec{".", ".", false, "", false}
	case "/":
		return opSpec{"/", "/", false, "", false}
	case ";":
		return opSpec{";", ";", true, "", false}
	case "?":
		return opSpec{"?", "&", true, "=", false}
	case "&":
		return opSpec{"&", "&", true, "=", false}
	}
	return opSpec{"", ",", false, "", false}
}

func isUnreserved(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		r == '-' || r == '.' || r == '_' || r == '~'
}

const reservedChars = ":/?#[]@!$&'()*+,;="

func isHexByte(c byte) bool { return isHex(c) }

// encode percent-encodes s as RFC 6570 section 3.2.1 prescribes.
func encode(s string, allowReserved bool) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case isUnreserved(r):
			b.WriteRune(r)
		case allowReserved && strings.ContainsRune(reservedChars, r):
			b.WriteRune(r)
		case allowReserved && r == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]):
			b.WriteString(s[i : i+3])
			n = 3
		default:
			for j := 0; j < n; j++ {
				fmt.Fprintf(&b, "%%%02X", s[i+j])
			}
		}
		i += n
	}
	return b.String()
}

func truncateRunes(s string, n int) string {
	i := 0
	for ; n > 0 && i < len(s); n-- {
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return s[:i]
}

type varspecT struct {
	name    string
	prefix  int
	explode bool
}

func splitSpec(s string) varspecT {
	v := varspecT{}
	if strings.HasSuffix(s, "*") {
		v.explode = true
		s = s[:len(s)-1]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		fmt.Sscanf(s[i+1:], "%d", &v.prefix)
		s = s[:i]
	}
	v.name = s
	return v
}

// expand expands a template, assumed valid, with the given variables.
func expand(tpl string, vs vars) string {
	var out strings.Builder
	for tpl != "" {
		i := strings.IndexByte(tpl, '{')
		if i < 0 {
			out.WriteString(tpl)
			break
		}
		out.WriteString(tpl[:i])
		j := strings.IndexByte(tpl, '}')
		out.WriteString(expandExpr(tpl[i+1:j], vs))
		tpl = tpl[j+1:]
	}
	return out.String()
}

func expandExpr(body string, vs vars) string {
	op := ""
	if strings.ContainsRune("+#./;?&", rune(body[0])) {
		op, body = body[:1], body[1:]
	}
	o := opSpecFor(op)
	var items []string
	for _, spec := range strings.Split(body, ",") {
		v := splitSpec(spec)
		if it, ok := expandVar(o, v, vs[v.name]); ok {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return ""
	}
	return o.first + strings.Join(items, o.sep)
}

func expandVar(o opSpec, v varspecT, val value) (string, bool) {
	enc := func(s string) string { return encode(s, o.allowR) }
	// named renders name=value, applying the empty-value rule.
	named := func(name, s string) string {
		if s == "" {
			return name + o.ifemp
		}
		return name + "=" + s
	}
	switch val.kind {
	case str:
		s := val.s
		if v.prefix > 0 {
			s = truncateRunes(s, v.prefix)
		}
		if o.named {
			return named(v.name, enc(s)), true
		}
		return enc(s), true
	case list:
		if len(val.l) == 0 {
			return "", false
		}
		var es []string
		for _, e := range val.l {
			es = append(es, enc(e))
		}
		if !v.explode {
			j := strings.Join(es, ",")
			if o.named {
				return named(v.name, j), true
			}
			return j, true
		}
		if !o.named {
			return strings.Join(es, o.sep), true
		}
		var ps []string
		for _, e := range es {
			ps = append(ps, named(v.name, e))
		}
		return strings.Join(ps, o.sep), true
	case assoc:
		if len(val.m) == 0 {
			return "", false
		}
		if !v.explode {
			var es []string
			for _, p := range val.m {
				es = append(es, enc(p.k), enc(p.v))
			}
			j := strings.Join(es, ",")
			if o.named {
				return named(v.name, j), true
			}
			return j, true
		}
		var ps []string
		for _, p := range val.m {
			if o.named {
				ps = append(ps, named(enc(p.k), enc(p.v)))
			} else {
				ps = append(ps, enc(p.k)+"="+enc(p.v))
			}
		}
		return strings.Join(ps, o.sep), true
	}
	return "", false
}
