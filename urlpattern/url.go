package urlpattern

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file implements the parts of the WHATWG URL Standard needed by URL
// Pattern: the basic URL parser (including state overrides), host parsing and
// serialisation, and the percent-encode sets.

// urlRecord is a URL record (URL Standard §4.1).
type urlRecord struct {
	scheme   string
	username string
	password string
	host     string
	hasHost  bool
	port     int // -1 means null
	path     []string
	opaque   bool // path is an opaque path (opath)
	opath    string
	query    string
	hasQuery bool
	frag     string
	hasFrag  bool
}

func newURLRecord() *urlRecord { return &urlRecord{port: -1} }

// newDummyURL returns the result of parsing "https://dummy.invalid/".
func newDummyURL() *urlRecord {
	return &urlRecord{scheme: "https", host: "dummy.invalid", hasHost: true, port: -1, path: []string{""}}
}

func (u *urlRecord) isSpecial() bool { return isSpecialScheme(u.scheme) }

func (u *urlRecord) includesCredentials() bool { return u.username != "" || u.password != "" }

// pathString is the URL path serializer.
func (u *urlRecord) pathString() string {
	if u.opaque {
		return u.opath
	}
	switch len(u.path) {
	case 0:
		return ""
	case 1:
		return "/" + u.path[0]
	}
	n := 0
	for _, s := range u.path {
		n += len(s) + 1
	}
	var b strings.Builder
	b.Grow(n)
	for _, s := range u.path {
		b.WriteByte('/')
		b.WriteString(s)
	}
	return b.String()
}

func (u *urlRecord) shortenPath() {
	if u.scheme == "file" && len(u.path) == 1 && isNormalizedWindowsDriveLetter(u.path[0]) {
		return
	}
	if len(u.path) > 0 {
		u.path = u.path[:len(u.path)-1]
	}
}

func isSpecialScheme(s string) bool {
	switch s {
	case "http", "https", "ws", "wss", "ftp", "file":
		return true
	}
	return false
}

// defaultPort returns the default port of a special scheme, or -1.
func defaultPort(s string) int {
	switch s {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	case "ftp":
		return 21
	}
	return -1
}

// ---- percent-encode sets ----

const (
	setC0 uint8 = 1 << iota
	setFragment
	setQuery
	setSpecialQuery
	setPath
	setUserinfo
)

var encodeTable [128]uint8

func init() {
	add := func(bits uint8, chars string) {
		for i := 0; i < len(chars); i++ {
			encodeTable[chars[i]] |= bits
		}
	}
	for c := 0; c < 128; c++ {
		if c < 0x20 || c == 0x7F {
			encodeTable[c] |= setC0 | setFragment | setQuery | setSpecialQuery | setPath | setUserinfo
		}
	}
	add(setFragment|setUserinfo|setPath, " \"<>`")
	add(setQuery|setSpecialQuery|setPath|setUserinfo, " \"#<>")
	add(setSpecialQuery, "'")
	add(setPath|setUserinfo, "?^`{}")
	add(setUserinfo, "/:;=@[\\]|")
}

const upperHex = "0123456789ABCDEF"

// appendEncoded appends the UTF-8 percent-encoding of r under set to dst.
func appendEncoded(dst []byte, r rune, set uint8) []byte {
	if r >= 0 && r < 0x80 {
		if encodeTable[r]&set == 0 {
			return append(dst, byte(r))
		}
		return append(dst, '%', upperHex[r>>4], upperHex[r&15])
	}
	var tmp [4]byte
	n := utf8.EncodeRune(tmp[:], r)
	for _, b := range tmp[:n] {
		dst = append(dst, '%', upperHex[b>>4], upperHex[b&15])
	}
	return dst
}

func percentEncodeString(s string, set uint8) string {
	var dst []byte
	for _, r := range s {
		dst = appendEncoded(dst, r, set)
	}
	return string(dst)
}

// ---- character helpers ----

func isASCIIAlpha(c rune) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isASCIIDigit(c rune) bool { return c >= '0' && c <= '9' }
func isASCIIAlnum(c rune) bool { return isASCIIAlpha(c) || isASCIIDigit(c) }
func isASCIIHex(c rune) bool {
	return isASCIIDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c rune) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func isWindowsDriveLetter(s string) bool {
	return len(s) == 2 && isASCIIAlpha(rune(s[0])) && (s[1] == ':' || s[1] == '|')
}

func isNormalizedWindowsDriveLetter(s string) bool {
	return len(s) == 2 && isASCIIAlpha(rune(s[0])) && s[1] == ':'
}

// startsWithWindowsDriveLetter reports whether r starts with a Windows drive letter.
func startsWithWindowsDriveLetter(r []rune) bool {
	if len(r) < 2 || !isASCIIAlpha(r[0]) || (r[1] != ':' && r[1] != '|') {
		return false
	}
	if len(r) == 2 {
		return true
	}
	switch r[2] {
	case '/', '\\', '?', '#':
		return true
	}
	return false
}

func isSingleDot(s string) bool {
	return s == "." || strings.EqualFold(s, "%2e")
}

func isDoubleDot(s string) bool {
	if len(s) > 6 {
		return false
	}
	switch strings.ToLower(s) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

// ---- basic URL parser ----

type parseState uint8

const (
	stNone parseState = iota // no state override
	stSchemeStart
	stScheme
	stNoScheme
	stSpecialRelativeOrAuthority
	stPathOrAuthority
	stRelative
	stRelativeSlash
	stSpecialAuthoritySlashes
	stSpecialAuthorityIgnoreSlashes
	stAuthority
	stHost
	stHostname
	stPort
	stFile
	stFileSlash
	stFileHost
	stPathStart
	stPath
	stOpaquePath
	stQuery
	stFragment
)

func isC0OrSpace(r rune) bool { return r <= 0x20 }

// prepareInput trims C0/space (when trim is set) and removes tabs and newlines.
func prepareInput(input string, trim bool) []rune {
	if trim {
		input = strings.TrimFunc(input, isC0OrSpace)
	}
	runes := make([]rune, 0, len(input))
	for _, r := range input {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		runes = append(runes, r)
	}
	return runes
}

// basicParse is the basic URL parser. With url == nil it returns a new URL
// record (or false on failure). With url != nil and an override state it
// modifies url in place and reports failure by false.
func basicParse(input string, base *urlRecord, url *urlRecord, override parseState) (*urlRecord, bool) {
	if url == nil {
		url = newURLRecord()
	}
	runes := prepareInput(input, override == stNone)
	state := override
	if state == stNone {
		state = stSchemeStart
	}
	n := len(runes)
	var buf []byte
	atSignSeen, insideBrackets, passwordTokenSeen := false, false, false
	ptr := 0
	var opb, fragB []byte
	opSeeded, fragSeeded := false, false

	remainingStarts := func(r rune) bool { return ptr+1 < n && runes[ptr+1] == r }

	for {
		c := rune(-1)
		if ptr >= 0 && ptr < n {
			c = runes[ptr]
		}
		special := url.isSpecial()
		switch state {
		case stSchemeStart:
			if c >= 0 && isASCIIAlpha(c) {
				buf = append(buf, byte(c|0x20))
				state = stScheme
			} else if override == stNone {
				state = stNoScheme
				ptr--
			} else {
				return nil, false
			}

		case stScheme:
			if c >= 0 && (isASCIIAlnum(c) || c == '+' || c == '-' || c == '.') {
				if c >= 'A' && c <= 'Z' {
					c |= 0x20
				}
				buf = append(buf, byte(c))
			} else if c == ':' {
				bs := string(buf)
				if override != stNone {
					if special && !isSpecialScheme(bs) {
						return url, true
					}
					if !special && isSpecialScheme(bs) {
						return url, true
					}
					if (url.includesCredentials() || url.port != -1) && bs == "file" {
						return url, true
					}
					if url.scheme == "file" && url.hasHost && url.host == "" {
						return url, true
					}
				}
				url.scheme = bs
				special = url.isSpecial()
				if override != stNone {
					if url.port == defaultPort(url.scheme) {
						url.port = -1
					}
					return url, true
				}
				buf = buf[:0]
				if url.scheme == "file" {
					state = stFile
				} else if special && base != nil && base.scheme == url.scheme {
					state = stSpecialRelativeOrAuthority
				} else if special {
					state = stSpecialAuthoritySlashes
				} else if remainingStarts('/') {
					state = stPathOrAuthority
					ptr++
				} else {
					url.path = nil
					url.opaque = true
					url.opath = ""
					state = stOpaquePath
				}
			} else if override == stNone {
				buf = buf[:0]
				state = stNoScheme
				ptr = -1
			} else {
				return nil, false
			}

		case stNoScheme:
			if base == nil || (base.opaque && c != '#') {
				return nil, false
			} else if base.opaque && c == '#' {
				url.scheme = base.scheme
				url.path = nil
				url.opaque = true
				url.opath = base.opath
				url.query, url.hasQuery = base.query, base.hasQuery
				url.frag, url.hasFrag = "", true
				state = stFragment
			} else if base.scheme != "file" {
				state = stRelative
				ptr--
			} else {
				state = stFile
				ptr--
			}

		case stSpecialRelativeOrAuthority:
			if c == '/' && remainingStarts('/') {
				state = stSpecialAuthorityIgnoreSlashes
				ptr++
			} else {
				state = stRelative
				ptr--
			}

		case stPathOrAuthority:
			if c == '/' {
				state = stAuthority
			} else {
				state = stPath
				ptr--
			}

		case stRelative:
			url.scheme = base.scheme
			special = url.isSpecial()
			if c == '/' {
				state = stRelativeSlash
			} else if special && c == '\\' {
				state = stRelativeSlash
			} else {
				url.username, url.password = base.username, base.password
				url.host, url.hasHost = base.host, base.hasHost
				url.port = base.port
				url.path = append([]string(nil), base.path...)
				url.query, url.hasQuery = base.query, base.hasQuery
				if c == '?' {
					url.query, url.hasQuery = "", true
					state = stQuery
				} else if c == '#' {
					url.frag, url.hasFrag = "", true
					state = stFragment
				} else if c != -1 {
					url.query, url.hasQuery = "", false
					url.shortenPath()
					state = stPath
					ptr--
				}
			}

		case stRelativeSlash:
			if special && (c == '/' || c == '\\') {
				state = stSpecialAuthorityIgnoreSlashes
			} else if c == '/' {
				state = stAuthority
			} else {
				url.username, url.password = base.username, base.password
				url.host, url.hasHost = base.host, base.hasHost
				url.port = base.port
				state = stPath
				ptr--
			}

		case stSpecialAuthoritySlashes:
			if c == '/' && remainingStarts('/') {
				state = stSpecialAuthorityIgnoreSlashes
				ptr++
			} else {
				state = stSpecialAuthorityIgnoreSlashes
				ptr--
			}

		case stSpecialAuthorityIgnoreSlashes:
			if c != '/' && c != '\\' {
				state = stAuthority
				ptr--
			}

		case stAuthority:
			if c == '@' {
				if atSignSeen {
					buf = append([]byte("%40"), buf...)
				}
				atSignSeen = true
				var userBuf, passBuf []byte
				if url.username != "" {
					userBuf = []byte(url.username)
				}
				if url.password != "" {
					passBuf = []byte(url.password)
				}
				for _, cp := range string(buf) {
					if cp == ':' && !passwordTokenSeen {
						passwordTokenSeen = true
						continue
					}
					if passwordTokenSeen {
						passBuf = appendEncoded(passBuf, cp, setUserinfo)
					} else {
						userBuf = appendEncoded(userBuf, cp, setUserinfo)
					}
				}
				url.username, url.password = string(userBuf), string(passBuf)
				buf = buf[:0]
			} else if c == -1 || c == '/' || c == '?' || c == '#' || (special && c == '\\') {
				if atSignSeen && len(buf) == 0 {
					return nil, false
				}
				ptr -= utf8.RuneCount(buf) + 1
				buf = buf[:0]
				state = stHost
			} else {
				buf = utf8.AppendRune(buf, c)
			}

		case stHost, stHostname:
			if override != stNone && url.scheme == "file" {
				ptr--
				state = stFileHost
			} else if c == ':' && !insideBrackets {
				if len(buf) == 0 {
					return nil, false
				}
				if override == stHostname {
					return nil, false
				}
				host, ok := parseHost(string(buf), !special)
				if !ok {
					return nil, false
				}
				url.host, url.hasHost = host, true
				buf = buf[:0]
				state = stPort
			} else if c == -1 || c == '/' || c == '?' || c == '#' || (special && c == '\\') {
				ptr--
				if special && len(buf) == 0 {
					return nil, false
				} else if override != stNone && len(buf) == 0 && (url.includesCredentials() || url.port != -1) {
					return nil, false
				}
				host, ok := parseHost(string(buf), !special)
				if !ok {
					return nil, false
				}
				url.host, url.hasHost = host, true
				buf = buf[:0]
				state = stPathStart
				if override != stNone {
					return url, true
				}
			} else {
				if c == '[' {
					insideBrackets = true
				}
				if c == ']' {
					insideBrackets = false
				}
				buf = utf8.AppendRune(buf, c)
			}

		case stPort:
			if c >= 0 && isASCIIDigit(c) {
				buf = append(buf, byte(c))
			} else if c == -1 || c == '/' || c == '?' || c == '#' || (special && c == '\\') || override != stNone {
				if len(buf) != 0 {
					port := 0
					for _, d := range buf {
						port = port*10 + int(d-'0')
						if port > 65535 {
							return nil, false
						}
					}
					if port == defaultPort(url.scheme) {
						url.port = -1
					} else {
						url.port = port
					}
					buf = buf[:0]
					if override != stNone {
						return url, true
					}
				}
				if override != stNone {
					return nil, false
				}
				state = stPathStart
				ptr--
			} else {
				return nil, false
			}

		case stFile:
			url.scheme = "file"
			special = true
			url.host, url.hasHost = "", true
			if c == '/' || c == '\\' {
				state = stFileSlash
			} else if base != nil && base.scheme == "file" {
				url.host, url.hasHost = base.host, base.hasHost
				url.path = append([]string(nil), base.path...)
				url.query, url.hasQuery = base.query, base.hasQuery
				if c == '?' {
					url.query, url.hasQuery = "", true
					state = stQuery
				} else if c == '#' {
					url.frag, url.hasFrag = "", true
					state = stFragment
				} else if c != -1 {
					url.query, url.hasQuery = "", false
					if !startsWithWindowsDriveLetter(runes[ptr:]) {
						url.shortenPath()
					} else {
						url.path = nil
					}
					state = stPath
					ptr--
				}
			} else {
				state = stPath
				ptr--
			}

		case stFileSlash:
			if c == '/' || c == '\\' {
				state = stFileHost
			} else {
				if base != nil && base.scheme == "file" {
					url.host, url.hasHost = base.host, base.hasHost
					if !startsWithWindowsDriveLetter(runes[ptr:]) && len(base.path) > 0 && isNormalizedWindowsDriveLetter(base.path[0]) {
						url.path = append(url.path, base.path[0])
					}
				}
				state = stPath
				ptr--
			}

		case stFileHost:
			if c == -1 || c == '/' || c == '\\' || c == '?' || c == '#' {
				ptr--
				if override == stNone && isWindowsDriveLetter(string(buf)) {
					state = stPath
				} else if len(buf) == 0 {
					url.host, url.hasHost = "", true
					if override != stNone {
						return url, true
					}
					state = stPathStart
				} else {
					host, ok := parseHost(string(buf), !special)
					if !ok {
						return nil, false
					}
					if host == "localhost" {
						host = ""
					}
					url.host, url.hasHost = host, true
					if override != stNone {
						return url, true
					}
					buf = buf[:0]
					state = stPathStart
				}
			} else {
				buf = utf8.AppendRune(buf, c)
			}

		case stPathStart:
			if special {
				state = stPath
				if c != '/' && c != '\\' {
					ptr--
				}
			} else if override == stNone && c == '?' {
				url.query, url.hasQuery = "", true
				state = stQuery
			} else if override == stNone && c == '#' {
				url.frag, url.hasFrag = "", true
				state = stFragment
			} else if c != -1 {
				state = stPath
				if c != '/' {
					ptr--
				}
			} else if override != stNone && !url.hasHost {
				url.path = append(url.path, "")
			}

		case stPath:
			if c == -1 || c == '/' || (special && c == '\\') || (override == stNone && (c == '?' || c == '#')) {
				bs := string(buf)
				slashLike := c == '/' || (special && c == '\\')
				if isDoubleDot(bs) {
					url.shortenPath()
					if !slashLike {
						url.path = append(url.path, "")
					}
				} else if isSingleDot(bs) && !slashLike {
					url.path = append(url.path, "")
				} else if !isSingleDot(bs) {
					if url.scheme == "file" && len(url.path) == 0 && isWindowsDriveLetter(bs) {
						bs = bs[:1] + ":"
					}
					url.path = append(url.path, bs)
				}
				buf = buf[:0]
				if c == '?' {
					url.query, url.hasQuery = "", true
					state = stQuery
				}
				if c == '#' {
					url.frag, url.hasFrag = "", true
					state = stFragment
				}
			} else {
				buf = appendEncoded(buf, c, setPath)
			}

		case stOpaquePath:
			if c == '?' {
				url.query, url.hasQuery = "", true
				state = stQuery
			} else if c == '#' {
				url.frag, url.hasFrag = "", true
				state = stFragment
			} else if c == ' ' {
				if !opSeeded {
					opb, opSeeded = []byte(url.opath), true
				}
				if remainingStarts('?') || remainingStarts('#') {
					opb = append(opb, "%20"...)
				} else {
					opb = append(opb, ' ')
				}
			} else if c != -1 {
				if !opSeeded {
					opb, opSeeded = []byte(url.opath), true
				}
				opb = appendEncoded(opb, c, setC0)
			}

		case stQuery:
			if (override == stNone && c == '#') || c == -1 {
				set := setQuery
				if special {
					set = setSpecialQuery
				}
				var enc []byte
				for _, r := range string(buf) {
					enc = appendEncoded(enc, r, set)
				}
				url.query += string(enc)
				buf = buf[:0]
				if c == '#' {
					url.frag, url.hasFrag = "", true
					state = stFragment
				}
			} else if c != -1 {
				buf = utf8.AppendRune(buf, c)
			}

		case stFragment:
			if c != -1 {
				if !fragSeeded {
					fragB, fragSeeded = []byte(url.frag), true
				}
				fragB = appendEncoded(fragB, c, setFragment)
			}
		}

		if ptr >= n {
			break
		}
		ptr++
	}
	if opSeeded {
		url.opath = string(opb)
	}
	if fragSeeded {
		url.frag = string(fragB)
	}
	return url, true
}

// parseURL parses input against an optional base (nil = none).
func parseURL(input string, base *urlRecord) (*urlRecord, bool) {
	return basicParse(input, base, nil, stNone)
}

// ---- hosts ----

func isForbiddenHostCodePoint(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\r', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|':
		return true
	}
	return false
}

func isForbiddenDomainCodePoint(c byte) bool {
	return isForbiddenHostCodePoint(c) || c <= 0x1F || c == '%' || c == 0x7F
}

// parseHost is the host parser; the result is the serialised host.
func parseHost(input string, isOpaque bool) (string, bool) {
	if strings.HasPrefix(input, "[") {
		if !strings.HasSuffix(input, "]") {
			return "", false
		}
		addr, ok := parseIPv6(input[1 : len(input)-1])
		if !ok {
			return "", false
		}
		return "[" + serializeIPv6(addr) + "]", true
	}
	if isOpaque {
		return parseOpaqueHost(input)
	}
	domain := percentDecodeToString(input)
	ascii, ok := domainToASCII(domain)
	if !ok {
		return "", false
	}
	if endsInANumber(ascii) {
		v, ok := parseIPv4(ascii)
		if !ok {
			return "", false
		}
		return serializeIPv4(v), true
	}
	return ascii, true
}

func parseOpaqueHost(input string) (string, bool) {
	for i := 0; i < len(input); i++ {
		if isForbiddenHostCodePoint(input[i]) {
			return "", false
		}
	}
	var dst []byte
	for _, r := range input {
		dst = appendEncoded(dst, r, setC0)
	}
	return string(dst), true
}

// percentDecodeToString percent-decodes s and UTF-8 decodes the result
// (replacing invalid sequences with U+FFFD).
func percentDecodeToString(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isASCIIHex(rune(s[i+1])) && isASCIIHex(rune(s[i+2])) {
			b = append(b, byte(hexVal(rune(s[i+1]))<<4|hexVal(rune(s[i+2]))))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return strings.ToValidUTF8(string(b), "�")
}

func domainToASCII(domain string) (string, bool) {
	var result string
	if isASCIIString(domain) {
		result = asciiLower(domain)
	} else {
		var err error
		result, err = idnaProfile.ToASCII(domain)
		if err != nil {
			return "", false
		}
	}
	if result == "" {
		return "", false
	}
	for i := 0; i < len(result); i++ {
		if isForbiddenDomainCodePoint(result[i]) {
			return "", false
		}
	}
	return result, true
}

func endsInANumber(s string) bool {
	parts := strings.Split(s, ".")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
		if len(parts) == 0 {
			return false
		}
	}
	last := parts[len(parts)-1]
	if last != "" {
		allDigits := true
		for i := 0; i < len(last); i++ {
			if last[i] < '0' || last[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	_, ok := parseIPv4Number(last)
	return ok
}

const ipv4Cap = 1 << 40

// parseIPv4Number parses an IPv4 number; values saturate at ipv4Cap.
func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	radix := uint64(10)
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
		radix = 16
	} else if len(s) >= 2 && s[0] == '0' {
		s = s[1:]
		radix = 8
	}
	if s == "" {
		return 0, true
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := rune(s[i])
		var d uint64
		switch {
		case isASCIIDigit(c):
			d = uint64(c - '0')
		case radix == 16 && isASCIIHex(c):
			d = uint64(hexVal(c))
		default:
			return 0, false
		}
		if d >= radix {
			return 0, false
		}
		v = v*radix + d
		if v > ipv4Cap {
			v = ipv4Cap
		}
	}
	return v, true
}

func parseIPv4(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return 0, false
	}
	nums := make([]uint64, 0, 4)
	for _, p := range parts {
		v, ok := parseIPv4Number(p)
		if !ok {
			return 0, false
		}
		nums = append(nums, v)
	}
	for _, v := range nums[:len(nums)-1] {
		if v > 255 {
			return 0, false
		}
	}
	last := nums[len(nums)-1]
	limit := uint64(1) << (8 * uint(5-len(nums)))
	if last >= limit {
		return 0, false
	}
	ipv4 := last
	for i, v := range nums[:len(nums)-1] {
		ipv4 += v << (8 * uint(3-i))
	}
	return uint32(ipv4), true
}

func serializeIPv4(v uint32) string {
	return strconv.Itoa(int(v>>24)) + "." + strconv.Itoa(int(v>>16&255)) + "." +
		strconv.Itoa(int(v>>8&255)) + "." + strconv.Itoa(int(v&255))
}

func parseIPv6(in string) ([8]uint16, bool) {
	var addr [8]uint16
	pieceIndex := 0
	compress := -1
	p := 0
	n := len(in)
	c := func() rune {
		if p < n {
			return rune(in[p])
		}
		return -1
	}
	if c() == ':' {
		if !(p+1 < n && in[p+1] == ':') {
			return addr, false
		}
		p += 2
		pieceIndex++
		compress = pieceIndex
	}
	for c() != -1 {
		if pieceIndex == 8 {
			return addr, false
		}
		if c() == ':' {
			if compress != -1 {
				return addr, false
			}
			p++
			pieceIndex++
			compress = pieceIndex
			continue
		}
		value, length := 0, 0
		for length < 4 && c() != -1 && isASCIIHex(c()) {
			value = value*16 + hexVal(c())
			p++
			length++
		}
		if c() == '.' {
			if length == 0 {
				return addr, false
			}
			p -= length
			if pieceIndex > 6 {
				return addr, false
			}
			numbersSeen := 0
			for c() != -1 {
				ipv4Piece := -1
				if numbersSeen > 0 {
					if c() == '.' && numbersSeen < 4 {
						p++
					} else {
						return addr, false
					}
				}
				if c() == -1 || !isASCIIDigit(c()) {
					return addr, false
				}
				for c() != -1 && isASCIIDigit(c()) {
					number := int(c() - '0')
					if ipv4Piece == -1 {
						ipv4Piece = number
					} else if ipv4Piece == 0 {
						return addr, false
					} else {
						ipv4Piece = ipv4Piece*10 + number
					}
					if ipv4Piece > 255 {
						return addr, false
					}
					p++
				}
				addr[pieceIndex] = addr[pieceIndex]*0x100 + uint16(ipv4Piece)
				numbersSeen++
				if numbersSeen == 2 || numbersSeen == 4 {
					pieceIndex++
				}
			}
			if numbersSeen != 4 {
				return addr, false
			}
			break
		} else if c() == ':' {
			p++
			if c() == -1 {
				return addr, false
			}
		} else if c() != -1 {
			return addr, false
		}
		addr[pieceIndex] = uint16(value)
		pieceIndex++
	}
	if compress != -1 {
		swaps := pieceIndex - compress
		pieceIndex = 7
		for pieceIndex != 0 && swaps > 0 {
			addr[pieceIndex], addr[compress+swaps-1] = addr[compress+swaps-1], addr[pieceIndex]
			pieceIndex--
			swaps--
		}
	} else if pieceIndex != 8 {
		return addr, false
	}
	return addr, true
}

func serializeIPv6(a [8]uint16) string {
	// Find the first longest run (length > 1) of zero pieces.
	longestIdx, longestSize := -1, 1
	foundIdx, foundSize := -1, 0
	for i, v := range a {
		if v != 0 {
			if foundSize > longestSize {
				longestIdx, longestSize = foundIdx, foundSize
			}
			foundIdx, foundSize = -1, 0
		} else {
			if foundIdx == -1 {
				foundIdx = i
			}
			foundSize++
		}
	}
	compress := longestIdx
	if foundSize > longestSize {
		compress = foundIdx
	}
	var b strings.Builder
	ignore0 := false
	for i, v := range a {
		if ignore0 && v == 0 {
			continue
		} else if ignore0 {
			ignore0 = false
		}
		if compress == i {
			if i == 0 {
				b.WriteString("::")
			} else {
				b.WriteByte(':')
			}
			ignore0 = true
			continue
		}
		b.WriteString(strconv.FormatUint(uint64(v), 16))
		if i != 7 {
			b.WriteByte(':')
		}
	}
	return b.String()
}
