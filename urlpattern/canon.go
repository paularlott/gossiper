package urlpattern

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile is the "domain parser ToASCII" profile with beStrict = false:
// CheckHyphens=false, CheckBidi=true, CheckJoiners=true,
// UseSTD3ASCIIRules=false, Transitional_Processing=false,
// VerifyDnsLength=false.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.Transitional(false),
	idna.CheckHyphens(false),
	idna.CheckJoiners(true),
	idna.BidiRule(),
	idna.VerifyDNSLength(false),
)

// encodeFunc is an encoding callback (spec §2.1.5).
type encodeFunc func(string) (string, error)

var errCanon = errors.New("urlpattern: invalid URL component")

func canonProtocol(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	u, ok := basicParse(value+"://dummy.invalid/", nil, nil, stNone)
	if !ok {
		return "", errCanon
	}
	return u.scheme, nil
}

func canonUsername(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	return percentEncodeString(value, setUserinfo), nil
}

func canonPassword(value string) (string, error) { return canonUsername(value) }

func canonHostname(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	u := newDummyURL()
	if _, ok := basicParse(value, nil, u, stHostname); !ok {
		return "", errCanon
	}
	if !u.hasHost {
		return "", nil
	}
	return u.host, nil
}

func canonIPv6Hostname(value string) (string, error) {
	var b strings.Builder
	for _, r := range value {
		if !isASCIIHex(r) && r != '[' && r != ']' && r != ':' {
			return "", errCanon
		}
		if r >= 'A' && r <= 'Z' {
			r |= 0x20
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

// canonPortFor canonicalizes a port; protocol is nil when not supplied.
func canonPortFor(value string, protocol *string) (string, error) {
	if value == "" {
		return value, nil
	}
	u := newDummyURL()
	if protocol != nil {
		u.scheme = *protocol
	} else {
		u.scheme = ""
	}
	if _, ok := basicParse(value, nil, u, stPort); !ok {
		return "", errCanon
	}
	if u.port < 0 {
		return "", nil
	}
	return itoa(u.port), nil
}

func canonPort(value string) (string, error) { return canonPortFor(value, nil) }

func canonPathname(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	leadingSlash := value[0] == '/'
	modified := value
	if !leadingSlash {
		modified = "/-" + value
	}
	u := newDummyURL()
	u.path = nil
	basicParse(modified, nil, u, stPathStart)
	result := u.pathString()
	if !leadingSlash {
		result = result[2:]
	}
	return result, nil
}

func canonOpaquePathname(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	u := newDummyURL()
	u.path = nil
	u.opaque = true
	u.opath = ""
	if _, ok := basicParse(value, nil, u, stOpaquePath); !ok {
		return "", errCanon
	}
	return u.pathString(), nil
}

func canonSearch(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	u := newDummyURL()
	u.query, u.hasQuery = "", true
	basicParse(value, nil, u, stQuery)
	return u.query, nil
}

func canonHash(value string) (string, error) {
	if value == "" {
		return value, nil
	}
	u := newDummyURL()
	u.frag, u.hasFrag = "", true
	basicParse(value, nil, u, stFragment)
	return u.frag, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ---- URLPatternInit processing (spec §3.2) ----

// Init is the dictionary form of a URL pattern or of a URL to match
// (URLPatternInit). A nil field is absent; a non-nil field is present, even if
// it points at the empty string.
type Init struct {
	Protocol, Username, Password, Hostname, Port, Pathname, Search, Hash *string
	// BaseURL supplies defaults for components that are not given.
	BaseURL *string
}

// S returns a pointer to s, for filling in [Init] fields.
func S(s string) *string { return &s }

// processBaseURLString escapes the pattern syntax in a base URL component when
// building a pattern.
func processBaseURLString(input string, isPattern bool) string {
	if !isPattern {
		return input
	}
	return escapePatternString(input)
}

func isAbsolutePathname(input string, isPattern bool) bool {
	if input == "" {
		return false
	}
	if input[0] == '/' {
		return true
	}
	if !isPattern {
		return false
	}
	if len(input) < 2 {
		return false
	}
	if input[0] == '\\' && input[1] == '/' {
		return true
	}
	if input[0] == '{' && input[1] == '/' {
		return true
	}
	return false
}

// processInit implements "process a URLPatternInit". pre holds the initial
// component values (all nil for type "pattern").
func processInit(init Init, isPattern bool, pre Init) (Init, error) {
	result := pre
	result.BaseURL = nil
	var baseURL *urlRecord
	if init.BaseURL != nil {
		b, ok := parseURL(*init.BaseURL, nil)
		if !ok {
			return Init{}, errors.New("urlpattern: invalid base URL")
		}
		baseURL = b
		if init.Protocol == nil {
			result.Protocol = S(processBaseURLString(baseURL.scheme, isPattern))
		}
		if !isPattern && init.Protocol == nil && init.Hostname == nil && init.Port == nil && init.Username == nil {
			result.Username = S(processBaseURLString(baseURL.username, isPattern))
		}
		if !isPattern && init.Protocol == nil && init.Hostname == nil && init.Port == nil && init.Username == nil && init.Password == nil {
			result.Password = S(processBaseURLString(baseURL.password, isPattern))
		}
		if init.Protocol == nil && init.Hostname == nil {
			baseHost := ""
			if baseURL.hasHost {
				baseHost = baseURL.host
			}
			result.Hostname = S(processBaseURLString(baseHost, isPattern))
		}
		if init.Protocol == nil && init.Hostname == nil && init.Port == nil {
			if baseURL.port < 0 {
				result.Port = S("")
			} else {
				result.Port = S(itoa(baseURL.port))
			}
		}
		if init.Protocol == nil && init.Hostname == nil && init.Port == nil && init.Pathname == nil {
			result.Pathname = S(processBaseURLString(baseURL.pathString(), isPattern))
		}
		if init.Protocol == nil && init.Hostname == nil && init.Port == nil && init.Pathname == nil && init.Search == nil {
			q := ""
			if baseURL.hasQuery {
				q = baseURL.query
			}
			result.Search = S(processBaseURLString(q, isPattern))
		}
		if init.Protocol == nil && init.Hostname == nil && init.Port == nil && init.Pathname == nil && init.Search == nil && init.Hash == nil {
			f := ""
			if baseURL.hasFrag {
				f = baseURL.frag
			}
			result.Hash = S(processBaseURLString(f, isPattern))
		}
	}
	if init.Protocol != nil {
		v, err := processProtocolForInit(*init.Protocol, isPattern)
		if err != nil {
			return Init{}, err
		}
		result.Protocol = &v
	}
	if init.Username != nil {
		v := *init.Username
		if !isPattern {
			var err error
			if v, err = canonUsername(v); err != nil {
				return Init{}, err
			}
		}
		result.Username = &v
	}
	if init.Password != nil {
		v := *init.Password
		if !isPattern {
			var err error
			if v, err = canonPassword(v); err != nil {
				return Init{}, err
			}
		}
		result.Password = &v
	}
	if init.Hostname != nil {
		v := *init.Hostname
		if !isPattern {
			var err error
			if v, err = canonHostname(v); err != nil {
				return Init{}, err
			}
		}
		result.Hostname = &v
	}
	resultProtocol := ""
	if result.Protocol != nil {
		resultProtocol = *result.Protocol
	}
	if init.Port != nil {
		v := *init.Port
		if !isPattern {
			var err error
			if v, err = canonPortFor(v, &resultProtocol); err != nil {
				return Init{}, err
			}
		}
		result.Port = &v
	}
	if init.Pathname != nil {
		p := *init.Pathname
		if baseURL != nil && !baseURL.opaque && !isAbsolutePathname(p, isPattern) {
			baseURLPath := processBaseURLString(baseURL.pathString(), isPattern)
			if i := strings.LastIndexByte(baseURLPath, '/'); i >= 0 {
				p = baseURLPath[:i+1] + p
			}
		}
		if !isPattern {
			var err error
			if isSpecialScheme(resultProtocol) || resultProtocol == "" {
				p, err = canonPathname(p)
			} else {
				p, err = canonOpaquePathname(p)
			}
			if err != nil {
				return Init{}, err
			}
		}
		result.Pathname = &p
	}
	if init.Search != nil {
		v := strings.TrimPrefix(*init.Search, "?")
		if !isPattern {
			var err error
			if v, err = canonSearch(v); err != nil {
				return Init{}, err
			}
		}
		result.Search = &v
	}
	if init.Hash != nil {
		v := strings.TrimPrefix(*init.Hash, "#")
		if !isPattern {
			var err error
			if v, err = canonHash(v); err != nil {
				return Init{}, err
			}
		}
		result.Hash = &v
	}
	return result, nil
}

func processProtocolForInit(value string, isPattern bool) (string, error) {
	stripped := strings.TrimSuffix(value, ":")
	if isPattern {
		return stripped, nil
	}
	return canonProtocol(stripped)
}
