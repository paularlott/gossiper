package urlpattern

// This file implements the constructor string parser (spec §1.6).

type ctorState uint8

const (
	csInit ctorState = iota
	csProtocol
	csAuthority
	csUsername
	csPassword
	csHostname
	csPort
	csPathname
	csSearch
	csHash
	csDone
)

type ctorParser struct {
	input          []rune
	tokens         []token
	result         Init
	componentStart int
	tokenIndex     int
	tokenIncrement int
	groupDepth     int
	ipv6Depth      int
	protocolSpec   bool // protocol matches a special scheme
	state          ctorState
}

func (p *ctorParser) setResult(st ctorState, v string) {
	switch st {
	case csProtocol:
		p.result.Protocol = &v
	case csUsername:
		p.result.Username = &v
	case csPassword:
		p.result.Password = &v
	case csHostname:
		p.result.Hostname = &v
	case csPort:
		p.result.Port = &v
	case csPathname:
		p.result.Pathname = &v
	case csSearch:
		p.result.Search = &v
	case csHash:
		p.result.Hash = &v
	}
}

func (p *ctorParser) safeToken(i int) token {
	if i < len(p.tokens) {
		return p.tokens[i]
	}
	return p.tokens[len(p.tokens)-1]
}

func (p *ctorParser) isNonSpecialPatternChar(i int, value string) bool {
	t := p.safeToken(i)
	if t.value != value {
		return false
	}
	return t.typ == tkChar || t.typ == tkEscapedChar || t.typ == tkInvalidChar
}

func (p *ctorParser) isProtocolSuffix() bool { return p.isNonSpecialPatternChar(p.tokenIndex, ":") }

func (p *ctorParser) nextIsAuthoritySlashes() bool {
	return p.isNonSpecialPatternChar(p.tokenIndex+1, "/") && p.isNonSpecialPatternChar(p.tokenIndex+2, "/")
}

func (p *ctorParser) isIdentityTerminator() bool { return p.isNonSpecialPatternChar(p.tokenIndex, "@") }
func (p *ctorParser) isPasswordPrefix() bool     { return p.isNonSpecialPatternChar(p.tokenIndex, ":") }
func (p *ctorParser) isPortPrefix() bool         { return p.isNonSpecialPatternChar(p.tokenIndex, ":") }
func (p *ctorParser) isPathnameStart() bool      { return p.isNonSpecialPatternChar(p.tokenIndex, "/") }
func (p *ctorParser) isHashPrefix() bool         { return p.isNonSpecialPatternChar(p.tokenIndex, "#") }
func (p *ctorParser) isIPv6Open() bool           { return p.isNonSpecialPatternChar(p.tokenIndex, "[") }
func (p *ctorParser) isIPv6Close() bool          { return p.isNonSpecialPatternChar(p.tokenIndex, "]") }
func (p *ctorParser) isGroupOpen() bool          { return p.tokens[p.tokenIndex].typ == tkOpen }
func (p *ctorParser) isGroupClose() bool         { return p.tokens[p.tokenIndex].typ == tkClose }

func (p *ctorParser) isSearchPrefix() bool {
	if p.isNonSpecialPatternChar(p.tokenIndex, "?") {
		return true
	}
	if p.tokens[p.tokenIndex].value != "?" {
		return false
	}
	prev := p.tokenIndex - 1
	if prev < 0 {
		return true
	}
	switch p.safeToken(prev).typ {
	case tkName, tkRegexp, tkClose, tkAsterisk:
		return false
	}
	return true
}

func (p *ctorParser) makeComponentString() string {
	tok := p.tokens[p.tokenIndex]
	start := p.safeToken(p.componentStart)
	return string(p.input[start.index:tok.index])
}

func (p *ctorParser) rewind() {
	p.tokenIndex = p.componentStart
	p.tokenIncrement = 0
}

func (p *ctorParser) rewindAndSetState(st ctorState) {
	p.rewind()
	p.state = st
}

func (p *ctorParser) changeState(newState ctorState, skip int) {
	if p.state != csInit && p.state != csAuthority && p.state != csDone {
		p.setResult(p.state, p.makeComponentString())
	}
	if p.state != csInit && newState != csDone {
		st := p.state
		if (st == csProtocol || st == csAuthority || st == csUsername || st == csPassword) &&
			(newState == csPort || newState == csPathname || newState == csSearch || newState == csHash) &&
			p.result.Hostname == nil {
			p.setResult(csHostname, "")
		}
		if (st == csProtocol || st == csAuthority || st == csUsername || st == csPassword || st == csHostname || st == csPort) &&
			(newState == csSearch || newState == csHash) && p.result.Pathname == nil {
			if p.protocolSpec {
				p.setResult(csPathname, "/")
			} else {
				p.setResult(csPathname, "")
			}
		}
		if (st == csProtocol || st == csAuthority || st == csUsername || st == csPassword || st == csHostname ||
			st == csPort || st == csPathname) && newState == csHash && p.result.Search == nil {
			p.setResult(csSearch, "")
		}
	}
	p.state = newState
	p.tokenIndex += skip
	p.componentStart = p.tokenIndex
	p.tokenIncrement = 0
}

func (p *ctorParser) computeProtocolMatchesSpecialScheme() error {
	s := p.makeComponentString()
	c, err := compileComponent(s, canonProtocol, defaultOptions)
	if err != nil {
		return err
	}
	p.protocolSpec = c.matchesSpecialScheme()
	return nil
}

// parseConstructorString implements "parse a constructor string".
func parseConstructorString(input string) (Init, error) {
	runes := []rune(input)
	toks, err := tokenize(runes, false)
	if err != nil {
		return Init{}, err
	}
	p := &ctorParser{input: runes, tokens: toks, state: csInit}
	for p.tokenIndex < len(p.tokens) {
		p.tokenIncrement = 1
		if p.tokens[p.tokenIndex].typ == tkEnd {
			if p.state == csInit {
				p.rewind()
				if p.isHashPrefix() {
					p.changeState(csHash, 1)
				} else if p.isSearchPrefix() {
					p.changeState(csSearch, 1)
				} else {
					p.changeState(csPathname, 0)
				}
				p.tokenIndex += p.tokenIncrement
				continue
			}
			if p.state == csAuthority {
				p.rewindAndSetState(csHostname)
				p.tokenIndex += p.tokenIncrement
				continue
			}
			p.changeState(csDone, 0)
			break
		}
		if p.isGroupOpen() {
			p.groupDepth++
			p.tokenIndex += p.tokenIncrement
			continue
		}
		if p.groupDepth > 0 {
			if p.isGroupClose() {
				p.groupDepth--
			} else {
				p.tokenIndex += p.tokenIncrement
				continue
			}
		}
		switch p.state {
		case csInit:
			if p.isProtocolSuffix() {
				p.rewindAndSetState(csProtocol)
			}
		case csProtocol:
			if p.isProtocolSuffix() {
				if err := p.computeProtocolMatchesSpecialScheme(); err != nil {
					return Init{}, err
				}
				next := csPathname
				skip := 1
				if p.nextIsAuthoritySlashes() {
					next = csAuthority
					skip = 3
				} else if p.protocolSpec {
					next = csAuthority
				}
				p.changeState(next, skip)
			}
		case csAuthority:
			if p.isIdentityTerminator() {
				p.rewindAndSetState(csUsername)
			} else if p.isPathnameStart() || p.isSearchPrefix() || p.isHashPrefix() {
				p.rewindAndSetState(csHostname)
			}
		case csUsername:
			if p.isPasswordPrefix() {
				p.changeState(csPassword, 1)
			} else if p.isIdentityTerminator() {
				p.changeState(csHostname, 1)
			}
		case csPassword:
			if p.isIdentityTerminator() {
				p.changeState(csHostname, 1)
			}
		case csHostname:
			if p.isIPv6Open() {
				p.ipv6Depth++
			} else if p.isIPv6Close() {
				p.ipv6Depth--
			} else if p.isPortPrefix() && p.ipv6Depth == 0 {
				p.changeState(csPort, 1)
			} else if p.isPathnameStart() {
				p.changeState(csPathname, 0)
			} else if p.isSearchPrefix() {
				p.changeState(csSearch, 1)
			} else if p.isHashPrefix() {
				p.changeState(csHash, 1)
			}
		case csPort:
			if p.isPathnameStart() {
				p.changeState(csPathname, 0)
			} else if p.isSearchPrefix() {
				p.changeState(csSearch, 1)
			} else if p.isHashPrefix() {
				p.changeState(csHash, 1)
			}
		case csPathname:
			if p.isSearchPrefix() {
				p.changeState(csSearch, 1)
			} else if p.isHashPrefix() {
				p.changeState(csHash, 1)
			}
		case csSearch:
			if p.isHashPrefix() {
				p.changeState(csHash, 1)
			}
		}
		p.tokenIndex += p.tokenIncrement
	}
	if p.result.Hostname != nil && p.result.Port == nil {
		p.setResult(csPort, "")
	}
	return p.result, nil
}
