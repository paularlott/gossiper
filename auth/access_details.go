package auth

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DetailType is the type of a Mercure authorization detail.
const DetailType = "https://mercure.rocks/authorization-detail"

// Default limits on Mercure authorization details.
const (
	DefaultMaxDetails       = 64
	DefaultMaxTopics        = 256
	DefaultMaxPatternLength = 4096
)

// Detail is one Mercure authorization detail.
type Detail struct {
	Actions []string        // as given; unknown ones are included and ignored by the hub
	Topics  []TopicMatcher  // never empty
	Payload json.RawMessage // a JSON object; nil when absent
}

// TopicMatcher is one entry of a detail's topics.
type TopicMatcher struct {
	Match     string // the matcher; "*" matches every topic whatever the type
	MatchType string // "exact" when the token gave none
}

// detailParser parses and bounds the authorization_details claim.
type detailParser struct {
	types      map[string]struct{}
	validate   func(matchType, pattern string) error
	maxDetails int
	maxTopics  int
	maxPattern int
}

// parse returns the Mercure details of an authorization_details claim, in
// token order. Details of other types are skipped; any malformed or over-limit
// Mercure detail fails the whole claim.
func (p *detailParser) parse(raw json.RawMessage) ([]Detail, error) {
	if !present(raw) {
		return nil, nil
	}
	if firstNonSpace(raw) != '[' {
		return nil, errors.New("authorization_details is not an array")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("authorization_details: %w", err)
	}
	var out []Detail
	for i, e := range entries {
		if firstNonSpace(e) != '{' {
			continue // not an object, so not a Mercure detail
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(e, &obj); err != nil {
			return nil, fmt.Errorf("authorization_details[%d]: %w", i, err)
		}
		var typ string
		if t := obj["type"]; len(t) == 0 || firstNonSpace(t) != '"' || json.Unmarshal(t, &typ) != nil || typ != DetailType {
			continue
		}
		if len(out) >= p.maxDetails {
			return nil, fmt.Errorf("more than %d Mercure authorization details", p.maxDetails)
		}
		d, err := p.detail(obj)
		if err != nil {
			return nil, fmt.Errorf("authorization_details[%d]: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func (p *detailParser) detail(obj map[string]json.RawMessage) (Detail, error) {
	var d Detail

	actions, err := array(obj["actions"])
	if err != nil {
		return d, fmt.Errorf("actions: %w", err)
	}
	for _, a := range actions {
		s, ok := jsonString(a)
		if !ok {
			return d, errors.New("actions: entry is not a string")
		}
		d.Actions = append(d.Actions, s)
	}

	topics, err := array(obj["topics"])
	if err != nil {
		return d, fmt.Errorf("topics: %w", err)
	}
	if len(topics) > p.maxTopics {
		return d, fmt.Errorf("topics: more than %d entries", p.maxTopics)
	}
	for _, t := range topics {
		m, err := p.topic(t)
		if err != nil {
			return d, fmt.Errorf("topics: %w", err)
		}
		d.Topics = append(d.Topics, m)
	}

	if pl, ok := obj["payload"]; ok {
		if firstNonSpace(pl) != '{' {
			return d, errors.New("payload is not an object")
		}
		d.Payload = append(json.RawMessage(nil), pl...)
	}
	return d, nil
}

func (p *detailParser) topic(raw json.RawMessage) (TopicMatcher, error) {
	var m TopicMatcher
	if firstNonSpace(raw) != '{' {
		return m, errors.New("matcher is not an object")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return m, err
	}
	var ok bool
	if m.Match, ok = jsonString(obj["match"]); !ok || m.Match == "" {
		return m, errors.New("match is missing or not a non-empty string")
	}
	if len(m.Match) > p.maxPattern {
		return m, fmt.Errorf("match longer than %d bytes", p.maxPattern)
	}
	m.MatchType = "exact"
	if mt, present := obj["match_type"]; present {
		if m.MatchType, ok = jsonString(mt); !ok {
			return m, errors.New("match_type is not a string")
		}
	}
	if _, ok := p.types[m.MatchType]; !ok {
		return m, fmt.Errorf("unsupported match_type %q", m.MatchType)
	}
	if p.validate != nil && m.Match != "*" {
		if err := p.validate(m.MatchType, m.Match); err != nil {
			return m, fmt.Errorf("invalid %s matcher: %w", m.MatchType, err)
		}
	}
	return m, nil
}

// array decodes a required, non-empty JSON array.
func array(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing")
	}
	if firstNonSpace(raw) != '[' {
		return nil, errors.New("not an array")
	}
	var a []json.RawMessage
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if len(a) == 0 {
		return nil, errors.New("empty")
	}
	return a, nil
}

// jsonString decodes raw as a JSON string; ok is false for any other type.
func jsonString(raw json.RawMessage) (s string, ok bool) {
	if len(raw) == 0 || firstNonSpace(raw) != '"' {
		return "", false
	}
	return s, json.Unmarshal(raw, &s) == nil
}

// present reports whether raw is a value other than absent or JSON null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}
