package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/auth"
)

// tenantsFile is the JSON file named by --tenants-file.
type tenantsFile struct {
	Tenants []tenantSpec `json:"tenants"`
}

// tenantSpec is one tenant: the hosts that pick its hub, and the hub's keys.
type tenantSpec struct {
	Name    string         `json:"name"`
	Hosts   []string       `json:"hosts,omitempty"`
	Mercure *tenantMercure `json:"mercure,omitempty"`
}

// tenantMercure is a tenant's Mercure hub settings; the rest are the server's.
type tenantMercure struct {
	PublisherKey         string   `json:"publisher_key,omitempty"`
	PublisherAlg         string   `json:"publisher_alg,omitempty"`
	PublisherJWKSURL     string   `json:"publisher_jwks_url,omitempty"`
	SubscriberKey        string   `json:"subscriber_key,omitempty"`
	SubscriberAlg        string   `json:"subscriber_alg,omitempty"`
	SubscriberJWKSURL    string   `json:"subscriber_jwks_url,omitempty"`
	TrustedIssuers       []string `json:"trusted_issuers,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ResourceIdentifier   string   `json:"resource_identifier,omitempty"`
	HubURL               string   `json:"hub_url,omitempty"`
	Anonymous            bool     `json:"anonymous,omitempty"`
	Subscriptions        bool     `json:"subscriptions,omitempty"`
	// The tenant's browser settings; each, when set, replaces the server's.
	CORSOrigins           []string `json:"cors_origins,omitempty"`
	PublishOrigins        []string `json:"publish_origins,omitempty"`
	CookieName            string   `json:"cookie_name,omitempty"`
	AccessTokenCookieName string   `json:"access_token_cookie_name,omitempty"`
}

// loadTenants reads and checks the tenants file; nil without one.
func loadTenants(path string) ([]tenantSpec, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tenants file: %w", err)
	}
	specs, err := parseTenants(data)
	if err != nil {
		return nil, fmt.Errorf("tenants file %s: %w", path, err)
	}
	return specs, nil
}

func parseTenants(data []byte) ([]tenantSpec, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f tenantsFile
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after the tenants")
	}
	seen := map[string]bool{}
	for _, t := range f.Tenants {
		if !validTenantName(t.Name) {
			return nil, fmt.Errorf("tenant name %q: use letters, digits, '.', '_' and '-'", t.Name)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("duplicate tenant %q", t.Name)
		}
		seen[t.Name] = true
		if t.Mercure == nil {
			return nil, fmt.Errorf("tenant %q: no mercure settings", t.Name)
		}
		if len(t.Hosts) == 0 {
			return nil, fmt.Errorf("tenant %q: give it hosts: the host picks a tenant's hub", t.Name)
		}
	}
	return f.Tenants, nil
}

func validTenantName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// errWeakKey refuses an HMAC secret shorter than its algorithm's hash size.
var errWeakKey = errors.New("the HMAC secret is shorter than its algorithm needs (32 bytes for HS256; gossiper genkey makes one); allow-weak-keys accepts it")

// checkKeys refuses a tenant's weak HMAC secrets, unless the server allows them.
func (s *Server) checkKeys(t tenantSpec) error {
	if s.settings.AllowWeakKeys || t.Mercure == nil {
		return nil
	}
	m := t.Mercure
	for name, k := range map[string]auth.KeyConfig{"publisher_key": {Key: m.PublisherKey, Algorithm: m.PublisherAlg},
		"subscriber_key": {Key: m.SubscriberKey, Algorithm: m.SubscriberAlg}} {
		if auth.WeakSecret(k) {
			return fmt.Errorf("%s: %w", name, errWeakKey)
		}
	}
	return nil
}

// mercureTenants returns the tenants' hubs: each takes the server's settings with its own keys.
func mercureTenants(base gossiper.Config, specs []tenantSpec) []gossiper.Tenant {
	base.Transport = nil
	var out []gossiper.Tenant
	for _, t := range specs {
		m := t.Mercure
		cfg := base
		cfg.PublisherKey = auth.KeyConfig{Key: m.PublisherKey, Algorithm: m.PublisherAlg, JWKSURL: m.PublisherJWKSURL}
		defaultAlgorithm(&cfg.PublisherKey)
		cfg.SubscriberKey = auth.KeyConfig{Key: m.SubscriberKey, Algorithm: m.SubscriberAlg, JWKSURL: m.SubscriberJWKSURL}
		defaultAlgorithm(&cfg.SubscriberKey)
		cfg.TrustedIssuers = m.TrustedIssuers
		cfg.Issuers = nil
		for _, as := range m.AuthorizationServers {
			cfg.Issuers = append(cfg.Issuers, auth.Issuer{Issuer: as, Discover: true})
		}
		cfg.ResourceIdentifier = m.ResourceIdentifier
		cfg.HubURL = m.HubURL
		cfg.Anonymous = m.Anonymous
		cfg.Subscriptions = m.Subscriptions
		if m.CORSOrigins != nil {
			cfg.CORSOrigins = m.CORSOrigins
		}
		if m.PublishOrigins != nil {
			cfg.PublishOrigins = m.PublishOrigins
		}
		if m.CookieName != "" {
			cfg.CookieName = m.CookieName
		}
		if m.AccessTokenCookieName != "" {
			cfg.AccessTokenCookieName = m.AccessTokenCookieName
		}
		out = append(out, gossiper.Tenant{Name: t.Name, Hosts: t.Hosts, Config: cfg})
	}
	return out
}

// noServerMercureKeys refuses the server's own Mercure keys alongside tenants: with tenants there is one hub
// per tenant, picked by host, and each has its own keys.
func noServerMercureKeys(s Settings) error {
	for name, v := range map[string]string{
		"publisher-key": s.PublisherKey, "publisher-jwks-url": s.PublisherJWKS, "subscriber-key": s.SubscriberKey,
		"subscriber-jwks-url": s.SubscriberJWKS, "authorization-servers": strings.Join(s.AuthServers, ","),
		"resource-identifier": s.ResourceID, "hub-url": s.HubURL,
	} {
		if v != "" {
			return fmt.Errorf("%s: with tenants every hub is a tenant's: set it in the tenants file", name)
		}
	}
	if s.Anonymous {
		return errors.New("anonymous: with tenants every hub is a tenant's: set it in the tenants file")
	}
	return nil
}
