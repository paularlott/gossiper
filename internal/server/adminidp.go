package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/paularlott/gossiper/auth"
)

// The admin API takes the static --api-token, tokens of an identity provider (--admin-issuer), or both. An IdP's
// token is an OAuth access token (RFC 9068) for the admin API (--admin-audience), and says what its holder may do
// in authorization details (RFC 9396) of the admin type (--admin-detail-type):
//
//	{"type": "urn:gossiper:admin", "actions": ["read", "write"], "tenants": ["acme"]}
//
// "write" implies "read"; without "tenants" a detail covers every tenant. Each detail is a rule of its own: a caller
// may do what any one of them allows. For an IdP without authorization details, --admin-scope names a scope that
// gives full access.

// DefaultAdminDetailType is the authorization detail type of the admin API.
const DefaultAdminDetailType = "urn:gossiper:admin"

// grant is what a caller of the admin API may do: rules, each reading (or writing) every tenant or those it names.
// Each is a detail of the token, taken alone: reading every tenant and writing one is not writing every one.
type grant struct{ rules []rule }

type rule struct {
	write   bool            // read and write; read only otherwise
	all     bool            // every tenant
	tenants map[string]bool // or these
}

// fullGrant is the static token's: everything.
var fullGrant = grant{rules: []rule{{write: true, all: true}}}

// may reports whether g allows a request that reads (or, with write, changes) anything at all.
func (g grant) may(write bool) bool {
	for _, r := range g.rules {
		if r.write || !write {
			return true
		}
	}
	return false
}

// allows reports whether g allows reading (or, with write, changing) the named tenant.
func (g grant) allows(write bool, name string) bool {
	for _, r := range g.rules {
		if (r.write || !write) && (r.all || r.tenants[name]) {
			return true
		}
	}
	return false
}

// errNoAdminRights is a valid token of the IdP that gives no access to the admin API (403, not 401).
var errNoAdminRights = errors.New("the token gives no access to the admin API")

type grantKey struct{}

// grantOf returns the grant the request was authenticated with.
func grantOf(r *http.Request) grant {
	g, _ := r.Context().Value(grantKey{}).(grant)
	return g
}

// adminIdP verifies the admin API tokens of an identity provider.
type adminIdP struct {
	v          *auth.AccessVerifier
	detailType string
	scope      string
}

// newAdminIdP trusts the issuer, its keys found by discovery (RFC 8414, OpenID Connect), for tokens whose audience
// includes audience; cas are trusted for its certificate as well as the system's.
func newAdminIdP(issuer, audience, detailType, scope string, insecure bool, cas *x509.CertPool) (*adminIdP, error) {
	if detailType == "" {
		detailType = DefaultAdminDetailType
	}
	var client *http.Client
	if cas != nil {
		client = auth.KeyURLClient(cas, insecure)
	}
	v, err := auth.NewAccessVerifier(auth.AccessConfig{
		HTTPClient:         client,
		Issuers:            []auth.Issuer{{Issuer: issuer, Discover: true}},
		Audience:           audience,
		AllowInsecureHTTP:  insecure,
		SkipMercureDetails: true, // a hub's business, not the admin API's
	})
	if err != nil {
		return nil, err
	}
	return &adminIdP{v: v, detailType: detailType, scope: scope}, nil
}

func (p *adminIdP) close() { p.v.Close() }

// grant verifies tok and returns what it allows: an error for a token that is not valid, errNoAdminRights for one
// that is but allows nothing.
func (p *adminIdP) grant(ctx context.Context, tok string) (grant, error) {
	c, err := p.v.Verify(ctx, tok)
	if err != nil {
		return grant{}, err
	}
	if p.scope != "" && slices.Contains(strings.Fields(c.Scope), p.scope) {
		return fullGrant, nil
	}
	var details []struct {
		Type    string   `json:"type"`
		Actions []string `json:"actions"`
		Tenants []string `json:"tenants"`
	}
	if len(c.RawDetails) > 0 && json.Unmarshal(c.RawDetails, &details) != nil {
		return grant{}, errNoAdminRights
	}
	var g grant
	for _, d := range details {
		if d.Type != p.detailType {
			continue
		}
		read, write := slices.Contains(d.Actions, "read"), slices.Contains(d.Actions, "write")
		if !read && !write {
			continue
		}
		r := rule{write: write, all: d.Tenants == nil || slices.Contains(d.Tenants, "*")}
		if !r.all {
			r.tenants = map[string]bool{}
			for _, t := range d.Tenants {
				r.tenants[t] = true
			}
		}
		g.rules = append(g.rules, r)
	}
	if len(g.rules) == 0 {
		return grant{}, errNoAdminRights
	}
	return g, nil
}

// looksLikeJWT reports whether tok has a JWT's three dot-separated parts (the static token is not checked against
// the IdP, nor a JWT against a bcrypt hash).
func looksLikeJWT(tok string) bool { return strings.Count(tok, ".") == 2 }
