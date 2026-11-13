package gossiper

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/auth"
)

// source is where a request's token came from.
type source int

const (
	noToken source = iota
	fromHeader
	fromQuery
	fromCookie
)

// role is what a token is checked for: each role has its own keys.
type role int

const (
	rolePublisher role = iota
	roleSubscriber
)

// errBadPresentation is an Authorization header that is not a bearer token: a malformed request (400).
var errBadPresentation = errors.New("authorization header is not a bearer token")

// token returns the request's token: the Authorization header (which wins over any cookie), then, for draft-07,
// the "authorization" query parameter, then the Mercure 1.0 cookie, then the draft-07 cookie.
func (h *Hub) token(r *http.Request) (string, source, error) {
	if a := r.Header.Get("Authorization"); a != "" {
		if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
			if t := strings.TrimSpace(a[7:]); t != "" {
				return t, fromHeader, nil
			}
		}
		return "", fromHeader, errBadPresentation
	}
	if h.cfg.Protocol.legacy() && !h.cfg.DisableQueryAuthorization {
		if q, ok := r.URL.Query()["authorization"]; ok && len(q) > 0 && q[0] != "" {
			return q[0], fromQuery, nil
		}
	}
	if h.cfg.Protocol.modern() {
		if c, err := r.Cookie(h.cfg.AccessTokenCookieName); err == nil && c.Value != "" {
			return c.Value, fromCookie, nil
		}
	}
	if h.cfg.Protocol.legacy() {
		if c, err := r.Cookie(h.cfg.CookieName); err == nil && c.Value != "" {
			return c.Value, fromCookie, nil
		}
	}
	return "", noToken, nil
}

// authenticate verifies the request's token for role. With no token it returns nil grants and true: the caller
// decides whether that is allowed. On failure it has written the error response and returns false.
func (h *Hub) authenticate(w http.ResponseWriter, r *http.Request, as role) (*grants, source, bool) {
	tok, src, err := h.token(r)
	if err != nil {
		h.writeAuthError(w, r, http.StatusBadRequest, "invalid_request")
		return nil, src, false
	}
	if src == noToken {
		return nil, noToken, true
	}
	g, err := h.verify(r, tok, as)
	if err == nil {
		return g, src, true
	}
	// A token that cannot be decoded is invalid like any other (RFC 6750: "expired, revoked, malformed, or
	// invalid"): 401 invalid_token. 400 invalid_request is for a malformed request, as above.
	h.log.Debug("token refused", "error", err.Error())
	h.writeAuthError(w, r, http.StatusUnauthorized, "invalid_token")
	return nil, src, false
}

// verify checks tok with the verifier of its revision and role: a token that looks like a Mercure 1.0 access
// token (typ at+jwt, or authorization_details) is one, any other a draft-07 token.
// A token verified before is taken from the cache (tokenCache).
func (h *Hub) verify(r *http.Request, tok string, as role) (*grants, error) {
	k := tokenKey{tok: tok, as: as}
	access := auth.IsAccessToken(tok)
	if access {
		k.aud = h.resourceIdentifier(r)
	}
	if g, ok := h.tokens.get(k); ok {
		return g, nil
	}
	g, err := h.verifyToken(r, tok, as, access, k.aud)
	if err == nil {
		h.tokens.put(k, g)
	}
	return g, err
}

// verifyToken checks tok's signature and claims; aud is the audience of a Mercure 1.0 access token.
func (h *Hub) verifyToken(r *http.Request, tok string, as role, access bool, aud string) (*grants, error) {
	if access {
		v := h.asub
		if as == rolePublisher {
			v = h.apub
		}
		if v == nil {
			return nil, errors.New("no trusted issuer for Mercure 1.0 tokens: " + auth.ErrInvalid.Error())
		}
		c, err := v.VerifyAudience(r.Context(), tok, aud)
		if err != nil {
			return nil, err
		}
		return grantsFromAccess(c), nil
	}
	v := h.sub
	if as == rolePublisher {
		v = h.pub
	}
	if v == nil { // no draft-07 verifier: still tell a token that is not a JWT at all from one refused, for the log
		if _, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{}); err != nil {
			return nil, auth.ErrMalformed
		}
		return nil, auth.ErrInvalid
	}
	c, err := v.Verify(r.Context(), tok)
	if err != nil {
		return nil, err
	}
	return grantsFromClaims(c), nil
}

// resourceIdentifier is the hub's resource identifier for r: the configured one, the hub URL when it is absolute,
// else the URL of the hub the client contacted.
func (h *Hub) resourceIdentifier(r *http.Request) string {
	if h.cfg.ResourceIdentifier != "" {
		return h.cfg.ResourceIdentifier
	}
	if u, _ := url.Parse(h.cfg.HubURL); u != nil && u.IsAbs() {
		return h.cfg.HubURL
	}
	return h.requestOrigin(r) + hubPath
}

// requestOrigin is the scheme and host the client contacted; with TrustForwardedProto, X-Forwarded-Proto names
// the scheme.
func (h *Hub) requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if h.cfg.TrustForwardedProto {
		if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
			scheme = p
		}
	}
	return scheme + "://" + r.Host
}

// metadataURL is the URL of the hub's protected resource metadata, as the client contacted the hub.
func (h *Hub) metadataURL(r *http.Request) string {
	origin := h.requestOrigin(r)
	if u, _ := url.Parse(h.cfg.HubURL); u != nil && u.IsAbs() {
		origin = u.Scheme + "://" + u.Host
	}
	return origin + metadataPath
}

// writeAuthError writes a token failure: status, and a Bearer challenge with the error code (none for a missing
// token) and, for Mercure 1.0, where the protected resource metadata is.
func (h *Hub) writeAuthError(w http.ResponseWriter, r *http.Request, status int, code string) {
	var params []string
	if code != "" {
		params = append(params, `error="`+code+`"`)
	}
	if h.cfg.Protocol.modern() {
		params = append(params, `resource_metadata="`+h.metadataURL(r)+`"`)
	}
	challenge := "Bearer"
	if len(params) > 0 {
		challenge += " " + strings.Join(params, ", ")
	}
	w.Header().Set("WWW-Authenticate", challenge)
	writeError(w, status, http.StatusText(status))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'")
}

// exposedHeaders are the response headers a cross-origin subscriber may read.
const exposedHeaders = "Link, Last-Event-ID, Mercure-Last-Event-ID, Accept-Query"

// cors sets the CORS response headers. An allowed origin is echoed with credentials (so the authorization cookie
// works cross-origin); "*" allows any origin but never with credentials, as reflecting arbitrary origins on a
// credentialed endpoint would let any site read a subscriber's updates.
func (h *Hub) cors(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	hd := w.Header()
	switch {
	case originListed(origin, h.cfg.CORSOrigins):
		hd.Set("Access-Control-Allow-Origin", origin)
		hd.Set("Access-Control-Allow-Credentials", "true")
	case slices.Contains(h.cfg.CORSOrigins, "*"):
		hd.Set("Access-Control-Allow-Origin", "*")
	default:
		return
	}
	if r.Method != http.MethodOptions {
		hd.Set("Access-Control-Expose-Headers", exposedHeaders)
	}
}

// preflight answers a CORS preflight request.
func (h *Hub) preflight(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Add("Vary", "Access-Control-Request-Method")
	hd.Add("Vary", "Access-Control-Request-Headers")
	method := r.Header.Get("Access-Control-Request-Method")
	if hd.Get("Access-Control-Allow-Origin") != "" && method != "" {
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPost, methodQuery:
			hd.Set("Access-Control-Allow-Methods", method)
		}
		if req := r.Header.Get("Access-Control-Request-Headers"); req != "" && validHeaderList(req) {
			hd.Set("Access-Control-Allow-Headers", req)
		}
		hd.Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// validHeaderList reports whether s is a comma-separated list of header names (tokens), so it is safe to echo.
func validHeaderList(s string) bool {
	if len(s) > 1024 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_,. !#$%&'*+^`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// originListed reports whether origin is named in list ("*" is not a name).
func originListed(origin string, list []string) bool {
	return slices.Contains(list, strings.TrimSuffix(strings.ToLower(origin), "/"))
}

// originIn reports whether origin is in list, "*" allowing any.
func originIn(origin string, list []string) bool {
	return slices.Contains(list, "*") || originListed(origin, list)
}

// publishOriginAllowed is the CSRF check of a publish authorized by a cookie: the request's Origin (or, without
// one, its Referer's origin) must be one of the publish origins.
func (h *Hub) publishOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			return false
		}
		u, err := url.Parse(ref)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}
		origin = u.Scheme + "://" + u.Host
	}
	return originIn(origin, h.cfg.PublishOrigins)
}

// metadata is the hub's OAuth 2.0 protected resource metadata (RFC 9728), with the Mercure members.
type metadata struct {
	Resource                     string   `json:"resource"`
	AuthorizationServers         []string `json:"authorization_servers,omitempty"`
	AuthorizationDetailsTypes    []string `json:"authorization_details_types_supported"`
	BearerMethodsSupported       []string `json:"bearer_methods_supported"`
	MercureCookie                string   `json:"mercure_cookie,omitempty"`
	MercureMatcherTypesSupported []string `json:"mercure_matcher_types_supported"`
	MercureSubscriptions         bool     `json:"mercure_subscriptions,omitempty"`
}

// serveMetadata serves the protected resource metadata.
func (h *Hub) serveMetadata(w http.ResponseWriter, r *http.Request) {
	md := metadata{
		Resource:                     h.resourceIdentifier(r),
		AuthorizationDetailsTypes:    []string{auth.DetailType},
		BearerMethodsSupported:       []string{"header"},
		MercureCookie:                h.cfg.AccessTokenCookieName,
		MercureMatcherTypesSupported: []string{"exact", "urlpattern"},
		MercureSubscriptions:         h.cfg.Subscriptions,
	}
	for _, is := range h.cfg.Issuers {
		if is.Discover { // an authorization server, as opposed to a publisher issuing its own tokens
			md.AuthorizationServers = append(md.AuthorizationServers, is.Issuer)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(jsonMarshal(md))
}
