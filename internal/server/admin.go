package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossiper/internal/configstore"
	"golang.org/x/crypto/bcrypt"
)

// apiError is the body of every error the API answers.
type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// httpError is an error with the status the API answers it with.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func fail(status int, format string, args ...any) error {
	return &httpError{status, fmt.Sprintf(format, args...)}
}

func writeErr(w http.ResponseWriter, err error) {
	var he *httpError
	if errors.As(err, &he) {
		writeJSON(w, he.status, apiError{he.msg})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{"internal error"})
}

// maxAPIBody bounds a request body.
const maxAPIBody = 1 << 20

// adminRoute is one operation of the admin API. The OpenAPI document (web/openapi/openapi.yaml) describes every one,
// and nothing else under /api but /api/openapi.json (tested).
type adminRoute struct {
	method, path string
	handle       func(a *adminAPI, w http.ResponseWriter, r *http.Request) error
}

var adminRouteList = []adminRoute{
	{"GET", "/api/tenants", (*adminAPI).listTenants},
	{"POST", "/api/tenants", (*adminAPI).createTenant},
	{"GET", "/api/tenants/{tenant}", (*adminAPI).getTenant},
	{"PUT", "/api/tenants/{tenant}", (*adminAPI).putTenant},
	{"DELETE", "/api/tenants/{tenant}", (*adminAPI).deleteTenant},
	{"POST", "/api/tenants/{tenant}/rotate", (*adminAPI).rotateKeys},
	{"DELETE", "/api/tenants/{tenant}/previous-keys", (*adminAPI).dropPreviousKeys},
	{"GET", "/api/status", (*adminAPI).status},
}

// adminRoutes registers the admin API on mux.
func (s *Server) adminRoutes(mux *http.ServeMux) {
	a := &adminAPI{s: s, token: s.settings.APIToken, idp: s.adminIDP, limiter: newFailLimiter(60, time.Minute, maxFailEntries),
		bcrypts: make(chan struct{}, maxBcrypts)}
	for _, rt := range adminRouteList {
		mux.Handle(rt.method+" "+rt.path, a.auth(func(w http.ResponseWriter, r *http.Request) error {
			return rt.handle(a, w, r)
		}))
	}
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, apiError{"no such API endpoint"})
	}))
}

type adminAPI struct {
	s       *Server
	token   string    // the static token ("" for none)
	idp     *adminIDP // or nil
	limiter *failLimiter
	good    atomic.Pointer[[sha256.Size]byte] // the digest of the last token a bcrypt hash accepted
	bcrypts chan struct{}                     // the bcrypt comparisons under way
}

const (
	maxBcrypts     = 4     // bcrypt comparisons at once: over it a request is refused (429) unchecked
	maxFailEntries = 10000 // addresses the failed authentications are counted for, in a window
)

// errBusy is a token not checked: too many bcrypt comparisons under way.
var errBusy = errors.New("busy")

// auth runs h for requests carrying the API token. Failed attempts are limited per address.
func (a *adminAPI) auth(h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := a.s.clientIP(r)
		if wait := a.limiter.blocked(ip); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, apiError{"too many failed authentications"})
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		token = strings.TrimSpace(token)
		var g grant
		var err error
		if ok {
			ok = false
			// An IdP's token (a JWT) is verified by it; the static token is compared (with bcrypt for a hash).
			if a.idp != nil && looksLikeJWT(token) {
				g, err = a.idp.grant(r.Context(), token)
				if errors.Is(err, errNoAdminRights) {
					writeJSON(w, http.StatusForbidden, apiError{err.Error()})
					return
				}
				ok, err = err == nil, nil
			}
			if !ok && a.token != "" {
				if ok, err = a.valid(token); ok {
					g = fullGrant
				}
			}
		}
		if err != nil {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, apiError{"too many authentications under way"})
			return
		}
		if !ok {
			a.limiter.fail(ip)
			w.Header().Set("WWW-Authenticate", `Bearer realm="gossiper"`)
			writeJSON(w, http.StatusUnauthorized, apiError{"a valid API token is required"})
			return
		}
		if !g.may(r.Method != http.MethodGet) {
			writeJSON(w, http.StatusForbidden, apiError{"the token does not allow this"})
			return
		}
		if name := r.PathValue("tenant"); name != "" && !g.allows(r.Method != http.MethodGet, name) {
			writeJSON(w, http.StatusForbidden, apiError{"the token does not allow this tenant"})
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), grantKey{}, g))
		r.Body = http.MaxBytesReader(w, r.Body, maxAPIBody)
		if err := h(w, r); err != nil {
			writeErr(w, err)
		}
	})
}

// valid reports whether token is the API token: the setting itself, or a token its bcrypt hash accepts. With
// maxBcrypts comparisons under way it does not check (errBusy): failed attempts would otherwise take every CPU.
func (a *adminAPI) valid(token string) (bool, error) {
	if token == "" || len(token) > 4096 {
		return false, nil
	}
	if !strings.HasPrefix(a.token, "$2") {
		x, y := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(a.token))
		return subtle.ConstantTimeCompare(x[:], y[:]) == 1, nil
	}
	d := sha256.Sum256([]byte(token))
	if g := a.good.Load(); g != nil && subtle.ConstantTimeCompare(g[:], d[:]) == 1 {
		return true, nil // bcrypt once per token, not once per request
	}
	select {
	case a.bcrypts <- struct{}{}:
		defer func() { <-a.bcrypts }()
	default:
		return false, errBusy
	}
	if bcrypt.CompareHashAndPassword([]byte(a.token), []byte(token)) != nil {
		return false, nil
	}
	a.good.Store(&d)
	return true, nil
}

// clientIP is the address of the client that made r: the peer's, or, when the peer is a trusted proxy, the address
// X-Forwarded-For names after the trusted proxies (read from the right, as each proxy appends the address it saw).
func (s *Server) clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = h
	}
	if !s.trusted(ip) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if ap, err := netip.ParseAddrPort(hop); err == nil { // some proxies add the port
			hop = ap.Addr().String()
		}
		if _, err := netip.ParseAddr(hop); err != nil {
			break // not an address: what is left of the header cannot be trusted
		}
		ip = hop
		if !s.trusted(hop) {
			break
		}
	}
	return ip
}

// trusted reports whether ip is one of the trusted proxies.
func (s *Server) trusted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseProxies parses the trusted proxies: addresses and CIDR ranges.
func parseProxies(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range list {
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("trusted proxies: %q is neither an address nor a CIDR range", v)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// failLimiter counts failed authentications per address in fixed windows. Past its entries addresses in a window, the
// others share one count: memory stays bounded, and spreading attempts over many addresses gains nothing.
type failLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries int
	start   time.Time
	counts  map[string]int
}

func newFailLimiter(max int, window time.Duration, entries int) *failLimiter {
	return &failLimiter{max: max, window: window, entries: entries, start: time.Now(), counts: map[string]int{}}
}

// key is what ip's failures are counted under: its own count, or, the table full, the one the others share ("").
func (l *failLimiter) key(ip string) string {
	if _, ok := l.counts[ip]; ok || len(l.counts) < l.entries {
		return ip
	}
	return ""
}

func (l *failLimiter) roll(now time.Time) {
	if now.Sub(l.start) >= l.window {
		l.start, l.counts = now, map[string]int{}
	}
}

// blocked returns how long ip must wait, 0 when it may try.
func (l *failLimiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.roll(now)
	if l.counts[l.key(ip)] < l.max {
		return 0
	}
	return l.window - now.Sub(l.start)
}

func (l *failLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(time.Now())
	l.counts[l.key(ip)]++
}

// storedTenant is a tenant's record: its spec, and when it was created, which orders tenants that clash (the older is
// served).
type storedTenant struct {
	Spec    tenantSpec `json:"spec"`
	Created int64      `json:"created"`
	// Previous are the keys a rotation replaced, still accepted until their time.
	Previous *previousKeys `json:"previous,omitempty"`
}

// tenantView is a tenant as the API shows it: secrets left out.
type tenantView struct {
	Name    string       `json:"name"`
	Source  string       `json:"source"`
	Hosts   []string     `json:"hosts,omitempty"`
	Mercure *mercureView `json:"mercure,omitempty"`
	Problem string       `json:"problem,omitempty"`
}

type mercureView struct {
	tenantMercure
	PublisherKeySet  bool `json:"publisher_key_set,omitempty"`
	SubscriberKeySet bool `json:"subscriber_key_set,omitempty"`
	// When the previous keys of a rotation stop being accepted (absent: none is).
	PublisherPreviousKeyUntil  *time.Time `json:"publisher_previous_key_until,omitempty"`
	SubscriberPreviousKeyUntil *time.Time `json:"subscriber_previous_key_until,omitempty"`
}

// isPublicKey reports whether a Mercure key is a PEM public key, which may be shown, rather than an HMAC secret.
func isPublicKey(k string) bool {
	return strings.Contains(k, "-----BEGIN PUBLIC KEY-----") || strings.Contains(k, "-----BEGIN RSA PUBLIC KEY-----")
}

func viewTenant(t tenantSpec, fromFile bool, problem string) tenantView {
	v := tenantView{Name: t.Name, Source: "database", Hosts: t.Hosts, Problem: problem}
	if fromFile {
		v.Source = "file"
	}
	if m := t.Mercure; m != nil {
		mv := &mercureView{tenantMercure: *m}
		if m.PublisherKey != "" && !isPublicKey(m.PublisherKey) {
			mv.PublisherKey, mv.PublisherKeySet = "", true
		}
		if m.SubscriberKey != "" && !isPublicKey(m.SubscriberKey) {
			mv.SubscriberKey, mv.SubscriberKeySet = "", true
		}
		if p := t.previous.active(time.Now()); p != nil {
			if p.PublisherKey != "" {
				u := time.Unix(0, p.PublisherUntil).UTC()
				mv.PublisherPreviousKeyUntil = &u
			}
			if p.SubscriberKey != "" {
				u := time.Unix(0, p.SubscriberUntil).UTC()
				mv.SubscriberPreviousKeyUntil = &u
			}
		}
		v.Mercure = mv
	}
	return v
}

// tenants returns every tenant as the API shows them: those served, then those of the database left out. The records
// are shown as stored: no hub's settings are checked here (the last check of each is used).
func (a *adminAPI) tenants() []tenantView {
	resolved, problems := a.s.resolveTenants(a.s.storeList(), a.s.knownProblem)
	var out []tenantView
	served := map[string]bool{}
	for _, t := range resolved {
		out = append(out, viewTenant(t.spec, t.fromFile, ""))
		served[t.spec.Name] = true
	}
	why := map[string]string{}
	for _, p := range problems {
		if !served[p.tenant] && why[p.tenant] == "" {
			why[p.tenant] = p.msg
		}
	}
	for _, r := range a.s.store.List(tenantPrefix) {
		var st storedTenant
		if json.Unmarshal(r.Value, &st) != nil || served[st.Spec.Name] {
			continue
		}
		st.Spec.previous = st.Previous
		out = append(out, viewTenant(st.Spec, false, why[st.Spec.Name]))
	}
	return out
}

func (a *adminAPI) tenant(name string) (tenantView, bool) {
	for _, t := range a.tenants() {
		if t.Name == name {
			return t, true
		}
	}
	return tenantView{}, false
}

func (a *adminAPI) listTenants(w http.ResponseWriter, r *http.Request) error {
	g := grantOf(r)
	out := slices.DeleteFunc(a.tenants(), func(t tenantView) bool { return !g.allows(false, t.Name) })
	if out == nil {
		out = []tenantView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
	return nil
}

func (a *adminAPI) getTenant(w http.ResponseWriter, r *http.Request) error {
	t, ok := a.tenant(r.PathValue("tenant"))
	if !ok {
		return fail(http.StatusNotFound, "no tenant %q", r.PathValue("tenant"))
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

// decode reads a JSON body into v, refusing unknown fields and trailing data.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return fail(http.StatusRequestEntityTooLarge, "the body is larger than %d bytes", maxAPIBody)
		}
		return fail(http.StatusBadRequest, "invalid JSON body: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail(http.StatusBadRequest, "unexpected data after the JSON body")
	}
	return nil
}

func (a *adminAPI) createTenant(w http.ResponseWriter, r *http.Request) error {
	var in tenantSpec
	if err := decode(r, &in); err != nil {
		return err
	}
	if !grantOf(r).allows(true, in.Name) {
		return fail(http.StatusForbidden, "the token does not allow tenant %q", in.Name)
	}
	if _, err := a.writeTenant(r.Context(), in, true); err != nil {
		return err
	}
	t, _ := a.tenant(in.Name)
	w.Header().Set("Location", "/api/tenants/"+in.Name)
	writeJSON(w, http.StatusCreated, t)
	return nil
}

func (a *adminAPI) putTenant(w http.ResponseWriter, r *http.Request) error {
	var in tenantSpec
	if err := decode(r, &in); err != nil {
		return err
	}
	name := r.PathValue("tenant")
	if in.Name == "" {
		in.Name = name
	} else if in.Name != name {
		return fail(http.StatusBadRequest, "the body names tenant %q, the path %q", in.Name, name)
	}
	created, err := a.writeTenant(r.Context(), in, false)
	if err != nil {
		return err
	}
	t, _ := a.tenant(name)
	writeJSON(w, map[bool]int{true: http.StatusCreated, false: http.StatusOK}[created], t)
	return nil
}

// fileTenant reports whether the tenants file has the named tenant.
func (s *Server) fileTenant(name string) bool {
	for _, t := range s.tenants {
		if t.Name == name {
			return true
		}
	}
	return false
}

// writeTenant stores tenant in, created only when create, and reports whether it is new.
func (a *adminAPI) writeTenant(ctx context.Context, in tenantSpec, create bool) (bool, error) {
	if err := checkSpec(in); err != nil {
		return false, fail(http.StatusBadRequest, "%v", err)
	}
	if err := a.s.checkKeys(in); err != nil {
		return false, fail(http.StatusBadRequest, "%v", err)
	}
	// Its hub's settings on their own (an unknown algorithm, a bad key) are the request's fault: 400, where a clash
	// with another tenant is 409.
	if err := a.s.checkRecord(in); err != nil {
		return false, fail(http.StatusBadRequest, "%v", err)
	}
	if a.s.fileTenant(in.Name) {
		return false, fail(http.StatusConflict, "tenant %q is defined in the tenants file", in.Name)
	}
	var isNew bool
	err := a.change(ctx, func(tx *configstore.Tx) error {
		created := time.Now().UnixNano()
		var previous *previousKeys
		if old, ok := tx.Get(tenantKey(in.Name)); ok {
			if create {
				return fail(http.StatusConflict, "tenant %q exists", in.Name)
			}
			var st storedTenant
			if json.Unmarshal(old.Value, &st) == nil {
				created = st.Created
				previous = keptPrevious(st, in)
			}
		} else {
			isNew = true
		}
		tx.Put(tenantKey(in.Name), specJSON(storedTenant{Spec: in, Created: created, Previous: previous}))
		return nil
	})
	if err == nil {
		a.s.log.Info(map[bool]string{true: "tenant created", false: "tenant changed"}[isNew], "tenant", in.Name)
	}
	return isNew, err
}

// keptPrevious is what a replacement of st by in keeps of its previous keys: a key's previous key while that key is
// unchanged (a PUT that changes a key replaces it at once: rotate to keep the old one a while).
func keptPrevious(st storedTenant, in tenantSpec) *previousKeys {
	p := st.Previous.active(time.Now())
	if p == nil || st.Spec.Mercure == nil || in.Mercure == nil {
		return nil
	}
	out := *p
	if in.Mercure.PublisherKey != st.Spec.Mercure.PublisherKey {
		out.PublisherKey, out.PublisherUntil = "", 0
	}
	if in.Mercure.SubscriberKey != st.Spec.Mercure.SubscriberKey {
		out.SubscriberKey, out.SubscriberUntil = "", 0
	}
	return out.active(time.Now())
}

// maxGrace bounds how long a rotated key stays accepted.
const maxGrace = 7 * 24 * time.Hour

// defaultGrace is how long a rotated key stays accepted when the request does not say.
const defaultGrace = time.Hour

// rotateRequest is the body of POST /api/tenants/{tenant}/rotate.
type rotateRequest struct {
	PublisherKey  string `json:"publisher_key,omitempty"`
	SubscriberKey string `json:"subscriber_key,omitempty"`
	Grace         string `json:"grace,omitempty"`
}

// rotateKeys replaces a database tenant's publisher or subscriber key, or both, keeping each replaced key accepted for
// the grace period (default an hour; "0s" replaces it at once). Every node applies it without a restart: the tenant's
// hub starts over with both keys, so its subscribers reconnect, with Last-Event-ID and the tokens they hold.
func (a *adminAPI) rotateKeys(w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("tenant")
	var in rotateRequest
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.PublisherKey == "" && in.SubscriberKey == "" {
		return fail(http.StatusBadRequest, "give publisher_key, subscriber_key or both: the new keys")
	}
	grace := defaultGrace
	if in.Grace != "" {
		d, err := time.ParseDuration(in.Grace)
		if err != nil || d < 0 || d > maxGrace {
			return fail(http.StatusBadRequest, "grace: a duration from 0s to %s, e.g. 1h", maxGrace)
		}
		grace = d
	}
	if a.s.fileTenant(name) {
		var exists bool
		_ = a.s.store.Update(r.Context(), func(tx *configstore.Tx) error { _, exists = tx.Get(tenantKey(name)); return nil })
		if !exists {
			return fail(http.StatusConflict, "tenant %q is defined in the tenants file: change its keys there", name)
		}
	}
	until := time.Now().Add(grace).UnixNano()
	err := a.change(r.Context(), func(tx *configstore.Tx) error {
		rec, ok := tx.Get(tenantKey(name))
		if !ok {
			return fail(http.StatusNotFound, "no tenant %q", name)
		}
		var st storedTenant
		if err := json.Unmarshal(rec.Value, &st); err != nil || st.Spec.Mercure == nil {
			return fail(http.StatusConflict, "tenant %q: unreadable record", name)
		}
		spec := st.Spec
		m := *spec.Mercure
		prev := st.Previous.active(time.Now())
		if prev == nil {
			prev = &previousKeys{}
		}
		if k := in.PublisherKey; k != "" {
			if m.PublisherJWKSURL != "" {
				return fail(http.StatusBadRequest, "tenant %q takes its publisher keys from a key set: rotate them there, or PUT a publisher_key", name)
			}
			if k == m.PublisherKey {
				return fail(http.StatusBadRequest, "publisher_key: the tenant's key already")
			}
			if m.SubscriberKey == "" && in.SubscriberKey == "" && m.SubscriberJWKSURL == "" {
				// Its subscribers' tokens are signed with the publisher key too: the replaced one stays theirs as well.
				prev.SubscriberKey, prev.SubscriberUntil = "", 0
			}
			prev.PublisherKey, prev.PublisherUntil = m.PublisherKey, until
			m.PublisherKey = k
		}
		if k := in.SubscriberKey; k != "" {
			if m.SubscriberJWKSURL != "" {
				return fail(http.StatusBadRequest, "tenant %q takes its subscriber keys from a key set: rotate them there, or PUT a subscriber_key", name)
			}
			if k == m.SubscriberKey {
				return fail(http.StatusBadRequest, "subscriber_key: the tenant's key already")
			}
			// A tenant without a subscriber key signs its subscribers' tokens with the publisher key: that one is
			// the subscribers' previous key now.
			old := m.SubscriberKey
			if old == "" {
				old = st.Spec.Mercure.PublisherKey
			}
			prev.SubscriberKey, prev.SubscriberUntil = old, until
			m.SubscriberKey = k
		}
		if grace == 0 {
			if in.PublisherKey != "" {
				prev.PublisherKey, prev.PublisherUntil = "", 0
			}
			if in.SubscriberKey != "" {
				prev.SubscriberKey, prev.SubscriberUntil = "", 0
			}
		}
		spec.Mercure = &m
		spec.previous = prev.active(time.Now())
		if err := a.s.checkKeys(spec); err != nil {
			return fail(http.StatusBadRequest, "%v", err)
		}
		if err := a.s.checkRecord(spec); err != nil {
			return fail(http.StatusBadRequest, "%v", err)
		}
		tx.Put(tenantKey(name), specJSON(storedTenant{Spec: spec, Created: st.Created, Previous: spec.previous}))
		return nil
	})
	if err != nil {
		return err
	}
	a.s.log.Info("tenant keys rotated", "tenant", name, "grace", grace.String())
	t, _ := a.tenant(name)
	writeJSON(w, http.StatusOK, t)
	return nil
}

// dropPreviousKeys ends a rotation's grace period at once: the replaced keys stop being accepted, and the tenant's
// hub starts over, ending the streams opened with them.
func (a *adminAPI) dropPreviousKeys(w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("tenant")
	err := a.change(r.Context(), func(tx *configstore.Tx) error {
		rec, ok := tx.Get(tenantKey(name))
		if !ok {
			if a.s.fileTenant(name) {
				return fail(http.StatusConflict, "tenant %q is defined in the tenants file", name)
			}
			return fail(http.StatusNotFound, "no tenant %q", name)
		}
		var st storedTenant
		if err := json.Unmarshal(rec.Value, &st); err != nil {
			return fail(http.StatusConflict, "tenant %q: unreadable record", name)
		}
		if st.Previous == nil {
			return nil
		}
		st.Previous = nil
		tx.Put(tenantKey(name), specJSON(st))
		return nil
	})
	if err != nil {
		return err
	}
	a.s.log.Info("tenant previous keys dropped", "tenant", name)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// change runs fn on the database, and keeps what it wrote only when the tenants still fit together: a change that
// would leave out a tenant that is served now (itself or another) is refused. The records written were checked on
// their own; between them only clashes are looked for.
func (a *adminAPI) change(ctx context.Context, fn func(tx *configstore.Tx) error) error {
	return a.s.store.Update(ctx, func(tx *configstore.Tx) error {
		_, before := a.s.resolveTenants(tx.List, a.s.knownProblem)
		if err := fn(tx); err != nil {
			return err
		}
		_, after := a.s.resolveTenants(tx.List, a.s.knownProblem)
		had := map[problem]bool{}
		for _, p := range before {
			had[p] = true
		}
		for _, p := range after {
			if !had[p] {
				return fail(http.StatusConflict, "tenant %q: %s", p.tenant, p.msg)
			}
		}
		return nil
	})
}

func (a *adminAPI) deleteTenant(w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("tenant")
	// A database record the tenants file shadows can still be deleted (it would come back when the file drops the
	// name); the file's tenant itself cannot.
	err := a.change(r.Context(), func(tx *configstore.Tx) error {
		if _, ok := tx.Get(tenantKey(name)); !ok {
			if a.s.fileTenant(name) {
				return fail(http.StatusConflict, "tenant %q is defined in the tenants file", name)
			}
			return fail(http.StatusNotFound, "no tenant %q", name)
		}
		tx.Delete(tenantKey(name))
		return nil
	})
	if err != nil {
		return err
	}
	a.s.log.Info("tenant deleted", "tenant", name)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *adminAPI) status(w http.ResponseWriter, _ *http.Request) error {
	st := a.s.store.Stats()
	file, db := 0, 0
	for _, t := range a.tenants() {
		if t.Source == "file" {
			file++
		} else {
			db++
		}
	}
	out := map[string]any{
		"node": a.s.store.NodeID(), "records": st.Records, "tombstones": st.Tombstones, "peers": st.Peers,
		"tenants": map[string]int{"file": file, "database": db},
	}
	if !st.LastSync.IsZero() {
		out["last_sync"] = st.LastSync.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
