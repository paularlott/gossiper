// Package server runs a gossiper hub as a standalone HTTP server: the hub, health and metrics endpoints, and
// optionally a gossip cluster.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/compression/snappy"
	"github.com/paularlott/gossip/encryption/aes"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/gossiper/cluster"
	"github.com/paularlott/gossiper/historydb"
	"github.com/paularlott/gossiper/internal/configstore"
	"github.com/paularlott/logger"
)

// Settings are the server's settings, from flags, the environment or the config file.
type Settings struct {
	Listen         string
	AdminListen    string   // the admin API, its docs, metrics and profiling on a listener of their own (empty: on Listen)
	TrustedProxies []string // proxies (addresses or CIDR ranges) whose X-Forwarded-For names the client
	HTTPOnly       bool     // plain HTTP (and h2c), behind a TLS-terminating proxy; HTTPS otherwise
	TLSCert        string   // with TLSKey, the certificate served; else a self-signed one
	TLSKey         string
	TLSDir         string   // the self-signed certificate is kept here (empty: made at each start)
	TLSHosts       []string // further names and addresses for the self-signed certificate
	Metrics        bool
	LogLevel       string
	LogFmt         string

	Protocol         string
	TrustedIssuers   []string
	AuthServers      []string
	ResourceID       string
	HubURL           string
	CookieAccessName string
	InsecureKeyURLs  bool
	KeyURLsCAFile    string // PEM certificates trusted for key and discovery URLs, as well as the system's
	TrustForwarded   bool
	MaxLifetime      string

	PublisherKey     string
	PublisherAlg     string
	PublisherJWKS    string
	SubscriberKey    string
	SubscriberAlg    string
	SubscriberJWKS   string
	Anonymous        bool
	Subscriptions    bool
	ModernSubsFormat bool
	CORSOrigins      []string
	PublishOrigins   []string
	CookieName       string
	NoQueryAuth      bool
	AllowWeakKeys    bool
	ExtraDirectives  string // FrankenPHP's MERCURE_EXTRA_DIRECTIVES
	TokenExpiryClose bool

	Heartbeat      string
	WriteTimeout   string
	DispatchBuffer int
	MaxSubscribers int // open streams on this node, all hubs together (0: unbounded)
	MaxPerIP       int // open streams of one client address on this node (0: unbounded)
	MaxHubSubs     int // open streams of one hub: with tenants, each tenant's (0: unbounded)
	MaxSelectors   int
	MaxPatterns    int
	HistorySize    int
	HistoryBytes   int64
	HistoryBudget  int64 // all the tenants' histories together
	HistoryAge     string
	HistoryDB      string // SQLite file the history is kept in, so it survives restarts
	ReplayWindow   string
	MaxPublishSize int64

	NodeID           string
	ClusterBind      string
	ClusterAdvertise string
	ClusterPeers     []string
	ClusterKey       string
	ClusterInsecure  bool
	ShutdownTimeout  string
	ShutdownDelay    string // readiness answers 503 this long before the listeners close

	TenantsFile string
	Database    string
	APIToken    string
	// The admin API also takes (or takes instead) the access tokens of an identity provider: AdminIssuer trusts
	// its issuer (keys by discovery), for tokens of AdminAudience; what they allow is in authorization details of
	// AdminDetailType (default urn:gossiper:admin), or AdminScope gives full access.
	AdminIssuer     string
	AdminAudience   string
	AdminDetailType string
	AdminScope      string

	Pprof bool
}

// maxPacketAge is how far from this node's clock a cluster packet may be stamped.
const maxPacketAge = time.Minute

// loadCAs returns the system's certificate authorities and the PEM certificates of path ("": nil, the system's
// alone).
func loadCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificate", path)
	}
	return pool, nil
}

// defaultAlgorithm sets a static key's algorithm, when none is given, to the key's own: HS256 for a secret, RS256,
// ES256 (and so on) or EdDSA for a PEM public key, never HMAC with a public key. A key that does not parse is left
// as it is, for its verifier to refuse.
func defaultAlgorithm(k *auth.KeyConfig) {
	if k.Algorithm != "" || k.Key == "" {
		return
	}
	if alg, err := auth.DefaultAlgorithm(k.Key); err == nil {
		k.Algorithm = alg
	}
}

// Defaults returns the default settings.
func Defaults() Settings {
	return Settings{
		Listen: ":8080", LogLevel: "info", Protocol: "modern", TrustedIssuers: []string{"https://localhost"}, LogFmt: "console", Heartbeat: "30s",
		WriteTimeout: "30s", DispatchBuffer: 1000, HistorySize: 10000, HistoryBytes: 64 << 20, HistoryBudget: 1 << 30, ReplayWindow: "5s",
		MaxPublishSize: 1 << 20, MaxSelectors: 256, MaxPatterns: 32, HistoryAge: "1h", ShutdownTimeout: "10s",
		MaxSubscribers: 100000, MaxPerIP: 1000, ShutdownDelay: "0s",
	}
}

func duration(name, s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

// backfillWait is how long a starting node with peers to join waits for one to copy the history of.
const backfillWait = 10 * time.Second

// replicator is what the server needs of the cluster transport.
type replicator interface {
	Ready() bool     // the node has caught up with the cluster
	Dropped() uint64 // updates not sent to a peer
}

// Server is a running hub server.
type Server struct {
	Hub     *gossiper.Hub
	Handler http.Handler
	// AdminHandler serves the admin API, its docs, metrics and profiling when AdminListen is set (they are then not on
	// Handler); nil otherwise.
	AdminHandler http.Handler
	proxies      []netip.Prefix
	settings     Settings
	log          logger.Logger
	gossip       *gossip.Cluster
	histDB       *historydb.Store
	adminIDP     *adminIDP   // the admin API's identity provider, or nil
	certs        *certSource // the TLS certificate; nil with HTTPOnly
	repl         replicator  // the cluster transport, when clustered
	shutdown     time.Duration
	shutdownWait time.Duration // ShutdownDelay
	streams      *streamLimits

	// Tenants serves the hubs of the tenants, when the tenants file gives any or there is a database (Hub is then
	// nil).
	Tenants *gossiper.Tenants
	tenants []tenantSpec // the tenants file's

	// store is the database of tenants the admin API edits, when Database is set.
	store          *configstore.Store
	baseConfig     gossiper.Config // the settings every tenant's hub starts from
	applyMu        sync.Mutex
	mercureApplied map[string]tenantSpec // the tenants whose hubs run, as last applied
	reported       map[string]bool       // tenants left out, already logged
	checked        checkCache            // each database record's own check, by its spec
	validated      atomic.Int64          // database records whose hub settings were checked (keys parsed)
	stopWatch      chan struct{}
	watchDone      chan struct{}
	closeWatch     sync.Once
	draining       atomic.Bool // shutting down: /readyz answers 503
}

// New builds the server: the hub and, with ClusterBind set, the gossip cluster it joins. Call Close to stop it.
func New(s Settings, log logger.Logger) (*Server, error) {
	if log == nil {
		log = logger.NewNullLogger()
	}
	if s.ExtraDirectives != "" {
		applyExtraDirectives(&s, s.ExtraDirectives, log)
	}
	protocol, err := gossiper.ParseProtocol(s.Protocol)
	if err != nil {
		return nil, err
	}
	var issuers []auth.Issuer
	for _, as := range splitList(s.AuthServers) { // OAuth authorization servers: their keys come from discovery
		issuers = append(issuers, auth.Issuer{Issuer: as, Discover: true})
	}
	keyCAs, err := loadCAs(s.KeyURLsCAFile)
	if err != nil {
		return nil, fmt.Errorf("key urls ca file: %w", err)
	}
	cfg := gossiper.Config{
		Protocol:                  protocol,
		TrustedIssuers:            splitList(s.TrustedIssuers),
		Issuers:                   issuers,
		ResourceIdentifier:        s.ResourceID,
		HubURL:                    s.HubURL,
		AccessTokenCookieName:     s.CookieAccessName,
		AllowInsecureKeyURLs:      s.InsecureKeyURLs,
		KeyURLsCAs:                keyCAs,
		TrustForwardedProto:       s.TrustForwarded,
		PublisherKey:              auth.KeyConfig{Key: s.PublisherKey, Algorithm: s.PublisherAlg, JWKSURL: s.PublisherJWKS},
		SubscriberKey:             auth.KeyConfig{Key: s.SubscriberKey, Algorithm: s.SubscriberAlg, JWKSURL: s.SubscriberJWKS},
		Anonymous:                 s.Anonymous,
		Subscriptions:             s.Subscriptions,
		ModernSubscriptionFormat:  s.ModernSubsFormat,
		CORSOrigins:               splitList(s.CORSOrigins),
		PublishOrigins:            splitList(s.PublishOrigins),
		CookieName:                s.CookieName,
		DisableQueryAuthorization: s.NoQueryAuth,
		CloseOnTokenExpiry:        s.TokenExpiryClose,
		DispatchBuffer:            s.DispatchBuffer,
		MaxSubscribers:            s.MaxHubSubs,
		MaxTopicSelectors:         s.MaxSelectors,
		MaxPatternSelectors:       s.MaxPatterns,
		HistorySize:               s.HistorySize,
		HistoryBytes:              s.HistoryBytes,
		MaxPublishBytes:           s.MaxPublishSize,
		NodeID:                    s.NodeID,
		Logger:                    log,
	}
	// A key's algorithm defaults to its own (HS256 for a secret, a PEM public key's own); with a JWK Set and no
	// algorithm, every public-key algorithm is accepted.
	if cfg.PublisherKey.Key == "" && cfg.PublisherKey.JWKSURL == "" {
		cfg.PublisherKey = auth.KeyConfig{}
	}
	if cfg.SubscriberKey.Key == "" && cfg.SubscriberKey.JWKSURL == "" {
		cfg.SubscriberKey = auth.KeyConfig{}
	}
	defaultAlgorithm(&cfg.PublisherKey)
	defaultAlgorithm(&cfg.SubscriberKey)
	if cfg.MaxConnectionLifetime, err = duration("max connection lifetime", s.MaxLifetime); err != nil {
		return nil, err
	}
	if cfg.Heartbeat, err = duration("heartbeat", s.Heartbeat); err != nil {
		return nil, err
	}
	if cfg.Heartbeat == 0 && s.Heartbeat != "" {
		cfg.Heartbeat = -1 // "0s" turns it off
	}
	if cfg.WriteTimeout, err = duration("write timeout", s.WriteTimeout); err != nil {
		return nil, err
	}
	if cfg.HistoryAge, err = duration("history age", s.HistoryAge); err != nil {
		return nil, err
	}
	if cfg.HistoryAge == 0 && s.HistoryAge != "" {
		cfg.HistoryAge = -1 // "0s" keeps updates however old
	}
	if cfg.ReplayWindow, err = duration("replay window", s.ReplayWindow); err != nil {
		return nil, err
	}
	shutdown, err := duration("shutdown timeout", s.ShutdownTimeout)
	if err != nil {
		return nil, err
	}
	if shutdown <= 0 {
		shutdown = 10 * time.Second
	}
	shutdownWait, err := duration("shutdown delay", s.ShutdownDelay)
	if err != nil {
		return nil, err
	}
	if s.Pprof && s.AdminListen == "" {
		// /debug/pprof/cmdline shows the command line, keys and all: never on the public listener.
		return nil, errors.New("pprof: set admin-listen: profiling is served only on the admin listener")
	}
	if s.MaxSubscribers < 0 || s.MaxPerIP < 0 || s.MaxHubSubs < 0 {
		return nil, errors.New("max subscribers: 0 (unbounded) or more")
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		return nil, errors.New("tls: set both the certificate and the key, or neither")
	}
	proxies, err := parseProxies(splitList(s.TrustedProxies))
	if err != nil {
		return nil, err
	}

	if s.ClusterBind != "" && s.ClusterKey == "" {
		// Without a key anyone who reaches the gossip port joins the cluster: reads every update and the tenants'
		// keys, and injects updates and tenants of its own.
		if !s.ClusterInsecure {
			return nil, errors.New("cluster-bind needs cluster-key (gossiper genkey): without it the cluster is unencrypted and anyone who reaches its port can join (cluster-insecure allows it, on a trusted network)")
		}
		log.Warn("cluster without a key: gossip is unencrypted and unauthenticated (cluster-insecure)")
	}
	if !s.AllowWeakKeys {
		for name, k := range map[string]auth.KeyConfig{"publisher-key": {Key: s.PublisherKey, Algorithm: s.PublisherAlg},
			"subscriber-key": {Key: s.SubscriberKey, Algorithm: s.SubscriberAlg}} {
			if auth.WeakSecret(k) {
				return nil, fmt.Errorf("%s: %s", name, errWeakKey)
			}
		}
	}
	if (s.APIToken != "" || s.AdminIssuer != "") && s.Database == "" {
		return nil, errors.New("admin API: it needs a database (set database)")
	}
	if s.AdminIssuer != "" && s.AdminAudience == "" {
		return nil, errors.New("admin issuer: set admin-audience, the admin API's identifier in the identity provider")
	}
	if (s.AdminAudience != "" || s.AdminDetailType != "" || s.AdminScope != "") && s.AdminIssuer == "" {
		return nil, errors.New("admin audience, detail type and scope: they need admin-issuer")
	}
	certs, err := newServerCerts(s, log)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if certs != nil && certs.selfSigned() {
		where := filepath.Join(s.TLSDir, selfSignedCert)
		if s.TLSDir == "" {
			where = "none (made at each start; set tls-dir to keep it)"
		}
		log.Warn("serving HTTPS with a self-signed certificate: clients trust its file as a CA file, or skip verification",
			"file", where, "sha256", certs.fingerprint(), "hosts", strings.Join(certs.hosts, ","))
	}
	srv := &Server{settings: s, log: log, shutdown: shutdown, shutdownWait: shutdownWait, proxies: proxies, certs: certs,
		mercureApplied: map[string]tenantSpec{}, reported: map[string]bool{}}
	if srv.tenants, err = loadTenants(s.TenantsFile); err != nil {
		return nil, err
	}
	for _, t := range srv.tenants {
		if err := srv.checkKeys(t); err != nil {
			return nil, fmt.Errorf("tenants file: tenant %q: %w", t.Name, err)
		}
	}
	if len(srv.tenants) == 0 && s.Database == "" { // a single hub
		if err := hostAudience(s, protocol); err != nil {
			return nil, err
		}
	}
	if s.HistoryDB != "" {
		if srv.histDB, err = historydb.Open(s.HistoryDB, log.WithGroup("history")); err != nil {
			return nil, err
		}
		cfg.HistoryStore = srv.histDB
	}
	if s.InsecureKeyURLs {
		log.Warn("allow-insecure-key-urls: key and discovery URLs may use plain HTTP or a certificate that does not verify; development only")
	}
	if s.AdminIssuer != "" {
		if srv.adminIDP, err = newAdminIDP(s.AdminIssuer, s.AdminAudience, s.AdminDetailType, s.AdminScope, s.InsecureKeyURLs, cfg.KeyURLsCAs); err != nil {
			if srv.histDB != nil {
				_ = srv.histDB.Close()
			}
			return nil, fmt.Errorf("admin issuer: %w", err)
		}
	}
	cleanup := func() {
		if srv.adminIDP != nil {
			srv.adminIDP.close()
		}
		if srv.store != nil {
			_ = srv.store.Close()
		}
		if srv.histDB != nil {
			_ = srv.histDB.Close()
		}
		if srv.gossip != nil {
			srv.gossip.Stop()
		}
	}
	if s.ClusterBind != "" {
		if srv.gossip, err = newGossip(s, log); err != nil {
			cleanup()
			return nil, err
		}
		var backfill time.Duration // a node with peers to join copies the history of one as it starts
		if len(splitList(s.ClusterPeers)) > 0 {
			backfill = backfillWait
		}
		fast := cluster.New(srv.gossip, cluster.Options{Backfill: backfill})
		cfg.Transport, srv.repl = fast, fast
		if cfg.NodeID == "" {
			cfg.NodeID = srv.gossip.LocalNode().ID.String()
		}
	}
	changed := make(chan struct{}, 1)
	if s.Database != "" {
		srv.store, err = configstore.Open(configstore.Options{
			Path: s.Database, Cluster: srv.gossip, Logger: log.WithGroup("database"),
			OnChange: func([]string) {
				select {
				case changed <- struct{}{}:
				default:
				}
			},
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("database: %w", err)
		}
	}
	srv.baseConfig = cfg
	resolved, problems := srv.resolveTenants(srv.storeList(), srv.checkRecord)
	for _, p := range problems {
		log.Warn("tenant left out", "tenant", p.tenant, "reason", p.msg)
		srv.reported[p.tenant+"\x00"+p.msg] = true
	}
	if len(srv.tenants) > 0 || srv.store != nil {
		// Multi-tenant: one hub per tenant, picked by host; the server's own keys would belong to no one.
		if err = noServerMercureKeys(s); err == nil {
			initial := specs(resolved)
			for _, t := range initial {
				srv.mercureApplied[t.Name] = t
			}
			srv.Tenants, err = gossiper.NewTenants(mercureTenants(cfg, initial), cfg.Transport, gossiper.HistoryBudget(s.HistoryBudget))
		}
	} else {
		srv.Hub, err = gossiper.New(cfg)
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	if srv.store != nil {
		srv.stopWatch, srv.watchDone = make(chan struct{}), make(chan struct{})
		go srv.watchStore(changed, srv.stopWatch)
	}
	if srv.gossip != nil {
		if len(s.ClusterPeers) > 0 {
			if err := srv.gossip.Join(splitList(s.ClusterPeers)); err != nil {
				log.Warn("cluster: could not join yet, retrying in the background", "error", err.Error())
			}
		}
	}
	srv.Handler, srv.AdminHandler = srv.routes()
	return srv, nil
}

// hostAudience refuses a single hub that takes Mercure 1.0 tokens from an authorization server without knowing its
// own resource identifier: the audience would be the hub URL the client contacted, from its Host header, so a token
// the server issued for another hub would pass here with that hub's name as the Host. The default issuer (tokens
// signed with the hub's own key) is left alone.
func hostAudience(s Settings, p gossiper.Protocol) error {
	if p == gossiper.ProtocolLegacy || s.ResourceID != "" {
		return nil
	}
	if u, err := url.Parse(s.HubURL); err == nil && u.IsAbs() {
		return nil
	}
	issuers := splitList(s.TrustedIssuers)
	keyed := s.PublisherKey != "" || s.PublisherJWKS != "" || s.SubscriberKey != "" || s.SubscriberJWKS != ""
	if len(splitList(s.AuthServers)) > 0 || keyed && len(issuers) > 0 && !slices.Equal(issuers, Defaults().TrustedIssuers) {
		return errors.New("resource-identifier: Mercure 1.0 tokens of an authorization server or a trusted issuer must be bound to this hub: set resource-identifier or an absolute hub-url (else the audience comes from the client's Host header)")
	}
	return nil
}

func newGossip(s Settings, log logger.Logger) (*gossip.Cluster, error) {
	gc := gossip.DefaultConfig()
	gc.NodeID = s.NodeID
	gc.BindAddr = s.ClusterBind
	gc.AdvertiseAddr = s.ClusterAdvertise
	gc.MsgCodec = shamaton.New()
	gc.Compressor = snappy.New()
	gc.Logger = log.WithGroup("cluster")
	gc.ApplicationVersion = "gossiper/1"
	// Every update is one message to every other node: gossip's default queues (sized for its own state traffic)
	// would drop updates in a burst.
	gc.SendQueueSize = max(gc.SendQueueSize, 16384)
	gc.IncomingPacketQueueDepth = max(gc.IncomingPacketQueueDepth, 16384)
	if s.ClusterKey != "" {
		key, err := base64.StdEncoding.DecodeString(s.ClusterKey)
		if n := len(key); err != nil || (n != 16 && n != 24 && n != 32) { // a raw key can be valid base64 too
			key = []byte(s.ClusterKey)
		}
		if n := len(key); n != 16 && n != 24 && n != 32 {
			return nil, errors.New("cluster key: must be 16, 24 or 32 bytes (raw, or base64)")
		}
		gc.EncryptionKey = key
		gc.Cipher = aes.New()
		// A packet recorded on the network and sent again later would still decrypt: gossip remembers the messages
		// it saw for a while only, so older ones are refused. The nodes' clocks must agree within this (they must
		// within seconds anyway: see the hub's skew bound).
		gc.MaxPacketAge = maxPacketAge
	}
	gc.Transport = gossip.NewSocketTransport(gc)
	c, err := gossip.NewCluster(gc)
	if err != nil {
		return nil, err
	}
	c.Start()
	return c, nil
}

// splitList flattens comma- or space-separated values.
func splitList(in []string) []string {
	var out []string
	for _, v := range in {
		out = append(out, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })...)
	}
	return out
}

// routes returns the handler of the main listener and, with AdminListen set, the admin listener's (else nil, and the
// admin routes are on the main one). Both answer /healthz and /readyz.
func (s *Server) routes() (http.Handler, http.Handler) {
	mux := http.NewServeMux()
	var mercure http.Handler = s.Hub
	if s.Tenants != nil {
		mercure = s.Tenants
	}
	s.streams = newStreamLimits(s.settings.MaxSubscribers, s.settings.MaxPerIP)
	mercure = s.limitStreams(mercure)
	mux.Handle("/.well-known/mercure", mercure)
	mux.Handle("/.well-known/mercure/", mercure)
	mux.Handle("/.well-known/oauth-protected-resource/.well-known/mercure", mercure)
	s.healthRoutes(mux)
	admin := mux
	if s.settings.AdminListen != "" {
		admin = http.NewServeMux()
		s.healthRoutes(admin)
	}
	if s.store != nil && (s.settings.APIToken != "" || s.adminIDP != nil) {
		admin.HandleFunc("GET /api-docs", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api-docs/", http.StatusMovedPermanently)
		})
		admin.HandleFunc("GET /api-docs/{$}", apiDocs)
		admin.HandleFunc("GET /api-docs/assets/{file}", apiDocsAsset)
		admin.HandleFunc("GET /api/openapi.json", openAPIDocument)
		s.adminRoutes(admin)
		if t := s.settings.APIToken; t != "" && !strings.HasPrefix(t, "$2") && len(t) < 32 {
			s.log.Warn("the API token is short: use 32 characters or more (gossiper genkey makes one), or its bcrypt hash")
		}
	}
	if s.settings.AdminListen == "" && (s.settings.Metrics || (s.store != nil && (s.settings.APIToken != "" || s.adminIDP != nil))) {
		s.log.Warn("the admin API and metrics are served on the public listener: set admin-listen (e.g. an internal address) to keep them off it")
	}
	if s.settings.Pprof {
		admin.HandleFunc("/debug/pprof/", pprof.Index)
		admin.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		admin.HandleFunc("/debug/pprof/profile", pprof.Profile)
		admin.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		admin.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	if s.settings.Metrics {
		admin.HandleFunc("GET /metrics", s.metrics)
	}
	if admin == mux {
		return mux, nil
	}
	return mux, admin
}

func (s *Server) healthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if s.draining.Load() { // shutting down: send new clients elsewhere
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("draining\n"))
			return
		}
		if s.repl != nil && !s.repl.Ready() { // still catching up: replay would miss updates
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("syncing\n"))
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
}

// metrics writes the hub's counters in the Prometheus text format.
func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	var st gossiper.StatsSnapshot
	if s.Tenants != nil {
		st = s.Tenants.Stats()
	} else {
		st = s.Hub.Stats()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	metric := func(name, typ, help string, v uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, typ, name, v)
	}
	metric("gossiper_subscribers", "gauge", "Open subscriber streams on this node.", st.Subscribers)
	metric("gossiper_published_total", "counter", "Updates published through this node.", st.Published)
	metric("gossiper_applied_total", "counter", "Updates applied on this node.", st.Applied)
	metric("gossiper_delivered_total", "counter", "Events written to subscribers.", st.Delivered)
	metric("gossiper_dropped_subscribers_total", "counter", "Subscribers disconnected for falling behind.", st.Dropped)
	metric("gossiper_replayed_total", "counter", "Events sent from the history.", st.Replayed)
	metric("gossiper_replay_misses_total", "counter", "Reconnections whose last event ID was not in the history.", st.ReplayMisses)
	metric("gossiper_duplicates_total", "counter", "Updates received twice and ignored.", st.Duplicates)
	metric("gossiper_publish_rejected_total", "counter", "Publish requests refused.", st.PublishRejected)
	metric("gossiper_refused_total", "counter", "Updates from other nodes refused for a clock far ahead.", st.Refused)
	metric("gossiper_history_updates", "gauge", "Updates held in the history.", uint64(st.HistoryLen))
	metric("gossiper_history_bytes", "gauge", "Memory the history holds, in bytes (every tenant's).", uint64(st.HistoryBytes))
	metric("gossiper_key_sets_failing", "gauge", "Remote key sets (JWK Sets, discovery) whose last fetch failed: their tokens are refused.", st.KeySetsFailing)
	if s.store != nil {
		ds := s.store.Stats()
		metric("gossiper_database_records", "gauge", "Live records in this node's tenant database.", uint64(ds.Records))
		metric("gossiper_database_tombstones", "gauge", "Deleted records remembered in this node's tenant database.", uint64(ds.Tombstones))
	}
	if s.gossip != nil {
		metric("gossiper_cluster_nodes", "gauge", "Alive nodes in the gossip cluster.", uint64(s.gossip.NumAliveNodes()))
	}
	if s.histDB != nil {
		metric("gossiper_history_unwritten_total", "counter", "Updates not written to the history database: it could not keep up.", s.histDB.Unwritten())
	}
	if s.repl != nil {
		metric("gossiper_replication_dropped_total", "counter", "Updates not sent to a peer: it left the cluster, or fell too far behind (counted per peer).", s.repl.Dropped())
	}
	_, _ = w.Write([]byte(b.String()))
}

// Run serves until ctx ends, then shuts down gracefully: streams end (clients reconnect elsewhere), the HTTP
// server drains, and the node leaves the cluster.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.settings.Listen)
	if err != nil {
		return err
	}
	var admin net.Listener
	if s.AdminHandler != nil {
		if admin, err = net.Listen("tcp", s.settings.AdminListen); err != nil {
			ln.Close()
			return fmt.Errorf("admin listener: %w", err)
		}
	}
	return s.Serve(ctx, ln, admin)
}

// Serve is Run on existing listeners: admin serves AdminHandler, and must be given when there is one.
func (s *Server) Serve(ctx context.Context, ln, admin net.Listener) error {
	if (s.AdminHandler != nil) != (admin != nil) {
		return errors.New("an admin listener is needed with admin-listen, and only then")
	}
	servers := []*http.Server{s.httpServer(s.Handler)}
	listeners := []net.Listener{ln}
	if admin != nil {
		servers, listeners = append(servers, s.httpServer(s.AdminHandler)), append(listeners, admin)
	}
	errc := make(chan error, len(servers))
	for i, hs := range servers {
		go func() {
			if s.certs != nil {
				errc <- hs.ServeTLS(listeners[i], "", "")
			} else {
				errc <- hs.Serve(listeners[i])
			}
		}()
	}
	if s.certs != nil {
		go s.certs.watch()
	}
	s.log.Info("listening", "addr", ln.Addr().String(), "tls", s.certs != nil)
	if admin != nil {
		s.log.Info("admin listening", "addr", admin.Addr().String())
	}
	var failed error
	select {
	case failed = <-errc:
	case <-ctx.Done():
	}
	s.draining.Store(true)
	if s.shutdownWait > 0 && failed == nil {
		// Still serving, while /readyz answers 503: a load balancer stops sending new clients before the listeners
		// close.
		s.log.Info("draining", "delay", s.shutdownWait.String())
		t := time.NewTimer(s.shutdownWait)
		select {
		case <-t.C:
		case failed = <-errc:
		}
		t.Stop()
	}
	sctx, cancel := context.WithTimeout(context.Background(), s.shutdown)
	defer cancel()
	s.log.Info("shutting down")
	// The listeners close, and the hub ends the open streams (their clients reconnect, to another node when there is
	// one), which the HTTP servers would otherwise wait for; they drain what is left, and the node leaves the cluster.
	var wg sync.WaitGroup
	for _, hs := range servers {
		wg.Go(func() { _ = hs.Shutdown(sctx) })
	}
	s.Close(sctx)
	wg.Wait()
	for range len(servers) - btoi(failed != nil) {
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) && failed == nil {
			failed = err
		}
	}
	if errors.Is(failed, http.ErrServerClosed) {
		return nil
	}
	return failed
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Server) httpServer(h http.Handler) *http.Server {
	hs := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		Protocols:         new(http.Protocols),
		ErrorLog:          stdlog.New(httpErrorLog{s.log}, "", 0),
	}
	// HTTP/2 also without TLS (h2c), behind a proxy that terminates TLS: a streaming publish and a client's
	// subscriptions then share one connection.
	hs.Protocols.SetHTTP1(true)
	hs.Protocols.SetHTTP2(true)
	hs.Protocols.SetUnencryptedHTTP2(true)
	if s.certs != nil {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certs.GetCertificate}
	}
	return hs
}

// httpErrorLog takes the HTTP servers' own log lines into the server's log: failed TLS handshakes (scanners, clients
// that do not trust a self-signed certificate) at debug, as they are the client's business, the rest as warnings.
type httpErrorLog struct{ log logger.Logger }

func (l httpErrorLog) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if strings.Contains(msg, "TLS handshake error") {
		l.log.Debug(msg)
	} else {
		l.log.Warn(msg)
	}
	return len(p), nil
}

// ReloadCertificate loads the TLS certificate again now (SIGHUP): renewed files, or a self-signed certificate made
// again. A renewal is also picked up by itself within an hour.
func (s *Server) ReloadCertificate() error {
	if s.certs == nil {
		return nil
	}
	return s.certs.Reload()
}

// Close stops the hub and leaves the cluster.
func (s *Server) Close(ctx context.Context) {
	if s.stopWatch != nil {
		s.closeWatch.Do(func() { close(s.stopWatch) })
		<-s.watchDone
	}
	if err := s.closeMercure(ctx); err != nil {
		s.log.Warn("hub did not close cleanly", "error", err.Error())
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			s.log.Warn("database did not close cleanly", "error", err.Error())
		}
	}
	if s.histDB != nil {
		if err := s.histDB.Close(); err != nil {
			s.log.Warn("history database did not close cleanly", "error", err.Error())
		}
	}
	if s.adminIDP != nil {
		s.adminIDP.close()
	}
	if s.certs != nil {
		s.certs.Close()
	}
	if s.gossip != nil {
		s.gossip.Leave()
		s.gossip.Stop()
	}
}

// closeMercure stops the hub, or every tenant's.
func (s *Server) closeMercure(ctx context.Context) error {
	if s.Tenants != nil {
		return s.Tenants.Close(ctx)
	}
	return s.Hub.Close(ctx)
}
