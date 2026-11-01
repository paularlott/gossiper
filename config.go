package gossiper

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/paularlott/gossiper/auth"
	"github.com/paularlott/logger"
)

// Config configures a Hub. The zero value of each field selects its default.
type Config struct {
	// Protocol selects the protocol revisions accepted. Default ProtocolBoth.
	Protocol Protocol

	// PublisherKey verifies publishers' tokens: draft-07 tokens, and Mercure 1.0 access tokens of the trusted
	// issuers. With no key, no JWK Set URL and no Issuers, publishing over HTTP is refused (the Go API,
	// Hub.Publish, still works).
	PublisherKey auth.KeyConfig
	// SubscriberKey verifies subscribers' tokens. Empty: the publisher key is used.
	SubscriberKey auth.KeyConfig
	// TrustedIssuers are the iss values accepted in Mercure 1.0 access tokens signed with the publisher or
	// subscriber key. Empty: Mercure 1.0 tokens are accepted only from Issuers.
	TrustedIssuers []string
	// Issuers are further Mercure 1.0 token issuers, each with its own keys (a static key, a JWK Set URL, or
	// discovery from an authorization server's metadata), trusted for publishing and subscribing.
	Issuers []auth.Issuer
	// ResourceIdentifier is the hub's OAuth resource identifier: Mercure 1.0 tokens must name it in aud. Default:
	// the hub URL the client contacted (scheme, host, /.well-known/mercure), as HubURL is when it is absolute.
	ResourceIdentifier string
	// AllowInsecureKeyURLs lets JWK Set and discovery URLs use plain HTTP, or https with a certificate that does
	// not verify (for tests and development).
	AllowInsecureKeyURLs bool
	// KeyURLsCAs, when set, are the certificate authorities trusted for JWK Set and discovery URLs, as well as the
	// system's: an identity provider with a certificate of a private CA, or a self-signed one.
	KeyURLsCAs *x509.CertPool
	// TrustForwardedProto takes the scheme clients used from the X-Forwarded-Proto header, behind a proxy that
	// terminates TLS and sets it; it decides the default resource identifier and the metadata URL. Default off:
	// the header is ignored.
	TrustForwardedProto bool
	// HistoryStore keeps the history on disk (nil: in memory only). The hub loads what it holds when it starts, and a
	// publish returns once its update is stored; while the store cannot keep up, publishes are refused (503). Hubs
	// of several tenants may share one; the caller closes it after the hubs.
	HistoryStore HistoryStore

	// Anonymous lets subscribers connect without a token; they receive public updates only.
	Anonymous bool
	// Subscriptions turns on the active subscriptions feature: subscription events and the subscriptions API.
	Subscriptions bool
	// ModernSubscriptionFormat formats subscription events and the subscriptions API as current reference hubs
	// do: events of type "mercure", lowercase "subscription"/"subscriptions" types, no JSON-LD @context, and the
	// last event ID in the Link header instead of the body. Default: the format of the published protocol draft
	// (draft-dunglas-mercure-07), which older hubs and clients use.
	ModernSubscriptionFormat bool

	// CORSOrigins are the origins allowed to make cross-origin requests to the hub ("*" for any).
	CORSOrigins []string
	// PublishOrigins are the origins allowed to publish with the authorization cookie (CSRF protection). "*"
	// allows any origin; a cookie publish with neither Origin nor Referer is always refused, and with no publish
	// origins every cookie publish is.
	PublishOrigins []string
	// CookieName is the draft-07 authorization cookie's name. Default "mercureAuthorization".
	CookieName string
	// AccessTokenCookieName is the Mercure 1.0 authorization cookie's name. Default
	// "__Secure-mercure_access_token".
	AccessTokenCookieName string
	// DisableQueryAuthorization refuses the token in the "authorization" query parameter.
	DisableQueryAuthorization bool

	// Heartbeat is how often an idle stream is sent a comment, keeping proxies from closing it. Default 30s;
	// negative disables.
	Heartbeat time.Duration
	// WriteTimeout bounds each write to a subscriber; one that does not take an event in time is disconnected.
	// Default 30s.
	WriteTimeout time.Duration
	// DispatchBuffer is how many updates may wait for one subscriber. A subscriber that falls further behind is
	// disconnected; it reconnects with its last event ID and catches up from the history. Default 1000.
	DispatchBuffer int
	// MaxSubscribers bounds the open streams of this hub (503 over it); with Tenants, of each tenant's hub. Default
	// 0: unbounded.
	MaxSubscribers int
	// MaxTopicSelectors bounds the topic selectors of one subscription request. Default 256.
	MaxTopicSelectors int
	// MaxPatternSelectors bounds those of them that match by pattern (URI templates, URL patterns), which cost
	// far more to evaluate than exact ones. Default 32.
	MaxPatternSelectors int
	// MaxPublishBytes bounds a publish request's body. Default 1 MiB.
	MaxPublishBytes int64
	// CloseOnTokenExpiry ends a stream when its subscriber's draft-07 token expires (the client reconnects with a
	// fresh token, or is refused). Streams opened with a Mercure 1.0 token always end when it expires.
	CloseOnTokenExpiry bool
	// MaxConnectionLifetime ends every stream after this long, so long-lived subscribers authenticate again.
	// Default 0: no limit.
	MaxConnectionLifetime time.Duration

	// HistorySize bounds the updates kept for replay (Last-Event-ID). Default 10000; negative keeps none.
	HistorySize int
	// HistoryBytes bounds the memory they hold. Default 64 MiB; negative: no byte bound.
	HistoryBytes int64
	// HistoryAge drops updates older than this, also while nothing is published, so a node that was busy and is quiet
	// lets go of them. Default one hour; negative: no age bound.
	HistoryAge time.Duration
	// ReplayWindow is how late an update may reach this node and still be replayed to a subscriber whose cursor
	// is a later update. Default 5s.
	ReplayWindow time.Duration

	// MatchCacheSize bounds the topic matcher's caches. Default 10000.
	MatchCacheSize int

	// HubURL is the hub's URL, its path /.well-known/mercure. It is the base that relative URL patterns and
	// topics are resolved against, and the Link target of the subscriptions API. Set it to the absolute URL
	// subscribers use, so URL patterns naming the hub's host match relative topics. Default
	// "https://localhost/.well-known/mercure" as a base, "/.well-known/mercure" as a link.
	HubURL string

	// Transport replicates updates between nodes. Nil: a single node.
	Transport Transport
	// NodeID names this node in published updates. Default: the transport's, or a random one.
	NodeID string

	// Logger receives the hub's logs. Default: none.
	Logger logger.Logger
}

func (c *Config) withDefaults() (Config, error) {
	cfg := *c
	if cfg.CookieName == "" {
		cfg.CookieName = "mercureAuthorization"
	}
	if cfg.AccessTokenCookieName == "" {
		cfg.AccessTokenCookieName = "__Secure-mercure_access_token"
	}
	if cfg.Protocol < ProtocolBoth || cfg.Protocol > ProtocolModern {
		return cfg, errors.New("gossiper: unknown Protocol")
	}
	if cfg.MaxConnectionLifetime < 0 {
		return cfg, errors.New("gossiper: MaxConnectionLifetime is negative")
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = 30 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.DispatchBuffer <= 0 {
		cfg.DispatchBuffer = 1000
	}
	if cfg.MaxTopicSelectors <= 0 {
		cfg.MaxTopicSelectors = 256
	}
	if cfg.MaxPatternSelectors <= 0 {
		cfg.MaxPatternSelectors = 32
	}
	if cfg.MaxPublishBytes <= 0 {
		cfg.MaxPublishBytes = 1 << 20
	}
	switch {
	case cfg.HistorySize == 0:
		cfg.HistorySize = 10000
	case cfg.HistorySize < 0:
		cfg.HistorySize = 0
	}
	switch {
	case cfg.HistoryBytes == 0:
		cfg.HistoryBytes = 64 << 20
	case cfg.HistoryBytes < 0:
		cfg.HistoryBytes = 0
	}
	if cfg.HistorySize == 0 {
		cfg.HistoryBytes = 0
	}
	switch {
	case cfg.HistoryAge == 0:
		cfg.HistoryAge = time.Hour
	case cfg.HistoryAge < 0:
		cfg.HistoryAge = 0
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 5 * time.Second
	}
	if cfg.MatchCacheSize <= 0 {
		cfg.MatchCacheSize = 10000
	}
	if cfg.HubURL == "" {
		cfg.HubURL = hubPath
	}
	if u, err := url.Parse(cfg.HubURL); err != nil || u.Path != hubPath || u.RawQuery != "" || u.Fragment != "" ||
		(u.IsAbs() && u.Host == "") {
		return cfg, errors.New("gossiper: HubURL must be /.well-known/mercure or an absolute URL with that path")
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.NewNullLogger()
	}
	for _, o := range append(append([]string(nil), cfg.CORSOrigins...), cfg.PublishOrigins...) {
		if o == "*" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return cfg, errors.New("gossiper: origin " + o + " is not a scheme://host[:port] origin")
		}
	}
	cfg.CORSOrigins = normaliseOrigins(cfg.CORSOrigins)
	cfg.PublishOrigins = normaliseOrigins(cfg.PublishOrigins)
	return cfg, nil
}

func normaliseOrigins(in []string) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		out = append(out, strings.TrimSuffix(strings.ToLower(o), "/"))
	}
	return out
}

func hasKey(k auth.KeyConfig) bool { return k.Key != "" || k.JWKSURL != "" }
