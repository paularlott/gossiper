// Command gossiper runs a Mercure-compatible hub.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/cli"
	cli_toml "github.com/paularlott/cli/toml"
	"github.com/paularlott/gossiper/build"
	"github.com/paularlott/gossiper/internal/server"
	logslog "github.com/paularlott/logger/slog"
)

const envPrefix = "GOSSIPER_"

func main() {
	if err := root().Execute(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func root() *cli.Command {
	s := server.Defaults()
	cfgName := "gossiper.toml"
	cfgFile := cli_toml.NewConfigFile(&cfgName, func() []string {
		paths := []string{"."}
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths, filepath.Join(home, ".config", "gossiper"))
		}
		if runtime.GOOS != "windows" {
			paths = append(paths, "/etc/gossiper")
		}
		return paths
	})
	return &cli.Command{
		Name:        "gossiper",
		Version:     build.FullVersion(),
		Usage:       "Clustered, multi-tenant Mercure hub",
		Description: "Every setting is a flag, a GOSSIPER_* environment variable, or a key in gossiper.toml.",
		ConfigFile:  cfgFile,
		Suggestions: true,
		Flags: []cli.Flag{&cli.StringFlag{Name: "config", Aliases: []string{"c"}, AssignTo: &cfgName, Global: true,
			Usage: "Configuration file (TOML)", EnvVars: []string{envPrefix + "CONFIG"},
			DefaultText: "gossiper.toml in the current directory, ~/.config/gossiper/ or /etc/gossiper/"}},
		Commands: []*cli.Command{serveCmd(&s), tokenCmd(), genkeyCmd(), healthcheckCmd()},
	}
}

// str is a string setting; aliases are further environment variables, after GOSSIPER_*.
func str(name, usage string, to *string, aliases ...string) *cli.StringFlag {
	return &cli.StringFlag{Name: name, Usage: usage, AssignTo: to, DefaultValue: *to, ConfigPath: []string{key(name)},
		EnvVars: append([]string{env(name)}, aliases...)}
}

func strs(name, usage string, to *[]string, aliases ...string) *cli.StringSliceFlag {
	return &cli.StringSliceFlag{Name: name, Usage: usage, AssignTo: to, DefaultValue: *to, ConfigPath: []string{key(name)},
		EnvVars: append([]string{env(name)}, aliases...)}
}

func boolean(name, usage string, to *bool) *cli.BoolFlag {
	return &cli.BoolFlag{Name: name, Usage: usage, AssignTo: to, DefaultValue: *to, ConfigPath: []string{key(name)},
		EnvVars: []string{env(name)}}
}

func integer(name, usage string, to *int) *cli.IntFlag {
	return &cli.IntFlag{Name: name, Usage: usage, AssignTo: to, DefaultValue: *to, ConfigPath: []string{key(name)},
		EnvVars: []string{env(name)}}
}

func integer64(name, usage string, to *int64) *cli.Int64Flag {
	return &cli.Int64Flag{Name: name, Usage: usage, AssignTo: to, DefaultValue: *to, ConfigPath: []string{key(name)},
		EnvVars: []string{env(name)}}
}

// key is a flag's config-file key: dashes become underscores.
func key(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}

// env is a flag's environment variable: GOSSIPER_ and the key in capitals.
func env(name string) string {
	b := []byte(key(name))
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return envPrefix + string(b)
}

func serveCmd(s *server.Settings) *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "Run the hub",
		Flags: []cli.Flag{
			str("listen", "Address to listen on", &s.Listen),
			str("admin-listen", "Address of a listener of its own for the admin API, its docs, metrics and profiling (default: on listen)", &s.AdminListen),
			boolean("admin-ui", "Serve the status page at / on the admin listener, with no login (admin-listen only; --admin-ui=false turns it off)", &s.AdminUI),
			strs("trusted-proxies", "Proxies (addresses or CIDR ranges) whose X-Forwarded-For header names the client, for the per-address limits (admin API failed logins, streams); set it behind a load balancer", &s.TrustedProxies),
			boolean("http-only", "Serve plain HTTP (and HTTP/2 without TLS), behind a proxy that terminates TLS; HTTPS otherwise", &s.HTTPOnly),
			str("tls-cert", "TLS certificate file (PEM), with tls-key; renewed files are picked up within an hour, or at once on SIGHUP (default: a self-signed certificate)", &s.TLSCert),
			str("tls-key", "TLS private key file (PEM)", &s.TLSKey),
			str("tls-dir", "Directory the self-signed certificate is kept in, so clients can trust its file (default: a new one at each start)", &s.TLSDir),
			strs("tls-hosts", "Further host names and addresses for the self-signed certificate (beside localhost, the host name, the listen, admin-listen, hub-url and cluster-advertise hosts)", &s.TLSHosts),
			boolean("metrics", "Serve Prometheus metrics at /metrics", &s.Metrics),
			boolean("pprof", "Serve Go profiling at /debug/pprof/ on the admin listener (needs admin-listen; for diagnosis)", &s.Pprof),
			str("log-level", "Log level: trace, debug, info, warn, error", &s.LogLevel),
			str("log-format", "Log format: console or json", &s.LogFmt),
			str("protocol", "Protocol revisions accepted: modern (Mercure 1.0), both, or legacy (draft-07)", &s.Protocol),
			str("publisher-key", "Publishers' JWT key: an HMAC secret or a PEM public key", &s.PublisherKey, "MERCURE_PUBLISHER_JWT_KEY"),
			str("publisher-alg", "Publishers' JWT algorithm (HS256, RS256, ES256, EdDSA, ...; default: HS256 with a secret, a PEM public key's own (RS256, ES256, ...; never HMAC), any public-key algorithm with a JWK Set)", &s.PublisherAlg, "MERCURE_PUBLISHER_JWT_ALG"),
			str("publisher-jwks-url", "Publishers' JWK Set URL (instead of a key)", &s.PublisherJWKS),
			str("subscriber-key", "Subscribers' JWT key (default: the publisher key)", &s.SubscriberKey, "MERCURE_SUBSCRIBER_JWT_KEY"),
			str("subscriber-alg", "Subscribers' JWT algorithm (default: HS256 with a secret, a PEM public key's own, any public-key algorithm with a JWK Set)", &s.SubscriberAlg, "MERCURE_SUBSCRIBER_JWT_ALG"),
			strs("trusted-issuers", "iss values accepted in Mercure 1.0 tokens signed with the publisher or subscriber key", &s.TrustedIssuers, "MERCURE_TRUSTED_ISSUERS"),
			strs("authorization-servers", "OAuth authorization servers issuing Mercure 1.0 tokens (keys found by RFC 8414 discovery)", &s.AuthServers),
			str("resource-identifier", "The aud Mercure 1.0 tokens must carry (default: an absolute hub-url, else the hub URL the client contacted)", &s.ResourceID, "MERCURE_RESOURCE_IDENTIFIER"),
			str("hub-url", "The hub's public URL, https://host/.well-known/mercure: base for relative topics and URL patterns", &s.HubURL),
			str("access-token-cookie-name", "Mercure 1.0 authorization cookie name", &s.CookieAccessName),
			boolean("allow-insecure-key-urls", "Allow plain-HTTP JWK Set and discovery URLs, and https ones with a certificate that does not verify (development only)", &s.InsecureKeyURLs),
			str("key-urls-ca-file", "PEM certificates (a private CA, or an identity provider's self-signed one) trusted for JWK Set and discovery URLs, as well as the system's", &s.KeyURLsCAFile),
			boolean("trust-forwarded-proto", "Take the client's scheme from X-Forwarded-Proto (behind a TLS-terminating proxy)", &s.TrustForwarded),
			str("max-connection-lifetime", "End every stream after this long (empty: no limit)", &s.MaxLifetime),
			str("subscriber-jwks-url", "Subscribers' JWK Set URL (instead of a key)", &s.SubscriberJWKS),
			boolean("anonymous", "Allow subscribers without a token (public updates only)", &s.Anonymous),
			boolean("subscriptions", "Enable subscription events and the subscriptions API", &s.Subscriptions),
			boolean("modern-subscription-format", "Format subscription events as current reference hubs do (event type mercure, no JSON-LD)", &s.ModernSubsFormat),
			strs("cors-origins", "Origins allowed to make cross-origin requests (* for any)", &s.CORSOrigins),
			strs("publish-origins", "Origins allowed to publish with the authorization cookie", &s.PublishOrigins),
			str("cookie-name", "Authorization cookie name", &s.CookieName),
			str("mercure-extra-directives", "FrankenPHP's extra mercure directives (anonymous, subscriptions, cors_origins, publish_origins, cookie_name, heartbeat, write_timeout, protocol_version_compatibility), applied where not set otherwise", &s.ExtraDirectives, "MERCURE_EXTRA_DIRECTIVES"),
			boolean("allow-weak-keys", "Accept HMAC secrets shorter than their algorithm needs (32 bytes for HS256), the server's and the tenants'", &s.AllowWeakKeys),
			boolean("no-query-authorization", `Refuse the token in the "authorization" query parameter`, &s.NoQueryAuth),
			boolean("close-on-token-expiry", "End a stream when its subscriber's token expires", &s.TokenExpiryClose),
			str("heartbeat", "Idle stream heartbeat interval (0s disables)", &s.Heartbeat),
			str("write-timeout", "Per-write timeout for subscriber streams", &s.WriteTimeout),
			integer("dispatch-buffer", "Updates queued per subscriber before it is disconnected", &s.DispatchBuffer),
			integer("max-subscribers", "Open streams allowed on this node, all hubs together (503 over it; 0: unbounded)", &s.MaxSubscribers),
			integer("max-subscribers-per-ip", "Open streams allowed per client address on this node (429 over it; 0: unbounded)", &s.MaxPerIP),
			integer("max-hub-subscribers", "Open streams allowed per hub on this node; with tenants, per tenant (0: unbounded)", &s.MaxHubSubs),
			integer("max-topic-selectors", "Topic matchers allowed in one subscription request", &s.MaxSelectors),
			integer("max-pattern-selectors", "Of them, matchers that match by pattern (URI templates, URL patterns)", &s.MaxPatterns),
			integer("history-size", "Updates kept for Last-Event-ID replay (negative: none)", &s.HistorySize),
			integer64("history-bytes", "Memory the history may hold, in bytes (each tenant's)", &s.HistoryBytes),
			integer64("history-budget", "Memory all the tenants' histories may hold together, in bytes; the largest give up their oldest updates first (0: no budget)", &s.HistoryBudget),
			str("history-age", "Drop history older than this, also while idle (0: no age bound)", &s.HistoryAge),
			boolean("history-persist", "Write the history to the database too, in the background, so a node has it back after a restart (a single node, or a cluster that stopped all at once)", &s.HistoryPersist),
			str("history-flush", "How often the history is written to the database, with history-persist", &s.HistoryFlush),
			str("replay-window", "How late an update may arrive and still be replayed", &s.ReplayWindow),
			integer64("max-publish-size", "Largest publish request body, in bytes", &s.MaxPublishSize),
			str("cluster-bind", "Gossip bind address (host:port); enables clustering", &s.ClusterBind),
			str("cluster-advertise", "Gossip address advertised to peers", &s.ClusterAdvertise),
			strs("cluster-peers", "Gossip peers to join (host:port, hostname or srv+name)", &s.ClusterPeers),
			str("cluster-key", "Gossip encryption key: 16, 24 or 32 bytes, base64 (see genkey); required to cluster", &s.ClusterKey),
			boolean("cluster-insecure", "Cluster without cluster-key: gossip unencrypted and unauthenticated (trusted networks only)", &s.ClusterInsecure),
			str("shutdown-timeout", "Time allowed for a graceful shutdown", &s.ShutdownTimeout),
			str("shutdown-delay", "On shutdown, keep serving this long with /readyz answering 503 before closing (a few seconds behind a load balancer)", &s.ShutdownDelay),
			str("tenants-file", "JSON file of tenants: each gets its own hub and keys, picked by host and isolated from the others", &s.TenantsFile),
			str("database", "SQLite file of tenants the admin API manages, replicated to every node (alongside the tenants file's)", &s.Database),
			str("api-token", "Bearer token of the admin API at /api (plain or bcrypt); needs database", &s.APIToken),
			str("admin-issuer", "Identity provider whose access tokens the admin API takes (keys by discovery); needs database", &s.AdminIssuer),
			str("admin-audience", "The admin API's identifier (resource) in the identity provider: the tokens' aud", &s.AdminAudience),
			str("admin-detail-type", "Authorization details type of the admin API in the IdP's tokens (default: urn:gossiper:admin)", &s.AdminDetailType),
			str("admin-scope", "A scope of the IdP's tokens that gives full access to the admin API (for an IdP without authorization details)", &s.AdminScope),
		},
		Run: func(ctx context.Context, _ *cli.Command) error { return serve(ctx, *s) },
	}
}

// serve builds the server from the settings and runs it until the process is told to stop. A variable so the tests
// can look at the settings the command line produced without starting a server.
var serve = func(ctx context.Context, s server.Settings) error {
	log := logslog.New(logslog.Config{Level: s.LogLevel, Format: s.LogFmt})
	srv, err := server.New(s, log)
	if err != nil {
		return err
	}
	log.Info("starting", "version", build.Version, "built", build.Date)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				_ = srv.ReloadCertificate()
			}
		}
	}()
	return srv.Run(ctx)
}

func tokenCmd() *cli.Command {
	var keyArg, sub, payload, ttl, issuer, audience, matchType, clientID string
	var publish, subscribe []string
	var modern bool
	return &cli.Command{
		Name:  "token",
		Usage: "Print an HS256 token for testing: draft-07, or with --modern a Mercure 1.0 access token",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "key", Usage: "HMAC secret", AssignTo: &keyArg, Required: true,
				EnvVars: []string{env("publisher-key"), "MERCURE_PUBLISHER_JWT_KEY"}},
			&cli.StringSliceFlag{Name: "publish", Usage: "Topic selectors or matchers the token may publish to", AssignTo: &publish},
			&cli.StringSliceFlag{Name: "subscribe", Usage: "Topic selectors or matchers the token may receive private updates of", AssignTo: &subscribe},
			&cli.StringFlag{Name: "payload", Usage: "JSON value for the subscription payload", AssignTo: &payload},
			&cli.StringFlag{Name: "subject", Usage: "The token's subject", AssignTo: &sub},
			&cli.StringFlag{Name: "ttl", Usage: "Lifetime (e.g. 1h; draft-07 empty: no expiry; Mercure 1.0 default 1h)", AssignTo: &ttl},
			&cli.BoolFlag{Name: "modern", Usage: "Mint a Mercure 1.0 (draft-08) at+jwt access token", AssignTo: &modern},
			&cli.StringFlag{Name: "issuer", Usage: "Mercure 1.0: iss", AssignTo: &issuer, DefaultValue: "https://localhost"},
			&cli.StringFlag{Name: "audience", Usage: "Mercure 1.0: aud, the hub's resource identifier", AssignTo: &audience,
				DefaultValue: "https://localhost:8080/.well-known/mercure"},
			&cli.StringFlag{Name: "match-type", Usage: "Mercure 1.0: matcher type of the grants (exact or urlpattern)", AssignTo: &matchType, DefaultValue: "exact"},
			&cli.StringFlag{Name: "client-id", Usage: "Mercure 1.0: client_id", AssignTo: &clientID, DefaultValue: "gossiper-cli"},
		},
		Run: func(ctx context.Context, _ *cli.Command) error {
			var pl any
			if payload != "" {
				if err := json.Unmarshal([]byte(payload), &pl); err != nil {
					return fmt.Errorf("payload: %w", err)
				}
			}
			if modern && ttl == "" {
				ttl = "1h" // Mercure 1.0 tokens must expire
			}
			claims := jwt.MapClaims{}
			if ttl != "" {
				d, err := time.ParseDuration(ttl)
				if err != nil || d <= 0 {
					return errors.New("ttl: a positive duration, e.g. 1h")
				}
				claims["exp"] = time.Now().Add(d).Unix()
			}
			if sub != "" {
				claims["sub"] = sub
			}
			t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			if modern {
				if matchType != "exact" && matchType != "urlpattern" {
					return errors.New("match-type: exact or urlpattern")
				}
				t.Header["typ"] = "at+jwt"
				if sub == "" {
					claims["sub"] = clientID
				}
				jti := make([]byte, 16)
				_, _ = rand.Read(jti)
				claims["iss"], claims["aud"], claims["client_id"] = issuer, audience, clientID
				claims["iat"], claims["jti"] = time.Now().Unix(), base64.RawURLEncoding.EncodeToString(jti)
				var details []any
				for _, g := range []struct {
					action string
					topics []string
				}{{"publish", publish}, {"subscribe", subscribe}} {
					if len(g.topics) == 0 {
						continue
					}
					var ms []any
					for _, m := range g.topics {
						ms = append(ms, map[string]string{"match": m, "match_type": matchType})
					}
					d := map[string]any{"type": "https://mercure.rocks/authorization-detail", "actions": []string{g.action}, "topics": ms}
					if g.action == "subscribe" && pl != nil {
						d["payload"] = pl
					}
					details = append(details, d)
				}
				claims["authorization_details"] = details
			} else {
				m := map[string]any{}
				if publish != nil {
					m["publish"] = publish
				}
				if subscribe != nil {
					m["subscribe"] = subscribe
				}
				if pl != nil {
					m["payload"] = pl
				}
				claims["mercure"] = m
			}
			tok, err := t.SignedString([]byte(keyArg))
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		},
	}
}

// healthcheckCmd checks a running server's readiness, for container health checks (the image has no curl). Without
// --url it asks the server of the same settings (listen, http-only) on the loopback address. It sends nothing but
// the request, so it does not verify the server's certificate (a self-signed one, or one for the public name).
func healthcheckCmd() *cli.Command {
	var target string
	s := server.Defaults()
	return &cli.Command{
		Name:  "healthcheck",
		Usage: "Exit 0 when the server answers ready, 1 otherwise",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "url", Usage: "The readiness URL (default: from listen and http-only)", AssignTo: &target},
			str("listen", "The server's listen address", &s.Listen),
			boolean("http-only", "The server serves plain HTTP", &s.HTTPOnly),
		},
		Run: func(ctx context.Context, _ *cli.Command) error {
			if target == "" {
				target = readyURL(s.Listen, s.HTTPOnly)
			}
			return checkReady(ctx, target)
		},
	}
}

// checkReady asks target, a readiness URL, and returns an error unless it answers 200.
func checkReady(ctx context.Context, target string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // a readiness probe, sending nothing
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", resp.Status)
	}
	return nil
}

// readyURL is the readiness URL of a server listening on listen: its port on the address it listens on, or the
// loopback address when it listens on every address.
func readyURL(listen string, httpOnly bool) string {
	scheme, host, port := "https", "127.0.0.1", "8080"
	if httpOnly {
		scheme = "http"
	}
	if h, p, err := net.SplitHostPort(listen); err == nil {
		if p != "" {
			port = p
		}
		if ip := net.ParseIP(h); h != "" && (ip == nil || !ip.IsUnspecified()) {
			host = h
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/readyz"
}

func genkeyCmd() *cli.Command {
	return &cli.Command{
		Name:  "genkey",
		Usage: "Print a random 32-byte key, base64 (for cluster-key or an HMAC secret)",
		Run: func(ctx context.Context, _ *cli.Command) error {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			fmt.Println(base64.StdEncoding.EncodeToString(b))
			return nil
		},
	}
}
