package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/internal/server"
)

func TestNames(t *testing.T) {
	if got := key("publisher-jwks-url"); got != "publisher_jwks_url" {
		t.Fatalf("key: %q", got)
	}
	if got := env("publisher-jwks-url"); got != "GOSSIPER_PUBLISHER_JWKS_URL" {
		t.Fatalf("env: %q", got)
	}
}

// run executes the command line args and returns what it printed.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	oldArgs := os.Args
	os.Args = append([]string{"gossiper"}, args...)
	err := root().Execute(context.Background())
	w.Close()
	os.Stdout, os.Args = old, oldArgs
	out, _ := io.ReadAll(r)
	return string(out), err
}

func TestTokenCommand(t *testing.T) {
	const k = "token-command-secret-0123456789abcdef"
	out, err := run(t, "token", "--key", k, "--publish", "https://example.com/{x}", "--subscribe", "*",
		"--payload", `{"user":"u1"}`, "--subject", "me", "--ttl", "1h")
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(strings.TrimSpace(out), claims, func(*jwt.Token) (any, error) { return []byte(k), nil },
		jwt.WithValidMethods([]string{"HS256"})); err != nil {
		t.Fatalf("token does not verify: %v (%q)", err, out)
	}
	m := claims["mercure"].(map[string]any)
	if m["publish"].([]any)[0] != "https://example.com/{x}" || m["subscribe"].([]any)[0] != "*" ||
		m["payload"].(map[string]any)["user"] != "u1" || claims["sub"] != "me" || claims["exp"] == nil {
		t.Fatalf("claims: %v", claims)
	}
	if _, err := run(t, "token", "--key", k, "--payload", "{"); err == nil {
		t.Fatal("bad payload accepted")
	}
	if _, err := run(t, "token", "--key", k, "--ttl", "-1h"); err == nil {
		t.Fatal("negative ttl accepted")
	}
}

func TestGenkey(t *testing.T) {
	out, err := run(t, "genkey")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.TrimSpace(out)); n != 44 {
		t.Fatalf("genkey printed %d characters: %q", n, out)
	}
}

func TestTokenCommandModern(t *testing.T) {
	const k = "token-command-secret-0123456789abcdef"
	out, err := run(t, "token", "--key", k, "--modern", "--issuer", "https://app.example", "--audience",
		"https://hub.example/.well-known/mercure", "--publish", "https://example.com/books/:id", "--match-type", "urlpattern",
		"--subscribe", "*", "--payload", `{"u":1}`)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(strings.TrimSpace(out), claims, func(*jwt.Token) (any, error) { return []byte(k), nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if tok.Header["typ"] != "at+jwt" || claims["iss"] != "https://app.example" ||
		claims["aud"] != "https://hub.example/.well-known/mercure" || claims["exp"] == nil || claims["jti"] == "" ||
		claims["sub"] != "gossiper-cli" || claims["client_id"] != "gossiper-cli" || claims["mercure"] != nil {
		t.Fatalf("claims %v header %v", claims, tok.Header)
	}
	details := claims["authorization_details"].([]any)
	if len(details) != 2 {
		t.Fatalf("details %v", details)
	}
	pub := details[0].(map[string]any)
	if pub["actions"].([]any)[0] != "publish" || pub["topics"].([]any)[0].(map[string]any)["match_type"] != "urlpattern" || pub["payload"] != nil {
		t.Fatalf("publish detail %v", pub)
	}
	sub := details[1].(map[string]any)
	if sub["actions"].([]any)[0] != "subscribe" || sub["payload"].(map[string]any)["u"] != float64(1) {
		t.Fatalf("subscribe detail %v", sub)
	}
	if _, err := run(t, "token", "--key", k, "--modern", "--match-type", "regex"); err == nil {
		t.Fatal("bad match type accepted")
	}
}

func TestEnvAliases(t *testing.T) {
	t.Setenv("MERCURE_PUBLISHER_JWT_KEY", "alias-secret-0123456789abcdef0123")
	out, err := run(t, "token", "--publish", "*")
	if err != nil {
		t.Fatalf("token with MERCURE_PUBLISHER_JWT_KEY: %v", err)
	}
	if _, err := jwt.Parse(strings.TrimSpace(out), func(*jwt.Token) (any, error) { return []byte("alias-secret-0123456789abcdef0123"), nil }); err != nil {
		t.Fatalf("token not signed with the alias key: %v", err)
	}
}

// settingCase is one setting in all three of its forms: the flag, the environment variable and the config key.
type settingCase struct {
	flag    string   // --tenants-file
	args    []string // the flag's values; none for a boolean
	toml    string   // tenants_file = "..."
	env     string   // the environment variable's value
	envName string   // GOSSIPER_TENANTS_FILE
	apply   func(*server.Settings)
}

func settingCases() []settingCase {
	return []settingCase{
		{"tenants-file", []string{"/etc/t.json"}, `tenants_file = "/etc/t.json"`, "/etc/t.json", "GOSSIPER_TENANTS_FILE", func(s *server.Settings) { s.TenantsFile = "/etc/t.json" }},
		{"database", []string{"/var/g.db"}, `database = "/var/g.db"`, "/var/g.db", "GOSSIPER_DATABASE", func(s *server.Settings) { s.Database = "/var/g.db" }},
		{"api-token", []string{"tok"}, `api_token = "tok"`, "tok", "GOSSIPER_API_TOKEN", func(s *server.Settings) { s.APIToken = "tok" }},
		{"heartbeat", []string{"15s"}, `heartbeat = "15s"`, "15s", "GOSSIPER_HEARTBEAT", func(s *server.Settings) { s.Heartbeat = "15s" }},
		{"dispatch-buffer", []string{"50"}, `dispatch_buffer = 50`, "50", "GOSSIPER_DISPATCH_BUFFER", func(s *server.Settings) { s.DispatchBuffer = 50 }},
		{"history-bytes", []string{"1048576"}, `history_bytes = 1048576`, "1048576", "GOSSIPER_HISTORY_BYTES", func(s *server.Settings) { s.HistoryBytes = 1048576 }},
		{"max-publish-size", []string{"2097152"}, `max_publish_size = 2097152`, "2097152", "GOSSIPER_MAX_PUBLISH_SIZE", func(s *server.Settings) { s.MaxPublishSize = 2097152 }},
		{"cluster-peers", []string{"a:7946", "--cluster-peers", "b:7946"}, `cluster_peers = ["a:7946", "b:7946"]`,
			"a:7946,b:7946", "GOSSIPER_CLUSTER_PEERS", func(s *server.Settings) { s.ClusterPeers = []string{"a:7946", "b:7946"} }},
		{"metrics", nil, `metrics = true`, "true", "GOSSIPER_METRICS", func(s *server.Settings) { s.Metrics = true }},
		{"cluster-insecure", nil, `cluster_insecure = true`, "true", "GOSSIPER_CLUSTER_INSECURE", func(s *server.Settings) { s.ClusterInsecure = true }},
		{"history-budget", []string{"1048576"}, `history_budget = 1048576`, "1048576", "GOSSIPER_HISTORY_BUDGET", func(s *server.Settings) { s.HistoryBudget = 1048576 }},
		{"history-db", []string{"/data/history.db"}, `history_db = "/data/history.db"`, "/data/history.db", "GOSSIPER_HISTORY_DB", func(s *server.Settings) { s.HistoryDB = "/data/history.db" }},
		{"admin-listen", []string{"127.0.0.1:9090"}, `admin_listen = "127.0.0.1:9090"`, "127.0.0.1:9090", "GOSSIPER_ADMIN_LISTEN", func(s *server.Settings) { s.AdminListen = "127.0.0.1:9090" }},
		{"trusted-proxies", []string{"10.0.0.0/8"}, `trusted_proxies = ["10.0.0.0/8"]`, "10.0.0.0/8", "GOSSIPER_TRUSTED_PROXIES", func(s *server.Settings) { s.TrustedProxies = []string{"10.0.0.0/8"} }},
		{"max-subscribers", []string{"500"}, `max_subscribers = 500`, "500", "GOSSIPER_MAX_SUBSCRIBERS", func(s *server.Settings) { s.MaxSubscribers = 500 }},
		{"max-subscribers-per-ip", []string{"20"}, `max_subscribers_per_ip = 20`, "20", "GOSSIPER_MAX_SUBSCRIBERS_PER_IP", func(s *server.Settings) { s.MaxPerIP = 20 }},
		{"max-hub-subscribers", []string{"30"}, `max_hub_subscribers = 30`, "30", "GOSSIPER_MAX_HUB_SUBSCRIBERS", func(s *server.Settings) { s.MaxHubSubs = 30 }},
		{"shutdown-delay", []string{"5s"}, `shutdown_delay = "5s"`, "5s", "GOSSIPER_SHUTDOWN_DELAY", func(s *server.Settings) { s.ShutdownDelay = "5s" }},
		{"publisher-alg", []string{"RS256"}, `publisher_alg = "RS256"`, "RS256", "GOSSIPER_PUBLISHER_ALG", func(s *server.Settings) { s.PublisherAlg = "RS256" }},
	}
}

// parse runs the serve command line against a stand-in server and returns the settings it produced.
func parse(t *testing.T, args ...string) server.Settings {
	t.Helper()
	var got server.Settings
	called := false
	old := serve
	serve = func(_ context.Context, s server.Settings) error { got, called = s, true; return nil }
	t.Cleanup(func() { serve = old })
	if _, err := run(t, append([]string{"serve"}, args...)...); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("serve not called")
	}
	return got
}

func writeConfig(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gossiper.toml")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	got := parse(t, "--config", filepath.Join(t.TempDir(), "none.toml"))
	if want := server.Defaults(); !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults changed:\n got %+v\nwant %+v", got, want)
	}
}

func TestSettingFlags(t *testing.T) {
	want := server.Defaults()
	var args []string
	for _, c := range settingCases() {
		c.apply(&want)
		args = append(args, "--"+c.flag)
		args = append(args, c.args...)
	}
	// One flag at a time too: each must set only its own setting.
	for _, c := range settingCases() {
		w := server.Defaults()
		c.apply(&w)
		one := append([]string{"--" + c.flag}, c.args...)
		if got := parse(t, append([]string{"--config", filepath.Join(t.TempDir(), "none.toml")}, one...)...); !reflect.DeepEqual(got, w) {
			t.Errorf("--%s:\n got %+v\nwant %+v", c.flag, got, w)
		}
	}
	got := parse(t, append([]string{"--config", filepath.Join(t.TempDir(), "none.toml")}, args...)...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("all flags:\n got %+v\nwant %+v", got, want)
	}
}

func TestSettingEnv(t *testing.T) {
	want := server.Defaults()
	for _, c := range settingCases() {
		c.apply(&want)
		t.Setenv(c.envName, c.env)
	}
	got := parse(t, "--config", filepath.Join(t.TempDir(), "none.toml"))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment:\n got %+v\nwant %+v", got, want)
	}
	for _, c := range settingCases() { // the names the flags derive match the table's
		if env(c.flag) != c.envName {
			t.Errorf("env(%s) = %s, want %s", c.flag, env(c.flag), c.envName)
		}
	}
}

func TestSettingConfigFile(t *testing.T) {
	want := server.Defaults()
	var lines []string
	for _, c := range settingCases() {
		c.apply(&want)
		lines = append(lines, c.toml)
	}
	got := parse(t, "--config", writeConfig(t, lines...))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config file:\n got %+v\nwant %+v", got, want)
	}
}

func TestSettingPrecedence(t *testing.T) {
	cfg := writeConfig(t, `node_id = "from-file"`, `log_level = "from-file"`, `dispatch_buffer = 7`)
	t.Setenv("GOSSIPER_NODE_ID", "from-env")
	t.Setenv("GOSSIPER_LOG_LEVEL", "from-env")
	got := parse(t, "--config", cfg, "--node-id", "from-flag")
	if got.NodeID != "from-flag" || got.LogLevel != "from-env" || got.DispatchBuffer != 7 {
		t.Fatalf("flag > environment > file: %q %q %d", got.NodeID, got.LogLevel, got.DispatchBuffer)
	}
}

func TestServeErrorsAreReturned(t *testing.T) {
	old := serve
	serve = func(context.Context, server.Settings) error { return errors.New("boom") }
	defer func() { serve = old }()
	if _, err := run(t, "serve", "--config", filepath.Join(t.TempDir(), "none.toml")); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestServeRunsHTTP runs the real serve command, single node: the hub takes a publish, and SIGTERM shuts it down
// cleanly.
func TestServeRunsHTTP(t *testing.T) {
	httpAddr := freeAddr(t)
	done := make(chan error, 1)
	go func() {
		_, err := run(t, "serve", "--config", filepath.Join(t.TempDir(), "none.toml"), "--listen", httpAddr,
			"--publisher-key", "cmd-test-secret-0123456789abcdef", "--anonymous", "--log-level", "error")
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + httpAddr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+httpAddr+"/.well-known/mercure", strings.NewReader("topic=t&data=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+cmdToken(t, "cmd-test-secret-0123456789abcdef"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish: %s", resp.Status)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop on SIGTERM")
	}
}

// cmdToken mints a draft-07 publisher token for key.
func cmdToken(t *testing.T, key string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}}).
		SignedString([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHealthcheck(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready\n")) }))
	defer ready.Close()
	if _, err := run(t, "healthcheck", "--url", ready.URL); err != nil {
		t.Fatalf("a ready server: %v", err)
	}
	draining := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer draining.Close()
	if _, err := run(t, "healthcheck", "--url", draining.URL); err == nil {
		t.Fatal("a server that is not ready passed")
	}
}
