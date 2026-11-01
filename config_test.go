package gossiper

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

func TestConfigDefaults(t *testing.T) {
	cfg, err := (&Config{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "mercureAuthorization" || cfg.Heartbeat != 30*time.Second || cfg.WriteTimeout != 30*time.Second ||
		cfg.DispatchBuffer != 1000 || cfg.MaxTopicSelectors != 256 || cfg.MaxPublishBytes != 1<<20 ||
		cfg.HistorySize != 10000 || cfg.HistoryBytes != 64<<20 || cfg.HistoryAge != time.Hour || cfg.ReplayWindow != 5*time.Second ||
		cfg.MatchCacheSize != 10000 || cfg.HubURL != "/.well-known/mercure" || cfg.Logger == nil {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestConfigExplicitValuesKept(t *testing.T) {
	in := Config{
		CookieName: "c", Heartbeat: time.Second, WriteTimeout: time.Second, DispatchBuffer: 7, MaxTopicSelectors: 3,
		MaxPublishBytes: 99, HistorySize: 5, HistoryBytes: 1234, HistoryAge: time.Minute, ReplayWindow: time.Second,
		MatchCacheSize: 4, HubURL: "https://hub.example/.well-known/mercure",
	}
	cfg, err := in.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "c" || cfg.Heartbeat != time.Second || cfg.WriteTimeout != time.Second || cfg.DispatchBuffer != 7 ||
		cfg.MaxTopicSelectors != 3 || cfg.MaxPublishBytes != 99 || cfg.HistorySize != 5 || cfg.HistoryBytes != 1234 ||
		cfg.HistoryAge != time.Minute || cfg.ReplayWindow != time.Second || cfg.MatchCacheSize != 4 || cfg.HubURL != "https://hub.example/.well-known/mercure" {
		t.Fatalf("explicit values changed: %+v", cfg)
	}
}

func TestConfigHistoryBounds(t *testing.T) {
	tests := []struct {
		name         string
		size         int
		bytes        int64
		wantN, wantB int64
	}{
		{"defaults", 0, 0, 10000, 64 << 20},
		{"size only", 50, 0, 50, 64 << 20},
		{"negative bytes means no byte bound", 50, -1, 50, 0},
		{"negative size disables history and its bytes", -1, 1000, 0, 0},
		{"negative size with default bytes", -1, 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := (&Config{HistorySize: tc.size, HistoryBytes: tc.bytes}).withDefaults()
			if err != nil {
				t.Fatal(err)
			}
			if int64(cfg.HistorySize) != tc.wantN || cfg.HistoryBytes != tc.wantB {
				t.Fatalf("size %d bytes %d, want %d %d", cfg.HistorySize, cfg.HistoryBytes, tc.wantN, tc.wantB)
			}
		})
	}
}

func TestConfigDoesNotMutateInput(t *testing.T) {
	in := Config{CORSOrigins: []string{"HTTP://Example.COM/"}}
	if _, err := in.withDefaults(); err != nil {
		t.Fatal(err)
	}
	if in.CookieName != "" || in.CORSOrigins[0] != "HTTP://Example.COM/" {
		t.Fatalf("withDefaults changed its receiver: %+v", in)
	}
}

func TestConfigOrigins(t *testing.T) {
	good := []string{"*", "http://example.com", "https://example.com:8443", "https://example.com/", "HTTPS://Example.COM", "http://[::1]:80"}
	for _, o := range good {
		if _, err := (&Config{CORSOrigins: []string{o}}).withDefaults(); err != nil {
			t.Errorf("CORS origin %q refused: %v", o, err)
		}
		if _, err := (&Config{PublishOrigins: []string{o}}).withDefaults(); err != nil {
			t.Errorf("publish origin %q refused: %v", o, err)
		}
	}
	bad := []string{"example.com", "http://example.com/path", "http://example.com?x=1", "//example.com", "http://", "http://%zz", "/"}
	for _, o := range bad {
		if _, err := (&Config{CORSOrigins: []string{o}}).withDefaults(); err == nil || !strings.Contains(err.Error(), "origin") {
			t.Errorf("CORS origin %q accepted (err %v)", o, err)
		}
		if _, err := (&Config{PublishOrigins: []string{o}}).withDefaults(); err == nil {
			t.Errorf("publish origin %q accepted", o)
		}
	}
	cfg, _ := (&Config{CORSOrigins: []string{"HTTPS://Example.COM/", "*"}, PublishOrigins: []string{"http://A.b"}}).withDefaults()
	if cfg.CORSOrigins[0] != "https://example.com" || cfg.CORSOrigins[1] != "*" || cfg.PublishOrigins[0] != "http://a.b" {
		t.Fatalf("origins not normalised: %v %v", cfg.CORSOrigins, cfg.PublishOrigins)
	}
}

func TestNewErrors(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"bad origin", Config{CORSOrigins: []string{"nope"}}, "origin"},
		{"bad publisher algorithm", Config{PublisherKey: auth.KeyConfig{Key: testSecret, Algorithm: "BOGUS"}}, ""},
		{"bad subscriber algorithm", Config{PublisherKey: auth.KeyConfig{Key: testSecret}, SubscriberKey: auth.KeyConfig{Key: testSecret, Algorithm: "BOGUS"}}, ""},
		{"transport start fails", Config{PublisherKey: auth.KeyConfig{Key: testSecret}, Transport: &fakeTransport{startErr: boom}}, "boom"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := New(tc.cfg)
			if err == nil {
				h.Close(t.Context())
				t.Fatal("New succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestNewWeakKeyWarns(t *testing.T) {
	log := &recLogger{}
	h, err := New(Config{PublisherKey: auth.KeyConfig{Key: "short"}, SubscriberKey: auth.KeyConfig{Key: "tiny"}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(t.Context())
	if !log.has("publisher key") || !log.has("subscriber key") {
		t.Fatalf("no weak key warnings: %v", log)
	}
}

func TestNewSeparateSubscriberKey(t *testing.T) {
	subSecret := "another-secret-another-secret-123"
	e := newEnv(t, Config{SubscriberKey: auth.KeyConfig{Key: subSecret}})
	subTok := signJWT(t, subSecret, mercureClaims(nil, all))
	pubTok := tokenFor(t, all, all)
	// A subscriber token signed with the publisher's key is refused, and the other way about.
	if r := e.do(t, "GET", e.hubURL()+"?topic=x", bearer(pubTok), ""); r.code != 401 {
		t.Fatalf("publisher token accepted by subscribe: %d", r.code)
	}
	c := e.subscribe(t, subTok, "x")
	e.publish(t, "hi", "x")
	c.expect("hi")
	if r := e.post(t, subTok, map[string][]string{"topic": {"x"}}); r.code != 401 {
		t.Fatalf("subscriber token accepted by publish: %d", r.code)
	}
}

func TestNoKeys(t *testing.T) {
	h, err := New(Config{Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(t.Context())
	if h.pub != nil || h.sub != nil {
		t.Fatal("verifiers made without keys")
	}
	// Go API still works.
	if _, err := h.Publish(t.Context(), &Update{Topics: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
}

func TestNodeID(t *testing.T) {
	h1, _ := New(Config{NodeID: "mine", Transport: newFakeTransport("theirs")})
	defer h1.Close(t.Context())
	h2, _ := New(Config{Transport: newFakeTransport("theirs")})
	defer h2.Close(t.Context())
	h3, _ := New(Config{})
	defer h3.Close(t.Context())
	h4, _ := New(Config{})
	defer h4.Close(t.Context())
	if h1.NodeID() != "mine" || h2.NodeID() != "theirs" {
		t.Fatalf("node ids %q %q", h1.NodeID(), h2.NodeID())
	}
	if h3.NodeID() == "" || h3.NodeID() == h4.NodeID() || strings.HasPrefix(h3.NodeID(), "urn:") {
		t.Fatalf("random node ids %q %q", h3.NodeID(), h4.NodeID())
	}
}

// A hub that checks Mercure 1.0 tokens against the Host the client sent says so, unless it knows its own URL.
func TestHostAudienceWarning(t *testing.T) {
	for hubURL, warns := range map[string]bool{"": true, "/.well-known/mercure": true, "https://hub.example/.well-known/mercure": false} {
		log := &recLogger{}
		h, err := New(Config{PublisherKey: auth.KeyConfig{Key: testSecret}, TrustedIssuers: []string{"https://localhost"}, HubURL: hubURL, Logger: log})
		if err != nil {
			t.Fatal(err)
		}
		if got := log.has("no resource identifier"); got != warns {
			t.Errorf("hub URL %q: warned %v, want %v", hubURL, got, warns)
		}
		h.Close(t.Context())
	}
}
