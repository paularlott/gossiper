package client

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The client is a module of its own, so its tests do not import the hub:
// they run the gossiper server from this repository (the client's parent
// folder) as a process, built once per test run.

var (
	buildOnce   sync.Once
	gossiperBin string
	buildErr    error
	buildDir    string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// gossiper builds the hub from the repository the client is in.
func gossiper(t testing.TB) string {
	t.Helper()
	buildOnce.Do(func() {
		if buildDir, buildErr = os.MkdirTemp("", "gossiper-client-test"); buildErr != nil {
			return
		}
		gossiperBin = filepath.Join(buildDir, "gossiper")
		cmd := exec.Command("go", "build", "-o", gossiperBin, "./cmd/gossiper")
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building gossiper: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return gossiperBin
}

// testHub is a gossiper process and the server the tests talk to, which
// passes every request on to it.
type testHub struct {
	direct string // the process's own address, http://host:port
}

// duplicates is how many updates the hub took as copies of ones it had.
func (h *testHub) duplicates(t *testing.T) int {
	t.Helper()
	resp, err := http.Get(h.direct + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "gossiper_duplicates_total "); ok {
			n, _ := strconv.ParseFloat(v, 64)
			return int(n)
		}
	}
	t.Fatal("no gossiper_duplicates_total in the metrics")
	return 0
}

// hub runs a hub until the test ends, with args added to its command line;
// drop closes the connections made to it so far.
func hub(t *testing.T, args ...string) (h *testHub, srv *httptest.Server, drop func()) {
	t.Helper()
	return hubWith(t, nil, args...)
}

// hubWith is hub with wrap around the handler that passes requests on, over
// HTTP/1.1 and HTTP/2 without TLS.
func hubWith(t *testing.T, wrap func(http.Handler) http.Handler, args ...string) (h *testHub, srv *httptest.Server, drop func()) {
	t.Helper()
	h = startHub(t, args)
	var handler http.Handler = forward(t, h.direct)
	if wrap != nil {
		handler = wrap(handler)
	}
	srv = httptest.NewUnstartedServer(handler)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	l := &conns{Listener: srv.Listener}
	srv.Listener = l
	srv.Start()
	t.Cleanup(func() {
		l.drop()
		srv.Close()
	})
	return h, srv, l.drop
}

// startHub starts a gossiper process with args added to its command line.
func startHub(t *testing.T, args []string) *testHub {
	t.Helper()
	bin := gossiper(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	cmd := exec.Command(bin, append([]string{"serve", "--listen", addr, "--http-only", "--log-level", "error",
		"--publisher-key", secret, "--protocol", "both", "--metrics", "--trust-forwarded-proto"}, args...)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		select {
		case <-exited:
			t.Fatalf("gossiper %v ended: %s", args, out.String())
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			_ = c.Close()
			return &testHub{direct: "http://" + addr}
		}
		if time.Now().After(deadline) {
			t.Fatalf("gossiper did not start: %s", out.String())
		}
	}
}

// forward passes requests on to the hub at target, both ways at once (a
// publish stream's lines and answers), over HTTP/2 without TLS. The hub sees
// the host and scheme the client asked for.
func forward(t *testing.T, target string) http.Handler {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(tr.CloseIdleConnections)
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.Out.Host = r.In.Host
			r.SetXForwarded()
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      nil,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		rp.ServeHTTP(w, r)
	})
}

// token is a draft-07 token granting pub and sub, signed with secret; exp, if
// not zero, is its expiry.
func token(t testing.TB, pub, sub []string, exp time.Time) string {
	t.Helper()
	m := map[string]any{}
	if pub != nil {
		m["publish"] = pub
	}
	if sub != nil {
		m["subscribe"] = sub
	}
	claims := map[string]any{"mercure": m}
	if !exp.IsZero() {
		claims["exp"] = exp.Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(mac, signing)
	return signing + "." + enc.EncodeToString(mac.Sum(nil))
}
