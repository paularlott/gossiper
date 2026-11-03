package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// node is a running server: its HTTP base URL and a way to stop it.
type node struct {
	*Server
	base  string
	admin string // the admin listener's base URL, with AdminListen set
	stop  func() error
}

// startNode runs a server on an ephemeral port until the test ends.
func startNode(t *testing.T, s Settings) *node {
	t.Helper()
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := &node{Server: srv, base: "http://" + ln.Addr().String()}
	var admin net.Listener
	if srv.AdminHandler != nil {
		if admin, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		n.admin = "http://" + admin.Addr().String()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, admin) }()
	var stopped atomic.Bool
	n.stop = func() error {
		if stopped.Swap(true) {
			return nil
		}
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			return fmt.Errorf("server did not stop")
		}
	}
	t.Cleanup(func() {
		if err := n.stop(); err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return n
}

func eventually(t *testing.T, d time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func metricsText(t *testing.T, base string) string {
	t.Helper()
	code, body := get(t, base+"/metrics")
	if code != 200 {
		t.Fatalf("metrics: %d", code)
	}
	return body
}

func metricValue(body, name string) (string, bool) {
	for _, l := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(l, name+" "); ok {
			return v, true
		}
	}
	return "", false
}

// clusterNodes starts n nodes joined in one gossip cluster; mod adjusts each node's settings.
func clusterNodes(t *testing.T, n int, mod func(i int, s *Settings)) []*node {
	t.Helper()
	key := testClusterKey
	binds := make([]string, n)
	for i := range binds {
		binds[i] = freePort(t, "both")
	}
	var nodes []*node
	for i := range binds {
		s := settings()
		s.ClusterBind, s.ClusterKey, s.ClusterPeers = binds[i], key, binds
		if mod != nil {
			mod(i, &s)
		}
		nodes = append(nodes, startNode(t, s))
	}
	eventually(t, 15*time.Second, "cluster formed", func() bool {
		for _, nd := range nodes {
			if nd.gossip.NumAliveNodes() < n {
				return false
			}
		}
		return true
	})
	return nodes
}

const testClusterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// Clustering needs a key, unless cluster-insecure says the network is trusted.
func TestClusterNeedsKey(t *testing.T) {
	s := settings()
	s.ClusterBind = freePort(t, "both")
	if _, err := New(s, nil); err == nil || !strings.Contains(err.Error(), "cluster-key") {
		t.Fatalf("a cluster without a key: %v", err)
	}
	s.ClusterInsecure = true
	srv, err := New(s, nil)
	if err != nil {
		t.Fatalf("cluster-insecure: %v", err)
	}
	srv.Close(context.Background())
}

type pkiFiles struct{ ca, cert, key string }

func writePKI(t *testing.T) pkiFiles {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	write := func(name string, b *pem.Block) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "server"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	return pkiFiles{
		ca:   write("ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		cert: write("server.pem", &pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:  write("server.key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	}
}

func TestHTTPListenerFailureClosesEverything(t *testing.T) {
	srv, err := New(settings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ln.Close() // Serve fails at once
	if err := srv.Serve(context.Background(), ln, nil); err == nil {
		t.Fatal("no error from a closed listener")
	}
}

func TestCloseWithoutServing(t *testing.T) {
	srv, err := New(settings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close(context.Background()) // never served: Close must not hang or panic
}

func TestClusterSurvivorsAfterNodeCloses(t *testing.T) {
	nodes := clusterNodes(t, 3, nil)
	if err := nodes[2].stop(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sse := subscribe(t, ctx, nodes[1].base, "https://example.com/alive")
	time.Sleep(50 * time.Millisecond)
	publish(t, nodes[0].base, "https://example.com/alive", "still here")
	receive(t, sse, "still here")
}

func TestHTTPTLS(t *testing.T) {
	p := writePKI(t)
	s := settings()
	s.HTTPOnly, s.TLSCert, s.TLSKey = false, p.cert, p.key
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, nil) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	pool := x509.NewCertPool()
	b, _ := os.ReadFile(p.ca)
	pool.AppendCertsFromPEM(b)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	var resp *http.Response
	eventually(t, 5*time.Second, "https up", func() bool {
		resp, err = hc.Get("https://" + ln.Addr().String() + "/healthz")
		return err == nil
	})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
}

func TestRun(t *testing.T) {
	addr := freePort(t, "tcp")
	s := settings()
	s.Listen = addr
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	eventually(t, 5*time.Second, "run up", func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// a bad address is an error from Run itself
	s.Listen = "256.0.0.1:99999"
	srv, _ = New(s, nil)
	defer srv.Close(context.Background())
	if err := srv.Run(context.Background()); err == nil {
		t.Fatal("bad listen address accepted")
	}
}

func TestClusterKeyForms(t *testing.T) {
	for name, key := range map[string]string{
		"raw 16 bytes": "0123456789abcdef",
		"raw 24 bytes": "0123456789abcdef01234567",
		"raw 32 bytes": "0123456789abcdef0123456789abcdef",
		"base64":       "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	} {
		t.Run(name, func(t *testing.T) {
			s := settings()
			s.ClusterBind, s.ClusterKey = freePort(t, "both"), key
			srv, err := New(s, nil)
			if err != nil {
				t.Fatal(err)
			}
			srv.Close(context.Background())
		})
	}
}
