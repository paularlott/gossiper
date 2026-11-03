package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// serveTLS runs a server of s, which serves HTTPS, and returns it with its address.
func serveTLS(t *testing.T, s Settings) (*Server, string) {
	t.Helper()
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, nil) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return srv, ln.Addr().String()
}

// healthz asks addr's /healthz over https with cfg, and returns the certificate it was served.
func healthz(t *testing.T, addr string, cfg *tls.Config) (*x509.Certificate, error) {
	t.Helper()
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := hc.Get("https://" + addr + "/healthz")
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
	return resp.TLS.PeerCertificates[0], nil
}

func trusting(t *testing.T, certFile string) *tls.Config {
	t.Helper()
	b, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		t.Fatal("no certificate in", certFile)
	}
	return &tls.Config{RootCAs: pool}
}

// HTTPS is the default: a self-signed certificate, kept in tls-dir, which clients trust as a CA file; the same one
// after a restart. Plain HTTP is refused.
func TestSelfSignedByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	s := settings()
	s.HTTPOnly, s.TLSDir = false, dir
	_, addr := serveTLS(t, s)
	certFile := filepath.Join(dir, selfSignedCert)
	first, err := healthz(t, addr, trusting(t, certFile))
	if err != nil {
		t.Fatalf("trusting its certificate file: %v", err)
	}
	if _, err := healthz(t, addr, &tls.Config{}); err == nil {
		t.Fatal("the self-signed certificate verified against the system's roots")
	}
	if resp, err := http.Get("http://" + addr + "/healthz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plain HTTP served")
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, selfSignedKey)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi.Mode(), err)
	}

	_, addr = serveTLS(t, s) // a restart keeps it
	again, err := healthz(t, addr, trusting(t, certFile))
	if err != nil || !again.Equal(first) {
		t.Fatalf("not the same certificate after a restart: %v", err)
	}

	s.TLSHosts = []string{"hub.internal"} // a host it does not cover: made again
	_, addr = serveTLS(t, s)
	third, err := healthz(t, addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil || third.Equal(first) || !slices.Contains(third.DNSNames, "hub.internal") {
		t.Fatalf("not made again for a new host: %v %v", err, third.DNSNames)
	}
}

// Without tls-dir the self-signed certificate is made at each start, and a client skips verification.
func TestSelfSignedWithoutDir(t *testing.T) {
	s := settings()
	s.HTTPOnly = false
	_, addr := serveTLS(t, s)
	c, err := healthz(t, addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.DNSNames, "localhost") || len(c.IPAddresses) < 2 {
		t.Fatalf("names %v, addresses %v", c.DNSNames, c.IPAddresses)
	}
}

// The admin listener serves HTTPS with the same certificate.
func TestAdminListenerTLS(t *testing.T) {
	s := adminSettings(t, "")
	s.HTTPOnly, s.AdminListen = false, "127.0.0.1:0"
	srv, err := New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	admin, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, admin) }()
	defer func() {
		cancel()
		<-done
	}()
	if _, err := healthz(t, admin.Addr().String(), &tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	}
}

// Renewed certificate files are served after a reload; a pair that does not load leaves the current one.
func TestCertificateReload(t *testing.T) {
	p := writePKI(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	cp := func(from, to string) {
		b, _ := os.ReadFile(from)
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cp(p.cert, cert)
	cp(p.key, key)
	s := settings()
	s.HTTPOnly, s.TLSCert, s.TLSKey = false, cert, key
	srv, addr := serveTLS(t, s)
	first, err := healthz(t, addr, trusting(t, p.ca))
	if err != nil {
		t.Fatal(err)
	}

	_ = os.WriteFile(key, []byte("half written"), 0o600)
	if srv.ReloadCertificate() == nil {
		t.Fatal("a broken key loaded")
	}
	if c, err := healthz(t, addr, trusting(t, p.ca)); err != nil || !c.Equal(first) {
		t.Fatalf("the current certificate was not kept: %v", err)
	}

	q := writePKI(t)
	cp(q.cert, cert)
	cp(q.key, key)
	if !srv.certs.due() {
		t.Fatal("renewed files not noticed")
	}
	if err := srv.ReloadCertificate(); err != nil {
		t.Fatal(err)
	}
	if c, err := healthz(t, addr, trusting(t, q.ca)); err != nil || c.Equal(first) {
		t.Fatalf("the renewed certificate is not served: %v", err)
	}
}

// A self-signed certificate near expiry is made again.
func TestSelfSignedRenewal(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost", "127.0.0.1"}
	c, err := loadOrCreateCert("", "", dir, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := loadOrCreateCert("", "", dir, hosts); !again.Leaf.Equal(c.Leaf) {
		t.Fatal("a valid certificate was made again")
	}
	cs := &certSource{dir: dir, hosts: hosts}
	c.Leaf.NotAfter = time.Now().Add(certRenewBefore - time.Hour) // as if near expiry
	cs.cur.Store(&c)
	if !cs.due() {
		t.Fatal("a certificate near expiry is not due")
	}
}

func TestSelfSignedHosts(t *testing.T) {
	s := Defaults()
	s.Listen, s.AdminListen, s.ClusterAdvertise = "0.0.0.0:8080", "10.1.2.3:9000", "node1:7946"
	s.HubURL, s.TLSHosts = "https://hub.example.com/.well-known/mercure", []string{"gossiper, 192.168.1.5"}
	got := selfSignedHosts(s)
	for _, want := range []string{"localhost", "127.0.0.1", "::1", "10.1.2.3", "node1", "hub.example.com", "gossiper", "192.168.1.5"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s missing from %v", want, got)
		}
	}
	if slices.Contains(got, "0.0.0.0") {
		t.Errorf("the unspecified address in %v", got)
	}
}

func TestTLSSettings(t *testing.T) {
	for name, mod := range map[string]func(*Settings){
		"http-only with a certificate": func(s *Settings) { s.TLSCert, s.TLSKey = "c.pem", "k.pem" },
		"tls-dir with a certificate": func(s *Settings) {
			s.HTTPOnly, s.TLSCert, s.TLSKey, s.TLSDir = false, "c.pem", "k.pem", "tls"
		},
		"missing certificate file": func(s *Settings) { s.HTTPOnly, s.TLSCert, s.TLSKey = false, "none.pem", "none.key" },
	} {
		t.Run(name, func(t *testing.T) {
			s := settings()
			mod(&s)
			if srv, err := New(s, nil); err == nil {
				srv.Close(t.Context())
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), "tls") {
				t.Errorf("refused, but not for TLS: %v", err)
			}
		})
	}
	// tls-dir from the environment (the container image's) does not stop an http-only server.
	s := settings()
	s.TLSDir, s.TLSHosts = filepath.Join(t.TempDir(), "tls"), []string{"a"}
	srv, err := New(s, nil)
	if err != nil {
		t.Fatalf("http-only with tls-dir: %v", err)
	}
	srv.Close(t.Context())
	if _, err := os.Stat(s.TLSDir); !os.IsNotExist(err) {
		t.Errorf("http-only made a certificate: %v", err)
	}
}
