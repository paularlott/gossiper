package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
)

// The listeners serve HTTPS unless HTTPOnly: with TLSCert and TLSKey, or else with a self-signed certificate, kept in
// TLSDir (made again when missing, within 30 days of expiry, or not covering a host it should) or, without TLSDir,
// made at each start. Clients trust it with its certificate file as a CA file, or skip verification.

// Self-signed certificate files in TLSDir.
const (
	selfSignedCert = "self-signed.crt"
	selfSignedKey  = "self-signed.key"
)

// certCheckEvery is how often the certificate is looked at for a renewal: renewals come weeks before expiry, and
// SIGHUP loads one at once (a variable so tests can shorten it).
var certCheckEvery = time.Hour

// certRenewBefore is how long before expiry a self-signed certificate is made again.
const certRenewBefore = 30 * 24 * time.Hour

// certSource serves the TLS certificate and replaces it without a restart: the configured pair when either file
// changes on disk (certbot, cert-manager or an operator renewing it), the self-signed certificate when it nears
// expiry, and either on Reload (SIGHUP). A pair that does not load (a renewal caught half-written, a mismatched key)
// leaves the current certificate in place and is tried again at the next check.
type certSource struct {
	certFile, keyFile, dir string
	hosts                  []string // the self-signed certificate's names and addresses
	log                    logger.Logger

	cur  atomic.Pointer[tls.Certificate]
	mu   sync.Mutex // one load at a time
	seen fileStamp  // the configured files as last loaded
	stop chan struct{}
	once sync.Once
}

// fileStamp identifies the content of the certificate and key files without reading them.
type fileStamp struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

func stampOf(certFile, keyFile string) (fileStamp, error) {
	c, err := os.Stat(certFile)
	if err != nil {
		return fileStamp{}, err
	}
	k, err := os.Stat(keyFile)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{certMod: c.ModTime(), keyMod: k.ModTime(), certSize: c.Size(), keySize: k.Size()}, nil
}

func newCertSource(certFile, keyFile, dir string, hosts []string, log logger.Logger) (*certSource, error) {
	cs := &certSource{certFile: certFile, keyFile: keyFile, dir: dir, hosts: hosts, log: log, stop: make(chan struct{})}
	if err := cs.load(); err != nil {
		return nil, err
	}
	return cs, nil
}

// load reads the certificate (or makes the self-signed one) and makes it current.
func (cs *certSource) load() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var st fileStamp
	if cs.certFile != "" {
		var err error
		if st, err = stampOf(cs.certFile, cs.keyFile); err != nil {
			return err
		}
	}
	c, err := loadOrCreateCert(cs.certFile, cs.keyFile, cs.dir, cs.hosts)
	if err != nil {
		return err
	}
	cs.cur.Store(&c)
	cs.seen = st
	return nil
}

// selfSigned reports whether the certificate is the self-signed one.
func (cs *certSource) selfSigned() bool { return cs.certFile == "" }

// due reports whether the certificate should be loaded again: the configured files changed, or the self-signed
// certificate nears expiry (loadOrCreateCert then makes a new one).
func (cs *certSource) due() bool {
	if cs.selfSigned() {
		c := cs.cur.Load()
		return c == nil || c.Leaf == nil || time.Until(c.Leaf.NotAfter) < certRenewBefore
	}
	st, err := stampOf(cs.certFile, cs.keyFile)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return err == nil && st != cs.seen
}

// Reload loads the certificate again now (SIGHUP).
func (cs *certSource) Reload() error {
	if err := cs.load(); err != nil {
		cs.log.Error("TLS certificate not reloaded: the current one stays in use", "error", err)
		return err
	}
	cs.log.Info("TLS certificate loaded", "not_after", cs.notAfter(), "sha256", cs.fingerprint())
	return nil
}

func (cs *certSource) notAfter() time.Time {
	if c := cs.cur.Load(); c != nil && c.Leaf != nil {
		return c.Leaf.NotAfter
	}
	return time.Time{}
}

// fingerprint is the SHA-256 of the current certificate, to compare with what a client sees.
func (cs *certSource) fingerprint() string {
	if c := cs.cur.Load(); c != nil && c.Leaf != nil {
		sum := sha256.Sum256(c.Leaf.Raw)
		return hex.EncodeToString(sum[:])
	}
	return ""
}

// watch checks for a renewal every certCheckEvery until Close.
func (cs *certSource) watch() {
	t := time.NewTicker(certCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-cs.stop:
			return
		case <-t.C:
			if cs.due() {
				_ = cs.Reload()
			}
		}
	}
}

func (cs *certSource) Close() { cs.once.Do(func() { close(cs.stop) }) }

// GetCertificate is the tls.Config hook: every handshake gets the current certificate.
func (cs *certSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cs.cur.Load(), nil
}

// loadOrCreateCert returns the configured certificate, or a self-signed one for hosts: kept in dir (made again when
// missing, nearing expiry, or not covering every host), or made afresh without dir.
func loadOrCreateCert(certFile, keyFile, dir string, hosts []string) (tls.Certificate, error) {
	if certFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	if dir != "" {
		certFile, keyFile = filepath.Join(dir, selfSignedCert), filepath.Join(dir, selfSignedKey)
		if c, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil && c.Leaf != nil &&
			time.Until(c.Leaf.NotAfter) > certRenewBefore && covers(c.Leaf, hosts) {
			return c, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"gossiper self-signed"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(397 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// covers reports whether c is valid for every one of hosts.
func covers(c *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		if c.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

// selfSignedHosts are the names and addresses the self-signed certificate is for: localhost and the loopback
// addresses, the machine's host name, those of the listeners, the hub URL and the cluster address, and extra.
func selfSignedHosts(s Settings) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	add := func(h string) {
		if ip := net.ParseIP(h); h != "" && (ip == nil || !ip.IsUnspecified()) && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	if name, err := os.Hostname(); err == nil {
		add(name)
	}
	for _, addr := range []string{s.Listen, s.AdminListen, s.ClusterAdvertise} {
		if h, _, err := net.SplitHostPort(addr); err == nil {
			add(h)
		}
	}
	if u, err := url.Parse(s.HubURL); err == nil {
		add(u.Hostname())
	}
	for _, h := range splitList(s.TLSHosts) {
		add(h)
	}
	return hosts
}

// newServerCerts returns the certificate source of the settings, nil with HTTPOnly.
func newServerCerts(s Settings, log logger.Logger) (*certSource, error) {
	if s.HTTPOnly {
		// tls-dir and tls-hosts may come from the environment (the container image sets tls-dir): left unused.
		if s.TLSCert != "" {
			return nil, errors.New("http-only: a certificate (tls-cert, tls-key) is not served with it")
		}
		return nil, nil
	}
	if s.TLSCert != "" && (s.TLSDir != "" || len(s.TLSHosts) > 0) {
		return nil, errors.New("tls-dir and tls-hosts are for the self-signed certificate: not used with tls-cert")
	}
	return newCertSource(s.TLSCert, s.TLSKey, s.TLSDir, selfSignedHosts(s), log)
}
