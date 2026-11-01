package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// parsePublicKeyPEM returns the first public key found in the PEM data. It
// understands PKIX "PUBLIC KEY", PKCS#1 "RSA PUBLIC KEY" and "CERTIFICATE"
// blocks.
func parsePublicKeyPEM(s string) (any, error) {
	rest := []byte(s)
	var firstErr error
	sawBlock := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawBlock = true
		var key any
		var err error
		switch block.Type {
		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			if cert, err = x509.ParseCertificate(block.Bytes); err == nil {
				key = cert.PublicKey
			}
		default:
			if strings.HasSuffix(block.Type, "PRIVATE KEY") {
				return nil, errors.New("auth: Key holds a private key; a public key or certificate is required")
			}
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("auth: parse %s PEM block: %w", block.Type, err)
			}
			continue
		}
		switch k := key.(type) {
		case *rsa.PublicKey:
			if n := k.N.BitLen(); n < minRSABits {
				return nil, fmt.Errorf("auth: RSA key of %d bits: at least %d are required", n, minRSABits)
			}
			return key, nil
		case *ecdsa.PublicKey, ed25519.PublicKey:
			return key, nil
		default:
			if firstErr == nil {
				firstErr = fmt.Errorf("auth: unsupported public key type %T", key)
			}
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if !sawBlock {
		return nil, errors.New("auth: Key is not valid PEM")
	}
	return nil, errors.New("auth: no public key or certificate found in PEM Key")
}

func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}
