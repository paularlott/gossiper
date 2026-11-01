package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxRedirects = 10

// checkURL requires an absolute https URL (http only when allowHTTP), with a
// host and no fragment.
func checkURL(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("invalid URL %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, fmt.Errorf("URL %q is not https", raw)
		}
	default:
		return nil, fmt.Errorf("invalid URL %q", raw)
	}
	return u, nil
}

// secureClient returns a copy of base (or a default client) whose redirects
// are refused unless they stay on https (or http when allowHTTP).
func secureClient(base *http.Client, allowHTTP bool) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	} else {
		c.Timeout = defaultHTTPTimeout
	}
	prev := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if _, err := checkURL(req.URL.String(), allowHTTP); err != nil {
			return fmt.Errorf("refusing redirect: %w", err)
		}
		if prev != nil {
			return prev(req, via)
		}
		if len(via) >= maxRedirects {
			return errors.New("stopped after too many redirects")
		}
		return nil
	}
	return &c
}

// metadataURLs lists where an issuer's metadata may live: RFC 8414 (the
// well-known segment inserted before the issuer's path), the same segment
// appended to the issuer, and OpenID Connect discovery.
func metadataURLs(u *url.URL) []string {
	base := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")
	urls := []string{base + "/.well-known/oauth-authorization-server" + path}
	if path != "" {
		urls = append(urls, base+path+"/.well-known/oauth-authorization-server")
	}
	return append(urls, base+path+"/.well-known/openid-configuration")
}

// discoverJWKSURI reads the issuer's authorization server metadata and returns
// its jwks_uri. The metadata issuer must equal the configured one (RFC 8414
// section 3.3) so that one issuer cannot hand out another's keys.
func discoverJWKSURI(ctx context.Context, client *http.Client, issuer string, allowHTTP bool) (string, error) {
	u, err := checkURL(issuer, allowHTTP)
	if err != nil {
		return "", err
	}
	var errs []error
	for _, m := range metadataURLs(u) {
		uri, err := fetchMetadata(ctx, client, m, issuer, allowHTTP)
		if err == nil {
			return uri, nil
		}
		errs = append(errs, err)
	}
	return "", fmt.Errorf("discovery of %s: %w", issuer, errors.Join(errs...))
}

func fetchMetadata(ctx context.Context, client *http.Client, metaURL, issuer string, allowHTTP bool) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: unexpected status %s", metaURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxJWKSSize {
		return "", fmt.Errorf("%s: response too large", metaURL)
	}
	var md struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &md); err != nil {
		return "", fmt.Errorf("%s: %w", metaURL, err)
	}
	if md.Issuer != issuer {
		return "", fmt.Errorf("%s: metadata issuer %q does not match", metaURL, md.Issuer)
	}
	if md.JWKSURI == "" {
		return "", fmt.Errorf("%s: no jwks_uri", metaURL)
	}
	if _, err := checkURL(md.JWKSURI, allowHTTP); err != nil {
		return "", fmt.Errorf("%s: jwks_uri: %w", metaURL, err)
	}
	return md.JWKSURI, nil
}
