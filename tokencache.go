package gossiper

import (
	"sync"
	"time"
)

// tokenCache remembers the tokens a hub verified, so that a client reconnecting (thousands at once when a node
// restarts) or publishing again is not verified again: a signature check costs far more than a lookup. An entry is
// good until its token expires, and for tokenTTL at most, so a key set that changes (a key withdrawn) is seen
// within that. It holds up to tokenCacheMax tokens in two generations: when the newer is full the older is dropped.
type tokenCache struct {
	mu       sync.Mutex
	cur, old map[tokenKey]cachedGrants
}

const (
	tokenTTL      = 5 * time.Minute
	tokenCacheMax = 10000
)

// tokenKey is a token as verified: the same token is verified again for another role, or for another audience
// (the hub URL a Mercure 1.0 token is checked against may follow the request's host).
type tokenKey struct {
	tok, aud string
	as       role
}

type cachedGrants struct {
	g     *grants
	until time.Time
}

func (c *tokenCache) get(k tokenKey) (*grants, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cur[k]
	if !ok {
		if e, ok = c.old[k]; ok {
			c.store(k, e)
		}
	}
	if !ok || time.Now().After(e.until) {
		return nil, false
	}
	return e.g, true
}

func (c *tokenCache) put(k tokenKey, g *grants) {
	until := time.Now().Add(tokenTTL)
	if !g.expiry.IsZero() && g.expiry.Before(until) {
		until = g.expiry
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store(k, cachedGrants{g, until})
}

// store adds an entry to the newer generation. Called with mu held.
func (c *tokenCache) store(k tokenKey, e cachedGrants) {
	if len(c.cur) >= tokenCacheMax/2 || c.cur == nil {
		c.old, c.cur = c.cur, make(map[tokenKey]cachedGrants)
	}
	c.cur[k] = e
}
