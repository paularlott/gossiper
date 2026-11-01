package gossiper

import (
	"fmt"
	"testing"
	"time"
)

// A cached token is good until it expires, for the role and audience it was verified for; the cache stays bounded.
func TestTokenCache(t *testing.T) {
	var c tokenCache
	k := tokenKey{tok: "t", aud: "https://a.test/.well-known/mercure", as: roleSubscriber}
	c.put(k, &grants{expiry: time.Now().Add(time.Hour)})
	if _, ok := c.get(k); !ok {
		t.Fatal("a cached token was not found")
	}
	for _, other := range []tokenKey{{tok: "t", aud: k.aud, as: rolePublisher}, {tok: "t", aud: "https://b.test/.well-known/mercure", as: roleSubscriber}} {
		if _, ok := c.get(other); ok {
			t.Errorf("found for %+v", other)
		}
	}
	gone := tokenKey{tok: "expired"}
	c.put(gone, &grants{expiry: time.Now().Add(-time.Second)})
	if _, ok := c.get(gone); ok {
		t.Error("an expired token was found")
	}
	for i := range 3 * tokenCacheMax {
		c.put(tokenKey{tok: fmt.Sprint(i)}, &grants{})
	}
	if n := len(c.cur) + len(c.old); n > tokenCacheMax {
		t.Errorf("the cache holds %d tokens", n)
	}
}
