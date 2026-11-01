package topic

import (
	"fmt"
	"sync"
	"testing"
)

func TestCacheBasic(t *testing.T) {
	c := newCache[string, int](100, 0)
	if _, ok := c.get("a"); ok {
		t.Fatal("empty cache hit")
	}
	c.set("a", 1, 1)
	if v, ok := c.get("a"); !ok || v != 1 {
		t.Fatalf("get(a) = %v, %v", v, ok)
	}
	c.set("a", 2, 1) // existing keys are left alone
	if v, _ := c.get("a"); v != 1 {
		t.Fatalf("get(a) = %v after duplicate set", v)
	}
}

func TestCacheMinimumSize(t *testing.T) {
	for _, n := range []int{-5, 0, 1, 2} {
		c := newCache[int, int](n, 0)
		for i := 0; i < 100; i++ {
			c.set(i, i, 1)
			if c.len() > 2 {
				t.Fatalf("size %d: len %d", n, c.len())
			}
		}
	}
}

func TestCacheRotationAndPromotion(t *testing.T) {
	c := newCache[int, int](4, 0) // one shard, two entries per generation
	c.set(1, 1, 1)
	c.set(2, 2, 1)
	c.set(3, 3, 1) // rotates: {1,2} become old
	if _, ok := c.get(1); !ok {
		t.Fatal("entry in old generation lost")
	}
	// 1 was promoted into young, which now holds {3, 1}: a further insert
	// rotates and drops 2 but keeps 1 and 3.
	c.set(4, 4, 1)
	if _, ok := c.get(2); ok {
		t.Error("idle entry survived two rotations")
	}
	for _, k := range []int{1, 3, 4} {
		if _, ok := c.get(k); !ok {
			t.Errorf("entry %d lost", k)
		}
	}
	if c.len() > 4 {
		t.Errorf("len = %d, want <= 4", c.len())
	}
}

func TestCacheCostLimit(t *testing.T) {
	c := newCache[int, int](1000, 100000)
	perGen := c.shards[0].maxCost
	c.set(0, 0, perGen+1) // too expensive on its own
	if _, ok := c.get(0); ok {
		t.Error("entry exceeding the cost budget was stored")
	}
	for i := 1; i < 1000; i++ {
		c.set(i, i, perGen/3+1)
		for j := range c.shards {
			s := &c.shards[j]
			if s.youngCost > s.maxCost {
				t.Fatalf("young cost %d exceeds %d", s.youngCost, s.maxCost)
			}
		}
	}
	if c.len() > 1000 {
		t.Errorf("len = %d", c.len())
	}
}

func TestCacheSharding(t *testing.T) {
	if n := len(newCache[string, int](2, 0).shards); n != 1 {
		t.Errorf("tiny cache has %d shards", n)
	}
	c := newCache[string, int](100000, 0)
	if n := len(c.shards); n != maxCacheShards {
		t.Errorf("large cache has %d shards, want %d", n, maxCacheShards)
	}
	for i := 0; i < 1000000; i++ {
		c.set(fmt.Sprint(i), i, 1)
	}
	if n := c.len(); n > 100000 {
		t.Errorf("len = %d, want <= 100000", n)
	}
	// Keys spread over several shards.
	used := 0
	for i := range c.shards {
		if len(c.shards[i].young) > 0 {
			used++
		}
	}
	if used < maxCacheShards/2 {
		t.Errorf("only %d of %d shards used", used, maxCacheShards)
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := newCache[int, int](256, 0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				k := (i*7 + g) % 1000
				if v, ok := c.get(k); ok && v != k {
					t.Errorf("get(%d) = %d", k, v)
					return
				}
				c.set(k, k, 1)
			}
		}(g)
	}
	wg.Wait()
	if c.len() > 256 {
		t.Errorf("len = %d, want <= 256", c.len())
	}
}

// len returns an upper bound on the number of cached entries (an entry that
// was promoted from old may be counted in both generations).
func (c *cache[K, V]) len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		n += len(s.young) + len(s.old)
		s.mu.RUnlock()
	}
	return n
}
