package topic

import (
	"hash/maphash"
	"math"
	"sync"
)

// maxCacheShards bounds the number of independently locked shards.
const maxCacheShards = 16

// cache is a bounded, sharded, two-generation cache. Each shard keeps a
// "young" and an "old" map. New entries go into young; when young reaches its
// entry or cost limit, old is discarded, young becomes old, and a fresh young
// map is started. A hit in old promotes the entry back into young, so entries
// in active use survive rotations while idle ones are dropped within two
// generations.
//
// Memory is bounded: every shard holds at most 2*maxEntries entries and, for
// callers supplying costs, at most roughly 2*maxCost total cost.
type cache[K comparable, V any] struct {
	seed   maphash.Seed
	shards []cacheShard[K, V]
}

type cacheEntry[V any] struct {
	v    V
	cost int
}

type cacheShard[K comparable, V any] struct {
	mu         sync.RWMutex
	young, old map[K]cacheEntry[V]
	youngCost  int
	maxEntries int // per generation
	maxCost    int // per generation
}

// newCache returns a cache holding at most max(entries, 2) entries in total.
// maxCost is the total cost budget across the cache; <= 0 disables cost
// accounting.
func newCache[K comparable, V any](entries, maxCost int) *cache[K, V] {
	if entries < 2 {
		entries = 2
	}
	shards := 1
	for shards < maxCacheShards && entries/(4*shards) >= 8 {
		shards *= 2
	}
	perGen := entries / (2 * shards)
	perGenCost := math.MaxInt
	if maxCost > 0 {
		perGenCost = max(1, maxCost/(2*shards))
	}
	c := &cache[K, V]{
		seed:   maphash.MakeSeed(),
		shards: make([]cacheShard[K, V], shards),
	}
	for i := range c.shards {
		s := &c.shards[i]
		s.young = make(map[K]cacheEntry[V])
		s.maxEntries = perGen
		s.maxCost = perGenCost
	}
	return c
}

func (c *cache[K, V]) shard(k K) *cacheShard[K, V] {
	if len(c.shards) == 1 {
		return &c.shards[0]
	}
	return &c.shards[maphash.Comparable(c.seed, k)&uint64(len(c.shards)-1)]
}

// get returns the cached value for k.
func (c *cache[K, V]) get(k K) (V, bool) {
	s := c.shard(k)
	s.mu.RLock()
	if e, ok := s.young[k]; ok {
		s.mu.RUnlock()
		return e.v, true
	}
	e, ok := s.old[k]
	s.mu.RUnlock()
	if !ok {
		var zero V
		return zero, false
	}
	s.mu.Lock()
	s.insertLocked(k, e)
	s.mu.Unlock()
	return e.v, true
}

// set stores v under k with the given cost. An entry whose cost alone exceeds
// the per-generation budget is not stored.
func (c *cache[K, V]) set(k K, v V, cost int) {
	s := c.shard(k)
	s.mu.Lock()
	s.insertLocked(k, cacheEntry[V]{v: v, cost: cost})
	s.mu.Unlock()
}

func (s *cacheShard[K, V]) insertLocked(k K, e cacheEntry[V]) {
	if e.cost > s.maxCost {
		return
	}
	if _, ok := s.young[k]; ok {
		return
	}
	if len(s.young) >= s.maxEntries || s.youngCost+e.cost > s.maxCost {
		s.old = s.young
		s.young = make(map[K]cacheEntry[V], min(s.maxEntries, 64))
		s.youngCost = 0
	}
	s.young[k] = e
	s.youngCost += e.cost
}
