package urlpattern

import (
	"hash/maphash"
	"sync"
)

const (
	defaultCacheSize = 1024
	maxShards        = 16
)

// Matcher matches URLs against URL patterns relative to a fixed base URL,
// caching compiled patterns (including failures) in a bounded, sharded,
// two-generation cache. It is safe for concurrent use.
type Matcher struct {
	base    *urlRecord // parsed base URL; nil if none or unparsable
	baseStr string     // base URL string used when compiling patterns
	seed    maphash.Seed
	perGen  int
	shards  []matcherShard
}

type cacheEntry struct {
	p   *Pattern
	err error
}

type matcherShard struct {
	mu        sync.Mutex
	cur, prev map[string]cacheEntry
}

// NewMatcher returns a Matcher resolving relative patterns and inputs against
// baseURL. cacheSize bounds the number of cached compiled patterns (at most
// max(cacheSize, 2) are retained; <= 0 selects 1024). If baseURL is empty or
// unparsable, relative patterns are invalid and relative inputs never match.
func NewMatcher(baseURL string, cacheSize int) *Matcher {
	if cacheSize <= 0 {
		cacheSize = defaultCacheSize
	}
	m := &Matcher{seed: maphash.MakeSeed()}
	if base, ok := parseBase(baseURL); ok && base != nil {
		m.base, m.baseStr = base, baseURL
	}
	n := maxShards
	for n > 1 && cacheSize/(2*n) < 1 {
		n /= 2
	}
	m.perGen = cacheSize / (2 * n)
	if m.perGen < 1 {
		m.perGen = 1
	}
	m.shards = make([]matcherShard, n)
	for i := range m.shards {
		m.shards[i].cur = make(map[string]cacheEntry)
	}
	return m
}

// get returns the compiled pattern for s, compiling and caching it on a miss.
func (m *Matcher) get(s string) (*Pattern, error) {
	sh := &m.shards[int(maphash.String(m.seed, s)%uint64(len(m.shards)))]
	sh.mu.Lock()
	if e, ok := sh.cur[s]; ok {
		sh.mu.Unlock()
		return e.p, e.err
	}
	if e, ok := sh.prev[s]; ok {
		sh.put(s, e, m.perGen)
		sh.mu.Unlock()
		return e.p, e.err
	}
	sh.mu.Unlock()

	p, err := Compile(s, m.baseStr)
	e := cacheEntry{p, err}
	sh.mu.Lock()
	sh.put(s, e, m.perGen)
	sh.mu.Unlock()
	return p, err
}

// put inserts into the current generation, rotating generations when full.
func (sh *matcherShard) put(key string, e cacheEntry, perGen int) {
	if _, ok := sh.cur[key]; !ok && len(sh.cur) >= perGen {
		sh.prev = sh.cur
		sh.cur = make(map[string]cacheEntry, perGen)
	}
	sh.cur[key] = e
}

// Len returns the number of cached patterns.
func (m *Matcher) Len() int {
	n := 0
	for i := range m.shards {
		sh := &m.shards[i]
		sh.mu.Lock()
		n += len(sh.cur) + len(sh.prev)
		sh.mu.Unlock()
	}
	return n
}

// Match reports whether input (a URL, resolved against the base URL when
// relative) matches pattern. An invalid pattern or unparsable input never
// matches.
func (m *Matcher) Match(input, pattern string) bool {
	p, err := m.get(pattern)
	if err != nil {
		return false
	}
	return p.testWith(input, m.base)
}

// Valid returns nil if pattern compiles, and the compile error otherwise.
func (m *Matcher) Valid(pattern string) error {
	_, err := m.get(pattern)
	return err
}
