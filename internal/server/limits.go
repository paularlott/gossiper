package server

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// streamLimits bounds the open subscription streams of this node: all of them, and those of one client address.
type streamLimits struct {
	max, perIP int // 0: unbounded
	open       atomic.Int64
	mu         sync.Mutex
	byIP       map[string]int
}

func newStreamLimits(max, perIP int) *streamLimits {
	return &streamLimits{max: max, perIP: perIP, byIP: map[string]int{}}
}

// acquire takes a slot for a stream of ip; on refusal it returns the status to answer, else 0.
func (l *streamLimits) acquire(ip string) int {
	if n := l.open.Add(1); l.max > 0 && n > int64(l.max) {
		l.open.Add(-1)
		return http.StatusServiceUnavailable
	}
	if l.perIP > 0 {
		l.mu.Lock()
		if l.byIP[ip] >= l.perIP {
			l.mu.Unlock()
			l.open.Add(-1)
			return http.StatusTooManyRequests
		}
		l.byIP[ip]++
		l.mu.Unlock()
	}
	return 0
}

func (l *streamLimits) release(ip string) {
	if l.perIP > 0 {
		l.mu.Lock()
		if l.byIP[ip]--; l.byIP[ip] <= 0 {
			delete(l.byIP, ip)
		}
		l.mu.Unlock()
	}
	l.open.Add(-1)
}

// isSubscribe reports whether r opens a stream, as the hub tells: GET or QUERY of the hub's own path (HEAD answers
// the headers only; the subscriptions API and the metadata are plain responses).
func isSubscribe(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == "QUERY") && r.URL.Path == "/.well-known/mercure"
}

// limitStreams applies the node's stream limits to the subscriptions h serves: over the node's, 503; over the
// client address's, 429.
func (s *Server) limitStreams(h http.Handler) http.Handler {
	l := s.streams
	if l.max == 0 && l.perIP == 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSubscribe(r) {
			h.ServeHTTP(w, r)
			return
		}
		ip := s.clientIP(r)
		if code := l.acquire(ip); code != 0 {
			w.Header().Set("Retry-After", "5")
			http.Error(w, http.StatusText(code), code)
			return
		}
		defer l.release(ip)
		h.ServeHTTP(w, r)
	})
}
