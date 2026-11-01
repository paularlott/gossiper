package gossiper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// sinkWriter is a ResponseWriter that counts the events written to it, for driving many streams in process.
type sinkWriter struct {
	hdr    http.Header
	events *atomic.Uint64
}

func (w *sinkWriter) Header() http.Header              { return w.hdr }
func (w *sinkWriter) WriteHeader(int)                  {}
func (w *sinkWriter) Flush()                           {}
func (w *sinkWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *sinkWriter) Write(p []byte) (int, error) {
	if len(p) > 2 { // an event, not the opening or heartbeat comment
		w.events.Add(1)
	}
	return len(p), nil
}

// BenchmarkFanout measures publishing one update to n subscribers (all of them matching) and getting it written to
// each. The streams are served in process, so the numbers are the hub's, not the network's.
func BenchmarkFanout(b *testing.B) {
	for _, n := range []int{1, 100, 10000} {
		b.Run(fmt.Sprintf("subscribers=%d", n), func(b *testing.B) {
			h, err := New(Config{PublisherKey: auth.KeyConfig{Key: testSecret}, DispatchBuffer: 512, HistorySize: -1, Heartbeat: -1})
			if err != nil {
				b.Fatal(err)
			}
			var delivered atomic.Uint64
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			tok := signJWT(b, testSecret, mercureClaims(nil, all))
			for i := 0; i < n; i++ {
				// A third of the subscribers use a template, a third "*", a third the exact topic.
				sel := [...]string{"bench/topic", "bench/{id}", "*"}[i%3]
				req := httptest.NewRequest("GET", hubPath+"?"+url.Values{"topic": {sel}}.Encode(), nil).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer "+tok)
				wg.Add(1)
				go func() {
					defer wg.Done()
					h.ServeHTTP(&sinkWriter{hdr: http.Header{}, events: &delivered}, req)
				}()
			}
			for h.stats.Subscribers.Load() != int64(n) {
				runtime.Gosched()
			}
			up := &Update{Topics: []string{"bench/topic"}, Data: strings.Repeat("x", 100)}
			const batch = 128
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				u := *up
				if _, err := h.Publish(ctx, &u); err != nil {
					b.Fatal(err)
				}
				if (i+1)%batch == 0 { // let the streams catch up: a full queue would drop the subscriber
					want := uint64(i+1) * uint64(n)
					for delivered.Load() < want {
						runtime.Gosched()
					}
				}
			}
			want := uint64(b.N) * uint64(n)
			for delivered.Load() < want {
				runtime.Gosched()
			}
			b.StopTimer()
			b.ReportMetric(float64(n), "subs")
			cancel()
			wg.Wait()
			h.Close(context.Background())
		})
	}
}

// BenchmarkPublishHTTP measures POSTing updates to a hub with one subscriber, over real HTTP connections.
func BenchmarkPublishHTTP(b *testing.B) {
	e := newEnv(b, Config{HistorySize: 1000, DispatchBuffer: 1 << 16})
	var seen atomic.Uint64
	resp, cancel, err := e.tryDial(url.Values{"topic": {"bench"}}, bearer(tokenFor(b, nil, all)))
	if err != nil {
		b.Fatal(err)
	}
	defer cancel()
	defer resp.Body.Close()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			seen.Add(uint64(strings.Count(string(buf[:n]), "\n\n")))
			if err != nil {
				return
			}
		}
	}()
	body := url.Values{"topic": {"bench"}, "data": {strings.Repeat("x", 100)}}.Encode()
	tok := "Bearer " + tokenFor(b, all, nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("POST", e.hubURL(), strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", tok)
			r, err := e.client.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			r.Body.Close()
			if r.StatusCode != 200 {
				b.Errorf("status %d", r.StatusCode)
				return
			}
		}
	})
}

// BenchmarkEncode measures building an event's frame.
func BenchmarkEncode(b *testing.B) {
	u := &Update{ID: "urn:uuid:01a18dc5-946b-79d8-801c-f6ba40752825", Type: "msg", Data: strings.Repeat("line of data\n", 10)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = u.encode()
	}
}
