// Command embed runs a gossiper hub inside an ordinary Go web application: the hub serves the Mercure endpoints,
// the application publishes from its own handlers through the Go API, and a page subscribes with EventSource.
//
//	go run ./examples/embed
//	open http://localhost:8080/
//	curl -X POST 'http://localhost:8080/say?msg=hello'
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/paularlott/gossiper"
)

const page = `<!doctype html>
<meta charset="utf-8">
<title>gossiper: embedded hub</title>
<ul id="log"></ul>
<script>
const url = new URL('/.well-known/mercure', location);
url.searchParams.append('match', 'https://example.com/chat');
const es = new EventSource(url);
es.onmessage = e => {
	const li = document.createElement('li');
	li.textContent = e.data;
	document.getElementById('log').append(li);
};
</script>
`

func main() {
	hub, err := gossiper.New(gossiper.Config{
		Anonymous: true, // the page subscribes without a token; it receives public updates only
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/mercure", hub)
	mux.Handle("/.well-known/mercure/", hub)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	})
	// The application publishes through the Go API: no token is needed, the caller is trusted.
	mux.HandleFunc("POST /say", func(w http.ResponseWriter, r *http.Request) {
		id, err := hub.Publish(r.Context(), &gossiper.Update{
			Topics: []string{"https://example.com/chat"},
			Data:   r.URL.Query().Get("msg"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, id)
	})

	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx) // stop accepting
		_ = hub.Close(sctx)    // end the open streams
	}()
	log.Println("listening on http://localhost:8080/")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
