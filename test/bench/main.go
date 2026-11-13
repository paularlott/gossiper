// Command bench measures gossiper's throughput, latency and memory against real server processes, on a single node
// and on a three-node cluster, in two suites. mercure: browsers' Mercure, a POST (or the Go client's streaming
// publish: publishes pipelined on one long POST, NDJSON both ways) per publish and a Server-Sent Events stream per
// subscriber. services: services talking to services through the hub, the Go client at both ends (a publish stream,
// SSE subscriptions).
//
//	go build -o bin/gossiper ./cmd/gossiper
//	go run ./test/bench -binary bin/gossiper [-mode single|cluster|both] [-suite mercure|services|all] [-out report.md] [-only text]
//
// Another hub, already running (e.g. the official Mercure hub, Mercure 1.0 only), or a cluster's nodes (-url a,b,c):
//
//	go run ./test/bench -url http://127.0.0.1:14000 -issuer https://localhost -sub-param match -http-only
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paularlott/gossiper/client"
)

const secret = "bench-secret-bench-secret-bench-secret-0123456789"

var (
	binary      = flag.String("binary", "bin/gossiper", "gossiper binary")
	mode        = flag.String("mode", "both", "single, cluster or both")
	outPath     = flag.String("out", "", "write the report (markdown) here as well as to stdout")
	scale       = flag.Float64("scale", 1, "multiplies message counts")
	only        = flag.String("only", "", "run only the workloads whose name contains this")
	hubURL      = flag.String("url", "", "benchmark the hub already running at this base URL instead of starting gossiper (a cluster: its nodes' URLs, comma separated)")
	suite       = flag.String("suite", "all", "mercure (HTTP POSTs and streams to SSE subscribers), services (the Go client at both ends) or all")
	issuer      = flag.String("issuer", "", "mint Mercure 1.0 access tokens (at+jwt) with this iss, for a hub that refuses draft-07 tokens")
	subParam    = flag.String("sub-param", "topic", "the subscription query parameter (match for a Mercure 1.0 only hub)")
	quiet       = flag.Duration("quiet", 10*time.Second, "how long a workload waits for an event before it counts what is missing as lost")
	streamProto = flag.String("stream-proto", "h1", "protocol of the Go client's streaming publish: h1, or h2c (HTTP/2 without TLS)")
	httpOnly    = flag.Bool("http-only", false, "run only the HTTP POST and SSE workloads (for a hub without streaming publishes; no services suite)")
	fanVia      = flag.String("fan-via", "both", "publishers of the fan-out workloads: http, stream or both")
	fanClients  = flag.Int("fan-stream-clients", 1, "Go clients (publish streams) of the streaming fan-out workloads")
	tenants     = flag.Bool("tenants", false, "run the hubs it starts in multi-tenant mode: one tenant, at host 127.0.0.1")

	worker          = flag.Bool("sub-worker", false, "internal: run subscribers for the parent process")
	workerSubs      = flag.Int("worker-subs", 0, "internal")
	workerTopic     = flag.String("worker-topic", "", "internal")
	workerBases     = flag.String("worker-bases", "", "internal")
	workerTransport = flag.String("worker-transport", "sse", "internal")
	workerFirst     = flag.Int("worker-first", 0, "internal")
	workerEach      = flag.Bool("worker-each", false, "internal")
)

// Transports of a workload: how it publishes and how it subscribes.
const (
	viaHTTP   = "http"
	viaStream = "stream" // the Go client's streaming publish: one long POST, NDJSON both ways (-stream-proto)
	viaSSE    = "sse"
	viaClient = "client" // the Go client's subscription (SSE, over -stream-proto)
)

func transportName(pub, sub string) string {
	names := map[string]string{viaHTTP: "HTTP POST", viaStream: map[string]string{"h2c": "HTTP/2 stream", "h1": "HTTP/1.1 stream"}[*streamProto], viaSSE: "SSE", viaClient: "Go client"}
	return names[pub] + " → " + names[sub]
}

// node is one server process.
type node struct {
	name      string
	cmd       *exec.Cmd
	http      string // base URL
	cluster   string
	peakRSS   atomic.Int64 // KiB
	stopWatch chan struct{}
}

func (n *node) rss() int64 {
	if n.cmd == nil {
		return 0
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(n.cmd.Process.Pid)).Output()
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return v
}

func (n *node) watch() {
	n.stopWatch = make(chan struct{})
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-n.stopWatch:
				return
			case <-t.C:
				if v := n.rss(); v > n.peakRSS.Load() {
					n.peakRSS.Store(v)
				}
			}
		}
	}()
}

func (n *node) stop() {
	if n.cmd == nil {
		return
	}
	if n.stopWatch != nil {
		close(n.stopWatch)
	}
	_ = n.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = n.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	}
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitTCP(addr string) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s did not come up", addr)
}

func logFile(dir, name string) *os.File {
	f, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		panic(err)
	}
	return f
}

// startGossiper starts n gossiper nodes, clustered when n > 1.
func startGossiper(dir string, n int) ([]*node, error) {
	var nodes []*node
	var peers []string
	for i := range n {
		hp, gp := freePort(), freePort()
		nd := &node{name: fmt.Sprintf("gossiper-%d", i+1), http: fmt.Sprintf("http://127.0.0.1:%d", hp)}
		// --protocol both: the benchmark speaks draft-07 unless -issuer and -sub-param match say otherwise.
		args := []string{"serve", "--listen", fmt.Sprintf("127.0.0.1:%d", hp), "--http-only", "--protocol", "both",
			"--log-level", "warn", "--pprof", "--admin-listen", fmt.Sprintf("127.0.0.1:%d", freePort()),
			"--max-subscribers-per-ip", "0"} // the subscribers all come from this machine
		if *tenants { // one tenant, reached at the address the benchmark uses
			f := filepath.Join(dir, "tenants.json")
			tf := `{"tenants":[{"name":"bench","hosts":["127.0.0.1"],"mercure":{"publisher_key":"` + secret + `","anonymous":true}}]}`
			if err := os.WriteFile(f, []byte(tf), 0o600); err != nil {
				return nil, err
			}
			args = append(args, "--tenants-file", f)
		} else {
			args = append(args, "--anonymous", "--publisher-key", secret)
		}
		if n > 1 {
			nd.cluster = fmt.Sprintf("127.0.0.1:%d", gp)
			args = append(args, "--cluster-bind", nd.cluster, "--cluster-advertise", nd.cluster,
				"--cluster-key", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
			if len(peers) > 0 {
				args = append(args, "--cluster-peers", strings.Join(peers, ","))
			}
			peers = append(peers, nd.cluster)
		}
		nd.cmd = exec.Command(*binary, args...)
		lf := logFile(dir, nd.name)
		nd.cmd.Stdout, nd.cmd.Stderr = lf, lf
		if err := nd.cmd.Start(); err != nil {
			return nil, err
		}
		nodes = append(nodes, nd)
		if err := waitTCP(strings.TrimPrefix(nd.http, "http://")); err != nil {
			return nil, err
		}
	}
	if n > 1 {
		if err := waitMesh(nodes); err != nil {
			return nil, err
		}
	}
	for _, nd := range nodes {
		nd.watch()
	}
	return nodes, nil
}

// waitMesh waits until an update published on the first node reaches a subscriber on each of the others.
func waitMesh(nodes []*node) error {
	tok := publisherToken()
	for _, nd := range nodes[1:] {
		s := subscribeSSE(nd.http, "https://bench.example/mesh")
		<-s.ready
		ok := false
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
			_ = publish(nodes[0].http, tok, "https://bench.example/mesh", "probe")
			time.Sleep(100 * time.Millisecond)
			if s.got.Load() > 0 {
				ok = true
				break
			}
		}
		s.cancel()
		if !ok {
			return fmt.Errorf("%s never joined the mesh", nd.name)
		}
	}
	return nil
}

// result is one workload's outcome.
type result struct {
	workload, transport string
	rate                string // throughput
	latency             string
	loss                string
	rss                 string // peak RSS during the workload, MiB, per node
	note                string
}

var results []result

func mib(kib int64) string { return fmt.Sprintf("%.0f", float64(kib)/1024) }

// measure runs fn with the nodes' peak RSS reset and returns the peaks as text.
func measure(nodes []*node, fn func()) string {
	for _, n := range nodes {
		n.peakRSS.Store(n.rss())
	}
	fn()
	time.Sleep(100 * time.Millisecond)
	var parts []string
	for _, n := range nodes {
		parts = append(parts, mib(n.peakRSS.Load()))
	}
	return strings.Join(parts, " / ")
}

func count(n int) int { return max(1, int(float64(n)**scale)) }

func want(name string) bool { return *only == "" || strings.Contains(name, *only) }

func lossText(got, want int64) string {
	if got >= want {
		return "0"
	}
	return fmt.Sprintf("%d of %d (%.2f%%)", want-got, want, 100*float64(want-got)/float64(want))
}

func si(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}

// ---- publishers ------------------------------------------------------------------------------------------------

func publisherToken() string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"mercure": map[string]any{"publish": []string{"*"}}})
	if *issuer != "" {
		t = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": *issuer, "aud": *hubURL + "/.well-known/mercure", "sub": "bench", "client_id": "bench",
			"exp": time.Now().Add(24 * time.Hour).Unix(), "iat": time.Now().Unix(),
			"authorization_details": []any{map[string]any{"type": "https://mercure.rocks/authorization-detail",
				"actions": []string{"publish"}, "topics": []any{map[string]any{"match": "*", "match_type": "urlpattern"}}}},
		})
		t.Header["typ"] = "at+jwt"
	}
	s, err := t.SignedString([]byte(secret))
	if err != nil {
		panic(err)
	}
	return s
}

var httpClient = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 512, MaxConnsPerHost: 0, IdleConnTimeout: time.Minute}}

func publish(base, tok, topic, data string) error {
	form := url.Values{"topic": {topic}, "data": {data}}
	req, _ := http.NewRequest(http.MethodPost, base+"/.well-known/mercure", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("publish: %s", resp.Status)
	}
	return nil
}

// streamClient is a Go client that publishes over a stream, in the protocol -stream-proto names.
func streamClient(base, tok string) *client.Client {
	c, err := client.New(client.Options{URL: base + "/.well-known/mercure", Token: tok, Transport: client.Stream,
		CleartextHTTP2: *streamProto == "h2c"})
	if err != nil {
		panic(err)
	}
	return c
}

// publishAll publishes "update 1" to "update n" on topic at base: over HTTP with conc concurrent POSTs, or with conc
// Go clients, each pipelining its share over its publish stream. With topics, update i goes to topic/(i%topics)
// instead. It returns the publishes that failed.
// With replicas, each update asks for that many copies (and has an ID of its own, as the client gives it).
func publishAll(base, topic, via string, n, conc, topics, replicas int) int64 {
	tok := publisherToken()
	topicOf := func(int64) string { return topic }
	if topics > 0 {
		topicOf = func(i int64) string { return topic + "/" + strconv.FormatInt(i%int64(topics), 10) }
	}
	var errs atomic.Int64
	var next atomic.Int64
	var wg sync.WaitGroup
	if via == viaHTTP {
		for range conc {
			wg.Go(func() {
				for {
					i := next.Add(1)
					if i > int64(n) {
						return
					}
					if err := publish(base, tok, topicOf(i), "update "+strconv.FormatInt(i, 10)); err != nil {
						errs.Add(1)
					}
				}
			})
		}
		wg.Wait()
		return errs.Load()
	}
	for range conc {
		c := streamClient(base, tok)
		wg.Go(func() {
			defer c.Close()
			var acks sync.WaitGroup
			for {
				i := next.Add(1)
				if i > int64(n) {
					break
				}
				acks.Add(1)
				err := c.PublishAsync(context.Background(), client.Update{Topics: []string{topicOf(i)}, Data: "update " + strconv.FormatInt(i, 10), Replicas: replicas},
					func(_ string, err error) {
						if err != nil {
							errs.Add(1)
						}
						acks.Done()
					})
				if err != nil {
					errs.Add(1)
					acks.Done()
				}
			}
			acks.Wait()
		})
	}
	wg.Wait()
	return errs.Load()
}

// ---- subscribers -----------------------------------------------------------------------------------------------

// subscriber counts the events of one subscription.
type subscriber struct {
	got        atomic.Int64 // distinct events: each "update N" once, and every other event
	mu         sync.Mutex
	seen       []uint64 // bitset of the update numbers received
	reconnects atomic.Int64
	cancel     context.CancelFunc
	ready      chan struct{}
}

func subscribe(base, topic, via string) *subscriber {
	if via == viaClient {
		return subscribeClient(base, topic)
	}
	return subscribeSSE(base, topic)
}

// subscribeClient subscribes as a service does: with the Go client, which resumes from the last event by itself.
func subscribeClient(base, topic string) *subscriber {
	ctx, cancel := context.WithCancel(context.Background())
	s := &subscriber{cancel: cancel, ready: make(chan struct{})}
	go func() {
		c, err := client.New(client.Options{URL: base + "/.well-known/mercure", CleartextHTTP2: *streamProto == "h2c",
			OnError: func(error) { s.reconnects.Add(1) }})
		if err != nil {
			close(s.ready)
			return
		}
		go func() { <-ctx.Done(); c.Close() }()
		spec := client.Subscribe{Topics: []string{topic}}
		if *subParam == "match" {
			spec = client.Subscribe{Match: []string{topic}}
		}
		var sub *client.Subscription
		for ctx.Err() == nil {
			if sub, err = c.Subscribe(ctx, spec); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		close(s.ready)
		if sub == nil {
			return
		}
		for ev := range sub.Events() {
			if s.first(ev.Data) {
				s.got.Add(1)
			}
		}
	}()
	return s
}

func subscribeSSE(base, topic string) *subscriber {
	ctx, cancel := context.WithCancel(context.Background())
	s := &subscriber{cancel: cancel, ready: make(chan struct{})}
	go func() {
		var readyOnce sync.Once
		defer readyOnce.Do(func() { close(s.ready) })
		last := ""
		for ctx.Err() == nil {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/mercure?"+*subParam+"="+url.QueryEscape(topic), nil)
			if last != "" {
				req.Header.Set("Last-Event-ID", last)
			}
			resp, err := sseClient.Do(req)
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			readyOnce.Do(func() { close(s.ready) })
			sc := bufio.NewScanner(resp.Body)
			id, data := "", ""
			for sc.Scan() {
				line := sc.Text()
				switch {
				case strings.HasPrefix(line, "id: "):
					id = line[4:]
				case strings.HasPrefix(line, "data: "):
					data = line[6:]
				case line == "" && id != "":
					last = id
					if s.first(data) { // a replayed event is not counted twice
						s.got.Add(1)
					}
					id, data = "", ""
				}
			}
			resp.Body.Close()
			if ctx.Err() == nil {
				s.reconnects.Add(1)
			}
		}
	}()
	return s
}

// first reports whether the event with data is new to the subscriber: an "update N" is counted once.
func (s *subscriber) first(data string) bool {
	n, err := strconv.Atoi(strings.TrimPrefix(data, "update "))
	if err != nil || !strings.HasPrefix(data, "update ") {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.seen) <= n/64 {
		s.seen = append(s.seen, 0)
	}
	if s.seen[n/64]&(1<<(n%64)) != 0 {
		return false
	}
	s.seen[n/64] |= 1 << (n % 64)
	return true
}

var sseClient = &http.Client{Transport: &http.Transport{MaxConnsPerHost: 0, MaxIdleConnsPerHost: -1}}

// subWorker runs subscribers in a process of their own, so that reading thousands of streams does not compete with
// the publishers for the CPU of one process. It reports its subscribers' counts on stdout.
func subWorker() {
	var ss []*subscriber
	bases := strings.Split(*workerBases, ",")
	for i := range *workerSubs {
		topic := *workerTopic
		if *workerEach {
			topic += "/" + strconv.Itoa(*workerFirst+i)
		}
		ss = append(ss, subscribe(bases[(*workerFirst+i)%len(bases)], topic, *workerTransport))
	}
	for _, s := range ss {
		<-s.ready
	}
	fmt.Println("ready")
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() { // each line asks for the counts: min, total, reconnects
		minGot, total, rec := int64(-1), int64(0), int64(0)
		for _, s := range ss {
			g := s.got.Load()
			total += g
			rec += s.reconnects.Load()
			if minGot < 0 || g < minGot {
				minGot = g
			}
		}
		fmt.Println(minGot, total, rec)
	}
}

// workerSet is the subscribers of the worker processes.
type workerSet struct {
	procs []*exec.Cmd
	ins   []io.WriteCloser
	outs  []*bufio.Scanner
}

// startWorkers starts subs subscribers in procs processes, spread over bases; each subscribes to topic, or with each
// to topic/i (the i-th subscriber).
func startWorkers(bases []string, topic, via string, subs, procs int, each bool) (*workerSet, error) {
	ws := &workerSet{}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	first := 0
	for i := range procs {
		n := subs / procs
		if i < subs%procs {
			n++
		}
		if n == 0 {
			continue
		}
		cmd := exec.Command(self, "-sub-worker", "-worker-subs", strconv.Itoa(n), "-worker-topic", topic,
			"-worker-bases", strings.Join(bases, ","), "-worker-transport", via, "-sub-param", *subParam,
			"-worker-first", strconv.Itoa(first), "-worker-each="+strconv.FormatBool(each), "-stream-proto", *streamProto)
		first += n
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(out)
		if !sc.Scan() || sc.Text() != "ready" {
			return nil, fmt.Errorf("subscriber worker did not start")
		}
		ws.procs, ws.ins, ws.outs = append(ws.procs, cmd), append(ws.ins, in), append(ws.outs, sc)
	}
	return ws, nil
}

// counts returns the fewest events any subscriber got, the total, and the reconnections.
func (ws *workerSet) counts() (minGot, total, reconnects int64) {
	minGot = -1
	for i := range ws.procs {
		fmt.Fprintln(ws.ins[i])
		ws.outs[i].Scan()
		var m, t, r int64
		fmt.Sscan(ws.outs[i].Text(), &m, &t, &r)
		if minGot < 0 || m < minGot {
			minGot = m
		}
		total += t
		reconnects += r
	}
	return
}

func (ws *workerSet) stop() {
	for i, c := range ws.procs {
		ws.ins[i].Close()
		_ = c.Process.Kill()
		_ = c.Wait()
	}
}

// ---- workloads -------------------------------------------------------------------------------------------------

// fanOut opens subs subscribers (in worker processes) spread over the nodes (a single one on the last node),
// subscribing via sub, and publishes n updates to the first node via pub with conc publishers; it reports the
// publish rate, the delivery rate and the loss. With each, every subscriber has a topic of its own and the updates
// are shared out among them; otherwise every subscriber gets every update.
func fanOut(nodes []*node, name, pub, sub string, subs, n, conc int, each bool, replicas int) {
	tr := transportName(pub, sub)
	if !want(name) && !want(tr) {
		return
	}
	tok := publisherToken()
	topic := "https://bench.example/" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var bases []string
	for _, nd := range nodes {
		bases = append(bases, nd.http)
	}
	if subs == 1 {
		bases = bases[len(bases)-1:]
	}
	before := make([]int64, len(nodes))
	for i, nd := range nodes {
		before[i] = nd.rss()
	}
	ws, err := startWorkers(bases, topic, sub, subs, min(4, subs), each)
	if err != nil {
		results = append(results, result{workload: name, transport: tr, note: err.Error()})
		return
	}
	defer ws.stop()
	time.Sleep(500 * time.Millisecond)
	var subsMem int64
	for i, nd := range nodes {
		subsMem += nd.rss() - before[i]
	}
	// warm up: until every subscriber has a first event (the subscriptions reached every node)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if each {
			warmEach(nodes[0].http, tok, topic, subs)
		} else {
			_ = publish(nodes[0].http, tok, topic, "warm")
		}
		time.Sleep(50 * time.Millisecond)
		if m, _, _ := ws.counts(); m > 0 {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	_, baseTotal, baseRec := ws.counts()
	var pubElapsed, total time.Duration
	var errs int64
	want := int64(n) * int64(subs)
	topics := 0
	if each {
		want, topics = int64(n), subs
	}
	var delivered, reconnects int64
	rss := measure(nodes, func() {
		start := time.Now()
		errs = publishAll(nodes[0].http, topic, pub, n, conc, topics, replicas)
		pubElapsed = time.Since(start)
		last, still := int64(-1), 0
		for still < int(*quiet/(20*time.Millisecond)) { // until every event arrived, or nothing more arrives for -quiet
			_, t, r := ws.counts()
			delivered, reconnects = t-baseTotal, r-baseRec
			if delivered >= want {
				break
			}
			if delivered == last {
				still++
			} else {
				last, still = delivered, 0
			}
			time.Sleep(20 * time.Millisecond)
		}
		total = time.Since(start) - time.Duration(still)*20*time.Millisecond
	})
	who := fmt.Sprintf("%d publishers", conc)
	if pub == viaStream {
		who = fmt.Sprintf("%d client", conc) + map[bool]string{true: "s"}[conc > 1]
	}
	results = append(results, result{workload: name, transport: tr, rss: rss,
		rate: fmt.Sprintf("%s publishes/s (%s)", si(float64(n)/pubElapsed.Seconds()), who),
		loss: lossText(min(delivered, want), want),
		note: fmt.Sprintf("%s events/s delivered; %.1f KiB per subscriber; %d reconnections; %d publish errors",
			si(float64(min(delivered, want))/total.Seconds()), float64(subsMem)/float64(subs), reconnects, errs)})
	time.Sleep(500 * time.Millisecond)
}

// warmEach publishes "warm" to topic/0 to topic/(n-1).
func warmEach(base, tok, topic string, n int) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for i := next.Add(1) - 1; i < int64(n); i = next.Add(1) - 1 {
				_ = publish(base, tok, topic+"/"+strconv.FormatInt(i, 10), "warm")
			}
		})
	}
	wg.Wait()
}

// latency measures publish-to-delivery latency for one subscriber on the last node, one publish at a time.
func latency(nodes []*node, name, via, sub string) {
	tr := transportName(via, sub)
	if !want(name) && !want(tr) {
		return
	}
	tok := publisherToken()
	topic := "https://bench.example/latency-" + via + "-" + sub
	s := subscribe(nodes[len(nodes)-1].http, topic, sub)
	<-s.ready
	defer s.cancel()
	pub := func(data string) error { return publish(nodes[0].http, tok, topic, data) }
	if via == viaStream {
		c := streamClient(nodes[0].http, tok)
		defer c.Close()
		pub = func(data string) error {
			_, err := c.Publish(context.Background(), client.Update{Topics: []string{topic}, Data: data})
			return err
		}
	}
	for deadline := time.Now().Add(20 * time.Second); s.got.Load() == 0 && time.Now().Before(deadline); {
		_ = pub("warm")
		time.Sleep(20 * time.Millisecond)
	}
	n := count(2000)
	lat := make([]time.Duration, 0, n)
	rss := measure(nodes, func() {
		for range n {
			before := s.got.Load()
			t := time.Now()
			if pub("x") != nil {
				continue
			}
			for s.got.Load() == before && time.Since(t) < 2*time.Second {
				time.Sleep(20 * time.Microsecond)
			}
			lat = append(lat, time.Since(t))
		}
	})
	slices.Sort(lat)
	results = append(results, result{workload: name, transport: tr, rss: rss,
		latency: fmt.Sprintf("p50 %v, p99 %v", lat[len(lat)/2].Round(time.Microsecond), lat[len(lat)*99/100].Round(time.Microsecond))})
}

func workloads(nodes []*node) {
	where, far := "", ""
	if len(nodes) > 1 {
		where, far = " (publish to node 1, subscribers on every node)", " (publish to node 1, subscriber on node 3)"
	}
	if *suite == "mercure" || *suite == "all" {
		one := "publish, 1 subscriber" + far
		fanOut(nodes, one, viaHTTP, viaSSE, 1, count(20000), 32, false, 0)
		if !*httpOnly {
			fanOut(nodes, one, viaStream, viaSSE, 1, count(400000), 1, false, 0)
			fanOut(nodes, one, viaStream, viaSSE, 1, count(400000), 4, false, 0)
		}
		for _, f := range []struct{ subs, n, conc int }{{1000, 1000, 16}, {5000, 200, 8}} {
			name := fmt.Sprintf("fan-out to %d subscribers%s", f.subs, where)
			if *fanVia != viaStream {
				fanOut(nodes, name, viaHTTP, viaSSE, f.subs, count(f.n), f.conc, false, 0)
			}
			if !*httpOnly && *fanVia != viaHTTP {
				fanOut(nodes, name, viaStream, viaSSE, f.subs, count(f.n), *fanClients, false, 0)
			}
		}
		lname := "publish → event latency" + far
		latency(nodes, lname, viaHTTP, viaSSE)
		if !*httpOnly {
			latency(nodes, lname, viaStream, viaSSE)
		}
	}
	if (*suite == "services" || *suite == "all") && !*httpOnly {
		// Services: the Go client publishing over a stream and subscribing; on a cluster, publishing to node 1.
		fanOut(nodes, "service → service"+far, viaStream, viaClient, 1, count(400000), 1, false, 0)
		fanOut(nodes, "4 services → 1 service"+far, viaStream, viaClient, 1, count(400000), 4, false, 0)
		fanOut(nodes, "service → 10 services, one topic"+where, viaStream, viaClient, 10, count(200000), 1, false, 0)
		fanOut(nodes, "service → 1000 services, a topic each"+where, viaStream, viaClient, 1000, count(400000), 1, true, 0)
		fanOut(nodes, "4 services → 1000 services, a topic each"+where, viaStream, viaClient, 1000, count(400000), 4, true, 0)
		if len(nodes) > 1 { // copies on the other nodes before each publish is answered
			fanOut(nodes, "service → service, 2 copies"+far, viaStream, viaClient, 1, count(400000), 1, false, 2)
			fanOut(nodes, "service → service, 3 copies"+far, viaStream, viaClient, 1, count(400000), 1, false, 3)
		}
		latency(nodes, "service → service latency"+far, viaStream, viaClient)
	}
}

// ---- main --------------------------------------------------------------------------------------------------------

func run(label string, n int, dir string) {
	fmt.Fprintf(os.Stderr, "== %s\n", label)
	var g []*node
	var err error
	if *hubURL != "" {
		for i, u := range strings.Split(*hubURL, ",") {
			g = append(g, &node{name: fmt.Sprintf("external-%d", i+1), http: strings.TrimSuffix(u, "/")})
		}
		if len(g) > 1 {
			err = waitMesh(g)
		}
	} else {
		g, err = startGossiper(dir, n)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gossiper:", err)
		os.Exit(1)
	}
	var idle []string
	for _, nd := range g {
		idle = append(idle, mib(nd.rss()))
	}
	results = append(results, result{workload: label + ": idle", rss: strings.Join(idle, " / ")})
	workloads(g)
	var after []string
	for _, nd := range g {
		after = append(after, mib(nd.rss()))
	}
	results = append(results, result{workload: label + ": after the workloads", rss: strings.Join(after, " / ")})
	for _, nd := range g {
		nd.stop()
	}
}

func main() {
	flag.Parse()
	if *worker {
		subWorker()
		return
	}
	dir, err := os.MkdirTemp("", "gossiper-bench-")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "logs in", dir)
	var reports []string
	report := func(title string) {
		var b strings.Builder
		fmt.Fprintf(&b, "## %s\n\n| Workload | Transport | Throughput | Latency | Lost | Peak RSS MiB (per node) | Notes |\n|---|---|---|---|---|---|---|\n", title)
		for _, r := range results {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", r.workload, r.transport, r.rate, r.latency, r.loss, r.rss, r.note)
		}
		reports = append(reports, b.String())
		results = nil
	}
	switch {
	case *hubURL != "" && strings.Contains(*hubURL, ","):
		run("cluster", 0, dir)
		report("Cluster")
	case *hubURL != "":
		run("single node", 1, dir)
		report("Single node")
	}
	if *hubURL == "" && (*mode == "single" || *mode == "both") {
		run("single node", 1, dir)
		report("Single node")
	}
	if *hubURL == "" && (*mode == "cluster" || *mode == "both") {
		run("3-node cluster", 3, dir)
		report("Three-node cluster")
	}
	out := strings.Join(reports, "\n")
	fmt.Println(out)
	if *outPath != "" {
		_ = os.WriteFile(*outPath, []byte(out), 0o644)
	}
}
