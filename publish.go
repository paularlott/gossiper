package gossiper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// servePublish handles POST /.well-known/mercure: an application/x-www-form-urlencoded update, or a stream of them
// (servePublishStream).
func (h *Hub) servePublish(w http.ResponseWriter, r *http.Request) {
	if !h.enterPublish() {
		writeError(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	defer h.publishers.Done()
	stream := false
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt == ndjson {
		// A stream's body does not end: over HTTP/1.1 a refusal would otherwise wait for it to be read first, and
		// without full duplex its answers cannot go out while it is read.
		if http.NewResponseController(w).EnableFullDuplex() != nil && r.ProtoMajor == 1 {
			writeError(w, http.StatusUnsupportedMediaType, "Streaming publish needs a full-duplex connection")
			return
		}
		stream = true
	}
	g, src, ok := h.authenticate(w, r, rolePublisher)
	if !ok {
		h.stats.PublishRejected.Add(1)
		return
	}
	if src == noToken {
		h.stats.PublishRejected.Add(1)
		h.writeAuthError(w, r, http.StatusUnauthorized, "")
		return
	}
	if src == fromCookie && !h.publishOriginAllowed(r) {
		h.stats.PublishRejected.Add(1)
		h.writeAuthError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	if stream {
		h.servePublishStream(w, r, g)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxPublishBytes)
	if err := r.ParseForm(); err != nil {
		h.stats.PublishRejected.Add(1)
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge))
			return
		}
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	form := r.PostForm
	u := &Update{Topics: form["topic"], Data: form.Get("data"), ID: form.Get("id"), Type: form.Get("type")}
	_, u.Private = form["private"]
	if v := r.Header.Get(replicasHeader); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			h.stats.PublishRejected.Add(1)
			writeError(w, http.StatusBadRequest, `Invalid "`+replicasHeader+`" header`)
			return
		}
		u.Replicas = n
	}
	if rs, ok := form["retry"]; ok {
		n, err := parseRetry(rs[0])
		if err != nil {
			h.stats.PublishRejected.Add(1)
			writeError(w, http.StatusBadRequest, `Invalid "retry" parameter`)
			return
		}
		u.Retry, u.HasRetry = n, true
	}
	if err := h.validate(u); err != nil {
		h.stats.PublishRejected.Add(1)
		status, msg := invalidUpdate(err)
		writeError(w, status, msg)
		return
	}
	if !h.canPublish(g, u) {
		h.stats.PublishRejected.Add(1)
		h.writeAuthError(w, r, http.StatusForbidden, "insufficient_scope")
		return
	}
	id, err := h.publish(r.Context(), u)
	if err == nil {
		err = h.replicated(r.Context(), u)
	}
	if err != nil {
		status, msg := h.publishFailed(err)
		writeError(w, status, msg)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(id))
}

// lineUpdate is one line of a streaming publish.
type lineUpdate struct {
	Topic    []string `json:"topic"`
	Data     string   `json:"data"`
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Private  bool     `json:"private"`
	Retry    *uint64  `json:"retry"`
	Replicas int      `json:"replicas"`
}

// replicasHeader asks a form publish for copies (Update.Replicas), as a stream's line does with "replicas".
const replicasHeader = "Gossiper-Replicas"

// A streaming publish (a Gossiper extension: Mercure clients never send it) is a POST of ndjson: its body is updates,
// one a line, each a JSON object with the fields of a form publish (topic, an array; data, id, type, private,
// retry; and replicas, for copies: see Update.Replicas), for as long as the client keeps it open; the answer streams one line for each, in order: {"id":"..."} once
// the update is published (and stored, with a HistoryStore), or {"line":n,"status":...,"error":"..."} for one that
// was refused, after which the stream goes on. An update published but not stored (the store failed) is answered
// {"id":"...","status":503,"error":"published, not stored"}. Over HTTP/2 (or HTTP/1.1 straight to the hub) one
// connection then publishes as fast as the client writes, without waiting for each answer; a body that ends is a
// batch.
//
// The hub ends the stream with a line without "line" (every line read before it is answered): {"status":401} when
// the token expires, 503 when the hub closes or its store fails, 408 after streamIdle without a line, 413 at a line
// over the size limit. The stream also ends when the client closes the body.
// streamIdle is how long a stream may go without a line before the hub ends it (a variable for the tests).
var streamIdle = 2 * time.Minute

const (
	ndjson = "application/x-ndjson"
	// answerBatch is the most answers gathered before they go out: answers go out when the hub has read everything the
	// client sent, or once this many are waiting.
	answerBatch = 1024
)

// streamAck is a line of a streaming publish's answer.
type streamAck struct {
	ID     string `json:"id,omitempty"`
	Line   int    `json:"line,omitempty"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// servePublishStream serves a streaming publish for the publisher whose grants are g.
func (h *Hub) servePublishStream(w http.ResponseWriter, r *http.Request, g *grants) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", ndjson)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	// A closing hub, or a failing store, ends the stream at once, even one waiting for its next line. Not once the
	// handler has returned: the response writer is gone then (an abort may run while it returns).
	var dmu sync.Mutex
	aborted, finished := false, false
	setReadDeadline := func() {
		dmu.Lock()
		if !aborted {
			_ = rc.SetReadDeadline(time.Now().Add(streamIdle))
		}
		dmu.Unlock()
	}
	abort := func() {
		dmu.Lock()
		defer dmu.Unlock()
		if finished {
			return
		}
		aborted = true
		_ = rc.SetReadDeadline(time.Now())
	}
	defer context.AfterFunc(h.closingCtx, abort)()
	defer func() { // runs first
		dmu.Lock()
		finished = true
		dmu.Unlock()
	}()
	in := bufio.NewReaderSize(r.Body, 64<<10)
	var out []streamAck
	var waits []awaited            // the updates of out that asked for copies
	stopped := make(chan struct{}) // the stream stops: the client is gone
	aw := &answerWriter{h: h, ctx: r.Context(), w: w, rc: rc, stop: sync.OnceFunc(func() { close(stopped); abort() })}
	// With a transport that makes copies, the answers go out from a goroutine of their own, each batch once the
	// updates it acknowledges have their copies, so that the stream is read on meanwhile; without, at once.
	var queue chan streamAnswers
	written := make(chan struct{})
	if _, copies := h.transport.(Replicator); copies {
		queue = make(chan streamAnswers, 64)
		go func() {
			defer close(written)
			for a := range queue {
				aw.write(a, len(queue) == 0)
			}
		}()
	}
	send := func() {
		if queue != nil {
			queue <- streamAnswers{out, waits}
			out, waits = nil, nil
		} else {
			aw.write(streamAnswers{out, waits}, true)
			out, waits = out[:0], waits[:0]
		}
	}
	// Updates that arrive in a row (the next line already read) and ask for no copies are published together, up to
	// runLen, through a transport that takes them so: each subscriber is woken once for them and writes them in one
	// go, instead of once for each. The run goes out as soon as the next read would wait for the client, and before
	// any other publish or answer, so a lone update is published as soon as it is read.
	var run []*Update
	var runAt, runLine []int // the index in out of each update's answer, and its line
	rp, _ := h.transport.(RunPublisher)
	runLen := h.runLen()
	publishRun := func() {
		if len(run) == 0 {
			return
		}
		errs := h.publishRun(r.Context(), rp, run)
		for i, u := range run {
			if errs != nil && errs[i] != nil {
				status, msg := h.publishFailed(errs[i])
				out[runAt[i]] = streamAck{Line: runLine[i], Status: status, Error: msg}
			} else {
				out[runAt[i]] = streamAck{ID: u.ID}
			}
		}
		clear(run)
		run, runAt, runLine = run[:0], runAt[:0], runLine[:0]
	}
	end := func(a *streamAck) {
		publishRun()
		if a != nil {
			out = append(out, *a)
		}
		if len(out) > 0 {
			send()
		}
		if queue == nil {
			return
		}
		close(queue)
		<-written
	}
	for line := 1; ; line++ {
		if len(out) > 0 && (in.Buffered() == 0 || len(out) >= answerBatch) { // about to wait for the client, or many waiting
			publishRun()
			send()
		}
		select {
		case <-stopped:
			end(nil)
			return
		default:
		}
		setReadDeadline()
		b, err := readLine(in, int(h.cfg.MaxPublishBytes))
		if err != nil {
			select {
			case <-h.closing:
				end(&streamAck{Status: http.StatusServiceUnavailable, Error: http.StatusText(http.StatusServiceUnavailable)})
				return
			case <-stopped:
				end(nil)
				return
			default:
			}
			switch {
			case errors.Is(err, bufio.ErrTooLong): // what follows the line cannot be read reliably: the stream ends
				out = append(out, streamAck{Line: line, Status: http.StatusRequestEntityTooLarge, Error: http.StatusText(http.StatusRequestEntityTooLarge)})
				end(&streamAck{Status: http.StatusRequestEntityTooLarge, Error: "the stream ends at an update over the limit"})
			case errors.Is(err, os.ErrDeadlineExceeded):
				end(&streamAck{Status: http.StatusRequestTimeout, Error: "idle"})
			default:
				end(nil)
			}
			return
		}
		select {
		case <-h.closing:
			end(&streamAck{Status: http.StatusServiceUnavailable, Error: http.StatusText(http.StatusServiceUnavailable)})
			return
		default:
		}
		if !g.expiry.IsZero() && time.Now().After(g.expiry) {
			end(&streamAck{Status: http.StatusUnauthorized, Error: "token expired"})
			return
		}
		if b = bytes.TrimSpace(b); len(b) == 0 {
			continue
		}
		u, status, msg := h.decodeLine(b, g)
		if u == nil {
			h.stats.PublishRejected.Add(1)
			out = append(out, streamAck{Line: line, Status: status, Error: msg})
			continue
		}
		if rp != nil && u.Replicas == 0 {
			out = append(out, streamAck{}) // answered once the run is published
			run, runAt, runLine = append(run, u), append(runAt, len(out)-1), append(runLine, line)
			if len(run) >= runLen || in.Buffered() == 0 {
				publishRun()
			}
			continue
		}
		publishRun() // what came before goes first
		id, err := h.publish(r.Context(), u)
		switch {
		case err != nil:
			status, msg := h.publishFailed(err)
			out = append(out, streamAck{Line: line, Status: status, Error: msg})
		default:
			out = append(out, streamAck{ID: id})
			if u.copied != nil {
				waits = append(waits, awaited{len(out) - 1, u})
			}
		}
	}
}

// streamAnswers is a batch of a stream's answers, and the updates among them that asked for copies.
type streamAnswers struct {
	acks  []streamAck
	waits []awaited
}

// awaited is an update that asked for copies, and the index of its answer.
type awaited struct {
	i int
	u *Update
}

// answerWriter writes a stream's answers, each batch once its updates have their copies. It calls stop (once) when
// the client is gone.
type answerWriter struct {
	h    *Hub
	ctx  context.Context
	w    http.ResponseWriter
	rc   *http.ResponseController
	stop func()
	buf  []byte
	gone bool
}

func (aw *answerWriter) write(a streamAnswers, flush bool) {
	if aw.gone {
		return // the stream stops; what it queued meanwhile is dropped
	}
	for _, wt := range a.waits {
		if err := aw.h.replicated(aw.ctx, wt.u); err != nil {
			status, msg := aw.h.publishFailed(err)
			a.acks[wt.i] = streamAck{ID: wt.u.ID, Status: status, Error: msg}
		}
	}
	aw.buf = aw.buf[:0]
	for _, ack := range a.acks {
		aw.buf = append(append(aw.buf, jsonMarshal(ack)...), '\n')
	}
	aw.send(aw.buf, flush)
}

func (aw *answerWriter) send(b []byte, flush bool) {
	_ = aw.rc.SetWriteDeadline(time.Now().Add(aw.h.cfg.WriteTimeout))
	if _, err := aw.w.Write(b); err != nil || (flush && aw.rc.Flush() != nil) {
		aw.gone = true
		aw.stop()
	}
}

// readLine returns the next line of in, without its end, refusing one over max bytes (bufio.ErrTooLong). The last
// line may end without a newline.
func readLine(in *bufio.Reader, max int) ([]byte, error) {
	var long []byte
	for {
		b, err := in.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			if long = append(long, b...); len(long) > max {
				return nil, bufio.ErrTooLong
			}
			continue
		}
		if long != nil {
			b = append(long, b...)
		}
		if len(b) > max+1 {
			return nil, bufio.ErrTooLong
		}
		if err == io.EOF && len(b) > 0 {
			return b, nil
		}
		return b, err
	}
}

// decodeLine decodes and checks one line of a stream: the update, or the status and message it is refused with.
func (h *Hub) decodeLine(b []byte, g *grants) (*Update, int, string) {
	var bu lineUpdate
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	// One JSON object, and nothing after it: neither trailing garbage nor a second object.
	if err := dec.Decode(&bu); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return nil, http.StatusBadRequest, "Invalid update"
	}
	u := &Update{Topics: bu.Topic, Data: bu.Data, ID: bu.ID, Type: bu.Type, Private: bu.Private, Replicas: bu.Replicas}
	if bu.Retry != nil {
		u.Retry, u.HasRetry = *bu.Retry, true
	}
	if err := h.validate(u); err != nil {
		status, msg := invalidUpdate(err)
		return nil, status, msg
	}
	if !h.canPublish(g, u) {
		return nil, http.StatusForbidden, "insufficient_scope"
	}
	return u, 0, ""
}

// invalidUpdate is the status and message an update refused for its fields is answered with.
func invalidUpdate(err error) (int, string) {
	switch err {
	case ErrTooLarge:
		return http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge)
	case ErrNoTopic:
		return http.StatusBadRequest, `Missing "topic" parameter`
	}
	return http.StatusBadRequest, upperFirst(err.Error())
}

// publishFailed is the status and message a publish the transport failed is answered with, in a form or a stream
// alike; an unexpected failure is logged.
func (h *Hub) publishFailed(err error) (int, string) {
	switch {
	case errors.Is(err, ErrUpdateTooLarge): // transports wrap it
		return http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge)
	case errors.Is(err, ErrNotReplicated):
		h.log.Warn("publish failed", "error", err.Error())
		return http.StatusServiceUnavailable, upperFirst(err.Error())
	case errors.Is(err, ErrTooFewNodes): // the client asked for more copies than there are nodes
		return http.StatusServiceUnavailable, upperFirst(err.Error())
	}
	h.log.Warn("publish failed", "error", err.Error())
	return http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable)
}

// canPublish reports whether the token grants publishing on every topic of u, canonical and alternate. A draft-07
// token without a publish claim, or with an empty one, may publish nothing, as may a Mercure 1.0 token without a
// publish grant.
func (h *Hub) canPublish(g *grants, u *Update) bool {
	if g == nil || len(g.publish) == 0 {
		return false
	}
	for i := range u.Topics {
		if !h.matchAny(g.publish, u.Topics[i:i+1]) {
			return false
		}
	}
	return true
}

func upperFirst(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
