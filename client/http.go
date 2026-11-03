package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// httpPublish publishes u with a POST, as Mercure's HTTP protocol does.
func (c *Client) httpPublish(ctx context.Context, u Update) (string, error) {
	form := url.Values{"topic": u.Topics}
	if u.Data != "" {
		form.Set("data", u.Data)
	}
	if u.ID != "" {
		form.Set("id", u.ID)
	}
	if u.Type != "" {
		form.Set("type", u.Type)
	}
	if u.Private {
		form.Set("private", "on")
	}
	if r := retryMillis(u.Retry); r > 0 {
		form.Set("retry", strconv.FormatUint(r, 10))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.hub.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	h, err := c.header(ctx)
	if err != nil {
		return "", err
	}
	c.setHeader(req, h)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u.Replicas > 0 {
		req.Header.Set("Gossiper-Replicas", strconv.Itoa(u.Replicas))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	return strings.TrimSpace(string(body)), nil
}

// followSSE opens s as a Server-Sent Events stream and reads it until it ends: nil when s or ctx ended, or the error
// that ended it.
func (s *Subscription) followSSE(ctx context.Context, onOpen func()) error {
	c := s.c
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.stop:
		case <-c.done:
		case <-ctx.Done():
		}
		cancel()
	}()
	u := *c.hub
	q := u.Query()
	for _, t := range s.spec.Topics {
		q.Add("topic", t)
	}
	for _, t := range s.spec.Match {
		q.Add("match", t)
	}
	for _, t := range s.spec.MatchURLPattern {
		q.Add("match_urlpattern", t)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	h, err := c.header(ctx)
	if err != nil {
		return err
	}
	c.setHeader(req, h)
	req.Header.Set("Accept", "text/event-stream")
	if id := s.LastEventID(); id != "" {
		req.Header.Set("Last-Event-ID", id)
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	onOpen()
	// The hub sends a heartbeat on idle streams: a stream silent for sseIdle is gone (a half-open connection, say).
	idle := time.AfterFunc(sseIdle, cancel)
	defer idle.Stop()
	err = readSSE(&idleReader{r: resp.Body, t: idle}, c.opts.MaxEventSize, func(ev Event) bool {
		// The ID is recorded before the event is delivered, so LastEventID names it as soon as the caller has it; and
		// put back if it cannot be, so that a reconnection does not skip it.
		s.mu.Lock()
		prev := s.lastID
		if ev.ID != "" {
			s.lastID = ev.ID
		}
		s.mu.Unlock()
		select {
		case s.events <- ev:
			return true
		case <-ctx.Done():
			s.mu.Lock()
			s.lastID = prev
			s.mu.Unlock()
			return false
		}
	})
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		err = ErrDisconnected
	}
	return err
}

// sseIdle is how long a subscription stream may stay silent before it is opened again: hubs send a heartbeat every
// 30s by default (Mercure's reference hubs too).
const sseIdle = 75 * time.Second

// idleReader resets t each time it reads something.
type idleReader struct {
	r io.Reader
	t *time.Timer
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	if n > 0 {
		i.t.Reset(sseIdle)
	}
	return n, err
}

// readSSE parses a Server-Sent Events stream, calling emit for each event until emit returns false or the stream ends.
// An event whose data, or any one line, is over limit bytes ends it with an error: what the hub sends is not held
// without limit.
func readSSE(r io.Reader, limit int, emit func(Event) bool) error {
	br := bufio.NewReaderSize(r, 64<<10)
	tooLarge := fmt.Errorf("mercure: event over %d bytes (Options.MaxEventSize)", limit)
	lineLimit := limit + 4096 // room for the field's name
	var ev Event
	var data, long []byte
	hasData := false
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull { // longer than the buffer: gathered
			long = append(long[:0], line...)
			for err == bufio.ErrBufferFull && len(long) <= lineLimit {
				line, err = br.ReadSlice('\n')
				long = append(long, line...)
			}
			if len(long) > lineLimit {
				return tooLarge
			}
			line = long
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = line[:len(line)-1]
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if len(line) == 0 {
			if hasData {
				ev.Data = string(data)
				if !emit(ev) {
					return nil
				}
			}
			ev, hasData = Event{}, false
			data = data[:0]
			continue
		}
		if line[0] == ':' {
			continue
		}
		field, value := line, line[len(line):]
		if i := bytes.IndexByte(line, ':'); i >= 0 {
			field, value = line[:i], line[i+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}
		switch string(field) {
		case "data":
			if hasData {
				data = append(data, '\n')
			}
			if len(data)+len(value) > limit {
				return tooLarge
			}
			data = append(data, value...)
			hasData = true
		case "id":
			ev.ID = string(value)
		case "event":
			ev.Type = string(value)
		case "retry":
			if n, err := strconv.ParseUint(string(value), 10, 63); err == nil {
				ev.Retry = time.Duration(n) * time.Millisecond
			}
		}
	}
}

// setHeader gives req the headers h, and the host to ask for: Options.Host, or a Host header (a tenant's, through
// a node's address).
func (c *Client) setHeader(req *http.Request, h http.Header) {
	if host := h.Get("Host"); host != "" {
		req.Host = host
		h.Del("Host")
	}
	if c.opts.Host != "" {
		req.Host = c.opts.Host
	}
	req.Header = h
}
