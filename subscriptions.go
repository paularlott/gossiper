package gossiper

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// subscriptionsTimeout bounds how long the subscriptions API waits for the other nodes.
const subscriptionsTimeout = 5 * time.Second

type subscriptionsDoc struct {
	Context       string         `json:"@context,omitempty"`
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	LastEventID   string         `json:"lastEventID,omitempty"`
	Subscriptions []Subscription `json:"subscriptions"`
}

type subscriptionDoc struct {
	Subscription
	LastEventID string `json:"lastEventID,omitempty"`
}

// formatSubscription sets the type a subscription document has in the response format.
func (h *Hub) formatSubscription(s Subscription, modern bool) Subscription {
	s.Context = ""
	if modern || s.modern() {
		s.Type = "subscription"
	} else {
		s.Type = "Subscription"
	}
	return s
}

// subscriptionsQuery is what a subscriptions API request asks for: every subscription, those of one matcher, or one.
type subscriptionsQuery struct {
	modern     bool   // a Mercure 1.0 path (/subscriptions/{match_type}/{match}/{subscriber})
	matchType  string // Mercure 1.0
	pattern    string // the selector (draft-07) or matcher (Mercure 1.0); "" for every subscription
	subscriber string // "" for a collection
}

// parseSubscriptionsPath reads a subscriptions API path. Under the collection, a first segment naming a matcher
// type (exact, urlpattern) starts a Mercure 1.0 path; any other a draft-07 one (/subscriptions/{topic}/{subscriber}).
// With only one protocol on, only its paths are read.
func (h *Hub) parseSubscriptionsPath(escaped string) (subscriptionsQuery, bool) {
	q := subscriptionsQuery{modern: !h.cfg.Protocol.legacy()}
	rest := strings.TrimPrefix(escaped, subscriptionsPath)
	if rest == "" {
		return q, true
	}
	parts := strings.Split(rest[1:], "/")
	for i, p := range parts {
		v, err := url.PathUnescape(p)
		if err != nil || v == "" {
			return q, false
		}
		parts[i] = v
	}
	if _, ok := kindOf(parts[0]); ok && parts[0] != "" && h.cfg.Protocol.modern() {
		q.modern = true
		q.matchType = parts[0]
		parts = parts[1:]
	} else if !h.cfg.Protocol.legacy() {
		return q, false
	}
	switch {
	case len(parts) == 0 && q.modern:
		return q, false
	case len(parts) > 2:
		return q, false
	}
	if len(parts) > 0 {
		q.pattern = parts[0]
	}
	if len(parts) > 1 {
		q.subscriber = parts[1]
	}
	return q, true
}

func (q subscriptionsQuery) wants(s Subscription) bool {
	if q.pattern != "" {
		if q.modern {
			if s.MatchType != q.matchType || s.Match != q.pattern {
				return false
			}
		} else if s.modern() || s.Topic != q.pattern {
			return false
		}
	}
	return q.subscriber == "" || s.Subscriber == q.subscriber
}

// serveSubscriptions handles the subscriptions API: the active subscriptions of every node, all of them, those of
// one matcher, or one.
func (h *Hub) serveSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Subscriptions {
		http.NotFound(w, r)
		return
	}
	g, src, ok := h.authenticate(w, r, roleSubscriber)
	if !ok {
		return
	}
	if src == noToken {
		h.writeAuthError(w, r, http.StatusUnauthorized, "")
		return
	}
	reqPath := r.URL.EscapedPath()
	if g == nil || !h.matchAny(g.subscribe, []string{reqPath}) {
		h.writeAuthError(w, r, http.StatusForbidden, "insufficient_scope")
		return
	}
	q, ok := h.parseSubscriptionsPath(reqPath)
	if !ok {
		http.NotFound(w, r)
		return
	}

	last := h.hist.last()
	if last == "" {
		last = earliest
	}
	subs := h.LocalSubscriptions()
	ctx, cancel := context.WithTimeout(r.Context(), subscriptionsTimeout)
	remote, complete, err := h.transport.RemoteSubscriptions(ctx)
	cancel()
	incomplete := err != nil || !complete
	if incomplete {
		h.log.Warn("subscriptions API: not every node answered", "error", errString(err))
	}
	subs = append(subs, remote...)
	// The format follows the request: a Mercure 1.0 request, or a token of that revision, gets Mercure 1.0
	// documents; a draft-07 one the draft-07 format unless ModernSubscriptionFormat is set.
	modern := q.modern || g.modern || h.cfg.ModernSubscriptionFormat
	out := subs[:0]
	for _, s := range subs {
		if q.wants(s) {
			out = append(out, h.formatSubscription(s, modern))
		}
	}
	slices.SortFunc(out, func(a, b Subscription) int { return strings.Compare(a.ID, b.ID) })
	out = slices.CompactFunc(out, func(a, b Subscription) bool { return a.ID == b.ID })
	// Without every node's answer a list may be missing subscriptions, and a subscription not found may exist on a
	// node that did not answer: neither is served as if it were the answer. A subscription found is.
	if incomplete && (q.subscriber == "" || len(out) == 0) {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "not every node answered: try again")
		return
	}

	hd := w.Header()
	if modern {
		hd.Set("Content-Type", "application/json")
		hd.Set("Link", "<"+h.cfg.HubURL+`>; rel="mercure"; last-event-id=`+quotedString(last)+`; type="mercure"; content-type="application/json"`)
	} else {
		hd.Set("Content-Type", "application/ld+json")
		hd.Set("Link", "<"+h.cfg.HubURL+`>; rel="mercure"`)
	}
	hd.Set("ETag", entityTag(last))
	// What a subscriber sees depends on its token: a shared cache must neither keep it nor give it to another.
	hd.Set("Cache-Control", "private, must-revalidate")
	hd.Add("Vary", "Authorization")
	hd.Add("Vary", "Cookie")
	var body []byte
	if q.subscriber != "" {
		if len(out) == 0 {
			hd.Del("Content-Type")
			http.NotFound(w, r)
			return
		}
		doc := subscriptionDoc{Subscription: out[0]}
		if !modern {
			doc.Context, doc.LastEventID = "https://mercure.rocks/", last
		}
		body = jsonMarshal(doc)
	} else {
		if out == nil {
			out = []Subscription{}
		}
		doc := subscriptionsDoc{ID: reqPath, Type: "subscriptions", Subscriptions: out}
		if !modern {
			doc.Context, doc.Type, doc.LastEventID = "https://mercure.rocks/", "Subscriptions", last
		}
		body = jsonMarshal(doc)
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// quotedString is s as an HTTP quoted-string: a quote or backslash is escaped with a backslash.
func quotedString(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return `"` + s + `"`
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// entityTag is an ETag naming the event ID id: id itself, quoted, with what an entity tag cannot hold (a quote, a
// space; and the percent sign, to keep it unambiguous) percent-encoded.
func entityTag(id string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(id); i++ {
		if c := id[i]; c == '"' || c == ' ' || c == '%' || c < 0x20 || c == 0x7f {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		} else {
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
