package gossiper

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits on the fields of an update. A field over its limit is refused when it is published.
const (
	MaxIDLength    = 1024 // bytes of an event ID
	MaxTypeLength  = 256  // bytes of an event type
	MaxTopicLength = 4096 // bytes of one topic
	MaxTopics      = 64   // topics (canonical and alternates) of one update
)

// Update is one event published to the hub: the canonical topic first, then its alternates.
//
// Stamp and Origin are set by the hub when the update is published: Stamp is the publishing node's hybrid logical
// clock reading and orders the hub's history; Origin is the id of the node that took the publish. Together they
// identify one publication, whatever ID the publisher chose.
type Update struct {
	ID       string   `msgpack:"i"`
	Topics   []string `msgpack:"t"`
	Data     string   `msgpack:"d,omitempty"`
	Private  bool     `msgpack:"p,omitempty"`
	Type     string   `msgpack:"y,omitempty"`
	Retry    uint64   `msgpack:"r,omitempty"`
	HasRetry bool     `msgpack:"h,omitempty"`
	Stamp    uint64   `msgpack:"s"`
	Origin   string   `msgpack:"o"`
	// Tenant is the tenant whose hub the update belongs to, when hubs of several tenants share a transport (see
	// Tenants); "" otherwise.
	Tenant string `msgpack:"n,omitempty"`

	// Replicas, when publishing, asks for that many copies before the publish is answered (see MaxReplicas); it
	// is not sent to the other nodes. An update that asks for copies and has an ID is Idempotent: every node drops
	// another with its ID for a while.
	Replicas   int  `msgpack:"-"`
	Idempotent bool `msgpack:"e,omitempty"`

	encoded  []byte                          // the SSE frame, built once by the hub when it applies the update
	ticket   uint64                          // the HistoryStore's, when the hub saved it
	unstored bool                            // the HistoryStore did not take it
	copied   func(ctx context.Context) error // waits for its copies, when it asked for some
	copiesBy time.Time                       // when copied gives up
}

// Errors returned for an update that cannot be published.
var (
	ErrNoTopic       = errors.New(`missing "topic" parameter`)
	ErrInvalidTopic  = errors.New(`invalid "topic" parameter`)
	ErrReservedTopic = errors.New(`"topic" addresses the hub's reserved namespace`)
	ErrInvalidID     = errors.New(`invalid "id" parameter`)
	ErrInvalidType   = errors.New(`invalid "type" parameter`)
	ErrInvalidRetry  = errors.New(`invalid "retry" parameter`)
	ErrInvalidData   = errors.New(`invalid "data" parameter`)
	// ErrTooLarge is an update over a limit (MaxTopics, MaxTopicLength, MaxIDLength, MaxTypeLength); over HTTP,
	// 413.
	ErrTooLarge = errors.New("update too large")
)

// validate checks the fields a publisher supplies, on their own (the hub adds the reserved namespace, which needs
// its URL). An empty ID is valid: the hub makes one.
func (u *Update) validate() error {
	if len(u.Topics) == 0 {
		return ErrNoTopic
	}
	if len(u.Topics) > MaxTopics {
		return ErrTooLarge
	}
	for _, t := range u.Topics {
		if len(t) > MaxTopicLength {
			return ErrTooLarge
		}
		if t == "" || t == "*" || !validText(t) {
			return ErrInvalidTopic
		}
	}
	if u.ID != "" {
		if len(u.ID) > MaxIDLength {
			return ErrTooLarge
		}
		// As the spec has it: no control or format characters, not "earliest", not starting with "#" (the hub's own).
		if !validText(u.ID) || u.ID[0] == '#' || u.ID == earliest {
			return ErrInvalidID
		}
	}
	if u.Type != "" {
		if len(u.Type) > MaxTypeLength {
			return ErrTooLarge
		}
		if !validText(u.Type) || u.Type == "mercure" { // "mercure" is the hub's own subscription events
			return ErrInvalidType
		}
	}
	if !utf8.ValidString(u.Data) {
		return ErrInvalidData
	}
	return nil
}

// parseRetry parses the "retry" field: decimal digits only, as the SSE format requires.
func parseRetry(s string) (uint64, error) {
	if s == "" || len(s) > 19 {
		return 0, ErrInvalidRetry
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrInvalidRetry
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, ErrInvalidRetry
	}
	return n, nil
}

// encode builds the update's SSE frame: event, retry, id, then one data line per line of the data (CR LF, CR and
// LF all end a line), and the blank line that ends the event. An update with no data still sends one empty data
// line, so EventSource dispatches it.
func (u *Update) encode() []byte {
	n := len(u.ID) + len(u.Data) + len(u.Type) + 32
	b := make([]byte, 0, n+strings.Count(u.Data, "\n")*6)
	if u.Type != "" {
		b = append(b, "event: "...)
		b = append(b, u.Type...)
		b = append(b, '\n')
	}
	if u.HasRetry {
		b = append(b, "retry: "...)
		b = strconv.AppendUint(b, u.Retry, 10)
		b = append(b, '\n')
	}
	b = append(b, "id: "...)
	b = append(b, u.ID...)
	b = append(b, '\n')
	data := u.Data
	for {
		i := strings.IndexAny(data, "\r\n")
		b = append(b, "data: "...)
		if i < 0 {
			b = append(b, data...)
			b = append(b, '\n')
			break
		}
		b = append(b, data[:i]...)
		b = append(b, '\n')
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			i++
		}
		data = data[i+1:]
	}
	return append(b, '\n')
}

// size is the memory an update holds in the history, roughly.
func (u *Update) size() int {
	n := len(u.ID) + len(u.Data) + len(u.Type) + len(u.Origin) + len(u.encoded) + 160
	for _, t := range u.Topics {
		n += len(t) + 16
	}
	return n
}
