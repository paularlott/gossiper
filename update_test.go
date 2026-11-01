package gossiper

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidate(t *testing.T) {
	topics := make([]string, MaxTopics+1)
	for i := range topics {
		topics[i] = "t" + strconv.Itoa(i)
	}
	ok := func(mod func(*Update)) *Update {
		u := &Update{Topics: []string{"https://example.com/a"}, ID: "id-1", Data: "d", Type: "ty"}
		if mod != nil {
			mod(u)
		}
		return u
	}
	tests := []struct {
		name string
		u    *Update
		want error
	}{
		{"valid", ok(nil), nil},
		{"valid without id", ok(func(u *Update) { u.ID = "" }), nil},
		{"valid without type", ok(func(u *Update) { u.Type = "" }), nil},
		{"valid empty data", ok(func(u *Update) { u.Data = "" }), nil},
		{"valid data with newlines", ok(func(u *Update) { u.Data = "a\r\nb\nc\r" }), nil},
		{"valid multibyte", ok(func(u *Update) { u.Topics = []string{"é/日本"}; u.ID = "é" }), nil},
		{"valid max topics", ok(func(u *Update) { u.Topics = topics[:MaxTopics] }), nil},
		{"valid max id", ok(func(u *Update) { u.ID = strings.Repeat("a", MaxIDLength) }), nil},
		{"valid max type", ok(func(u *Update) { u.Type = strings.Repeat("a", MaxTypeLength) }), nil},
		{"valid max topic", ok(func(u *Update) { u.Topics = []string{strings.Repeat("a", MaxTopicLength)} }), nil},
		{"valid id with hash inside", ok(func(u *Update) { u.ID = "a#b" }), nil},
		{"valid reserved lookalike", ok(func(u *Update) { u.Topics = []string{"/.well-known/mercure"} }), nil},
		{"valid earliest inside id", ok(func(u *Update) { u.ID = "earliest2" }), nil},

		{"no topics", ok(func(u *Update) { u.Topics = nil }), ErrNoTopic},
		{"empty topics", ok(func(u *Update) { u.Topics = []string{} }), ErrNoTopic},
		{"too many topics", ok(func(u *Update) { u.Topics = topics }), ErrTooLarge},
		{"empty topic", ok(func(u *Update) { u.Topics = []string{"a", ""} }), ErrInvalidTopic},
		{"topic too long", ok(func(u *Update) { u.Topics = []string{strings.Repeat("a", MaxTopicLength+1)} }), ErrTooLarge},
		{"topic invalid utf8", ok(func(u *Update) { u.Topics = []string{"a\xffb"} }), ErrInvalidTopic},
		{"topic with LF", ok(func(u *Update) { u.Topics = []string{"a\nb"} }), ErrInvalidTopic},
		{"topic with CR", ok(func(u *Update) { u.Topics = []string{"a\rb"} }), ErrInvalidTopic},
		{"topic with NUL", ok(func(u *Update) { u.Topics = []string{"a\x00b"} }), ErrInvalidTopic},
		{"topic with DEL", ok(func(u *Update) { u.Topics = []string{"a\x7fb"} }), ErrInvalidTopic},
		{"topic with tab", ok(func(u *Update) { u.Topics = []string{"a\tb"} }), ErrInvalidTopic},
		{"id too long", ok(func(u *Update) { u.ID = strings.Repeat("a", MaxIDLength+1) }), ErrTooLarge},
		{"id starts with hash", ok(func(u *Update) { u.ID = "#abc" }), ErrInvalidID},
		{"id earliest", ok(func(u *Update) { u.ID = "earliest" }), ErrInvalidID},
		{"id with LF", ok(func(u *Update) { u.ID = "a\nb" }), ErrInvalidID},
		{"id with CR", ok(func(u *Update) { u.ID = "a\rb" }), ErrInvalidID},
		{"id with NUL", ok(func(u *Update) { u.ID = "a\x00" }), ErrInvalidID},
		{"id invalid utf8", ok(func(u *Update) { u.ID = "\xc3" }), ErrInvalidID},
		{"type too long", ok(func(u *Update) { u.Type = strings.Repeat("a", MaxTypeLength+1) }), ErrTooLarge},
		{"type mercure", ok(func(u *Update) { u.Type = "mercure" }), ErrInvalidType},
		{"topic star", ok(func(u *Update) { u.Topics = []string{"*"} }), ErrInvalidTopic},
		{"topic with C1", ok(func(u *Update) { u.Topics = []string{"a\u0085b"} }), ErrInvalidTopic},
		{"topic with format char", ok(func(u *Update) { u.Topics = []string{"a\u200bb"} }), ErrInvalidTopic},
		{"id with format char", ok(func(u *Update) { u.ID = "a\u202eb" }), ErrInvalidID},
		{"type with LF", ok(func(u *Update) { u.Type = "a\nid: x" }), ErrInvalidType},
		{"type invalid utf8", ok(func(u *Update) { u.Type = "\xff" }), ErrInvalidType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.u.validate(); !errors.Is(err, tc.want) {
				t.Fatalf("validate() = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("data invalid utf8", func(t *testing.T) {
		u := ok(func(u *Update) { u.Data = "a\xffb" })
		if err := u.validate(); err == nil || !strings.Contains(err.Error(), "data") {
			t.Fatalf("validate() = %v, want a data error", err)
		}
	})
}

func TestParseRetry(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"0", 0, true},
		{"1", 1, true},
		{"3000", 3000, true},
		{"007", 7, true},
		{"1844674407370955161", 1844674407370955161, true}, // 19 digits
		{"9999999999999999999", 9999999999999999999, true}, // 19 digits, below MaxUint64
		{"", 0, false},
		{"-1", 0, false},
		{"+1", 0, false},
		{"1.5", 0, false},
		{"1e3", 0, false},
		{" 1", 0, false},
		{"1 ", 0, false},
		{"abc", 0, false},
		{"１２", 0, false}, // full-width digits
		{"12345678901234567890", 0, false},
		{strings.Repeat("0", 20), 0, false},
	}
	for _, tc := range tests {
		got, err := parseRetry(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseRetry(%q) = %d, %v; want %d ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidRetry) {
			t.Errorf("parseRetry(%q) error %v is not ErrInvalidRetry", tc.in, err)
		}
	}
	if n, err := parseRetry(strconv.FormatUint(math.MaxUint64, 10)); err == nil {
		t.Errorf("MaxUint64 (20 digits) accepted: %d", n)
	}
}

func TestEncode(t *testing.T) {
	tests := []struct {
		name string
		u    Update
		want string
	}{
		{"minimal", Update{ID: "1", Data: "x"}, "id: 1\ndata: x\n\n"},
		{"empty data", Update{ID: "1"}, "id: 1\ndata: \n\n"},
		{"type", Update{ID: "1", Type: "T", Data: "x"}, "event: T\nid: 1\ndata: x\n\n"},
		{"retry", Update{ID: "1", HasRetry: true, Retry: 250, Data: "x"}, "retry: 250\nid: 1\ndata: x\n\n"},
		{"retry zero", Update{ID: "1", HasRetry: true, Data: "x"}, "retry: 0\nid: 1\ndata: x\n\n"},
		{"retry without flag is dropped", Update{ID: "1", Retry: 9, Data: "x"}, "id: 1\ndata: x\n\n"},
		{"all fields order", Update{ID: "1", Type: "T", HasRetry: true, Retry: 5, Data: "x"}, "event: T\nretry: 5\nid: 1\ndata: x\n\n"},
		{"LF", Update{ID: "1", Data: "a\nb"}, "id: 1\ndata: a\ndata: b\n\n"},
		{"CRLF", Update{ID: "1", Data: "a\r\nb"}, "id: 1\ndata: a\ndata: b\n\n"},
		{"CR", Update{ID: "1", Data: "a\rb"}, "id: 1\ndata: a\ndata: b\n\n"},
		{"mixed", Update{ID: "1", Data: "a\nb\rc\r\nd"}, "id: 1\ndata: a\ndata: b\ndata: c\ndata: d\n\n"},
		{"trailing LF", Update{ID: "1", Data: "a\n"}, "id: 1\ndata: a\ndata: \n\n"},
		{"trailing CRLF", Update{ID: "1", Data: "a\r\n"}, "id: 1\ndata: a\ndata: \n\n"},
		{"trailing CR", Update{ID: "1", Data: "a\r"}, "id: 1\ndata: a\ndata: \n\n"},
		{"leading LF", Update{ID: "1", Data: "\na"}, "id: 1\ndata: \ndata: a\n\n"},
		{"only LF", Update{ID: "1", Data: "\n"}, "id: 1\ndata: \ndata: \n\n"},
		{"blank lines", Update{ID: "1", Data: "a\n\nb"}, "id: 1\ndata: a\ndata: \ndata: b\n\n"},
		{"CR CR LF", Update{ID: "1", Data: "a\r\r\nb"}, "id: 1\ndata: a\ndata: \ndata: b\n\n"},
		{"LF CR", Update{ID: "1", Data: "a\n\rb"}, "id: 1\ndata: a\ndata: \ndata: b\n\n"},
		{"injection attempt", Update{ID: "1", Data: "x\nid: evil\n\nevent: e"}, "id: 1\ndata: x\ndata: id: evil\ndata: \ndata: event: e\n\n"},
		{"colon and space data", Update{ID: "1", Data: " : x"}, "id: 1\ndata:  : x\n\n"},
		{"multibyte", Update{ID: "é", Type: "日", Data: "ü\n本"}, "event: 日\nid: é\ndata: ü\ndata: 本\n\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(tc.u.encode())
			if got != tc.want {
				t.Fatalf("encode() = %q, want %q", got, tc.want)
			}
			ev, err := parseFrame(got)
			if err != nil {
				t.Fatal(err)
			}
			if ev.ID != tc.u.ID || ev.Type != tc.u.Type {
				t.Fatalf("round trip lost id/type: %+v", ev)
			}
			if want := normaliseNewlines(tc.u.Data); ev.Data != want {
				t.Fatalf("round trip data %q, want %q", ev.Data, want)
			}
		})
	}
}

// normaliseNewlines is what a data field becomes on the wire: every CRLF, CR and LF a line break.
func normaliseNewlines(s string) string {
	return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s)
}

func TestEncodeLarge(t *testing.T) {
	data := strings.Repeat("line\n", 5000) + "end"
	u := Update{ID: "big", Data: data}
	ev, err := parseFrame(string(u.encode()))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Data != data {
		t.Fatal("large multi-line data did not round trip")
	}
}

func TestUpdateSize(t *testing.T) {
	u := &Update{ID: "abc", Topics: []string{"a", "bb"}, Data: "12345", Type: "t", Origin: "o"}
	base := u.size()
	u.encoded = make([]byte, 100)
	if got := u.size(); got != base+100 {
		t.Fatalf("size grew by %d with 100 encoded bytes", got-base)
	}
	u.Topics = append(u.Topics, "ccc")
	if got := u.size(); got <= base+100 {
		t.Fatalf("size did not count the extra topic")
	}
	if (&Update{}).size() <= 0 {
		t.Fatal("empty update has no size")
	}
}

func FuzzEncode(f *testing.F) {
	f.Add("id-1", "", "hello", "", false, uint64(0))
	f.Add("x", "T", "a\nb\r\nc\rd", "", true, uint64(1000))
	f.Add("x", "e", "x\nid: evil\n\nevent: e", "", true, uint64(0))
	f.Add("\xff", "t\ny", " \u0085\x00\x0b\x0c", "", false, uint64(1))
	f.Add("id", "type", "\r\r\n\n\r", "", false, uint64(math.MaxUint64))
	f.Fuzz(func(t *testing.T, id, typ, data, _ string, hasRetry bool, retry uint64) {
		u := &Update{Topics: []string{"t"}, ID: id, Type: typ, Data: data, HasRetry: hasRetry, Retry: retry}
		if id == "" || u.validate() != nil {
			t.Skip()
		}
		frame := string(u.encode())
		ev, err := parseFrame(frame)
		if err != nil {
			t.Fatalf("%v (update %+v)", err, u)
		}
		if ev.ID != id || ev.Type != typ {
			t.Fatalf("id/type changed: %+v from %+v", ev, u)
		}
		if want := normaliseNewlines(data); ev.Data != want {
			t.Fatalf("data %q, want %q", ev.Data, want)
		}
		if ev.HasRetry != hasRetry || (hasRetry && ev.Retry != strconv.FormatUint(retry, 10)) {
			t.Fatalf("retry changed: %+v", ev)
		}
		if !utf8.ValidString(frame) {
			t.Fatal("frame is not UTF-8")
		}
		if strings.Count(frame, "\n\n") != 1 {
			t.Fatalf("frame has a stray blank line: %q", frame)
		}
	})
}
