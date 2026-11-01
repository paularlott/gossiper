package urlpattern

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// wptSkip lists WPT cases (index into urlpatterntestdata.json) that are not
// run, with the reason. Keep this list minimal: an unsupported regexp feature
// is an "invalid pattern" error rather than a skip, and the data's expected
// result is adjusted below only where the standard's behaviour is
// unobservable through this API.
var wptSkip = map[int]string{
	213: "input given as (init dictionary, base URL string): this API has no base argument for TestInit/ExecInit; the standard throws a TypeError (compile-time API misuse, not a matching result)",
}

type wptCase struct {
	Pattern       []json.RawMessage `json:"pattern"`
	Inputs        []json.RawMessage `json:"inputs"`
	ExpectedObj   json.RawMessage   `json:"expected_obj"`
	ExpectedMatch json.RawMessage   `json:"expected_match"`
	ExactlyEmpty  []string          `json:"exactly_empty_components"`
}

func loadWPT(t testing.TB) []wptCase {
	t.Helper()
	data, err := os.ReadFile("testdata/urlpatterntestdata.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []wptCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func isJSONString(raw json.RawMessage) bool { return len(raw) > 0 && raw[0] == '"' }
func isJSONObject(raw json.RawMessage) bool { return len(raw) > 0 && raw[0] == '{' }

func rawString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func rawInit(t testing.TB, raw json.RawMessage) Init {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("bad init %s: %v", raw, err)
	}
	var in Init
	for k, a := range m {
		v, isString := a.(string)
		if !isString {
			continue // e.g. {"ignoreCase": true}: not an init member
		}
		switch k {
		case "protocol":
			in.Protocol = &v
		case "username":
			in.Username = &v
		case "password":
			in.Password = &v
		case "hostname":
			in.Hostname = &v
		case "port":
			in.Port = &v
		case "pathname":
			in.Pathname = &v
		case "search":
			in.Search = &v
		case "hash":
			in.Hash = &v
		case "baseURL":
			in.BaseURL = &v
		}
	}
	return in
}

func rawOptions(raw json.RawMessage) Options {
	var o struct {
		IgnoreCase bool `json:"ignoreCase"`
	}
	_ = json.Unmarshal(raw, &o)
	return Options{IgnoreCase: o.IgnoreCase}
}

// compileWPT mirrors the URLPattern constructor overloads. ok is false when
// the argument list matches no constructor (a TypeError in JavaScript).
func compileWPT(t testing.TB, args []json.RawMessage) (p *Pattern, err error, ok bool) {
	t.Helper()
	switch {
	case len(args) == 0:
		p, err = CompileInit(Init{}, "")
	case isJSONObject(args[0]):
		init := rawInit(t, args[0])
		var opts Options
		base := ""
		switch len(args) {
		case 1:
		case 2:
			if isJSONString(args[1]) {
				base = rawString(args[1])
			} else {
				opts = rawOptions(args[1])
			}
		default:
			return nil, nil, false
		}
		p, err = CompileInitWithOptions(init, base, opts)
	default:
		s := rawString(args[0])
		var opts Options
		base := ""
		switch len(args) {
		case 1:
		case 2:
			if isJSONString(args[1]) {
				base = rawString(args[1])
			} else {
				opts = rawOptions(args[1])
			}
		case 3:
			if !isJSONString(args[1]) || !isJSONObject(args[2]) {
				return nil, nil, false
			}
			base, opts = rawString(args[1]), rawOptions(args[2])
		default:
			return nil, nil, false
		}
		p, err = CompileWithOptions(s, base, opts)
	}
	return p, err, true
}

func componentOf(p *Pattern, name string) string {
	switch name {
	case "protocol":
		return p.Protocol()
	case "username":
		return p.Username()
	case "password":
		return p.Password()
	case "hostname":
		return p.Hostname()
	case "port":
		return p.Port()
	case "pathname":
		return p.Pathname()
	case "search":
		return p.Search()
	case "hash":
		return p.Hash()
	}
	panic("bad component " + name)
}

func resultComponent(r *Result, name string) ComponentResult {
	switch name {
	case "protocol":
		return r.Protocol
	case "username":
		return r.Username
	case "password":
		return r.Password
	case "hostname":
		return r.Hostname
	case "port":
		return r.Port
	case "pathname":
		return r.Pathname
	case "search":
		return r.Search
	case "hash":
		return r.Hash
	}
	panic("bad component " + name)
}

func runWPTCase(t *testing.T, c wptCase) {
	p, err, ok := compileWPT(t, c.Pattern)
	if string(c.ExpectedObj) == `"error"` {
		if ok && err == nil {
			t.Fatalf("expected a constructor error, got pattern %+v", p)
		}
		return
	}
	if !ok {
		t.Fatalf("constructor arguments match no overload")
	}
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	if len(c.ExpectedObj) > 0 {
		var exp map[string]string
		if err := json.Unmarshal(c.ExpectedObj, &exp); err != nil {
			t.Fatal(err)
		}
		for k, want := range exp {
			if got := componentOf(p, k); got != want {
				t.Errorf("pattern.%s = %q, want %q", k, got, want)
			}
		}
	}
	for _, k := range c.ExactlyEmpty {
		if got := componentOf(p, k); got != "" {
			t.Errorf("pattern.%s = %q, want empty", k, got)
		}
	}
	if c.Inputs == nil && len(c.ExpectedMatch) == 0 {
		return
	}

	var gotTest bool
	var got *Result
	args := c.Inputs
	switch {
	case len(args) == 0:
		gotTest, got = p.TestInit(Init{}), p.ExecInit(Init{})
	case isJSONObject(args[0]) && len(args) == 1:
		in := rawInit(t, args[0])
		gotTest, got = p.TestInit(in), p.ExecInit(in)
	case isJSONString(args[0]) && len(args) <= 2:
		base := ""
		if len(args) == 2 {
			base = rawString(args[1])
		}
		gotTest, got = p.Test(rawString(args[0]), base), p.Exec(rawString(args[0]), base)
	default:
		t.Fatalf("unsupported inputs %s", args)
	}
	if gotTest != (got != nil) {
		t.Errorf("Test = %v but Exec = %v", gotTest, got)
	}
	if string(c.ExpectedMatch) == "null" {
		if got != nil {
			t.Errorf("expected no match, got %+v", got)
		}
		return
	}
	if got == nil {
		t.Fatalf("expected a match, got none")
	}
	var exp map[string]json.RawMessage
	if err := json.Unmarshal(c.ExpectedMatch, &exp); err != nil {
		t.Fatal(err)
	}
	for k, raw := range exp {
		if k == "inputs" {
			continue
		}
		var want struct {
			Input  string             `json:"input"`
			Groups map[string]*string `json:"groups"`
		}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		have := resultComponent(got, k)
		if have.Input != want.Input {
			t.Errorf("%s.input = %q, want %q", k, have.Input, want.Input)
		}
		wantGroups := map[string]string{}
		for name, v := range want.Groups {
			if v != nil {
				wantGroups[name] = *v
			}
		}
		if !reflect.DeepEqual(have.Groups, wantGroups) {
			t.Errorf("%s.groups = %v, want %v", k, have.Groups, wantGroups)
		}
	}
}

func TestWPT(t *testing.T) {
	cases := loadWPT(t)
	var pass, fail, skipped int
	var failed []string
	for i, c := range cases {
		name := fmt.Sprintf("%03d", i)
		if raw, err := json.Marshal(c.Pattern); err == nil {
			s := string(raw)
			if len(s) > 60 {
				s = s[:60]
			}
			name += "/" + strings.Map(func(r rune) rune {
				if r == ' ' || r == '/' || r == '"' {
					return '_'
				}
				return r
			}, s)
		}
		if reason, ok := wptSkip[i]; ok {
			skipped++
			t.Run(name, func(t *testing.T) { t.Skip(reason) })
			continue
		}
		ok := t.Run(name, func(t *testing.T) { runWPTCase(t, c) })
		if ok {
			pass++
		} else {
			fail++
			failed = append(failed, name)
		}
	}
	sort.Strings(failed)
	t.Logf("WPT urlpatterntestdata.json: %d cases, %d passed, %d failed, %d skipped (%.1f%% of runnable)",
		len(cases), pass, fail, skipped, 100*float64(pass)/float64(pass+fail))
}
