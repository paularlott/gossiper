package urlpattern

import (
	"strconv"
	"strings"
	"testing"
)

// serializeURL is the URL serializer (URL Standard §4.5), used by tests.
func serializeURL(u *urlRecord) string {
	var b strings.Builder
	b.WriteString(u.scheme + ":")
	if u.hasHost {
		b.WriteString("//")
		if u.includesCredentials() {
			b.WriteString(u.username)
			if u.password != "" {
				b.WriteString(":" + u.password)
			}
			b.WriteString("@")
		}
		b.WriteString(u.host)
		if u.port >= 0 {
			b.WriteString(":" + strconv.Itoa(u.port))
		}
	} else if !u.opaque && len(u.path) > 1 && u.path[0] == "" {
		b.WriteString("/.")
	}
	b.WriteString(u.pathString())
	if u.hasQuery {
		b.WriteString("?" + u.query)
	}
	if u.hasFrag {
		b.WriteString("#" + u.frag)
	}
	return b.String()
}

func TestURLParser(t *testing.T) {
	const fail = "FAIL"
	tests := []struct{ in, base, want string }{
		{"http://example.com/a/./b/../c", "", "http://example.com/a/c"},
		{"HTTP://EXAMPLE.COM:80/", "", "http://example.com/"},
		{"https://example.com:443", "", "https://example.com/"},
		{"https://example.com:8443/x", "", "https://example.com:8443/x"},
		{"http://user:pa ss@example.com/", "", "http://user:pa%20ss@example.com/"},
		{"http://us@er:p@ss@example.com/", "", "http://us%40er:p%40ss@example.com/"},
		{"http://[::1]:8080/x", "", "http://[::1]:8080/x"},
		{"http://[2001:DB8:0:0:0:0:0:1]/", "", "http://[2001:db8::1]/"},
		{"http://[::ffff:1.2.3.4]/", "", "http://[::ffff:102:304]/"},
		{"http://[::1/", "", fail},
		{"http://[1:2:3:4:5:6:7:8:9]/", "", fail},
		{"http://0x7f.1/", "", "http://127.0.0.1/"},
		{"http://192.168.0.257/", "", fail},
		{"http://1.2.3.4.5/", "", fail},
		{"http://3232235777/", "", "http://192.168.1.1/"},
		{"http://a b/", "", fail},
		{"http://ex%41mple.com/", "", "http://example.com/"},
		{"http://EXAMPLE\u3002com/", "", "http://example.com/"},
		{"http://fa\u00df.de/", "", "http://xn--fa-hia.de/"},
		{"http://b\u00fccher.example/", "", "http://xn--bcher-kva.example/"},
		{"http://%zz/", "", fail},
		{"http://a%00b/", "", fail},
		{"http:///example.com/", "", "http://example.com/"},
		{"http:example.com/x", "", "http://example.com/x"},
		{"http:\\\\example.com\\x", "", "http://example.com/x"},
		{"file:///C|/foo", "", "file:///C:/foo"},
		{"file://localhost/etc", "", "file:///etc"},
		{"file:///a/../../b", "", "file:///b"},
		{"//example.org/x", "https://a/b", "https://example.org/x"},
		{"?q", "https://a/b?c#d", "https://a/b?q"},
		{"#f", "https://a/b?c#d", "https://a/b?c#f"},
		{"../x", "https://a/b/c/d", "https://a/b/x"},
		{"x", "https://a/b/c", "https://a/b/x"},
		{"/x", "https://a/b/c", "https://a/x"},
		{"", "https://a/b?c#d", "https://a/b?c"},
		{"x", "", fail},
		{"javascript:alert(1)", "", "javascript:alert(1)"},
		{"data:text/plain,hi there", "", "data:text/plain,hi there"},
		{"data:text/plain,hi \t\nthere ?x", "", "data:text/plain,hi there%20?x"},
		{"#frag", "data:x", "data:x#frag"},
		{"x", "data:x", fail},
		{"web+demo:/.//not-a-host/", "", "web+demo:/.//not-a-host/"},
		{"foo://bar/baz?q#f", "", "foo://bar/baz?q#f"},
		{"foo://ba z/", "", fail},
		{"  http://example.com/  ", "", "http://example.com/"},
		{"http://example.com/a b?c d#e f", "", "http://example.com/a%20b?c%20d#e%20f"},
		{"http://example.com/?a='b'", "", "http://example.com/?a=%27b%27"},
		{"foo://example.com/?a='b'", "", "foo://example.com/?a='b'"},
		{"http://example.com/\u00e9?\u00e9#\u00e9", "", "http://example.com/%C3%A9?%C3%A9#%C3%A9"},
		{"http://example.com/%2e/%2E%2e/x", "", "http://example.com/x"},
		{"http://example.com:99999/", "", fail},
		{"http://example.com:/", "", "http://example.com/"},
		{"http://example.com:80x/", "", fail},
		{"http://:80/", "", fail},
		{"http://@/", "", fail},
		{"1http://x/", "", fail},
		{"ht tp://x/", "", fail},
		{"https://example.com\\@evil.com/", "", "https://example.com/@evil.com/"},
		{"c:\\x", "", "c:\\x"},
		{"file:c:/x", "", "file:///c:/x"},
		{"/d:/x", "file:///c:/a/b", "file:///d:/x"},
		{"/x", "file:///c:/a/b", "file:///c:/x"},
		{"../../..", "file:///c:/a/b", "file:///c:/"},
		{"x", "file:///a/b", "file:///a/x"},
		{"?q", "file:///a/b", "file:///a/b?q"},
		{"#f", "file:///a/b", "file:///a/b#f"},
		{"//host/x", "file:///a", "file://host/x"},
		{"file://C|/x", "", "file:///C:/x"},
		{"file:", "", "file:///"},
		{"file://a b/", "", fail},
		{"//x", "http://a/b", "http://x/"},
		{"\\\\x\\y", "http://a/b", "http://x/y"},
		{"/\\x/y", "http://a/b", "http://x/y"},
		{"http:/x", "http://a/b", "http://a/x"},
		{"http:x", "http://a/b/c", "http://a/b/x"},
		{"//a:b@c/", "http://x/", "http://a:b@c/"},
		{"http://0300.0250.0.1/", "", "http://192.168.0.1/"},
		{"http://0x7f000001/", "", "http://127.0.0.1/"},
		{"http://1.2.3.0x/", "", "http://1.2.3.0/"},
		{"http://256.1.1.1/", "", fail},
		{"http://1.2.3.4./", "", "http://1.2.3.4/"},
		{"http://09/", "", fail},
		{"foo://host:8080/x", "", "foo://host:8080/x"},
		{"foo://HOST/", "", "foo://HOST/"},
		{"foo://h%41/", "", "foo://h%41/"},
		{"foo://a|b/", "", fail},
		{"foo:///x", "", "foo:///x"},
		{"foo:/x/../y", "", "foo:/y"},
		{"foo:/..//x", "", "foo:/.//x"},
		{"http://a:0/", "", "http://a:0/"},
		{"http://a./", "", "http://a./"},
		{"http://ex ample/", "", fail},
		{"http://%41%/", "", fail},
		{"HtTp://A/B", "", "http://a/B"},
		{"a+b-c.d://x", "", "a+b-c.d://x"},
		{"mailto:a@b.c", "", "mailto:a@b.c"},
		{"?a#b", "mailto:x", fail},
		{"ws://a:80/", "", "ws://a/"},
		{"ftp://a:21/", "", "ftp://a/"},
		{"wss://a:443/", "", "wss://a/"},
		{"http://a/b?c#d#e", "", "http://a/b?c#d#e"},
		{"http://a/x\x00y", "", "http://a/x%00y"},
	}
	for _, tc := range tests {
		var base *urlRecord
		if tc.base != "" {
			var ok bool
			if base, ok = parseURL(tc.base, nil); !ok {
				t.Fatalf("bad base %q", tc.base)
			}
		}
		u, ok := parseURL(tc.in, base)
		got := fail
		if ok {
			got = serializeURL(u)
		}
		if got != tc.want {
			t.Errorf("parse(%q, base %q) = %q, want %q", tc.in, tc.base, got, tc.want)
		}
	}
}

func TestParseDoesNotMutateBase(t *testing.T) {
	base, _ := parseURL("https://a/b/c/d", nil)
	before := serializeURL(base)
	for _, in := range []string{"../x", "../../../../y", "z", "?q", "#f", "/p"} {
		parseURL(in, base)
	}
	if after := serializeURL(base); after != before {
		t.Errorf("base mutated: %q -> %q", before, after)
	}
}

func TestIPv6Serialization(t *testing.T) {
	tests := map[string]string{
		"::":                   "::",
		"::1":                  "::1",
		"1::":                  "1::",
		"1:0:0:2:0:0:0:3":      "1:0:0:2::3",
		"1:2:3:4:5:6:7:8":      "1:2:3:4:5:6:7:8",
		"0:0:1:0:0:0:0:0":      "0:0:1::",
		"2001:db8:0:0:1:0:0:1": "2001:db8::1:0:0:1",
		"1:0:2:0:3:0:4:0":      "1:0:2:0:3:0:4:0",
		"::ffff:192.168.0.1":   "::ffff:c0a8:1",
		"0000:0000:0000:0000:0000:0000:0000:0001": "::1",
	}
	for in, want := range tests {
		a, ok := parseIPv6(in)
		if !ok {
			t.Errorf("parseIPv6(%q) failed", in)
			continue
		}
		if got := serializeIPv6(a); got != want {
			t.Errorf("serializeIPv6(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", ":", ":1", "1:", "1::2::3", "1:2:3:4:5:6:7", "12345::", "::g", "1.2.3.4", "::1.2.3", "::1.2.3.256", "::01.2.3.4", "1:2:3:4:5:6:7:8:9", "::1:2:3:4:5:6:7:8"} {
		if _, ok := parseIPv6(bad); ok {
			t.Errorf("parseIPv6(%q) succeeded", bad)
		}
	}
}

func TestCanonicalizers(t *testing.T) {
	type fn func(string) (string, error)
	tests := []struct {
		name  string
		f     fn
		in    string
		want  string
		isErr bool
	}{
		{"protocol", canonProtocol, "HTTP", "http", false},
		{"protocol bad", canonProtocol, "ht tp", "", true},
		{"protocol digit", canonProtocol, "1abc", "", true},
		{"username", canonUsername, "us er:@", "us%20er%3A%40", false},
		{"hostname", canonHostname, "EXAMPLE.com", "example.com", false},
		{"hostname path cut", canonHostname, "example.com/x", "example.com", false},
		{"hostname colon", canonHostname, "a:80", "", true},
		{"hostname ipv4", canonHostname, "0x7f.1", "127.0.0.1", false},
		{"hostname space", canonHostname, "a b", "", true},
		{"ipv6", canonIPv6Hostname, "[::AB]", "[::ab]", false},
		{"ipv6 bad", canonIPv6Hostname, "[::xy]", "", true},
		{"port", canonPort, "8080", "8080", false},
		{"port 80 kept without protocol", canonPort, "80", "80", false},
		{"port too big", canonPort, "65536", "", true},
		{"port not number", canonPort, "abc", "", true},
		{"pathname", canonPathname, "/a/./b/../c", "/a/c", false},
		{"pathname relative piece", canonPathname, "a b", "a%20b", false},
		{"pathname dots piece", canonPathname, "..", "..", false},
		{"pathname question", canonPathname, "?", "%3F", false},
		{"pathname hash", canonPathname, "#", "%23", false},
		{"opaque pathname", canonOpaquePathname, "a b\u00e9", "a b%C3%A9", false},
		{"search", canonSearch, "a b'c#d", "a%20b%27c%23d", false},
		{"hash", canonHash, "a b`c#d", "a%20b%60c#d", false},
	}
	for _, tc := range tests {
		got, err := tc.f(tc.in)
		if (err != nil) != tc.isErr || got != tc.want {
			t.Errorf("%s(%q) = %q, %v; want %q (err=%v)", tc.name, tc.in, got, err, tc.want, tc.isErr)
		}
	}
	p := "http"
	if got, err := canonPortFor("80", &p); err != nil || got != "" {
		t.Errorf("canonPortFor(80, http) = %q, %v", got, err)
	}
}
