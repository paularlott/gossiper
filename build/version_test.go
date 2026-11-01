package build

import "testing"

func TestFullVersion(t *testing.T) {
	saved := Date
	defer func() { Date = saved }()
	Date = ""
	if got := FullVersion(); got != Version {
		t.Fatalf("FullVersion() = %q, want %q", got, Version)
	}
	Date = "20261031.120000+1100"
	if got, want := FullVersion(), Version+" (built 20261031.120000+1100)"; got != want {
		t.Fatalf("FullVersion() = %q, want %q", got, want)
	}
}
