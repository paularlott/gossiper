// Package build holds the version of the build, for the CLI, the server's logs and the release tooling.
package build

var (
	// Version is the current version of gossiper. The release tasks read it (scripts/getversion) to tag and name
	// the release.
	Version = "0.2.0"

	// Date is the date the binary was built, set at link time (-ldflags "-X github.com/paularlott/gossiper/build.Date=...").
	Date string
)

// FullVersion returns the version with the build date when there is one, e.g. "0.2.0 (built 20261031.120000+1100)".
func FullVersion() string {
	if Date == "" {
		return Version
	}
	return Version + " (built " + Date + ")"
}
