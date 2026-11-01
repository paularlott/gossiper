package cluster_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain fails the run when a goroutine of a hub, of gossip or of an HTTP connection outlives every test.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		deadline := time.Now().Add(15 * time.Second)
		for {
			leaked := leakedGoroutines()
			if len(leaked) == 0 {
				break
			}
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr, "FAIL: %d goroutines left running after all tests:\n\n%s\n", len(leaked), strings.Join(leaked, "\n\n"))
				code = 1
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	os.Exit(code)
}
