package configstore_test

import (
	"path/filepath"
	"testing"

	"github.com/paularlott/gossiper/internal/configstore"
)

// StoredNodeID makes a node id once and gives it back every time; a store opened on the file writes under it.
func TestStoredNodeID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes", "a.db")
	first, err := configstore.StoredNodeID(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 36 {
		t.Fatalf("node id %q: want a UUID", first)
	}
	again, err := configstore.StoredNodeID(path)
	if err != nil || again != first {
		t.Fatalf("second read: %q %v, want %q", again, err, first)
	}
	s, err := configstore.Open(configstore.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if s.NodeID() != first {
		t.Errorf("the store writes as %q, the database holds %q", s.NodeID(), first)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := configstore.StoredNodeID(filepath.Join(t.TempDir(), "b.db"))
	if err != nil || other == first {
		t.Fatalf("another database: %q %v, want a different id", other, err)
	}
}
