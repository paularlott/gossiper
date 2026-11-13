package server

import (
	"fmt"
	"net/http"
	"testing"
)

// Every change made through the admin API is live on the node that answers it by the time it answers: a request
// sent right after the answer sees the change, never the state before it, and a later change is never undone by an
// earlier one's.
func TestAdminChangesLiveOnAnswer(t *testing.T) {
	n := startNode(t, adminSettings(t, ""))
	for i := range 5 { // several rounds: a change applied after the answer shows up as a flaky status here
		a := tn{name: fmt.Sprintf("live%d", i), host: fmt.Sprintf("live%d.test", i), secret: keyA}
		path := "/api/tenants/" + a.name

		// Created: its host is served at once.
		api(t, n.base, "PUT", path, a.spec(t), http.StatusCreated)
		if got := publishWith(t, n.base, a.host, keyA); got != http.StatusOK {
			t.Fatalf("round %d: a publish right after the tenant was created: %d, want 200", i, got)
		}

		// Replaced with the same key, then rotated: the new key is accepted at once, the old one for the grace period.
		api(t, n.base, "PUT", path, a.spec(t), http.StatusOK)
		api(t, n.base, "POST", path+"/rotate", map[string]any{"publisher_key": keyB, "grace": "24h"}, http.StatusOK)
		if got := publishWith(t, n.base, a.host, keyB); got != http.StatusOK {
			t.Fatalf("round %d: a publish with the new key right after the rotation: %d, want 200", i, got)
		}
		if got := publishWith(t, n.base, a.host, keyA); got != http.StatusOK {
			t.Fatalf("round %d: a publish with the old key during its grace period: %d, want 200", i, got)
		}

		// The previous key dropped: refused at once.
		call(t, n.base, "DELETE", path+"/previous-keys", apiToken, nil)
		if got := publishWith(t, n.base, a.host, keyA); got != http.StatusUnauthorized {
			t.Fatalf("round %d: a publish with the dropped key: %d, want 401", i, got)
		}

		// Deleted: its host is no longer served.
		call(t, n.base, "DELETE", path, apiToken, nil)
		if got := publishWith(t, n.base, a.host, keyB); got != http.StatusNotFound {
			t.Fatalf("round %d: a publish right after the tenant was deleted: %d, want 404", i, got)
		}
	}
}
