package gossiper

// Removing a tenant (Tenants.Remove) leaves nothing of it behind.

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossiper/auth"
)

// memStore is a HistoryStore in memory, by tenant: Drop deletes what it holds of the tenant.
type memStore struct {
	mu   sync.Mutex
	next uint64
	rows map[string][]*Update
}

func (m *memStore) Load(tenant string, fn func(*Update)) error {
	m.mu.Lock()
	rows := append([]*Update(nil), m.rows[tenant]...)
	m.mu.Unlock()
	for _, u := range rows {
		c := *u
		c.encoded = nil
		fn(&c)
	}
	return nil
}
func (m *memStore) Save(u *Update) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string][]*Update{}
	}
	m.rows[u.Tenant] = append(m.rows[u.Tenant], u)
	m.next++
	return m.next
}
func (m *memStore) Ready(context.Context) error        { return nil }
func (m *memStore) Wait(context.Context, uint64) error { return nil }
func (m *memStore) Trim(string, uint64, string)        {}
func (m *memStore) count(tenant string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows[tenant])
}
func (m *memStore) Drop(_ context.Context, t string) error {
	m.mu.Lock()
	delete(m.rows, t)
	m.mu.Unlock()
	return nil
}

// A peer's update in flight during Remove may reach the removed hub after it closed and its stored history was
// dropped: a closed hub neither applies nor stores it, so a tenant created again under the name does not load it.
func TestClosedHubDoesNotSaveAfterRemove(t *testing.T) {
	st := &memStore{}
	cfg := Config{PublisherKey: auth.KeyConfig{Key: testSecret}, HistoryStore: st}
	ts, err := NewTenants([]Tenant{{Name: "acme", Hosts: []string{"acme.test"}, Config: cfg}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close(context.Background())
	stale := ts.Hub("acme") // what an Apply in flight holds
	if err := ts.Remove(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	stale.Apply(&Update{ID: "urn:late", Topics: []string{"https://example.com/t"}, Stamp: uint64(stale.clock.Now()),
		Origin: "peer", Tenant: "acme"})
	if n := st.count("acme"); n != 0 {
		t.Errorf("the removed tenant has %d stored updates after Remove returned", n)
	}
	if err := ts.Set(Tenant{Name: "acme", Hosts: []string{"acme.test"}, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	if n := ts.Hub("acme").Stats().HistoryLen; n != 0 {
		t.Errorf("the re-created tenant starts with %d updates of the removed one", n)
	}
}

// Adding and removing tenants leaves no goroutine behind (hub housekeeping, verifiers, budget accounting).
func TestRemoveLeavesNoGoroutines(t *testing.T) {
	ts, err := NewTenants(nil, nil, HistoryBudget(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close(context.Background())
	cfg := Config{PublisherKey: auth.KeyConfig{Key: testSecret}, Subscriptions: true}
	cycle := func() {
		if err := ts.Set(Tenant{Name: "churn", Hosts: []string{"churn.test"}, Config: cfg}); err != nil {
			t.Fatal(err)
		}
		h := ts.Hub("churn")
		h.Apply(&Update{ID: "urn:x", Topics: []string{"https://example.com/t"}, Data: "x", Stamp: uint64(h.clock.Now()),
			Origin: "peer", Tenant: "churn"})
		if err := ts.Remove(context.Background(), "churn"); err != nil {
			t.Fatal(err)
		}
	}
	cycle()
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()
	for range 50 {
		cycle()
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Errorf("goroutines: %d after 50 add/remove cycles, %d before", n, base)
	}
	if used := ts.budget.used.Load(); used != 0 {
		t.Errorf("history budget still counts %d bytes of removed tenants", used)
	}
}
