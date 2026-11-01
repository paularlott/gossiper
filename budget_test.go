package gossiper

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossiper/auth"
)

// The tenants' histories together stay within the budget, and the largest gives up its oldest updates first: a quiet
// tenant keeps its history while a busy one fills the budget.
func TestHistoryBudget(t *testing.T) {
	cfg := func(secret string) Config {
		return Config{PublisherKey: auth.KeyConfig{Key: secret, Algorithm: "HS256"}, HistoryBytes: 1 << 30}
	}
	ts, err := NewTenants([]Tenant{
		{Name: "busy", Hosts: []string{"busy.test"}, Config: cfg("busy-secret-busy-secret-busy-secret!")},
		{Name: "quiet", Hosts: []string{"quiet.test"}, Config: cfg("quiet-secret-quiet-secret-quiet-sec!")},
	}, nil, HistoryBudget(256<<10))
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close(context.Background())
	clock := hlc.NewClock()
	data := strings.Repeat("x", 1000)
	apply := func(tenant string, i int) {
		ts.Apply(&Update{Tenant: tenant, ID: fmt.Sprintf("%s-%d", tenant, i), Topics: []string{"https://t.test/a"}, Data: data,
			Origin: "peer", Stamp: uint64(clock.Now())})
	}
	for i := range 20 {
		apply("quiet", i)
	}
	for i := range 500 {
		apply("busy", i)
	}
	hub := func(name string) *Hub { return ts.set.Load().hubs[name] }
	deadline := time.Now().Add(5 * time.Second)
	for ts.budget.used.Load() > 256<<10 {
		if time.Now().After(deadline) {
			t.Fatalf("budget not kept: %d bytes held", ts.budget.used.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := hub("quiet").hist.len(); n != 20 {
		t.Errorf("the quiet tenant holds %d updates, want its 20", n)
	}
	busy := hub("busy").hist
	if n := busy.len(); n == 0 || n >= 500 {
		t.Errorf("the busy tenant holds %d updates", n)
	}
	if !busy.held("busy-499") || busy.held("busy-0") {
		t.Error("the busy tenant did not keep its newest updates")
	}
	if got, want := ts.Stats().HistoryBytes, ts.budget.used.Load(); got != want {
		t.Errorf("stats say %d bytes, the budget %d", got, want)
	}

	// A tenant removed gives its share back.
	if err := ts.Remove(context.Background(), "busy"); err != nil {
		t.Fatal(err)
	}
	if got, want := ts.budget.used.Load(), hub("quiet").hist.size(); got != want {
		t.Errorf("after removing a tenant the budget counts %d bytes, the remaining history holds %d", got, want)
	}
}

// Histories of the same size are brought down together: a tie does not stop the budget from being kept.
func TestHistoryBudgetTie(t *testing.T) {
	cfg := func(secret string) Config {
		return Config{PublisherKey: auth.KeyConfig{Key: secret, Algorithm: "HS256"}, HistoryBytes: 1 << 30}
	}
	ts, err := NewTenants([]Tenant{
		{Name: "a", Hosts: []string{"a.test"}, Config: cfg("aaaa-secret-aaaa-secret-aaaa-secret!")},
		{Name: "b", Hosts: []string{"b.test"}, Config: cfg("bbbb-secret-bbbb-secret-bbbb-secret!")},
		{Name: "c", Hosts: []string{"c.test"}, Config: cfg("cccc-secret-cccc-secret-cccc-secret!")},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close(context.Background())
	clock := hlc.NewClock()
	for _, name := range []string{"a", "b", "c"} {
		for i := range 30 {
			ts.Apply(&Update{Tenant: name, ID: fmt.Sprint(name, i), Topics: []string{"https://t.test/a"}, Data: strings.Repeat("x", 1000),
				Origin: "peer", Stamp: uint64(clock.Now())})
		}
	}
	hubs := ts.set.Load().hubs
	var total int64
	for _, h := range hubs {
		total += h.hist.size()
	}
	limit := total / 2
	if freed := shedTo(hubs, total-limit); freed < total-limit {
		t.Fatalf("freed %d bytes of three equal histories, want %d", freed, total-limit)
	}
	for name, h := range hubs {
		if n := h.hist.len(); n < 10 || n > 20 {
			t.Errorf("tenant %s holds %d of its 30 updates; the three should share the budget", name, n)
		}
	}
}

// The tenants' histories are copied in stamp order without gaps, however the pages of the hubs interleave.
func TestTenantsHistoryPages(t *testing.T) {
	cfg := func(secret string) Config {
		return Config{PublisherKey: auth.KeyConfig{Key: secret, Algorithm: "HS256"}, HistoryBytes: 1 << 30}
	}
	ts, err := NewTenants([]Tenant{
		{Name: "a", Hosts: []string{"a.test"}, Config: cfg("aaaa-secret-aaaa-secret-aaaa-secret!")},
		{Name: "b", Hosts: []string{"b.test"}, Config: cfg("bbbb-secret-bbbb-secret-bbbb-secret!")},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close(context.Background())
	clock := hlc.NewClock()
	var want []string
	apply := func(name string, size int) {
		id := fmt.Sprint(name, len(want))
		want = append(want, id)
		ts.Apply(&Update{Tenant: name, ID: id, Topics: []string{"https://t.test/a"}, Data: strings.Repeat("x", size),
			Origin: "peer", Stamp: uint64(clock.Now())})
	}
	for range 10 { // many large updates of a, then a small one of b after them all
		apply("a", 3000)
	}
	apply("b", 10)
	var got []string
	var stamp uint64
	origin := ""
	for {
		ups, more := ts.History(stamp, origin, 10000)
		for _, u := range ups {
			got = append(got, u.ID)
		}
		if !more || len(ups) == 0 {
			break
		}
		stamp, origin = ups[len(ups)-1].Stamp, ups[len(ups)-1].Origin
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("copied %v, want %v", got, want)
	}
}
