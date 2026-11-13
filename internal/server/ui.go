package server

import (
	"io/fs"
	"net/http"
	"slices"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossiper"
	"github.com/paularlott/gossiper/build"
	webassets "github.com/paularlott/gossiper/web"
)

// The status page: a read-only dashboard at / on the admin listener (admin-listen), with no login, and the JSON it
// polls at /ui/status.json. Anyone who reaches the admin listener sees them, so they show aggregates only: no tenant
// names or hosts, keys, tokens, topics, client or node addresses, nor any setting.

// started is when the process started, for the uptime.
var started = time.Now()

// uiCSP lets the page run its own built script and stylesheet only, and fetch only from this server. Alpine's CSP
// build evaluates the page's expressions without eval.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// uiRoutes registers the status page and its JSON on the admin listener's mux.
func (s *Server) uiRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", uiPage)
	mux.HandleFunc("GET /ui/assets/{file}", apiDocsAsset) // the same build output (dist/assets), gzipped
	mux.HandleFunc("GET /ui/status.json", s.uiStatus)
}

// uiPage serves the status page (web/ui/index.html, built into dist by Vite). Before a web build it answers a plain
// message: the JSON is still served.
func uiPage(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	b, err := fs.ReadFile(webassets.Dist, "dist/ui/index.html")
	if err != nil {
		http.Error(w, "The status page was not built into this binary (task webassets). Its data is at /ui/status.json.",
			http.StatusNotFound)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache") // it names the current hashed assets
	h.Set("Content-Security-Policy", uiCSP)
	h.Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(b)
}

// readiness is what /readyz answers: draining (shutting down), syncing (catching up with the cluster) or ready.
func (s *Server) readiness() string {
	switch {
	case s.draining.Load():
		return "draining"
	case s.repl != nil && !s.repl.Ready():
		return "syncing"
	}
	return "ready"
}

// uiStatusJSON is the body of /ui/status.json. Every field is safe for anyone on the admin network: counts, states,
// the version and node ids. TestUIStatusLeaksNothing checks what it must never carry.
type uiStatusJSON struct {
	Version       string       `json:"version"`
	BuildDate     string       `json:"build_date,omitempty"`
	Now           string       `json:"now"`     // the server's clock, for rates between polls
	Started       string       `json:"started"` // when the process started
	UptimeSeconds int64        `json:"uptime_seconds"`
	Node          string       `json:"node,omitempty"` // this node's id
	Readiness     string       `json:"readiness"`      // ready, draining or syncing, as /readyz answers
	Mode          string       `json:"mode"`           // cluster or single
	NodeCount     int          `json:"node_count"`     // the nodes known: this one and its peers, in any state
	NodesAlive    int          `json:"nodes_alive"`
	Nodes         []uiNodeJSON `json:"nodes"`
	MultiTenant   bool         `json:"multi_tenant"` // tenants (file or database) rather than a single hub
	Tenants       uiTenants    `json:"tenants"`
	Hub           uiHubJSON    `json:"hub"`
	Store         *uiStoreJSON `json:"store,omitempty"` // the tenant database, with the admin API
	// ReplicationDropped is the updates not sent to a peer (cluster mode).
	ReplicationDropped *uint64 `json:"replication_dropped,omitempty"`
	// HistoryUnwritten is the updates not written to the history database (history-persist).
	HistoryUnwritten *uint64 `json:"history_unwritten,omitempty"`
}

// uiNodeJSON is a node of the cluster as this node sees it: its id and state, never its address.
type uiNodeJSON struct {
	ID    string `json:"id"`
	State string `json:"state"`           // alive, suspect, leaving or dead
	Since string `json:"since,omitempty"` // when this node last learnt the state
	Local bool   `json:"local,omitempty"`
}

type uiTenants struct {
	Total    int `json:"total"`
	File     int `json:"file"`
	Database int `json:"database"`
}

// uiHubJSON is gossiper.StatsSnapshot: every hub's together, as /metrics shows them.
type uiHubJSON struct {
	Subscribers     uint64 `json:"subscribers"`
	Published       uint64 `json:"published"`
	Applied         uint64 `json:"applied"`
	Delivered       uint64 `json:"delivered"`
	Dropped         uint64 `json:"dropped"`
	Replayed        uint64 `json:"replayed"`
	ReplayMisses    uint64 `json:"replay_misses"`
	Duplicates      uint64 `json:"duplicates"`
	PublishRejected uint64 `json:"publish_rejected"`
	Refused         uint64 `json:"refused"`
	KeySetsFailing  uint64 `json:"key_sets_failing"`
	HistoryUpdates  int    `json:"history_updates"`
	HistoryBytes    int64  `json:"history_bytes"`
}

// uiStoreJSON is the replicated tenant database's state (configstore.Stats).
type uiStoreJSON struct {
	Records     int    `json:"records"`
	Tombstones  int    `json:"tombstones"`
	Peers       int    `json:"peers"`
	PeersSynced int    `json:"peers_synced"`
	LastSync    string `json:"last_sync,omitempty"`
	Syncs       uint64 `json:"syncs"`
	Repairs     uint64 `json:"repairs"`
	SyncErrors  uint64 `json:"sync_errors"`
	Pushes      uint64 `json:"pushes"`
	PushErrors  uint64 `json:"push_errors"`
	Received    uint64 `json:"received"`
}

// hubStats is every hub's counters together, as /metrics reports them.
func (s *Server) hubStats() gossiper.StatsSnapshot {
	if s.Tenants != nil {
		return s.Tenants.Stats()
	}
	return s.Hub.Stats()
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// uiStatus serves /ui/status.json.
func (s *Server) uiStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.overview())
}

// overview gathers the status page's data.
func (s *Server) overview() uiStatusJSON {
	now := time.Now()
	out := uiStatusJSON{
		Version: build.Version, BuildDate: build.Date, Now: rfc3339(now), Started: rfc3339(started),
		UptimeSeconds: int64(now.Sub(started).Seconds()), Readiness: s.readiness(), Mode: "single",
		Nodes: []uiNodeJSON{}, MultiTenant: s.Tenants != nil,
	}
	switch {
	case s.gossip != nil:
		out.Node = s.gossip.LocalNode().ID.String()
	case s.Hub != nil:
		out.Node = s.Hub.NodeID()
	case s.store != nil:
		out.Node = s.store.NodeID()
	}
	if s.gossip != nil {
		out.Mode = "cluster"
		out.Nodes = clusterNodeList(s.gossip)
		for _, n := range out.Nodes {
			if n.State == "alive" {
				out.NodesAlive++
			}
		}
		d := s.repl.Dropped()
		out.ReplicationDropped = &d
	} else {
		out.Nodes = append(out.Nodes, uiNodeJSON{ID: out.Node, State: "alive", Since: out.Started, Local: true})
		out.NodesAlive = 1
	}
	out.NodeCount = len(out.Nodes)

	if s.store != nil { // as GET /api/status counts them
		for _, t := range (&adminAPI{s: s}).tenants() {
			if t.Source == "file" {
				out.Tenants.File++
			} else {
				out.Tenants.Database++
			}
		}
	} else {
		out.Tenants.File = len(s.tenants)
	}
	out.Tenants.Total = out.Tenants.File + out.Tenants.Database

	st := s.hubStats()
	out.Hub = uiHubJSON{Subscribers: st.Subscribers, Published: st.Published, Applied: st.Applied, Delivered: st.Delivered,
		Dropped: st.Dropped, Replayed: st.Replayed, ReplayMisses: st.ReplayMisses, Duplicates: st.Duplicates,
		PublishRejected: st.PublishRejected, Refused: st.Refused, KeySetsFailing: st.KeySetsFailing,
		HistoryUpdates: st.HistoryLen, HistoryBytes: st.HistoryBytes}

	if s.store != nil {
		ds := s.store.Stats()
		out.Store = &uiStoreJSON{Records: ds.Records, Tombstones: ds.Tombstones, Peers: ds.Peers, PeersSynced: ds.PeersSynced,
			Syncs: ds.Syncs, Repairs: ds.Repairs, SyncErrors: ds.SyncErrors, Pushes: ds.Pushes, PushErrors: ds.PushErrors,
			Received: ds.Received}
		if !ds.LastSync.IsZero() {
			out.Store.LastSync = rfc3339(ds.LastSync)
		}
	}
	if s.histDB != nil {
		u := s.histDB.Unwritten()
		out.HistoryUnwritten = &u
	}
	return out
}

// clusterNodeList returns every node the gossip cluster knows (this one included), by id: ids and states only, never
// addresses. The gossip library does not expose when a node was last heard from; since is when its state was last
// set.
func clusterNodeList(c *gossip.Cluster) []uiNodeJSON {
	local := c.LocalNode().ID
	var out []uiNodeJSON
	for _, n := range c.Nodes() {
		state, at := n.GetStateSnapshot()
		v := uiNodeJSON{ID: n.ID.String(), State: nodeState(state), Local: n.ID == local}
		if t := at.Time(); !t.IsZero() && t.Unix() > 0 {
			v.Since = rfc3339(t)
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b uiNodeJSON) int {
		switch {
		case a.Local != b.Local:
			if a.Local {
				return -1
			}
			return 1
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	return out
}

func nodeState(s gossip.NodeState) string {
	switch s {
	case gossip.NodeAlive:
		return "alive"
	case gossip.NodeSuspect:
		return "suspect"
	case gossip.NodeLeaving:
		return "leaving"
	case gossip.NodeDead:
		return "dead"
	}
	return "unknown"
}
