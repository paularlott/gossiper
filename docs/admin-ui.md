# Status page

With `--admin-listen` set, the admin listener serves a read-only status page at `/`: readiness, the cluster's nodes, the tenant count, the hub's counters with rates, the version and the uptime. It polls `/ui/status.json` every 3 seconds.

Neither needs a login, so anyone who reaches the admin listener can see them. They show aggregates only: no tenant names or hosts, keys or tokens, topics, client or node addresses, or settings. Keep the admin listener on an internal network, as for `/metrics`.

| | |
| --- | --- |
| `--admin-ui` | on; `--admin-ui=false` (`GOSSIPER_ADMIN_UI=false`, `admin_ui = false`) turns the page and its JSON off |
| Without `--admin-listen` | not served: the admin routes then share the public listener |
| Theme | dark by default, whatever the OS prefers; the toggle is kept in the browser's local storage |
| Offline | everything is built into the binary (Tailwind CSS, Alpine.js); the page loads nothing from elsewhere |

A build without the web assets (`go install`, see the [README](../README.md#development)) answers 404 at `/` with a short message; `/ui/status.json` still works.

## `/ui/status.json`

| Field | |
| --- | --- |
| `version`, `build_date` | the build (`build_date` only when set at link time) |
| `now`, `started`, `uptime_seconds` | the server's clock, the process start, the uptime |
| `node` | this node's id |
| `readiness` | `ready`, `draining` or `syncing`, as `/readyz` answers |
| `mode` | `cluster` or `single` |
| `node_count`, `nodes_alive` | the nodes known (this one included, in any state) and those alive |
| `nodes[]` | `id`, `state` (`alive`, `suspect`, `leaving`, `dead`), `since` (when this node last learnt that state), `local` |
| `multi_tenant`, `tenants` | tenants rather than a single hub; `total`, `file`, `database`, counted as `GET /api/status` counts them |
| `hub` | every hub's counters together, as `/metrics`: `subscribers`, `published`, `applied`, `delivered`, `dropped`, `replayed`, `replay_misses`, `duplicates`, `publish_rejected`, `refused`, `key_sets_failing`, `history_updates`, `history_bytes` |
| `store` | the tenant database, with the admin API: `records`, `tombstones`, `peers`, `peers_synced`, `last_sync`, `syncs`, `repairs`, `sync_errors`, `pushes`, `push_errors`, `received` |
| `replication_dropped` | updates not sent to a peer (cluster) |
| `history_unwritten` | updates not written to the history database (`--history-persist`) |

Counters are totals since the process started; the page turns them into rates between two polls.
