# Running in production

## Checklist

- **Keys:** set them (32 bytes or more for HMAC), with `--hub-url` or `--resource-identifier`, and `--cluster-key` when clustering.
- **TLS:** give the nodes a real certificate with `--tls-cert`/`--tls-key`, or terminate TLS in a proxy and run them with `--http-only` on the private network, with `--trust-forwarded-proto` ([TLS](#tls)).
- **Limits:** bound what clients can hold with `--max-subscribers` (per node), `--max-subscribers-per-ip`, `--max-hub-subscribers` (per tenant), `--max-publish-size`, the history settings, and with many tenants `--history-budget`.
- **Admin API off the public port:** serve the admin API, its reference and the metrics on `--admin-listen` (for example `127.0.0.1:9090`, or an internal address). Without it they share `--listen`, and `--pprof` refuses to start.
- **Behind a proxy or load balancer:** list it in `--trusted-proxies`, so the limits on failed admin logins and streams per address count each client rather than the proxy. Set `--shutdown-delay` (a few seconds) so it sees `/readyz` fail before the listeners close.
- **Clocks:** synchronise the nodes' clocks (NTP or chrony). Updates stamped more than 5 seconds ahead of a node's clock are refused there.
- **History across restarts:** a node that restarts in a running cluster copies it from a peer. To keep it through a restart with no peer up (a single node, or every node at once), set `--database` and `--history-persist` (in the container, under `/data`).
- **Health checks:** point them at `/readyz`. It answers 503 while a node copies a peer's history and while it shuts down.
- **Metrics:** scrape `--metrics` and watch `gossiper_dropped_subscribers_total`, `gossiper_replication_dropped_total`, `gossiper_refused_total` (clock skew between nodes), `gossiper_key_sets_failing`, `gossiper_history_bytes` and `gossiper_history_unwritten_total` (updates the disk could not keep up with).

## Container image

`paularlott/gossiper` (linux/amd64 and linux/arm64) is a distroless image running as the `nonroot` user (UID 65532).

- **State** lives in the `/data` volume, which is also the working directory (where `gossiper.toml` is looked for). Put `--database` there, e.g. `/data/gossiper.db`. Run as another UID only with a `/data` it can write.
- **TLS:** the self-signed certificate is kept in `/data/tls`. Give it a real one with `GOSSIPER_TLS_CERT` and `GOSSIPER_TLS_KEY`, or set `GOSSIPER_HTTP_ONLY=true` behind a proxy that terminates TLS.
- **Logs** are JSON (`GOSSIPER_LOG_FORMAT=console` for plain text).
- **Ports:** 8080 (the hub) and 7946 TCP and UDP (gossip) are exposed. Publish the admin port (`--admin-listen`, e.g. `:9090`) only to an internal network.
- **Health:** the image's health check runs `gossiper healthcheck`.
- **Licences:** the third-party notices are in `/licenses`.

## TLS

Gossiper serves HTTPS (HTTP/2 included) unless `--http-only`.

- **`--tls-cert` and `--tls-key`:** your certificate. Renewed files (certbot, cert-manager) are picked up within an hour, or at once on `SIGHUP`. A pair that does not load leaves the current one in use.
- **Otherwise, a self-signed certificate** covering `localhost`, the loopback addresses, the machine's host name, the hosts of `--listen`, `--admin-listen`, `--hub-url` and `--cluster-advertise`, and any `--tls-hosts`. With `--tls-dir` it is kept there as `self-signed.crt` and made again when missing, within 30 days of expiry, or not covering a host it should. Without `--tls-dir` it is made at each start. The startup log gives its SHA-256 fingerprint.
- **Clients** trust the self-signed certificate with its file as a CA file (`curl --cacert`, the Go client's `CAFile`), or skip verification (`curl -k`, `InsecureSkipVerify`) in development. In a cluster each node has its own: give clients every node's file, or use a real certificate.
- **`--http-only`:** plain HTTP, and cleartext HTTP/2 to clients that ask for it, behind a proxy that terminates TLS.

`gossiper healthcheck` asks the server with the same settings (`--listen`, `--http-only`) on the loopback address, without checking its certificate. `--url` points it elsewhere.

## Endpoints

| Path | |
| --- | --- |
| `/.well-known/mercure` | GET (and QUERY) to subscribe over SSE, POST to publish (a form, or a stream of NDJSON) |
| `/.well-known/mercure/subscriptions[/…]` | the subscriptions API (`--subscriptions`) |
| `/.well-known/oauth-protected-resource/.well-known/mercure` | protected resource metadata (Mercure 1.0) |
| `/healthz`, `/readyz` | liveness, readiness (on the admin listener too) |
| `/metrics` | Prometheus metrics (`--metrics`) |
| `/api/…`, `/api/openapi.json`, `/api-docs/` | the [admin API](multi-tenancy.md#admin-api), its OpenAPI document and reference (`--api-token`, `--admin-issuer` or both) |
| `/debug/pprof/` | Go profiling (`--pprof`; keep it off in production) |
| `/`, `/ui/status.json` | the [status page](admin-ui.md) and its JSON, with no login (admin listener only; `--admin-ui=false` turns them off) |

With `--admin-listen` the metrics, the admin API and profiling are served there and not on `--listen`.
