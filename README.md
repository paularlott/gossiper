<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo.svg" alt="gossiper" width="420">
  </picture>
</p>

# Gossiper

Gossiper is a clustered, multi-tenant [Mercure](https://datatracker.ietf.org/doc/draft-dunglas-mercure/) hub. A publisher sends an update and every subscriber listening on a matching topic receives it, whichever node of the cluster each is connected to: browsers and services alike over Server-Sent Events, as from any Mercure hub, and services can publish over one long streaming request instead of a request per update.

- **Both protocol revisions.** Mercure 1.0 (draft-08: OAuth access tokens, `match` and URL patterns), the default as with the reference hub, and with `--protocol both` draft-07 (`topic` and URI templates) side by side, so old and new clients share one hub.
- **Drop-in for Mercure clients.** The Symfony Mercure component, API Platform, FrankenPHP apps, Laravel broadcasters and a plain browser `EventSource` (those still on draft-07 with `--protocol both`).
- **Fast for services.** A streaming publish carries a service's updates over one long request, a line each, as fast as it writes them: more than ten times the rate of a POST per update. The [Go client](client) uses it when asked (`Transport: client.Stream`, or `client.Auto` to fall back to Mercure's HTTP protocol with other hubs); by default it publishes with a POST per update.
- **Multi-tenant.** Tenants with hubs and keys of their own, picked by host name, from a file or an admin API, applied live across the cluster.
- **Clustered with [gossip](https://github.com/paularlott/gossip).** Any number of identical nodes behind a load balancer: no sticky sessions, no Redis.
- **Copies on demand.** A publish can ask to be answered only once several nodes hold it, and is then idempotent by its ID.
- **One static binary,** or a Go package to embed. MIT licensed, a clean-room implementation.

## Quick start

```bash
go install github.com/paularlott/gossiper/cmd/gossiper@latest

export MERCURE_PUBLISHER_JWT_KEY=$(gossiper genkey)
gossiper serve --anonymous --tls-dir tls
```

It serves HTTPS with a self-signed certificate, kept in `tls/self-signed.crt`. Subscribe in one terminal:

```bash
curl -N --cacert tls/self-signed.crt 'https://localhost:8080/.well-known/mercure?match_urlpattern=https://example.com/books/:id'
```

Publish from another:

```bash
TOKEN=$(gossiper token --modern --publish '*')
curl -X POST --cacert tls/self-signed.crt https://localhost:8080/.well-known/mercure \
  -H "Authorization: Bearer $TOKEN" \
  -d topic=https://example.com/books/1 -d data='{"title":"Dune"}'
```

The subscriber prints:

```
id: urn:uuid:01a18db6-b5d2-7b4c-803a-a49ec7ab1196
data: {"title":"Dune"}
```

`gossiper token` mints test tokens: Mercure 1.0 access tokens with `--modern` (issuer `https://localhost`, audience `https://localhost:8080/.well-known/mercure` unless you pass `--issuer` and `--audience`), draft-07 tokens without it (for a hub run with `--protocol both`). `task run-server` starts a development node with a tenant at `localhost`, the admin API and its reference.

## Using it with Symfony, API Platform or FrankenPHP

Point the application at Gossiper instead of a bundled hub:

```dotenv
MERCURE_URL=https://gossiper:8080/.well-known/mercure
MERCURE_PUBLIC_URL=https://example.com/.well-known/mercure
MERCURE_JWT_SECRET=<the same value as MERCURE_PUBLISHER_JWT_KEY>
```

The application must trust Gossiper's certificate: its own (`--tls-cert`), or the self-signed one with `--tls-hosts gossiper` and its file as the HTTP client's `cafile`. On a private network, `--http-only` and an `http://` URL also work.

Gossiper reads FrankenPHP's environment variables: `MERCURE_PUBLISHER_JWT_KEY`, `MERCURE_SUBSCRIBER_JWT_KEY`, `MERCURE_PUBLISHER_JWT_ALG`, `MERCURE_SUBSCRIBER_JWT_ALG`, `MERCURE_TRUSTED_ISSUERS`, `MERCURE_RESOURCE_IDENTIFIER`, and from `MERCURE_EXTRA_DIRECTIVES` the directives `anonymous`, `subscriptions`, `cors_origins`, `publish_origins`, `cookie_name`, `heartbeat`, `write_timeout` and `protocol_version_compatibility` (which turns on `--protocol both`; others, such as `playground`, are logged and ignored: Gossiper has no debugging UI; `gossiper token --modern` stands in for `mercure-token --dev`).

With FrankenPHP, leave the `mercure` directive out of the Caddyfile and route `/.well-known/mercure*` and `/.well-known/oauth-protected-resource/.well-known/mercure` to Gossiper, or give Gossiper its own host name. Applications publish over HTTP (Symfony's `Hub`); `mercure_publish()` belongs to FrankenPHP's embedded hub. `symfony/mercure` 0.8 or later with protocol version 1 sends Mercure 1.0 tokens, which Gossiper accepts by default; older versions send draft-07 tokens, accepted with `--protocol both`, as FrankenPHP's hub accepts them with `protocol_version_compatibility`.

## Protocol

Both revisions of Mercure:

- **Mercure 1.0** ([draft-08](https://datatracker.ietf.org/doc/draft-dunglas-mercure/)): access tokens (`at+jwt`), `match` and `match_urlpattern` subscriptions, protected resource metadata.
- **[draft-07](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure-07)**: the `mercure` JWT claim and URI-template `topic` selectors, what many Symfony, API Platform and FrankenPHP clients still speak (with `--protocol both`).

By default Gossiper accepts Mercure 1.0 only, as the reference hub does: draft-07 tokens, `topic` parameters, the `authorization` query parameter and the `mercureAuthorization` cookie are refused. `--protocol both` accepts draft-07 too, reading each request in the revision it uses; `--protocol legacy` accepts draft-07 only. Keys are HMAC secrets, PEM public keys or JWK Set URLs (see [Configuration](#configuration)); Mercure 1.0 tokens are checked against `--resource-identifier`.

The official [conformance suite](https://mercure.rocks/docs/ecosystem/conformance-tests) passes; it covers publishing, topic matching and private updates. OAuth tokens, replay and the subscriptions API, which it does not cover, are checked by the [compatibility suite](test/compat), which runs FrankenPHP's and Symfony's clients and compares Gossiper's answers with the reference hub's, and by Gossiper's own tests.

**Where Gossiper differs from the spec:**

- No publisher can forge the hub's own events: topics under its path (`/.well-known/mercure/…`, however spelled), the topic `*` and the event type `mercure` are refused. That is draft-08's rule; Gossiper applies it to draft-07 too.
- draft-07: a token whose `mercure.publish` claim is an empty array may publish nothing (the draft lets it publish public updates). Subscription events use the draft's JSON-LD unless `--modern-subscription-format`.
- Where the spec leaves the choice: a stream opened with a Mercure 1.0 token ends when the token expires, `--cors-origins '*'` never allows credentials, and the hub is always at `/.well-known/mercure`.

**Extensions**, which Mercure clients never send: the [streaming publish](#streaming-publish-and-the-go-client) and [copies](#copies-and-idempotent-publishes).

## Streaming publish and the Go client

Mercure's HTTP protocol costs a request per publish, which caps a busy service at tens of thousands of updates a second. Gossiper also takes a streaming publish: a POST with `Content-Type: application/x-ndjson` whose body is updates, one JSON object a line, for as long as the client keeps it open, answered by a line each, in order, as they are published:

```
→ {"topic":["https://example.com/books/1"],"data":"{\"title\":\"Dune\"}","id":"urn:book:1"}
→ {"topic":["https://example.com/books/2"],"private":true,"retry":3000}
← {"id":"urn:book:1"}
← {"id":"urn:uuid:01a1…"}
```

- **Fields:** those of a form publish (`topic` an array, `data`, `id`, `type`, `private`, `retry`), and `replicas` (see [Copies and idempotent publishes](#copies-and-idempotent-publishes)).
- **Refused updates** are answered with their line and the stream goes on: `{"line":n,"status":403,"error":"insufficient_scope"}`.
- **With `--history-db`** an update is answered once it is stored; one published but not stored (the disk failed) is answered `{"id":"…","status":503,"error":"Published, not stored"}`.
- **The stream ends** when the client closes the body (a body that ends is a batch), or with a last line from the hub without `line`: `401` when the token expires, `503` when the hub closes or its store fails, `408` after two minutes without a line, `413` at an update over `--max-publish-size`. Every line before it is answered; the lines after it were not published.
- **Transport:** HTTP/2 (over TLS, or without TLS to clients that ask for it) or full-duplex HTTP/1.1 straight to the hub (otherwise `415`). A proxy must not buffer request bodies; Caddy streams them.

It is the same hub, with the same tokens, grants, topics, private updates and history. Mercure clients never send this content type, so they are unaffected.

The [Go client](client) publishes with a POST per update by default, which any Mercure hub takes, or over a stream to a gossiper hub with `Transport: client.Stream` (`client.Auto` streams to a gossiper hub and POSTs to any other), and subscribes with Server-Sent Events, with the same calls. It is a module of its own that depends on nothing beyond Go's standard library, so a service that only publishes and subscribes does not take on the hub:

```sh
go get github.com/paularlott/gossiper/client
```

```go
c, err := client.New(client.Options{URL: "https://events.example/.well-known/mercure", Token: jwt, Transport: client.Stream})
defer c.Close()

id, err := c.Publish(ctx, client.Update{Topics: []string{"https://example.com/books/1"}, Data: `{"title":"Dune"}`})
c.PublishAsync(ctx, update, func(id string, err error) { … }) // pipelined: thousands in flight on one stream

sub, err := c.Subscribe(ctx, client.Subscribe{Topics: []string{"https://example.com/books/{id}"}})
for ev := range sub.Events() {
    fmt.Println(ev.ID, ev.Data)
}
```

- **TLS:** `CAFile` trusts a hub's certificate beside the system's (a private CA, or a node's `self-signed.crt`); `InsecureSkipVerify` takes any certificate, for development only.
- **Bypassing the proxy:** a service inside the cluster can talk to a node directly, with `URL` the node's address and `Host` the host name the hub (a tenant's) is reached at: `client.Options{URL: "https://10.0.0.5:8080/.well-known/mercure", Host: "events.example", CAFile: "node.crt"}`. To a node with `--http-only`, `CleartextHTTP2` makes the publish stream and every subscription share one connection, as HTTPS does by itself.
- **Order:** over a stream a client's publishes keep their order, resends included. With a POST per update, `Publish` returns once the hub has the update, so publishes made one after another keep their order; `PublishAsync` ones are requests of their own and may not.
- **Subscriptions** reconnect by themselves and resume from their last event ID: after a lost connection, a node shutting down, or an expired token (`TokenFunc` supplies fresh ones). One the hub refuses for good (401 even with a fresh token, 403, 404) ends, and `Err` says why. An event over `MaxEventSize` (default 8 MiB; raise it with the hub's `--max-publish-size`) ends the stream rather than fill the client's memory.
- **The publish stream** reopens by itself and sends again, first and in order, what its hub did not take. A stream that cannot open is retried with a growing delay (up to 10s); HTTP/2 pings, and 30s of silence while answers are due, catch a dead connection.

## Multi-tenancy

One server, or one cluster, can host tenants that never see each other's messages. List them in a JSON file named by `--tenants-file`:

```json
{
  "tenants": [
    {
      "name": "acme",
      "hosts": ["acme.events.example"],
      "mercure": {"publisher_key": "…32 bytes or more…", "trusted_issuers": ["https://acme.example"],
                  "cors_origins": ["https://app.acme.example"]}
    },
    {
      "name": "globex",
      "hosts": ["globex.events.example", "events.globex.example"],
      "mercure": {"publisher_jwks_url": "https://login.globex.example/.well-known/jwks.json"}
    }
  ]
}
```

Each tenant has a hub of its own (keys, subscribers, history, subscriptions API) reached at its `hosts`: the request's host picks the hub, any other host gets 404, and a token of one tenant is refused on another's host. A wildcard DNS record and certificate (`*.events.example`) cover every tenant. `mercure` takes the keys and settings of a hub (`publisher_key`, `publisher_alg`, `publisher_jwks_url`, the same for `subscriber_`, `trusted_issuers`, `authorization_servers`, `resource_identifier`, `hub_url`, `anonymous`, `subscriptions`, `cors_origins`, `publish_origins`, `cookie_name`, `access_token_cookie_name`); the server's other settings (limits, history, timeouts) apply to every tenant's hub, each separately. With tenants there is no hub of the server's own, so the server's key settings and `--anonymous` are refused. Two tenants may not share a key or a host.

Every node of a cluster needs the same tenants. Updates carry their tenant across the cluster; a node that lacks a tenant drops its updates.

### Admin API

With a database (`--database`, an SQLite file) and an API token (`--api-token`, plain or a bcrypt hash), an identity provider, or both, tenants are added, changed and removed at runtime:

```bash
gossiper serve --database /data/tenants.db --api-token "$ADMIN_TOKEN" ...

curl -H "Authorization: Bearer $ADMIN_TOKEN" -X PUT https://events.example/api/tenants/acme -d '{
  "hosts": ["acme.events.example"], "mercure": {"publisher_key": "…"}}'
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://events.example/api/tenants
curl -H "Authorization: Bearer $ADMIN_TOKEN" -X DELETE https://events.example/api/tenants/acme
```

The OpenAPI document is at `/api/openapi.json` and its reference at `/api-docs/`, both built into the binary (no request leaves the page).

**Signing in with an identity provider.** Instead of (or as well as) the static token, the API takes OAuth access tokens (RFC 9068) of an identity provider: people sign in there, with its second factors, and leaving the organization ends their access.

```bash
gossiper serve --database /data/tenants.db --admin-issuer https://idp.example/o/ops \
  --admin-audience https://events.example/api   # the API as a resource in the IdP: the tokens' aud
```

A token says what it may do in authorization details (RFC 9396) of type `urn:gossiper:admin` (`--admin-detail-type`):

```json
[{"type": "urn:gossiper:admin", "actions": ["read"]},
 {"type": "urn:gossiper:admin", "actions": ["write"], "tenants": ["acme"]}]
```

`write` implies `read`; a detail without `tenants` covers every tenant. Each detail is a rule of its own, so this token reads every tenant and changes only `acme`; a tenant it may not read is left out of the list. A valid token that allows nothing is answered 403. For an identity provider without authorization details, `--admin-scope gossiper:admin` gives a token with that scope full access. The static token keeps full access, so it can stay as a break-glass credential, or be left out.

- **Every node applies a change at once.** Each node's database replicates over the cluster's gossip network; a node that was down catches up when it returns. Give every node a database. Concurrent changes to one tenant settle on the later; deletions are remembered.
- **Live.** A new tenant's hub is ready within milliseconds. Changing a tenant's keys restarts its hub (subscribers reconnect with `Last-Event-ID`); changing only its hosts keeps streams open.
- **Validation.** An invalid tenant gets 400; one that clashes with another tenant (a host, a key, a name in the tenants file, which the API shows read-only) gets 409 and changes nothing. Changes are logged.
- **Secrets are write-only.** HMAC keys are never returned, so a `PUT` carries them again. The database holds them as given: protect it like the tenants file. Failed authentications are limited to 60 per address and minute.

## Clustering

Every node is identical. Publish to any node and subscribe to any node:

```bash
gossiper serve --cluster-bind 0.0.0.0:7946 --cluster-peers node1:7946,node2:7946,node3:7946 \
  --cluster-key "$(gossiper genkey)"   # the same key on every node
```

The key encrypts and authenticates gossip; without it anyone who reaches the port could join, read every update and the tenants' keys, and inject updates, so clustering refuses to start without one (`--cluster-insecure` allows it on a trusted network). [examples/cluster](examples/cluster) runs three nodes behind Caddy with Docker Compose.

The nodes' clocks must be synchronised (NTP, chrony, or the cloud provider's time service). Event IDs and the order of the history come from a hybrid logical clock, and a node refuses an update stamped more than 5 seconds ahead of its own clock: that update is lost on that node, not sent again, and counted in `gossiper_refused_total`. The tenants' configuration resolves concurrent edits by their time: a node refuses a peer's edit stamped more than a minute ahead of its own clock (logged; it is taken once the clock catches up), and within that a node with a clock ahead wins edits it should not.

Each node sends its updates to each peer in order, one batch in flight at a time; a batch the peer does not acknowledge is sent again while the peer is in the cluster, and updates a peer cannot decode (a node of another version during an upgrade) are dropped rather than sent forever. What is queued for a peer that leaves, or more than 64 MiB for one that cannot keep up, is dropped and counted in `gossiper_replication_dropped_total`. When a peer that was dropped comes back (it restarted, or a network split healed), the two exchange what was published while they were apart.

A publish is answered once the node that took it has applied it and queued it for its peers. Mercure promises no more (subscribers "SHOULD NOT assume that no events will be lost"), and clients catch up from the history with `Last-Event-ID`. A service that needs more asks for copies.

### Copies and idempotent publishes

A publish can ask for copies, a Gossiper extension: `"replicas": n` on a stream's line, the `Gossiper-Replicas: n` header on a form POST, or `Replicas` in the [Go client](client) or `Update`. It is answered once n nodes, the one that took it included, hold the update (and have stored it, on nodes with `--history-db`):

```
→ {"topic":["https://example.com/orders/42"],"data":"…","id":"urn:order:42:v3","replicas":2}
← {"id":"urn:order:42:v3"}
```

- With fewer than n nodes in the cluster, the update is refused and not published: `{"line":1,"status":503,"error":"Too few nodes: 1 of 2"}` (503 for a form).
- When the copies are not made within 10 seconds (a peer unreachable, or unable to store), it was published but the answer says so: `{"id":"urn:order:42:v3","status":503,"error":"Published, not on enough nodes: 1 of 2 nodes"}`.
- A publish that asks for copies is idempotent by its ID: published again within 5 minutes (the last 262,144 such IDs, on a busy hub), through any node, it is answered as the first and delivered to no one again. A service that got no answer (a timeout, a node gone) publishes again with the same ID; the Go client gives an update that asks for copies an ID when it has none, and sends it again by itself, on a new stream, when a node ends its stream or the connection to it is lost (through a load balancer, to another node). Publishes that do not ask for copies keep Mercure's behaviour: an ID used again is a new update.
- Asking for copies costs only those publishes: about one round trip to the peers, shared by every update of a batch. During a network split, a side with fewer than n nodes refuses them; ask for a majority (`replicas: 3` of 5) to make sure only one side accepts them.

The order of updates is each node's own: two services publishing to one topic through two nodes may be seen interleaved differently on different nodes, though a replay from the history is ordered the same everywhere.

### History and reconnection

A subscriber that reconnects with `Last-Event-ID` gets what it missed from the node it reaches.

- **Size:** each node keeps recent updates in memory, up to `--history-size` updates and `--history-bytes`, for `--history-age` (an hour; updates age out even while nothing is published). Each tenant's hub has its own, and `--history-budget` (1 GiB) bounds them together: over it, the largest histories give up their oldest updates first.
- **A starting node** with `--cluster-peers` copies the history of a peer that is itself ready before `/readyz` reports it ready, so subscribers can resume there too. It waits up to 10s for one, or 2s when every peer is starting too (a whole cluster starting).
- **Order:** event IDs are UUIDv7 URNs from a hybrid logical clock, ordered the same on every node. An update that reaches a node late is still replayed within `--replay-window` (5s), so a resuming subscriber may see a rare duplicate but misses nothing that arrived in the window.

`--history-db /data/history.db` keeps the history in a SQLite file as well, so a node (a single one included) has it back after a restart.

- **Batched writes:** the updates published while one batch is being written and synced go in the next, so a busy node pays for one sync per batch, not per update. A publish returns once its update is on disk.
- **Size:** what the history drops is deleted from the file in the same write as the next updates, so the file stays about the size of the history. Updates older than `--history-age` are not brought back.
- **A disk that cannot keep up** (its write queue half full, or writes failing): publishes wait up to 5 seconds for it, then are refused with 503 rather than publish updates it cannot store. Updates from other nodes are still applied; those the file cannot take are counted in `gossiper_history_unwritten_total`. A publish delivered but not written within 10s is answered 503 `Published, not stored`.

## Running in production

- Set the keys (32 bytes or more for HMAC), `--hub-url` or `--resource-identifier`, and `--cluster-key` when clustering.
- Give the nodes a real certificate with `--tls-cert`/`--tls-key`, or terminate TLS in a proxy and run them with `--http-only` on the private network, with `--trust-forwarded-proto` ([TLS](#tls)).
- Bound what clients can hold: `--max-subscribers` (per node) and `--max-subscribers-per-ip`, `--max-hub-subscribers` (per tenant), `--max-publish-size`, the history settings, and with many tenants `--history-budget`.
- Behind a load balancer, set `--shutdown-delay` (a few seconds) so it sees `/readyz` fail before the listeners close.
- Keep the admin API, its reference and the metrics off the public port with `--admin-listen` (for example `127.0.0.1:9090`, or an internal address); without it they share `--listen`, and `--pprof` refuses to start. Behind a proxy, list it in `--trusted-proxies` so the limits on failed admin logins and on streams per address count each client, not the proxy. The admin API checks at most four `--api-token` bcrypt hashes at once (429 beyond).
- Synchronise the nodes' clocks (NTP or chrony): updates stamped more than 5 seconds ahead of a node's clock are refused there.
- Keep the history across restarts with `--history-db` (in the container, under `/data`).
- Scrape `--metrics` and watch `gossiper_dropped_subscribers_total`, `gossiper_replication_dropped_total`, `gossiper_refused_total` (clock skew between nodes), `gossiper_key_sets_failing`, `gossiper_history_bytes` and `gossiper_history_unwritten_total` (updates the disk could not keep up with).
- Point health checks at `/readyz`: 503 while a node copies a peer's history, and while it shuts down. The container image runs `gossiper healthcheck` and keeps state in `/data`.

### TLS

Gossiper serves HTTPS (HTTP/2 included) unless `--http-only`:

- **`--tls-cert` and `--tls-key`:** your certificate. Renewed files (certbot, cert-manager) are picked up within an hour, or at once on `SIGHUP`; a pair that does not load leaves the current one in use.
- **Otherwise, a self-signed certificate** for `localhost`, the loopback addresses, the machine's host name, the hosts of `--listen`, `--admin-listen`, `--hub-url` and `--cluster-advertise`, and any `--tls-hosts`. With `--tls-dir` it is kept there as `self-signed.crt` (the container image keeps it in `/data/tls`), made again when missing, within 30 days of expiry, or not covering a host it should. Without `--tls-dir` it is made at each start. The startup log gives its SHA-256 fingerprint.
- **Clients** trust the self-signed certificate with its file as a CA file (`curl --cacert`, the Go client's `CAFile`), or skip verification (`curl -k`, `InsecureSkipVerify`) in development. In a cluster each node has its own: give clients every node's file, or use a real certificate.
- **`--http-only`:** plain HTTP, and HTTP/2 without TLS to clients that ask for it, behind a proxy that terminates TLS.

`gossiper healthcheck` asks the server of the same settings (`--listen`, `--http-only`) on the loopback address, without checking its certificate.

### Endpoints

| Path | |
| --- | --- |
| `/.well-known/mercure` | GET (and QUERY) to subscribe over SSE, POST to publish (a form, or a stream of NDJSON) |
| `/.well-known/mercure/subscriptions[/…]` | the subscriptions API (`--subscriptions`) |
| `/.well-known/oauth-protected-resource/.well-known/mercure` | protected resource metadata (Mercure 1.0) |
| `/healthz`, `/readyz` | liveness, readiness (on the admin listener too) |
| `/metrics` | Prometheus metrics (`--metrics`) |
| `/api/…`, `/api/openapi.json`, `/api-docs/` | the admin API, its OpenAPI document and reference (`--database` and `--api-token`) |
| `/debug/pprof/` | Go profiling (`--pprof`; keep it off in production) |

With `--admin-listen` the last three are served there and not on `--listen`.

## Configuration

Every setting is a flag, a `GOSSIPER_*` environment variable or a key in `gossiper.toml`; `gossiper serve --help` lists them all.

| Flag | Default | |
| --- | --- | --- |
| `--listen` | `:8080` | address (HTTPS unless `--http-only`) |
| `--admin-listen` | on `--listen` | address of the admin API, its reference, metrics and profiling |
| `--trusted-proxies` | | proxies (addresses, CIDR ranges) whose `X-Forwarded-For` names the client; set it behind a load balancer |
| `--http-only` | off | plain HTTP, behind a proxy that terminates TLS |
| `--tls-cert`, `--tls-key` | self-signed | the certificate and key served (PEM) |
| `--tls-dir`, `--tls-hosts` | made at each start | where the self-signed certificate is kept; further names and addresses for it |
| `--protocol` | `modern` | `modern` (Mercure 1.0 only), `both`, or `legacy` (draft-07 only) |
| `--publisher-key`, `--publisher-alg`, `--publisher-jwks-url` | HS256 for a secret, the key's own for a PEM key | publishers' JWT key: an HMAC secret, a PEM public key (RSA of 2048 bits or more; never taken as an HMAC secret) or a JWK Set URL (public-key algorithms only, unless `--publisher-alg` names an HS one) |
| `--subscriber-key`, `--subscriber-alg`, `--subscriber-jwks-url` | publisher's | subscribers' JWT key |
| `--trusted-issuers` | `https://localhost` | `iss` values accepted with those keys (Mercure 1.0) |
| `--authorization-servers` | | OAuth authorization servers, keys by discovery (Mercure 1.0) |
| `--resource-identifier`, `--hub-url` | | the `aud` of Mercure 1.0 tokens; the hub's public URL. One is required with `--authorization-servers` or non-default `--trusted-issuers` |
| `--anonymous`, `--subscriptions` | off | subscribers without a token; subscription events and API |
| `--cors-origins`, `--publish-origins` | | origins allowed cross-origin; origins allowed to publish with the cookie |
| `--heartbeat`, `--write-timeout` | `30s`, `30s` | keep-alive on idle streams; a stalled write drops the subscriber |
| `--dispatch-buffer` | `1000` | updates queued per subscriber before it is dropped to catch up |
| `--max-subscribers`, `--max-subscribers-per-ip` | `100000`, `1000` | open streams on this node (503 over it), and per client address (429); 0: unbounded |
| `--max-hub-subscribers` | unbounded | open streams per hub (each tenant's) |
| `--max-topic-selectors`, `--max-pattern-selectors` | `256`, `32` | matchers per subscription request |
| `--max-publish-size` | 1 MiB | largest publish |
| `--max-connection-lifetime` | none | end every stream after this long |
| `--history-size`, `--history-bytes`, `--history-age` | `10000`, 64 MiB, `1h` | replay history per hub (`--history-age 0`: no age bound) |
| `--history-budget` | 1 GiB | the tenants' histories together |
| `--history-db` | | SQLite file to keep the history in across restarts |
| `--cluster-bind`, `--cluster-peers`, `--cluster-key` | | clustering (`--cluster-insecure` to cluster without a key) |
| `--tenants-file`, `--database`, `--api-token` | | tenants; the admin API and its static token |
| `--admin-issuer`, `--admin-audience` | | an identity provider whose access tokens the admin API takes; the API's identifier (the tokens' `aud`) |
| `--admin-detail-type`, `--admin-scope` | `urn:gossiper:admin`, none | what an IdP token may do: its authorization details of this type, or this scope for full access |
| `--allow-weak-keys`, `--allow-insecure-key-urls` | off | accept short HMAC secrets; key and discovery URLs over plain HTTP or with a certificate that does not verify (development only) |
| `--key-urls-ca-file` | | PEM certificates trusted for key and discovery URLs, as well as the system's: an identity provider with a private CA, or a self-signed certificate |
| `--shutdown-delay` | `0s` | on shutdown, report not ready (`/readyz` 503) and keep serving this long first: a few seconds behind a load balancer |
| `--metrics`, `--pprof`, `--log-level` | off, off, `info` | `--pprof` needs `--admin-listen` |

## Embedding

```go
hub, err := gossiper.New(gossiper.Config{
    PublisherKey:   auth.KeyConfig{Key: os.Getenv("MERCURE_PUBLISHER_JWT_KEY")},
    TrustedIssuers: []string{"https://app.example"},
    Anonymous:      true,
})
mux.Handle("/.well-known/mercure", hub)
mux.Handle("/.well-known/mercure/", hub)
mux.Handle("/.well-known/oauth-protected-resource/.well-known/mercure", hub)

// Publish from Go: the caller is trusted, no token needed.
id, err := hub.Publish(ctx, &gossiper.Update{Topics: []string{"https://example.com/chat"}, Data: "hello"})
```

The hub accepts Mercure 1.0 only unless `Config.Protocol` says otherwise (`gossiper.ProtocolBoth` for draft-07 clients too). See [examples/embed](examples/embed). To cluster an embedded hub, pass `cluster.New(gossipCluster, cluster.Options{})` as `Config.Transport`.

| Package | |
| --- | --- |
| [`gossiper`](.) | the hub: HTTP handlers (streaming publish included), fan-out, history, the `Transport` interface |
| [`cluster`](cluster) | fast replication over a gossip cluster |
| [`historydb`](historydb) | the history in a SQLite file, written in batches (`--history-db`) |
| [`client`](client) | Go client: streaming publish and SSE, or Mercure's HTTP protocol with other hubs |
| [`auth`](auth) | JWT verification: draft-07 tokens and RFC 9068 access tokens, static keys, JWK Sets and discovery |
| [`topic`](topic), [`urlpattern`](urlpattern) | draft-07 topic selectors; WHATWG URL Pattern matching in linear time |
| [`cmd/gossiper`](cmd/gossiper) | the server binary |

## Development

Gossiper builds with Go 1.27.3 or later, and Node.js 24 for the admin API's reference ([web/openapi/openapi.yaml](web/openapi/openapi.yaml), bundled by Redocly CLI and rendered by Redoc into the binary; `go build` alone works too, without it). Builds and releases use [Task](https://taskfile.dev); the version is in [build/version.go](build/version.go).

```bash
task build              # bin/gossiper for this machine
task run-server         # a development node on :8080
task test:race          # unit and cluster tests
task test:compat        # FrankenPHP and Symfony clients, against Gossiper and FrankenPHP's hub (Docker)
task test:failover      # real processes killed and restarted under load
task test:conformance   # Mercure's conformance suite (browsers, needs Node.js)
task apidocs-lint       # lint the OpenAPI description
task all                # zipped binaries for Linux, macOS and Windows on amd64 and arm64, in bin/
task release            # test, build, tag v<version>, push the container, create the GitHub release
```

[Mercure's conformance suite](https://mercure.rocks/docs/ecosystem/conformance-tests) is AGPL-licensed: `task test:conformance` fetches it into a temporary directory each run and drives it against the hub over HTTP, so none of it is part of this repository or the binary.

`go run ./test/bench -binary bin/gossiper` benchmarks throughput, latency and memory; results in [docs/benchmarks.md](docs/benchmarks.md).

## Licence

MIT. See [LICENSE.txt](LICENSE.txt). The URL Pattern tests use web-platform-tests data (BSD-3-Clause, [urlpattern/testdata](urlpattern/testdata)). Mercure is a protocol by Kévin Dunglas; Gossiper is an independent implementation and is not affiliated with the Mercure project.
