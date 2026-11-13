# Configuration

Every setting is a flag, a `GOSSIPER_*` environment variable, or a key in a TOML file. The variable is the flag in capitals with dashes as underscores (`--max-publish-size` → `GOSSIPER_MAX_PUBLISH_SIZE`); the TOML key is the flag with underscores (`max_publish_size = 2097152`). `gossiper serve --help` lists them all.

The TOML file is `-c`/`--config` (`GOSSIPER_CONFIG`), or else `gossiper.toml` in the current directory, `~/.config/gossiper/` or `/etc/gossiper/`. FrankenPHP's `MERCURE_*` variables are read too ([protocol](protocol.md#symfony-api-platform-and-frankenphp)).

## Listening and TLS

| Flag | Default | |
| --- | --- | --- |
| `--listen` | `:8080` | address (HTTPS unless `--http-only`) |
| `--admin-listen` | on `--listen` | address of the admin API, its reference, metrics and profiling |
| `--trusted-proxies` | | proxies (addresses, CIDR ranges) whose `X-Forwarded-For` names the client; set it behind a load balancer |
| `--trust-forwarded-proto` | off | take the client's scheme from `X-Forwarded-Proto` (behind a proxy that terminates TLS) |
| `--http-only` | off | plain HTTP, behind a proxy that terminates TLS |
| `--tls-cert`, `--tls-key` | self-signed | the certificate and key served (PEM) |
| `--tls-dir`, `--tls-hosts` | made at each start | where the self-signed certificate is kept; further names and addresses for it |

## Protocol and keys

| Flag | Default | |
| --- | --- | --- |
| `--protocol` | `modern` | `modern` (Mercure 1.0 only), `both`, or `legacy` (draft-07 only) |
| `--publisher-key`, `--publisher-alg`, `--publisher-jwks-url` | HS256 for a secret, the key's own for a PEM key | publishers' JWT key: an HMAC secret, a PEM public key (RSA of 2048 bits or more; never taken as an HMAC secret) or a JWK Set URL (public-key algorithms only, unless `--publisher-alg` names an HS one) |
| `--subscriber-key`, `--subscriber-alg`, `--subscriber-jwks-url` | the publisher's | subscribers' JWT key |
| `--trusted-issuers` | `https://localhost` | `iss` values accepted with those keys (Mercure 1.0) |
| `--authorization-servers` | | OAuth authorization servers, keys by discovery (Mercure 1.0) |
| `--resource-identifier`, `--hub-url` | | the `aud` of Mercure 1.0 tokens; the hub's public URL. One is required with `--authorization-servers` or non-default `--trusted-issuers` |
| `--cookie-name`, `--access-token-cookie-name` | `mercureAuthorization`, `__Secure-mercure_access_token` | the draft-07 and Mercure 1.0 authorization cookies |
| `--no-query-authorization` | off | refuse the token in the `authorization` query parameter (draft-07) |
| `--allow-weak-keys` | off | accept short HMAC secrets (development only) |
| `--allow-insecure-key-urls` | off | key and discovery URLs over plain HTTP or with a certificate that does not verify (development only) |
| `--key-urls-ca-file` | | PEM certificates trusted for key and discovery URLs, as well as the system's |
| `--mercure-extra-directives` | | FrankenPHP's extra `mercure` directives, applied where not set otherwise |

## Subscribers and publishing

| Flag | Default | |
| --- | --- | --- |
| `--anonymous`, `--subscriptions` | off | subscribers without a token; subscription events and API |
| `--modern-subscription-format` | off | subscription events as current reference hubs send them (event type `mercure`, no JSON-LD) |
| `--cors-origins`, `--publish-origins` | | origins allowed cross-origin; origins allowed to publish with the cookie |
| `--heartbeat`, `--write-timeout` | `30s`, `30s` | keep-alive on idle streams; a stalled write drops the subscriber |
| `--close-on-token-expiry` | off | end a stream when its subscriber's draft-07 token expires (Mercure 1.0 streams always do) |
| `--max-connection-lifetime` | none | end every stream after this long |
| `--dispatch-buffer` | `1000` | updates queued per subscriber before it is dropped to catch up |
| `--max-subscribers`, `--max-subscribers-per-ip` | `100000`, `1000` | open streams on this node (503 over it), and per client address (429); 0: unbounded |
| `--max-hub-subscribers` | unbounded | open streams per hub (each tenant's) |
| `--max-topic-selectors`, `--max-pattern-selectors` | `256`, `32` | matchers per subscription request |
| `--max-publish-size` | `1048576` (1 MiB) | largest publish request body, in bytes |

## History

| Flag | Default | |
| --- | --- | --- |
| `--history-size`, `--history-bytes`, `--history-age` | `10000`, 64 MiB, `1h` | replay history per hub (`--history-age 0`: no age bound) |
| `--history-budget` | 1 GiB | the tenants' histories together |
| `--history-persist` | off | also write the history to `--database`, in the background, so a node has it back after a restart (a single node, or a cluster that stopped all at once) |
| `--history-flush` | `1s` | how often the history is written, with `--history-persist` |
| `--replay-window` | `5s` | how late an update may arrive and still be replayed |

## Clustering

| Flag | Default | |
| --- | --- | --- |
| `--cluster-bind` | | gossip address (`host:port`; TCP and UDP); enables clustering |
| `--cluster-advertise` | | gossip address advertised to peers (behind NAT, in containers) |
| `--cluster-peers` | | peers to join (`host:port`, a host name, or `srv+name`) |
| `--cluster-key` | | gossip encryption key, the same on every node (`gossiper genkey`) |
| `--cluster-insecure` | off | cluster without a key: unencrypted and unauthenticated (trusted networks only) |

## Tenants and the admin API

| Flag | Default | |
| --- | --- | --- |
| `--tenants-file` | | tenants, from a JSON file ([multi-tenancy](multi-tenancy.md)) |
| `--database` | | the SQLite file of the tenants the admin API manages, the node's ID and, with `--history-persist`, the history; without it they are kept in memory |
| `--api-token` | | the admin API's static token (plain or a bcrypt hash) |
| `--admin-issuer`, `--admin-audience` | | an identity provider whose access tokens the admin API takes; the API's identifier (the tokens' `aud`) |
| `--admin-detail-type`, `--admin-scope` | `urn:gossiper:admin`, none | what an IdP token may do: its authorization details of this type, or this scope for full access |

## Operations

| Flag | Default | |
| --- | --- | --- |
| `--shutdown-delay` | `0s` | on shutdown, report not ready (`/readyz` 503) and keep serving this long first: a few seconds behind a load balancer |
| `--shutdown-timeout` | `10s` | time allowed for a graceful shutdown |
| `--metrics`, `--pprof` | off, off | Prometheus metrics; Go profiling (`--pprof` needs `--admin-listen`) |
| `--log-level`, `--log-format` | `info`, `console` | `trace` … `error`; `console` or `json` (the container image sets `json`) |

## Other commands

- `gossiper genkey` prints a random 32-byte key (base64), for `--cluster-key` or an HMAC secret.
- `gossiper token` mints test tokens: Mercure 1.0 access tokens with `--modern` (issuer `https://localhost`, audience `https://localhost:8080/.well-known/mercure` unless you pass `--issuer` and `--audience`), draft-07 tokens without it.
- `gossiper healthcheck` checks a running server's readiness (`/readyz`) on the loopback address, from `--listen` and `--http-only`, or at `--url`. The container image uses it.
