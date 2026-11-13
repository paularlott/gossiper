<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo.svg" alt="gossiper" width="420">
  </picture>
</p>

# Gossiper

Gossiper is a clustered, multi-tenant [Mercure](https://datatracker.ietf.org/doc/draft-dunglas-mercure/) hub. Publish an update to any node and every subscriber on a matching topic receives it, whichever node it is connected to. Browsers and services subscribe over Server-Sent Events as with any Mercure hub; services can also publish over one long streaming request.

- **Both protocol revisions:** Mercure 1.0 by default, and draft-07 alongside it with `--protocol both`.
- **Drop-in for Mercure clients:** Symfony, API Platform, FrankenPHP apps, Laravel broadcasters, a browser `EventSource`.
- **Fast for services:** a streaming publish carries updates at more than ten times the rate of a POST each.
- **Multi-tenant:** tenants with their own hubs and keys, picked by host name, managed live through an admin API.
- **Clustered with [gossip](https://github.com/paularlott/gossip):** identical nodes behind a load balancer; no sticky sessions, no Redis.
- **Copies on demand:** a publish can wait until several nodes hold it, and is then idempotent by its ID.
- **One static binary,** or a Go package to embed. MIT licensed, a clean-room implementation.

## Install

- **Binaries** for Linux, macOS and Windows (amd64, arm64) are on the [releases page](https://github.com/paularlott/gossiper/releases). The macOS ones are signed and notarized.
- **Container image** for linux/amd64 and linux/arm64, `paularlott/gossiper` on Docker Hub, with its state in `/data`:

  ```bash
  docker run -d -p 8080:8080 -v gossiper-data:/data \
    -e MERCURE_PUBLISHER_JWT_KEY="$(docker run --rm paularlott/gossiper genkey)" \
    -e GOSSIPER_ANONYMOUS=true -e GOSSIPER_HISTORY_DB=/data/history.db \
    paularlott/gossiper
  ```

  It serves HTTPS with a self-signed certificate in `/data/tls` and logs JSON; see [the container image](docs/production.md#container-image).
- **From source:** `go install github.com/paularlott/gossiper/cmd/gossiper@latest`. This build lacks the admin API's OpenAPI document and reference page (`/api/openapi.json` and `/api-docs/` answer 404), which need Node.js: see [Development](#development).

## Quick start

```bash
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

The subscriber prints a `:` comment when it connects, then the update:

```
:
id: urn:uuid:01a18db6-b5d2-7b4c-803a-a49ec7ab1196
data: {"title":"Dune"}
```

`gossiper token --modern` mints test tokens for a hub at `https://localhost:8080` (`--issuer` and `--audience` change that). `task run-server` starts a development node with a tenant, the admin API and its reference.

## Using it with Symfony, API Platform or FrankenPHP

Point the application at Gossiper instead of a bundled hub:

```dotenv
MERCURE_URL=https://gossiper:8080/.well-known/mercure
MERCURE_PUBLIC_URL=https://example.com/.well-known/mercure
MERCURE_JWT_SECRET=<the same value as MERCURE_PUBLISHER_JWT_KEY>
```

Gossiper reads FrankenPHP's `MERCURE_*` variables. `symfony/mercure` 0.9 or later works with the default; clients still on draft-07 tokens need `--protocol both`. Certificates, FrankenPHP routing and the details: [protocol](docs/protocol.md#symfony-api-platform-and-frankenphp).

## Documentation

| | |
| --- | --- |
| [Protocol](docs/protocol.md) | Mercure 1.0 and draft-07, conformance, where Gossiper differs from the spec, Symfony and FrankenPHP |
| [Streaming publish and the Go client](docs/streaming-and-go-client.md) | publishing over one long request; the Go client |
| [Multi-tenancy](docs/multi-tenancy.md) | tenants, the tenants file, the admin API, signing in with an identity provider |
| [Clustering](docs/clustering.md) | running nodes together, copies and idempotent publishes, history and reconnection |
| [Running in production](docs/production.md) | a checklist, the container image, TLS, endpoints |
| [Configuration](docs/configuration.md) | every flag, environment variable and `gossiper.toml` key |
| [Embedding](docs/embedding.md) | the hub as a Go package, and the packages |
| [Benchmarks](docs/benchmarks.md) | throughput, latency and memory |

## Development

Gossiper builds with Go 1.27.4 or later. The admin API's reference ([web/openapi/openapi.yaml](web/openapi/openapi.yaml), rendered by Redoc into the binary) needs Node.js 24; `go build` alone works without it. Builds and releases use [Task](https://taskfile.dev); the version is in [build/version.go](build/version.go).

```bash
task build              # bin/gossiper for this machine
task run-server         # a development node on :8080
task test:race          # unit and cluster tests
task test:compat        # FrankenPHP and Symfony clients, against Gossiper and FrankenPHP's hub (Docker)
task test:failover      # real processes killed and restarted under load
task test:conformance   # Mercure's conformance suite (browsers, needs Node.js)
task apidocs-lint       # lint the OpenAPI description
task all                # zipped binaries for Linux, macOS and Windows on amd64 and arm64, in bin/
task container:check    # build the linux/amd64 and linux/arm64 image without pushing it
task container:local    # build and push the image to LOCAL_REGISTRY (.env) instead of Docker Hub
task release            # test, build, tag v<version>, push the container, create the GitHub release
```

[Mercure's conformance suite](https://mercure.rocks/docs/ecosystem/conformance-tests) is AGPL-licensed: `task test:conformance` fetches it into a temporary directory each run, so none of it is part of this repository or the binary. `go run ./test/bench -binary bin/gossiper` runs the [benchmarks](docs/benchmarks.md).

## Licence

MIT. See [LICENSE.txt](LICENSE.txt). The URL Pattern tests use web-platform-tests data (BSD-3-Clause, [urlpattern/testdata](urlpattern/testdata)). Mercure is a protocol by Kévin Dunglas; Gossiper is an independent implementation and is not affiliated with the Mercure project.
