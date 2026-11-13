# Multi-tenancy

One server, or one cluster, can host tenants that never see each other's messages. Each tenant has a hub of its own (keys, subscribers, history, subscriptions API), reached at its host names:

- the request's host picks the hub, and any other host gets 404;
- a token of one tenant is refused on another's host;
- a wildcard DNS record and certificate (`*.events.example`) cover every tenant.

Tenants come from a file (`--tenants-file`), from the [admin API](#admin-api), or both.

## The tenants file

```json
{
  "tenants": [
    {
      "name": "acme",
      "hosts": ["acme.events.example"],
      "mercure": {"publisher_key": "…32 bytes or more…", "trusted_issuers": ["https://acme.example"],
                  "resource_identifier": "https://acme.events.example/.well-known/mercure",
                  "cors_origins": ["https://app.acme.example"]}
    },
    {
      "name": "globex",
      "hosts": ["globex.events.example", "events.globex.example"],
      "mercure": {"publisher_jwks_url": "https://login.globex.example/.well-known/jwks.json",
                  "trusted_issuers": ["https://login.globex.example"]}
    }
  ]
}
```

`mercure` takes a hub's keys and settings: `publisher_key`, `publisher_alg`, `publisher_jwks_url`, the same for `subscriber_`, `trusted_issuers`, `authorization_servers`, `resource_identifier`, `hub_url`, `anonymous`, `subscriptions`, `cors_origins`, `publish_origins`, `cookie_name` and `access_token_cookie_name`. The server's other settings (limits, history, timeouts) apply to every tenant's hub, each separately.

- **Every tenant needs a key:** `publisher_key`, `publisher_jwks_url` or `authorization_servers`. A tenant without one is refused (400 from the API; the server will not start with one in the tenants file).
- **Trusted issuers default to the server's.** Mercure 1.0 tokens signed with a tenant's keys must come from one of its `trusted_issuers`; a tenant that names none takes the server's `--trusted-issuers` (`https://localhost` by default), so `gossiper token --modern --key <the tenant's key>` works with it. A tenant's own list replaces the server's.
- **Set `resource_identifier`** (or an absolute `hub_url`) so tokens are bound to the tenant's hub. Without it, tokens are checked against the URL each client contacted, and a warning is logged.
- With tenants there is no hub of the server's own, so the server's key settings and `--anonymous` are refused.
- Two tenants may not share a key or a host.
- Every node of a cluster needs the same tenants. Updates carry their tenant across the cluster; a node that lacks the tenant drops them.

## Admin API

With a database (`--database`, an SQLite file) and an API token (`--api-token`, plain or a bcrypt hash), an identity provider, or both, tenants are added, changed and removed at runtime:

```bash
gossiper serve --database /data/tenants.db --api-token "$ADMIN_TOKEN" ...

curl -H "Authorization: Bearer $ADMIN_TOKEN" -X PUT https://events.example/api/tenants/acme -d '{
  "hosts": ["acme.events.example"],
  "mercure": {"publisher_key": "…", "trusted_issuers": ["https://acme.example"]}}'
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://events.example/api/tenants
curl -H "Authorization: Bearer $ADMIN_TOKEN" -X DELETE https://events.example/api/tenants/acme
```

`POST /api/tenants` creates a tenant (409 if the name is taken), `PUT /api/tenants/{name}` creates or replaces one, `GET` lists or reads them, and `DELETE` removes one. `GET /api/status` shows the database and its replication. The OpenAPI document is at `/api/openapi.json` and its reference at `/api-docs/`, built into release binaries and the container image.

- **Every node applies a change at once.** Each node's database replicates over the cluster's gossip network, and a node that was down catches up when it returns. Give every node a database. Concurrent changes to one tenant settle on the later one.
- **Live.** A new tenant's hub is ready within milliseconds. Changing a tenant's keys restarts its hub (subscribers reconnect with `Last-Event-ID`); changing only its hosts keeps streams open. To change keys without refusing clients' current tokens, [rotate them](#rotating-keys).
- **Delete cleans up.** Deleting a tenant closes its streams and deletes its history, in memory and in `--history-db`, on every node. A tenant created again under the same name starts empty, even on a node that was down while it was deleted. Deletions are remembered, so a returning node does not bring a deleted tenant back.
- **Validation.** An invalid tenant gets 400. One that clashes with another tenant (a host, a key, or a name in the tenants file) gets 409 and changes nothing. Tenants from the file are shown read-only and cannot be changed or deleted here. Changes are logged.
- **Secrets are write-only.** HMAC keys are never returned, so a `PUT` must carry them again. The database holds them as given (deleted ones are wiped from the file): protect it like the tenants file.
- **Limits.** Failed authentications are limited to 60 per address and minute. With a bcrypt-hashed `--api-token`, at most four comparisons run at once; further requests get 429.

### Rotating keys

A `PUT` with a new key replaces it at once: tokens signed with the old key are refused from then on. To rotate without breaking clients, keep the old key accepted while they move to the new one:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" -X POST https://events.example/api/tenants/acme/rotate \
  -d '{"publisher_key": "'"$(gossiper genkey)"'", "grace": "24h"}'
```

- **Both keys work during the grace period** (default `1h`, at most `168h`; `0s` replaces the key at once). Give `publisher_key`, `subscriber_key` or both. The tenant's view shows `publisher_previous_key_until` and `subscriber_previous_key_until` while a previous key is accepted.
- **No restart.** Every node applies it within moments. The tenant's hub starts over with both keys, so its subscribers reconnect with `Last-Event-ID` and the tokens they already hold.
- **Subscribers too.** A tenant without a subscriber key signs its subscribers' tokens with the publisher key, so rotating the publisher key keeps their tokens good for the grace period.
- **The grace period ends by itself**, or at once with `DELETE /api/tenants/acme/previous-keys` (for a leaked key): the old key is refused, and the tenant's streams start over, ending those opened with it. Without that, a stream opened with the old key ends when its token expires.
- **A previous key is still the tenant's:** no other tenant can take it until the grace period ends. A `PUT` that keeps a key keeps its previous key; one that changes the key drops it.
- Keys from a key set URL (`publisher_jwks_url`) rotate in the key set itself. Tenants from the tenants file change in the file.
- **Each rotation step reconnects the tenant's subscribers** (the rotation, and ending the grace period early), on every node at once, as any change of keys does. They resume with `Last-Event-ID` and miss nothing the history holds.
- **Upgrade every node first.** Nodes older than 0.2 ignore previous keys: they refuse the old key at once, and a change to the tenant made through one of them ends the grace period everywhere.

### Signing in with an identity provider

Instead of (or as well as) the static token, the API takes OAuth access tokens (RFC 9068) from an identity provider. People sign in there, with its second factors, and leaving the organization ends their access.

```bash
gossiper serve --database /data/tenants.db --admin-issuer https://idp.example/o/ops \
  --admin-audience https://events.example/api   # the API as a resource in the IdP: the tokens' aud
```

A token says what it may do in authorization details (RFC 9396) of type `urn:gossiper:admin` (`--admin-detail-type`):

```json
[{"type": "urn:gossiper:admin", "actions": ["read"]},
 {"type": "urn:gossiper:admin", "actions": ["write"], "tenants": ["acme"]}]
```

- `write` implies `read`. A detail without `tenants` covers every tenant.
- Each detail is a rule of its own: this token reads every tenant and changes only `acme`. A tenant it may not read is left out of the list.
- A valid token that allows nothing gets 403.
- For an identity provider without authorization details, `--admin-scope gossiper:admin` gives a token with that scope full access.
- The static token keeps full access, so it can stay as a break-glass credential, or be left out.
