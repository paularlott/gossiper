# Protocol

Gossiper speaks both revisions of [Mercure](https://datatracker.ietf.org/doc/draft-dunglas-mercure/):

- **Mercure 1.0** (draft-08): access tokens (`at+jwt`), `match` and `match_urlpattern` subscriptions, protected resource metadata. This is the default, as with the reference hub.
- **[draft-07](https://datatracker.ietf.org/doc/html/draft-dunglas-mercure-07)**: the `mercure` JWT claim and URI-template `topic` selectors, which many Symfony, API Platform and FrankenPHP clients still speak.

`--protocol` picks what the hub accepts:

| `--protocol` | Accepts |
| --- | --- |
| `modern` (default) | Mercure 1.0 only. draft-07 tokens, `topic` parameters, the `authorization` query parameter and the `mercureAuthorization` cookie are refused. |
| `both` | Both revisions, each request read in the revision it uses. |
| `legacy` | draft-07 only. |

Keys are HMAC secrets, PEM public keys or JWK Set URLs ([configuration](configuration.md)). Mercure 1.0 tokens are checked against `--resource-identifier` (or an absolute `--hub-url`).

## Conformance

The official [conformance suite](https://mercure.rocks/docs/ecosystem/conformance-tests) passes. It covers publishing, topic matching and private updates. The [compatibility suite](../test/compat) covers what it does not (OAuth tokens, replay, the subscriptions API): it runs FrankenPHP's and Symfony's clients and compares Gossiper's answers with the reference hub's.

## Where Gossiper differs from the spec

- No publisher can forge the hub's own events. Topics under its path (`/.well-known/mercure/…`, however spelled), the topic `*` and the event type `mercure` are refused. That is draft-08's rule; Gossiper applies it to draft-07 too.
- draft-07: a token whose `mercure.publish` claim is an empty array may publish nothing (the draft lets it publish public updates). Subscription events use the draft's JSON-LD unless `--modern-subscription-format`.
- Where the spec leaves the choice:
  - a stream opened with a Mercure 1.0 token ends when the token expires (`--close-on-token-expiry` does the same for draft-07 tokens);
  - `--cors-origins '*'` never allows credentials;
  - the hub is always at `/.well-known/mercure`.

## Extensions

Mercure clients never send these, so they are unaffected:

- [Streaming publish](streaming-and-go-client.md): many updates over one long request.
- [Copies](clustering.md#copies-and-idempotent-publishes): a publish answered once several nodes hold it, idempotent by its ID.

## Symfony, API Platform and FrankenPHP

Point the application at Gossiper instead of a bundled hub:

```dotenv
MERCURE_URL=https://gossiper:8080/.well-known/mercure
MERCURE_PUBLIC_URL=https://example.com/.well-known/mercure
MERCURE_JWT_SECRET=<the same value as MERCURE_PUBLISHER_JWT_KEY>
```

The application must trust Gossiper's certificate: a real one (`--tls-cert`), or the self-signed one with `--tls-hosts gossiper` and its file as the HTTP client's `cafile`. On a private network, `--http-only` and an `http://` URL also work.

`symfony/mercure` 0.9 or later with protocol version 1 sends Mercure 1.0 tokens, which Gossiper accepts by default. Older versions send draft-07 tokens: run Gossiper with `--protocol both`, as FrankenPHP's hub needs `protocol_version_compatibility`.

**FrankenPHP's environment variables** are read too: `MERCURE_PUBLISHER_JWT_KEY`, `MERCURE_SUBSCRIBER_JWT_KEY`, `MERCURE_PUBLISHER_JWT_ALG`, `MERCURE_SUBSCRIBER_JWT_ALG`, `MERCURE_TRUSTED_ISSUERS` and `MERCURE_RESOURCE_IDENTIFIER`. From `MERCURE_EXTRA_DIRECTIVES` it takes `anonymous`, `subscriptions`, `cors_origins`, `publish_origins`, `cookie_name`, `heartbeat`, `write_timeout` and `protocol_version_compatibility` (which turns on `--protocol both`). Others, such as `playground`, are logged and ignored: Gossiper has no debugging UI. `gossiper token --modern` stands in for `mercure-token --dev`.

**With FrankenPHP**, leave the `mercure` directive out of the Caddyfile and route `/.well-known/mercure*` and `/.well-known/oauth-protected-resource/.well-known/mercure` to Gossiper, or give Gossiper its own host name. Applications publish over HTTP (Symfony's `Hub`); `mercure_publish()` belongs to FrankenPHP's embedded hub.
