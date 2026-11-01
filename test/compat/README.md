# Gossiper protocol-compatibility suite

Proves Gossiper works as the Mercure hub of FrankenPHP/Symfony apps and is wire-compatible with the reference hub
bundled in FrankenPHP (`dunglas/frankenphp`, Caddy `mercure` directive, `protocol_version_compatibility 8`). The
reference is used as a black box (Docker image only).

## Run

```
docker compose -f test/compat/docker-compose.yml up -d --build
go test -tags compat -count=1 -v ./test/compat/          # ~65 s
docker compose -f test/compat/docker-compose.yml down -v
```

`COMPAT_UP=1` makes the test start the stack itself. Needs Docker, Go and Node 20+ (the JS test runs `npm install` of
`eventsource` once). The whole run takes about 3 minutes.

| Host port | Container | Role |
|---|---|---|
| 13000 | gossiper (`--protocol both`, the default) | must pass the legacy and the Mercure 1.0 suites |
| 13001 | gossiper `--modern-subscription-format` | draft-07 hub with the current subscription format |
| 13002 | app | FrankenPHP without hub, the PHP app publishing to 13000 |
| 13003 | reference | FrankenPHP built-in hub, `protocol_version_compatibility 8` (the legacy reference) + the PHP app |
| 13004 | gossiper-v1 (`--protocol modern`) | Mercure 1.0 only |
| 13005 | reference-modern | FrankenPHP built-in hub in its default Mercure 1.0 mode (`issuer` block) + the PHP app (the modern reference) |
| 13006 | app-v1 | FrankenPHP without hub, the PHP app publishing to 13004 |

Override with `COMPAT_GOSSIPER_URL`, `COMPAT_MODERN_URL`, `COMPAT_APP_URL`, `COMPAT_REFERENCE_URL`, `COMPAT_V1_URL`,
`COMPAT_REFERENCE_MODERN_URL`, `COMPAT_APP_V1_URL`.

The run writes `last-run-differences.txt` (every difference seen, classified `known` / `info` / `FAIL`).

## Layout

- `Dockerfile` (+ `.dockerignore`): Gossiper, multi-stage `golang:1.27.3-alpine` build from the repo root.
- `docker-compose.yml`: gossiper, gossiper-modern, app (FrankenPHP without hub, `MERCURE_URL=http://gossiper:3000/.well-known/mercure`), reference (FrankenPHP with hub).
- `php/`: the app on the official `symfony/mercure`, two composer projects (the two library versions cannot share a process; `public/index.php` routes):
  - `legacy/` symfony/mercure 0.7 (protocol 0.x): `/publish?topic=..&data=..&private=1&id=..&type=..&retry=..` (Hub + Update + FactoryTokenProvider/LcobucciFactory, returns the id), `/discover` (Symfony `Discovery` Link header, `Authorization::createCookie` -> `mercureAuthorization` cookie), `/info`.
  - `v1/` symfony/mercure 0.9 (protocol 1.0, RFC 9068 `at+jwt` with `iss`, `aud`, `sub`, `client_id`, `exp`, `authorization_details`): `/v1/publish` (same parameters, plus `grant=exact:T|urlpattern:P` to narrow the publisher token), `/v1/discover` (Link header; the library refuses the `__Secure-` cookie over plain HTTP, so the token is also returned in the JSON body), `/v1/info`.
- `caddy/`: Caddyfiles of the three FrankenPHP containers (no hub, legacy reference, modern reference).
- `compat_test.go`, `helpers_test.go` (legacy suite), `compat_modern_test.go`, `helpers_modern_test.go` (Mercure 1.0 suite), tag `compat`. `js/check.mjs`: Node tests (`MODERN=1` for Mercure 1.0).

## What is tested

a. Symfony client -> Gossiper -> Go SSE client (and the same against the reference, frames must be byte-identical):
   public, private (subscriber token), private to anonymous (not delivered), token for another topic, multi-topic,
   type/retry/id, multi-line and CRLF data, unicode (data, type, topic), empty data, `/discover` Link + cookie that
   authorizes a private subscription.

b. Differential (same raw request to both hubs; status, Content-Type, WWW-Authenticate error code, Link, Last-Event-ID,
   Mercure-Last-Event-ID, CORS headers hard; Vary/Cache-Control/ETag/security headers/body text soft = reported only):
   - publish auth matrix (~50 cases: no/bad/malformed/expired/nbf/alg none/HS512 tokens, selectors, empty publish
     array, missing claims, cookie with/without/bad Origin and Referer, `authorization` query, source precedence);
   - publish validation (~50: topic, id, retry, type, reserved namespace, UTF-8, size, content types, methods, paths);
   - subscribe requests (~30: no topic, anonymous, token via header/cookie/query, errors, Last-Event-ID forms, HEAD);
   - CORS (~20: origins, errors, preflights);
   - scenarios (~50, frames compared after normalising generated ids): public/private filtering, token selectors,
     multi-topic, `{id}`, `{?q,page}`, `{/a}{/b}`, `{+path}`, `*`, percent-encoding, ordering, replay by query param /
     header / `earliest` / unknown id / own ids / private / templates;
   - subscriptions API and subscription events: `gossiper-modern` against the reference (must match);
     default (draft-07) mode compared too, with the format differences marked known, plus a shape test of it.

c. Node 24 (`eventsource` + fetch streaming) against both hubs: cookie auth via `/discover`, private vs anonymous,
   custom event type/retry/multi-line/unicode, reconnection with `Last-Event-ID` (connection cut mid-stream, no loss and
   no duplicate, cookie re-sent), `lastEventID=` and `earliest` replay, Bearer fetch stream, refused bad token.

## Mercure 1.0 (draft-08) suite

Gossiper (`--protocol both` on 13000 and `--protocol modern` on 13004) against the modern reference (13005). Tokens
are minted per hub (`aud` = the hub URL the client contacts, `iss` = `https://localhost`, `typ: at+jwt`).

- publish auth (~85 cases): URL-pattern and exact grants (named groups, regexp groups, optional modifiers, scheme
  wildcards, relative and invalid patterns), several `authorization_details` entries, malformed entries (type, actions,
  match_type, empty), `iss` / `aud` (string, array, slash, origin only) / `typ` (missing, JWT, case, media type) / `exp` /
  `nbf` / `iat` / `sub` / `client_id` / `jti` variants, algorithms, malformed tokens, the `__Secure-mercure_access_token`
  cookie with Origin/Referer rules, legacy cookie names, `authorization` / `access_token` query parameters, source precedence;
- publish validation (~90): the legacy list plus reserved-namespace variants (absolute, scheme-relative, encoded dot,
  encoded slash, dot segments, double slash, case, query/fragment, alternate topic), topic `*`, `type=mercure`, Cf
  characters (zero-width, RLO, BOM, soft hyphen) in topic/id/type/data, C0/C1/DEL ids, limits, content types, methods;
- subscribe requests (~70): `match`, `match_exact`, `match_urlpattern`, mixes, unknown `match_*` (400), empty, invalid
  patterns/UTF-8/length, QUERY (body, content types, query string, token, origin), tokens by header/cookie/query,
  `last_event_id`, `Last-Event-ID`, legacy names;
- CORS and the protected resource metadata (RFC 9728): document members, `WWW-Authenticate: ...resource_metadata=`,
  Host / X-Forwarded-* / Forwarded handling, HEAD/POST/OPTIONS;
- ~50 scenarios compared frame by frame: all matcher types, private filtering with exact/pattern grants and with grants
  on the canonical or an alternate topic only, payload grants, cookie auth, QUERY streams, replay (query, header,
  earliest, unknown id, private, alternate-topic grants, patterns, custom ids), fields (id/type/retry/multi-line/unicode/Cf);
- subscription events and API in the modern shape (`/subscriptions/{match_type}/{match}/{subscriber}`, event type
  `mercure`, `match`/`match_type` members, payload), ~35 API requests with grants of different breadth;
- symfony/mercure 0.9 publishing through Gossiper (both modes) and through the reference (frames must be identical),
  publisher grant enforcement, `/v1/discover` token as `__Secure-` cookie;
- Node 24: `?match=` / `match_urlpattern` EventSource, QUERY via fetch, cookie and Bearer access tokens, reconnection
  with `Last-Event-ID`, `last_event_id` replay, protected-resource metadata and the 401 challenge.

## Result

All tests pass (legacy and Mercure 1.0). No Gossiper bug found: every difference below is either a documented design
choice (draft-07 format, limits, `both` mode affordances) or leniency/strictness at the edges.

## Differences (Gossiper vs reference)

| Area | Reference | Gossiper | Matters? |
|---|---|---|---|
| Default subscription events/API | `event: mercure`, `application/json`, type `subscription(s)` | draft-07: no event type, `@context`, `application/ld+json`, `Subscription(s)` | Only for clients of the subscription API; `--modern-subscription-format` is identical (tested) |
| `Access-Control-Expose-Headers` | `Accept-Query, Link, Mercure-Last-Event-ID` | `Link, Last-Event-ID, Mercure-Last-Event-ID` | No |
| `WWW-Authenticate` | adds `resource_metadata=` (OAuth) | plain `Bearer [error=..]` | No; error codes equal |
| Token that cannot be decoded (bad base64 payload; bad token in cookie or `?authorization=`) | 401 invalid_token (query: bare Bearer) | 400 invalid_request | No, both are auth failures |
| `?authorization=garbage` on subscribe | ignored, streams anonymously (200) | 400 | Minor (stricter) |
| `Authorization: <jwt>` without `Bearer` | 400 | accepted | Minor (lenient; nonstandard clients) |
| Origin `http://example.com/` (trailing slash) for cookie publish | 400 | accepted | No (browsers never send it) |
| `topic=` empty on subscribe | opens a stream | 400 | No |
| `match=` subscription param (newer protocol) | accepted | 400 (only `topic`) | Only for clients using the newer parameter; `topic` is what Symfony/Mercure JS use |
| `Last-Event-ID` query parameter (draft-07 name) | ignored | honoured | No (superset) |
| `Accept: application/json` on subscribe | 406 | 200 stream | No |
| `retry=` empty / `retry=0` on publish | empty ignored; 0 dropped | empty 400; `retry: 0` sent | Minor: `retry: 0` makes browsers reconnect with no delay; Symfony never sends it |
| `type` longer than 256 bytes | accepted | 400 | Minor (limit) |
| Body over 1 MiB | accepted | 413 (`--max-publish-size`) | Configurable |
| CORS preflight | only GET grants; plain OPTIONS 405 | grants GET/HEAD/POST, echoes valid request headers, `Max-Age: 600`; plain OPTIONS 204 | No (superset) |
| 405 responses | no `Allow` | `Allow` | No |
| `HEAD /subscriptions` | 405 | 200 | No |
| `/subscriptions/a/b/c` | 400 | 404 | No |
| Error body texts | e.g. `missing "match" subscription parameter` | `Missing "topic" parameter` | No (not machine-readable) |

## Differences in Mercure 1.0 mode (Gossiper vs the modern reference)

Identical on both: status codes and error classes for ~85 publish-auth cases (every `iss`/`aud`/`typ`/`exp`/grant
variant), URL-pattern matching, `*` handling, reserved-namespace checks, Cf-character rejection, `type=mercure`
rejection, `match*` parameter handling and unknown-type 400, QUERY semantics, replay and `Mercure-Last-Event-ID`,
private filtering with alternate-topic grants, subscription events and API documents, protected-resource metadata
(same members and values; the `resource_metadata` URL in `WWW-Authenticate` is identical), frames of the Symfony 0.9
client.

| Area | Reference | Gossiper | Matters? |
|---|---|---|---|
| Undecodable token classification | garbage / 2 segments: 400 invalid_request; bad base64 or JSON payload, bad cookie token: 401 invalid_token | `--protocol modern`: garbage and 2 segments 401, bad payload 400; `both`: matches the reference for garbage, 400 for bad payload | No: all refuse, 4xx |
| Field limits | id/topic too long: 400; type of any length accepted | 413 (id 1 KiB, topic 4 KiB, type 256 B) | Minor |
| `retry=` empty / `retry=0` | empty accepted and ignored; 0 dropped from the frame | empty 400; `retry: 0` emitted | Minor (`retry: 0` makes browsers reconnect with no delay) |
| Reserved namespace | `/.well-known%2Fmercure/...` and `/.well-known//mercure/...` accepted (different URLs) | 400 | No (stricter, safe) |
| Empty `match=`, `match_exact=`, `match_urlpattern=` | opens a stream | 400 | No |
| `last_event_id=` empty | replays from the start, `Mercure-Last-Event-ID: earliest` | treated as absent | No |
| QUERY without a `Content-Type` | 400 | 415 (both answer 415 for another media type) | No: both refuse it |
| Origin with trailing slash on cookie publish | 400 | accepted | No |
| Protected-resource metadata | 5 members | plus `mercure_matcher_types_supported`; `Cache-Control: max-age=300` | No |
| `Allow` on 405 | absent | present | No |
| Subscriptions API edge paths | `/subscriptions/{unknown type}`: 404; `/subscriptions/{unknown type}/{m}` and the 2-segment draft-07 path: 400; HEAD 405 | 200 empty list; 404; HEAD 200 | No |
| CORS | preflight only for GET; plain OPTIONS 405 | grants GET/HEAD/POST/QUERY and echoes valid request headers, `Max-Age: 600`; plain OPTIONS 204 | No (superset) |
| `Accept: application/json` on subscribe | 406 | streams | No |
| `Access-Control-Expose-Headers` | `Accept-Query, Link, Mercure-Last-Event-ID` | adds `Last-Event-ID` (both mode) | No |

`--protocol both` additionally accepts what draft-07 clients need on the same endpoint (all verified as the only
differences of that mode): the Mercure 1.0 endpoints also accept legacy `mercure`-claim tokens, the `topic` parameter (also
in QUERY bodies), `lastEventID`/`Last-Event-ID` query names, the `authorization` query parameter, the `mercureAuthorization`
cookie, the response header `Last-Event-ID`, and the draft-07 subscription format for legacy tokens. The reference in
modern mode refuses all of them (401/400), and so does `--protocol modern`.
