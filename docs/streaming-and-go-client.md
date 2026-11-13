# Streaming publish and the Go client

## Streaming publish

Mercure's HTTP protocol costs a request per publish, which caps a busy service at tens of thousands of updates a second. Gossiper also takes a streaming publish: a POST with `Content-Type: application/x-ndjson` whose body is one JSON update per line, kept open as long as the client likes. The hub answers each line, in order, as it is published:

```
→ {"topic":["https://example.com/books/1"],"data":"{\"title\":\"Dune\"}","id":"urn:book:1"}
→ {"topic":["https://example.com/books/2"],"private":true,"retry":3000}
← {"id":"urn:book:1"}
← {"id":"urn:uuid:01a1…"}
```

It is the same hub, with the same tokens, grants, topics, private updates and history.

- **Fields:** those of a form publish (`topic` as an array, `data`, `id`, `type`, `private`, `retry`), plus `replicas` ([copies](clustering.md#copies-and-idempotent-publishes)).
- **A refused update** is answered with its line number and the stream goes on: `{"line":n,"status":403,"error":"insufficient_scope"}`.
- **No answer waits for the disk:** with `--history-persist` the history is written in the background.
- **Runs:** lines that arrive together (up to 64) and ask for no copies are published as one run. Each subscriber is woken once for its updates of the run and writes them in one go, which multiplies fan-out from a single stream. A cluster sends the run to each peer in one message, and the peer applies it the same way; so do tenants' hubs. A line read on its own is published at once, so latency does not change, and every subscriber still gets its updates in publish order.
- **The stream ends** when the client closes the body (a body that ends is a batch), or with a last line from the hub that has no `line` field:
  - `401` when the token expires;
  - `503` when the hub closes or its store fails;
  - `408` after two minutes without a line;
  - `413` for an update over `--max-publish-size`.

  Every line before it is answered; the lines after it were not published.
- **Transport:** HTTP/2 (over TLS, or cleartext to clients that ask for it) or full-duplex HTTP/1.1 straight to the hub; otherwise `415`. A proxy in front must not buffer request bodies (Caddy streams them).

## Go client

The [Go client](../client) publishes and subscribes with the same calls against any Mercure hub. It is a module of its own with no dependencies beyond Go's standard library, so a service that only publishes and subscribes does not pull in the hub:

```sh
go get github.com/paularlott/gossiper/client
```

```go
c, err := client.New(client.Options{URL: "https://events.example/.well-known/mercure", Token: jwt, Transport: client.Stream})
defer c.Close()

id, err := c.Publish(ctx, client.Update{Topics: []string{"https://example.com/books/1"}, Data: `{"title":"Dune"}`})
c.PublishAsync(ctx, update, func(id string, err error) { … }) // pipelined: thousands in flight on one stream

sub, err := c.Subscribe(ctx, client.Subscribe{MatchURLPattern: []string{"https://example.com/books/:id"}})
for ev := range sub.Events() {
    fmt.Println(ev.ID, ev.Data)
}
```

`Subscribe` takes Mercure 1.0 matchers (`Match`, `MatchURLPattern`) or draft-07 `Topics` (URI templates, for a hub with `--protocol both`).

- **Transport:** by default a POST per update, which any Mercure hub takes. `client.Stream` uses the streaming publish (Gossiper only); `client.Auto` streams to a Gossiper hub and POSTs to any other.
- **TLS:** `CAFile` trusts a hub's certificate alongside the system's (a private CA, or a node's `self-signed.crt`). `InsecureSkipVerify` takes any certificate, for development only.
- **Bypassing the proxy:** a service inside the cluster can talk to a node directly, with `URL` the node's address and `Host` the hub's (or tenant's) host name: `client.Options{URL: "https://10.0.0.5:8080/.well-known/mercure", Host: "events.example", CAFile: "node.crt"}`. To a node with `--http-only`, `CleartextHTTP2` lets the publish stream and every subscription share one connection, as HTTPS does by itself.
- **Order:** over a stream, a client's publishes keep their order, resends included. With a POST per update, `Publish` returns once the hub has the update, so sequential publishes keep their order; `PublishAsync` ones may not.
- **Subscriptions** reconnect by themselves and resume from their last event ID: after a lost connection, a node shutting down, or an expired token (`TokenFunc` supplies fresh ones). One the hub refuses for good (401 even with a fresh token, 403, 404) ends, and `Err` says why. An event over `MaxEventSize` (default 8 MiB; match the hub's `--max-publish-size`) ends the stream rather than fill the client's memory.
- **The publish stream** reopens by itself and first resends, in order, what its hub did not take. A stream that cannot open is retried with a growing delay (up to 10s). HTTP/2 pings, and 30s of silence while answers are due, catch a dead connection.
