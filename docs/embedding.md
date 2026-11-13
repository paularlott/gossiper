# Embedding

Gossiper is also a Go package: mount a hub in your own server.

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

- The hub accepts Mercure 1.0 only unless `Config.Protocol` says otherwise (`gossiper.ProtocolBoth` for draft-07 clients too).
- To cluster an embedded hub, pass `cluster.New(gossipCluster, cluster.Options{})` as `Config.Transport`.
- [examples/embed](../examples/embed) is a complete program.

## Packages

| Package | |
| --- | --- |
| [`gossiper`](..) | the hub: HTTP handlers (streaming publish included), fan-out, history, the `Transport` interface |
| [`cluster`](../cluster) | replication over a gossip cluster |
| [`historydb`](../historydb) | the history in a SQLite file, written in batches (`--history-db`) |
| [`client`](../client) | Go client: streaming publish and SSE, or Mercure's HTTP protocol with other hubs ([docs](streaming-and-go-client.md#go-client)) |
| [`auth`](../auth) | JWT verification: draft-07 tokens and RFC 9068 access tokens, static keys, JWK Sets and discovery |
| [`topic`](../topic), [`urlpattern`](../urlpattern) | draft-07 topic selectors; WHATWG URL Pattern matching in linear time |
| [`cmd/gossiper`](../cmd/gossiper) | the server binary |
