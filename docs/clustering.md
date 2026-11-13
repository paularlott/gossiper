# Clustering

Every node is identical: publish to any node, subscribe to any node, no sticky sessions and no Redis.

```bash
gossiper serve --cluster-bind 0.0.0.0:7946 --cluster-peers node1:7946,node2:7946,node3:7946 \
  --cluster-key "$(gossiper genkey)"   # the same key on every node
```

- **The cluster key** encrypts and authenticates gossip. Without it anyone who reaches the port could join, read every update and the tenants' keys, and inject updates, so clustering refuses to start without one (`--cluster-insecure` allows it on a trusted network).
- **The cluster port** (7946 by default) needs both TCP and UDP. Behind NAT or in containers, set `--cluster-advertise` to the address peers should use.
- **Clocks must be synchronised** (NTP, chrony, or the cloud provider's time service). A node refuses an update stamped more than 5 seconds ahead of its own clock; it is lost on that node and counted in `gossiper_refused_total`. It also refuses a tenant change stamped more than a minute ahead (logged, and taken once its clock catches up).
- **Node IDs:** each node has an ID, a UUID. A node with a database (`--database`) makes one on its first start and keeps it there, so it comes back as the same node after a restart. Give every node its own database, never a copy of another node's: two nodes with one ID cannot share a cluster. A node without a database has a new ID at each start.

[examples/cluster](../examples/cluster) runs three nodes behind Caddy with Docker Compose.

## Delivery

A publish is answered once the node that took it has applied it and queued it for its peers. Mercure promises no more (subscribers "SHOULD NOT assume that no events will be lost"), and clients catch up from the history with `Last-Event-ID`. A service that needs more asks for [copies](#copies-and-idempotent-publishes).

- Each node sends its updates to each peer in order, and resends a batch the peer does not acknowledge while the peer is in the cluster.
- What is queued for a peer that leaves, or more than 64 MiB for one that cannot keep up, is dropped and counted in `gossiper_replication_dropped_total`.
- When a dropped peer comes back (it restarted, or a network split healed), the two exchange what was published while they were apart.
- Updates a peer cannot decode (a node of another version during an upgrade) are dropped rather than sent forever.

Order is per node: two services publishing to one topic through two nodes may be seen interleaved differently on different nodes. A replay from the history is ordered the same everywhere.

## Copies and idempotent publishes

A publish can ask for copies, a Gossiper extension: `"replicas": n` on a stream's line, the `Gossiper-Replicas: n` header on a form POST, or `Replicas` in the [Go client](streaming-and-go-client.md#go-client) or `Update`. It is answered once n nodes (at most 64), including the one that took it, hold the update:

```
→ {"topic":["https://example.com/orders/42"],"data":"…","id":"urn:order:42:v3","replicas":2}
← {"id":"urn:order:42:v3"}
```

- **Too few nodes:** with fewer than n nodes in the cluster, the update is refused and not published: `{"line":1,"status":503,"error":"Too few nodes: 1 of 2"}` (503 for a form).
- **Not copied in time:** when the copies are not made within 10 seconds, the update was published but the answer says so: `{"id":"urn:order:42:v3","status":503,"error":"Published, not on enough nodes: 1 of 2 nodes"}`.
- **Idempotent by ID:** published again with the same ID within 5 minutes, through any node, it is answered as the first and delivered to no one again. A service that got no answer (a timeout, a node gone) publishes again with the same ID. The Go client gives such an update an ID when it has none, and resends it by itself when a node ends its stream or the connection is lost. Publishes without copies keep Mercure's behaviour: a reused ID is a new update.
- **Cost:** about one round trip to the peers, shared by every update of a batch, and only for the publishes that ask.
- **Network splits:** a side with fewer than n nodes refuses them. Ask for a majority (`replicas: 3` of 5) so only one side accepts them.

## History and reconnection

A subscriber that reconnects with `Last-Event-ID` gets what it missed from the node it reaches.

- **Size:** each node keeps recent updates in memory: up to `--history-size` updates and `--history-bytes`, for `--history-age` (an hour). Each tenant's hub has its own, and `--history-budget` (1 GiB) bounds them together; over it, the largest histories give up their oldest updates first.
- **A starting node** with `--cluster-peers` copies the history of a ready peer before `/readyz` reports it ready, so subscribers can resume there too. It waits up to 10s for one, or 2s when every peer is starting too.
- **Order:** event IDs are UUIDv7 URNs ordered the same on every node. An update that reaches a node late is still replayed within `--replay-window` (5s), so a resuming subscriber may rarely see a duplicate but misses nothing that arrived in the window.

### Across a restart

A node that restarts in a running cluster copies the history from a peer. `--history-persist` also writes each node's history to its database (`--database`), so a node has it back with no peer to copy from: a single node, or a cluster whose nodes all stopped at once.

- **In the background:** the history is written every `--history-flush` (1s), in one transaction; no publish waits for the disk. A crash loses at most the last interval (in a cluster the peers still hold it); a clean stop writes everything first.
- **Every node writes everything:** each node keeps the whole history, so in a cluster each writes every update to its own database.
- The database holds about what the in-memory history does. Updates older than `--history-age` are not brought back.
- **A disk that cannot keep up:** what it cannot take is not stored (the history in memory is unaffected) and is counted in `gossiper_history_unwritten_total`.
