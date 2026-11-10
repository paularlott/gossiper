# Benchmarks

Measured with [test/bench](../test/bench) on one machine (Apple M5 Max, 18 cores, macOS), clients and servers
together. There are two suites:

- **mercure**: what browsers do. Each publish is an HTTP POST (or the [Go client](../client)'s streaming publish),
  and each subscriber is a Server-Sent Events stream that behaves like a browser's `EventSource`.
- **services**: services talking to services through the hub, with the Go client at both ends: a publish stream
  (`PublishAsync`) and SSE subscriptions (`Subscribe`).

Subscribers run in processes of their own, and streams use HTTP/1.1. On a cluster the publishers use node 1; a
single subscriber is on node 3, and many subscribers are spread over every node. Nothing was lost in any workload.

```bash
task build
go run ./test/bench -binary bin/gossiper -mode both                     # both suites, single node and cluster
go run ./test/bench -binary bin/gossiper -mode cluster -suite services
go run ./test/bench -url http://n1:3000,http://n2:3000,http://n3:3000   # a cluster already running
go run ./test/bench -url http://mercure -issuer https://localhost -sub-param match -http-only   # the official hub
```

The benchmark's subscribers all come from one address, so the hubs it starts run with `--max-subscribers-per-ip 0`.
A hub benchmarked with `-url` needs the same. The benchmark speaks draft-07 unless given `-issuer` and
`-sub-param match`, so the hubs it starts run with `--protocol both`; a hub at `-url` that accepts only Mercure 1.0
(gossiper's default, and the official hub's) needs `-issuer https://localhost -sub-param match`.

| Workload | What it does |
| --- | --- |
| Publish, 1 subscriber | 20k updates as POSTs, 32 at a time, or 400k over 1 or 4 streams, to a topic with one subscriber |
| Fan-out to 1000 / 5000 subscribers | 1000 / 200 updates to a topic that 1000 / 5000 SSE streams subscribe to |
| Service → service, 4 services → 1 service | 400k updates over 1 or 4 streams to a topic with one Go client receiving |
| Service → 10 services, one topic | 200k updates over a stream to a topic with 10 Go clients receiving each |
| Service → 1000 services, a topic each | 400k updates over 1 or 4 streams, shared out among 1000 topics with one Go client each: each update is delivered once |
| Latency | one update at a time, waiting for it to arrive |

## Against the official Mercure hub

These runs use Docker Desktop with 18 CPUs. Each hub runs in a container of its own, and the benchmark runs in another
on the same Docker network. Each workload ran twice, with the hubs interleaved, and the tables give the range.

| Hub | Configuration |
| --- | --- |
| `dunglas/mercure` 1.1.5, as shipped | its default configuration plus `anonymous`: its transport writes every update to a file before the publish returns |
| `dunglas/mercure`, in memory | `transport local`: nothing on disk |
| Gossiper | `serve --anonymous` |
| Gossiper, `--history-db` | the same, with the history in SQLite on a Docker volume: the one to compare with the official hub's file |

Inside Docker the network costs more than on the host, so these figures are lower than the native ones below.

| HTTP POST → SSE | Gossiper | Mercure, in memory | Gossiper, `--history-db` | Mercure, as shipped |
| --- | --- | --- | --- | --- |
| Publish, 1 subscriber (32 concurrent POSTs) | 16.4k/s | 12.8k–12.9k/s | 9.0k–11.2k/s | 1.0k–1.1k/s |
| Fan-out to 1000 subscribers | 6.99M events/s | 1.71M–1.95M events/s | 4.90M–4.91M events/s | 497k–519k events/s |
| Fan-out to 5000 subscribers | 4.17M–4.42M events/s | 1.59M–1.64M events/s | 2.62M–3.05M events/s | 815k–833k events/s |
| Publish → event latency, p50 / p99 | 188–199 µs / 4.9–5.0 ms | 253–263 µs / 4.9 ms | 471–493 µs / 1.2–1.4 ms | 2.9–3.4 ms / 7.2–8.3 ms |
| Peak container memory | 283 MiB | 460 MiB | 297 MiB | 471 MiB |
| Data on disk afterwards | | | 6.3 MiB | 13 MiB |

In memory, Gossiper publishes about a quarter faster than the official hub and delivers 2.5 to 4 times as many
events. On disk, it publishes 8 to 11 times as fast and delivers 3 to 10 times as many events, because a batch of
updates costs it one sync where the official hub syncs every update; its file is half the size. It uses about 40%
less memory either way.

The open-source official hub does not cluster, so the cluster results below are Gossiper's alone.

## Streaming publish and services, single node (Docker)

The same Docker setup as the comparison above. The official hub has no streaming publish.

| Stream → SSE | Gossiper | Gossiper, `--history-db` |
| --- | --- | --- |
| Publish, 1 subscriber, 1 client | 360k–367k/s | 213k–217k/s |
| Publish, 1 subscriber, 4 clients | 244k–268k/s | 207k–215k/s |
| Fan-out to 1000 subscribers, 1 client | 6.95M–7.54M events/s | 5.65M–7.21M events/s |
| Fan-out to 5000 subscribers, 1 client | 1.76M–1.97M events/s | 1.65M–1.75M events/s |
| Publish → event latency, p50 / p99 | 137–142 µs / 4.9–5.0 ms | 0.45–1.07 ms / 3.8–5.0 ms |

| Services (Go client → Go client) | Gossiper | Gossiper, `--history-db` |
| --- | --- | --- |
| Service → service | 369k–374k/s | 217k–225k/s |
| 4 services → 1 service | 258k–272k/s | 207k–215k/s |
| Service → 10 services, one topic | 175k–178k publishes/s, 1.72M–1.75M events/s | 189k–190k publishes/s, 1.89M–1.90M events/s |
| Service → 1000 services, a topic each | 314k–319k/s | 214k–223k/s |
| 4 services → 1000 services, a topic each | 362k–365k/s | 221k–227k/s |
| Latency, p50 / p99 | 190–205 µs / 5.0–5.1 ms | 448–454 µs / 4.0–4.5 ms |

A service publishing over a stream does about 370k updates a second in memory, and 220k with every update stored:
twenty times the official hub's best over HTTP.

## Three-node cluster (Docker)

Three Gossiper containers on one Docker network, the benchmark in a fourth; two runs in memory, two or three with
`--history-db`. Each node peaked at about 150 MiB.

| Mercure suite | Gossiper | Gossiper, `--history-db` |
| --- | --- | --- |
| Publish, 1 subscriber, HTTP POST | 14.1k–14.3k/s | 9.7k–11.1k/s |
| Publish, 1 subscriber, stream, 1 client | 305k–322k/s | 171k–180k/s |
| Publish, 1 subscriber, stream, 4 clients | 290k–295k/s | 158k–166k/s |
| Fan-out to 1000 subscribers, HTTP POST | 6.93M–7.43M events/s | 3.49M–3.89M events/s |
| Fan-out to 1000 subscribers, stream | 9.74M–11.27M events/s | 8.64M–9.95M events/s |
| Fan-out to 5000 subscribers, HTTP POST | 5.11M–5.39M events/s | 3.73M–3.91M events/s |
| Fan-out to 5000 subscribers, stream | 4.25M–5.31M events/s | 4.32M–4.82M events/s |
| Latency node 1 → node 3, HTTP POST, p50 / p99 | 211–215 µs / 4.8 ms | 830–890 µs / 2.1 ms |
| Latency node 1 → node 3, stream, p50 / p99 | 172–181 µs / 4.4–4.7 ms | 0.80–0.84 ms / 2.0–2.8 ms |

| Services suite | Gossiper | Gossiper, `--history-db` |
| --- | --- | --- |
| Service → service (node 1 → node 3) | 310k–319k/s | 168k–174k/s |
| 4 services → 1 service (node 1 → node 3) | 288k–293k/s | 161k–164k/s |
| Service → 10 services, one topic | 216k–226k publishes/s, 2.11M–2.20M events/s | 166k–172k publishes/s, 1.66M–1.72M events/s |
| Service → 1000 services, a topic each | 250k–251k/s | 159k–161k/s |
| 4 services → 1000 services, a topic each | 277k–282k/s | 152k–161k/s |
| Service → service, 2 copies (node 1 → node 3) | 283k–306k/s | |
| Service → service, 3 copies (node 1 → node 3) | 302k/s | |
| Latency node 1 → node 3, p50 / p99 | 251–342 µs / 5.1 ms | 0.79–1.18 ms / 2.8–4.8 ms |

Every update goes to every node, which costs a single stream about 15% of its rate in memory. Asking for copies
(each update answered once 2 or 3 nodes hold it) costs little more: the answers wait for the peers'
acknowledgements, which every update of a batch shares. Fan-out rises, to 10M
events a second to 1000 subscribers, because the subscribers' streams are spread over three nodes. With
`--history-db` every node stores an update before delivering it, so latency is about 0.8 ms.

## Native (macOS loopback)

One run on the host, without Docker. On macOS the loopback network stalls under bursts to thousands of streams, so
the 1000- and 5000-subscriber rows vary widely from run to run.

| Workload | Single node | Three-node cluster |
| --- | --- | --- |
| Publish, 1 subscriber, HTTP POST | 44.6k/s | 37.7k/s |
| Publish, 1 subscriber, stream, 1 / 4 clients | 562k / 666k/s | 369k / 413k/s |
| Fan-out to 1000 subscribers, HTTP POST / stream | 1.33M / 1.08M events/s | 1.81M / 2.64M events/s |
| Fan-out to 5000 subscribers, HTTP POST / stream | 333k / 967k events/s | 515k / 983k events/s |
| Latency, HTTP POST, p50 / p99 | 51 µs / 134 µs | 110 µs / 435 µs |
| Latency, stream, p50 / p99 | 45 µs / 102 µs | 105 µs / 248 µs |
| Service → service | 533k/s | 366k/s |
| 4 services → 1 service | 638k/s | 406k/s |
| Service → 10 services, one topic | 340k publishes/s, 3.28M events/s | 278k publishes/s, 2.70M events/s |
| Service → 1000 services, a topic each, 1 / 4 clients | 197k / 302k/s | 221k / 276k/s |
| Service → service, 2 / 3 copies | | 307k / 300k/s |
| Service → service latency, p50 / p99 | 47 µs / 130 µs | 109 µs / 268 µs |

An idle node takes 14 MiB (17–18 MiB in a cluster). After every workload, 5000 SSE subscribers included, a single
node held 364 MiB, and each cluster node 140–165 MiB.

## What sets the pace

The hub's own work per update is about a microsecond: token and topic checks, history, and routing. The rest is
moving bytes: a read, a write and a goroutine wake-up per message, unless several messages share them.

- **Publishing.**
  - A POST per update costs a request and a response.
  - A streaming publish reads many updates per read and answers many per write, so one client publishes 20 times as
    fast.
  - With `--history-db` the hub keeps reading the stream while the store syncs, and answers each batch once it is
    stored. The deletes that keep the file the size of the history go in the same transactions as the inserts.
  - One stream publishes its updates in order, one at a time. To fan out to thousands of subscribers as fast as
    possible, publish from several clients: one stream feeding 5000 subscribers in Docker delivers 1.8M events/s,
    eight POSTers 4.3M.
  - Go's HTTP/2 (h2c, `-stream-proto h2c`) costs more per message than HTTP/1.1 in memory: about 200k/s against 350k/s
    from one client in earlier runs. Once updates are stored, the two are close.
- **Delivery.**
  - Each subscriber has a goroutine and a queue of its own, so writes to subscribers run on every core.
  - A publish only queues the update for each subscriber, about 85 ns each.
  - A stream that has just written several events waits 200 µs before its next write, so a busy stream writes many
    events at once. A quiet stream writes each event at once, so its latency does not change.
  - While the hub queues more than 50k events a second, a stream whose writes carry few events waits up to 2 ms
    (until 64 events are queued) before writing. Thousands of streams each writing every event on its own would spend
    the machine on system calls.
- **Many topics or one.** What the hub pays for is publishes and writes, not topics or subscribers.
  - One update to 1000 subscribers on a topic is one publish, and the same bytes written to 1000 streams that each
    carry many events per write.
  - 1000 updates to 1000 topics with one subscriber each is 1000 publishes, and each write carries about one event.
  - So "1000 services, a topic each" runs at about the "service → service" rate, while fan-out from one topic
    delivers millions of events a second.
- **Clusters.**
  - Every update goes to every node.
  - Each peer has one batch in flight at a time; what is published while it waits for the acknowledgement goes in
    the next batch, so a busy node sends many updates per message.
  - The receiving node applies each peer's batches on a goroutine of its own, and acknowledges a batch once it is
    applied, so a slow reader there slows that peer's replication instead of losing events.
- **Many subscribers on one machine.** The subscriber processes are the limit, not the hub. On macOS the loopback
  network has stalled for seconds under bursts of hundreds of thousands of events, with nothing lost. The benchmark
  waits `-quiet` (10s by default) for a subscriber that stops receiving before it counts what is missing.
