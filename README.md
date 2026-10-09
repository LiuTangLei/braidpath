# BraidPath

**Weave paths. Repair loss. Keep latency in check.**

[![CI](https://github.com/LiuTangLei/braidpath/actions/workflows/ci.yml/badge.svg)](https://github.com/LiuTangLei/braidpath/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[简体中文](README.zh.md) · [Run it](docs/runtime.md) · [Architecture](docs/architecture.md) · [Carrier design](docs/transports.md) · [Validation plan](docs/validation.md) · [Roadmap](docs/roadmap.md)

BraidPath is a Rust multipath transport project combining **forward error correction (FEC), client interface aggregation, and nearby relay entrances**. Its goal is to adapt throughout a long-running session: combine independent path capacity when routes are clear, and preserve useful low-latency delivery when routes become congested.

“Braid” means weaving several imperfect paths into a more resilient connection.

> **Status: experimental UDP tunnel.** The client, main server and fixed-target relays run over real HTTP/3 and HTTP Datagrams. Opt-in `--adaptive` adds per-path pacing, independent health probes, sender-age admission and bounded outage recovery. These mechanisms are implemented; sustained WAN benefit and deployment readiness are not established. Round robin and the existing XOR settings remain the defaults.

## One interface works. Several can contribute.

The topology is:

```mermaid
flowchart LR
    App[Application] --> C[BraidPath client]
    C --> E[Ethernet]
    C --> W[Wi-Fi or cellular - optional]
    E --> M[Main server]
    E --> R1[Nearby relay A]
    E --> R2[Nearby relay B]
    W --> M
    W --> R1
    W --> R2
    R1 --> M
    R2 --> M
    M --> S[Destination service]
```

Nearby relays provide **logical server-side entrances**, giving one main server multiple route choices. Relays forward encrypted traffic; the client and main server own the aggregate session. Each transport path returns through its own entrance. Application downlink traffic is scheduled independently of uplink traffic.

| Client interfaces | Server entrances | Intended use |
| --- | --- | --- |
| One | One | FEC on a single path |
| One | Several | Route diversity where it exists |
| Several | One | Aggregate client access links |
| Several | Several | Schedule across interface–entrance pairs |

Entrance count is not independent capacity. Paths may share the last mile, transit routes, relay backhaul, or the main server's uplink. A single interface cannot exceed its access bandwidth by adding entrances.

## Design priorities

- **Repair at the aggregate layer.** Recover across paths without waiting for retransmission when enough timely repair information is available.
- **Keep original data moving.** The encoder emits originals immediately; network transmission still obeys queue limits and congestion control.
- **Treat direction and path quality separately.** Upload quality is not evidence of download quality. A slow path must not create unbounded reordering.
- **Probe without sacrificing an original.** Adaptive mode sends authenticated health probes even while application traffic is idle; probes and feedback share the same traffic budgets as business data.
- **Spend redundancy deliberately.** Measure FEC, retransmission, control traffic, and actual wire cost separately.
- **Make progress measurable.** Compare application P95/P99, deadline misses, completion and goodput under matched conditions. CPU-efficiency optimization comes later.

BBR is the only runtime congestion controller. The initial priority is latency and useful throughput; CPU-efficiency tuning is deferred. Adaptive pacing sets an additional operational allowance above each connection's independent congestion control. Growth requires actual use of that allowance; current local RTT and finalized interval loss can reduce the pace while fresh health keeps a path eligible. A low application-limited delivery rate does not establish a capacity ceiling.

The default adaptive target is 20 ms of local sender age and an added-delay control objective. Admission uses local ingress age alone. Health requires positive delivery on that path or a valid probe reply; fresh reports of complete loss through another path do not prove reachability. Stale or confirmed zero-delivery paths become probe-only. Same-generation recovery retains learned pace, while a new generation starts a new search. A pending queue-drain recovery survives the gap between RTT observations and rate-control ticks. Rate-change records preserve the RTT inputs and mixed baseline actually used, alongside diagnostic per-source observed minima. Original-only adaptive traffic can also test a higher allowance when loss has stalled a busy, low-delay path. A trial lasts at most four seconds and must demonstrate increased receiver service before its pace is retained; shared-group and aggregate limits still apply. Native probes report both 100 ms and 150 ms arrival rates over the complete requested population. These are application validation thresholds, separate from the 20 ms queue objective and from any cross-host latency guarantee. The mixed RTT baseline can still misclassify estimator switching as queueing, the minimum has no aging, and permanently reduced capacity can still receive bounded upward trials. See the [adaptive policy](docs/runtime.md#adaptive-mode).

Each interface–entrance pair owns an end-to-end Quinn/rustls connection to the main server. HTTP/3 handles ordinary requests and authenticated session admission; unreliable HTTP Datagrams carry aggregate records. Relays forward encrypted packets to a fixed destination.

**Xray is a design reference only:** no Xray dependency, sidecar or protocol compatibility. Stock Quinn does not imitate browser fingerprints, and this prototype provides no TCP fallback. An ordinary website response does not establish resistance to network filtering. See the [carrier analysis](docs/transports.md).

## Build and run

Rust 1.88 or newer:

```bash
git clone https://github.com/LiuTangLei/braidpath.git
cd braidpath
cargo build --release --locked
./target/release/braidpath --help
cargo test --all-targets --locked
```

Follow the [runtime guide](docs/runtime.md) for credentials, local forwarding, multiple entrances and measurement. The independent in-memory codec example remains available with `cargo run --locked --example loss_recovery`.

| Capability | Status |
| --- | --- |
| XOR `k + 1`, immediate originals, timed partial blocks | Implemented; at most one missing original per block |
| HTTP/3 website, verified server identity, authenticated session joins | Implemented experimental profile |
| Bidirectional FEC, session deduplication, UDP forwarding | Implemented; messages up to 1,000 bytes |
| Fixed-target opaque relays with source allowlists | Implemented |
| Interface × entrance paths | Linux interface binding; default-route sockets on other platforms |
| Round robin and optional quality-weighted scheduling | Implemented baselines; weighted service is charged on actual admitted bytes |
| Per-flow queues, original-ingress deadlines, admission-based repair credit | Implemented bounded mechanisms |
| Adaptive pacing, sender-age admission, idle health probes and feedback v2 | Implemented opt-in mode; performance acceptance pending |
| Aggregate and explicit bottleneck-group caps | Implemented; not automatic bottleneck detection or fairness proof |
| Startup/outage recovery and explicit session-epoch replacement | Implemented in adaptive mode; bounded backoff and server retention |
| Adaptive FEC, multi-erasure coding and coupled congestion control | Deferred or separate research work |
| Reliable streams, TCP, TUN, stream fallback, browser fingerprint shaping | Planned or deferred |

XOR cannot generally recover an entire failed path. Sparse traffic may exhaust the repair budget; FEC does not guarantee delivery. `--fec 4`, `--block-ms 3` and the 30% repair budget are unchanged; the new mechanisms do not establish a new FEC default. Multiple connections can compete unfairly at a shared bottleneck even with explicit group caps. Multi-interface capacity, competition fairness, independent HTTP/3 interoperability and deployment reachability remain separate acceptance gates.

## Inspiration

We draw inspiration from [Aggligator](https://github.com/remoc-rs/aggligator), especially its link abstraction, dynamic link lifecycle, and observability. BraidPath implements its own aggregation and recovery core.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Start with small, reproducible changes and explicit acceptance criteria. The [roadmap](docs/roadmap.md) separates codec correctness, network integration, multipath behavior, performance, and deployment readiness.

Test records and run results stay local. The repository contains source code, automated tests, and validation methods. See [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
