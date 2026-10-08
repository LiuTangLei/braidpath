# BraidPath

**Weave paths. Repair loss. Keep latency in check.**

[中文](README.md) · [Architecture](docs/architecture.md) · [Validation](docs/validation.md) · [Roadmap](docs/roadmap.md)

BraidPath is a new Rust project exploring **forward error correction, client-side interface aggregation, and same-location relay servers** to reduce loss-induced recovery delays and tail latency while using available path capacity.

**Status: an executable algorithm foundation, not a deployable tunnel.** There are no client, server, or relay binaries yet. No real-network performance gain has been established for this project.

## The topology

A client can reach the main server directly or through several nearby relays. Each local interface can form candidate paths to each entrance. The relays act as logical server-side entrances, approximating the path choices of a server with multiple interfaces. Return traffic must follow its corresponding entrance.

- **One interface, one entrance:** FEC still has a role on a single path.
- **One interface, several entrances:** exploit route diversity where it actually exists.
- **Several interfaces, one entrance:** use multiple client access links.
- **Several interfaces, several entrances:** schedule across the interface–entrance combinations.

Entrance count is not independent capacity. Paths can share the last mile, transit routes, relay backhaul, or the main server's uplink. FEC cannot remove congestion, guarantee delivery, or create bandwidth beyond those bottlenecks.

## Run the foundation

Rust 1.85 or newer; the current core has no third-party dependencies.

```bash
git clone https://github.com/LiuTangLei/braidpath.git
cd braidpath
cargo test --all-targets --locked
cargo run --locked --example loss_recovery
```

The example enumerates one interface and three logical entrances **in memory**, distributes four originals and one XOR repair symbol in round-robin order, erases one original, and recovers all four payloads. It opens no sockets and measures no latency.

## Implemented versus planned

| Implemented | Planned |
| --- | --- |
| Systematic XOR `k + 1`, one erasure per block | Multi-erasure / adaptive / sliding-window FEC |
| Immediate original emission and caller-driven deadline flush | Runtime timers and measured latency targets |
| Unequal payload lengths, per-block deduplication | Session-wide replay protection and stream reassembly |
| Interface × entrance identifiers | OS interface binding and bidirectional relays |
| Deterministic recovery and boundary tests | Live path measurement, scheduling, congestion control |
| Dependency-free codec foundation | Authentication, encryption, retransmission, TCP/UDP tunneling |

The XOR implementation is a baseline, not a final algorithm commitment. Sparse traffic produces short blocks and potentially high repair overhead. There is no hard redundancy budget yet. Coding repairs erasures; it is not an integrity or authentication mechanism.

## Design direction

Original packets should leave immediately. Repair work belongs at the aggregate session layer, where packets can be recovered across paths. Scheduling and repair are separate decisions. We intend to measure queueing, delivery latency, loss, path health, actual wire overhead, goodput, completion, and CPU in both directions.

We draw inspiration from [Aggligator](https://github.com/remoc-rs/aggligator), particularly its link abstraction, dynamic link lifecycle, and observability. BraidPath starts with a new codebase and history; it does not depend on Aggligator or KCP. An earlier experimental fork had `kcp` in its name, but the relevant experiments concerned general multipath aggregation and cross-path recovery, not a KCP-based product.

Test records, run results, and historical experiment notes stay local. This repository contains source code, automated tests, and validation methods. Architecture and development documents are currently in Chinese.

## Contributing

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
```

Start with reproducible scenarios and small, measurable changes. Clearly separate simulated results, loopback tests, and real-network evidence. Never commit infrastructure addresses, credentials, or raw private captures.

Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
