# Roadmap

The initial implementation prioritizes latency and useful throughput, with BBR as the default controller. CPU-efficiency tuning comes later; correctness and bounded queue/memory behavior remain required.

The stages below are ordered by dependency. Each stage produces a usable baseline or an explicit decision before increasing scope. Checked items describe the current source tree; unchecked items are future work. Run records remain local.

## M0 — Algorithm foundation

- [x] Small independent Rust crate, English default README and an additional translation.
- [x] XOR `k+1` codec with immediate original emission and caller-driven block deadline.
- [x] Bounded per-block decode state and deterministic erasure/reordering/duplicate cases.
- [x] Interface–entrance identity model and in-memory example.
- [x] Architecture, validation methods and cross-platform codec CI.
- [x] Source-based carrier design: Xray as a reference only, independent Rust implementation and explicit datagram/stream boundaries.

**M0 boundary:** codec correctness alone does not establish network behavior. The current experimental runtime also implements the subset of later stages checked below; no whole-stage performance or deployment exit gate is claimed.

Current protocol, commands and limits: [experimental runtime](runtime.md). Checked implementation work is distinct from completing each stage's exit gate.

## M1 — Secure single-path datagrams

- [x] Implement an experimental bounded wire format (not yet frozen): session epoch, direction, data/flow IDs, source/repair metadata, limits and version negotiation.
- [x] Select/pin Quinn and TLS dependencies for the engineering baseline; verify supported Rust versions and platforms.
- [ ] Keep the aggregate core independent of the carrier; define authenticated-record, size, bounded-send and observation contracts.
- [x] Prototype native HTTP/3 plus HTTP Datagrams with an ordinary website handler, authenticated request/context mapping and server identity verification; evaluate compatible Rust libraries without adding an Xray dependency.
- [ ] Pass the carrier semantics/cost gate against plain QUIC; trace effective settings, queue ownership, PMTU, fingerprint limitations and independent-peer behavior before selecting the deployment candidate.
- [ ] For intended filtered deployments, start the reachability comparison before selecting a default carrier; website behavior alone cannot establish reachability.
- [x] Implement authenticated session admission with operator-managed credentials and 0-RTT disabled.
- [x] Build minimal client/server CLI for QUIC DATAGRAM echo and load generation; FEC-off first, then XOR with canonical records.
- [x] Implement timer-driven block closing, path-size checks, bounded send/receive queues, expiry and session deduplication.
- [x] Separate original packet arrivals, FEC recovery, deduplication and UDP application acceptance in bounded per-direction/per-path counters and JSON statistics. Receiver feedback remains M2.

**Exit gate:** the single-path checks in the [validation plan](validation.md#2-secure-single-path-gate) pass under bounded packet-level impairment. The selected HTTP/3 candidate also passes the [carrier gate](validation.md#carrier-semantics-and-cost-gate). The service is explicitly unreliable datagrams with optional FEC. No custom reliable byte-stream claim yet.

**Do not advance if:** authentication, queue behavior, metadata validation or MTU adaptation cannot be demonstrated. Resolve the adapter/runtime choice before adding more paths. Controlled-network development can continue while field measurements are pending, but cannot establish or finalize a deployment default.

## M2 — Real interfaces and bidirectional relay entrances

- [x] Select the relay profile: fixed-destination L4 entrances for the web-facing candidate; authenticated TURN/UDP remains an optional controlled-network alternative.
- [x] Enforce the configured main service address/port, bounded relay state/rate and return mapping. Keep proxy authentication and TLS termination on the main server for the web-facing profile.
- [ ] Verify datagram boundaries, PMTU and batching; if TURN is selected, implement its socket adapter, authenticated allocation and refresh lifecycle.
- [x] Implement explicit Linux interface binding and a default-route mode.
- [ ] Validate multiple physical interfaces and platform-specific binding independently.
- [ ] Add session joins, path generations, bounded reconnection and control-operation replay across surviving paths.
- [x] Add a round-robin scheduler, bounded queues, per-path transport observations and per-direction aggregate pacing.
- [x] Add opt-in authenticated receiver feedback with bounded per-path gap and delay-change estimates.
- [ ] Add delivery-time scheduling and explicit bottleneck-group caps; demonstrate competition fairness.
- [ ] Validate 1×1 → 1×3 → 2×1 → 2×3, including single-interface operation, relay-only operation and path/relay outages.

**Exit gate:** native captures prove both directions use the requested interface/entrance; queues and state remain bounded; the multi-entrance shared-bottleneck competition test passes for the enabled policy. Datagram loss during outage remains visible.

**Do not advance if:** path identity collapses at a relay, binding silently uses another route, or multiple entrances merely win by increasing their share of a common bottleneck. Keep one active data path per affected group while resolving it.

## M3 — Budgeted recovery and measured scheduling

- [x] Bound generated-record repair credit before increasing parity or adding copies.
- [ ] Enforce redundancy ratios on actual admitted/sent originals rather than generated records, including queue expiry.
- [ ] Measure completion-cost scheduling against the simple M2 baseline; keep path probing bounded.
- [ ] Compare XOR with small-block multi-erasure coding; evaluate sliding windows only if block delay or burst loss justifies them.
- [ ] Handle sparse traffic, correlated losses, unequal RTTs and packet packing explicitly.
- [ ] Add delayed copies only as a separately measured, budgeted policy.
- [ ] Meet the applicable datagram, capacity, fairness and resource gates in both directions; record negative scenarios locally too.

**Exit gate:** useful delivery improves in the stated scenarios within the same total resource envelope. The selected default remains simple when an optimization fails its gate.

**Boundary:** lower mean RTT or a higher FEC recovery count alone does not establish lower application tail latency.

## M4 — Reliable flows and application adapters

- [ ] Selective application ACKs, bounded retransmission and receiver credit, without synthesizing QUIC ACKs for FEC recovery.
- [ ] Per-flow offsets, reassembly bounds, FIN/final-offset acknowledgment, reset and half-close.
- [ ] Session survival while paths remain, bounded all-path reconnect and explicit terminal failure.
- [x] UDP forwarding to a fixed target with explicit 1,000-byte maximum messages.
- [ ] TCP forwarding on the reliable-flow service.
- [ ] Compare FEC with the no-FEC reliable baseline; verify bytes, completion, timeout rates and latency under bulk/interactive coexistence.

**Exit gate:** reliable-stream correctness and the selected latency/goodput targets pass. A UDP delivery metric cannot substitute for this gate.

## M5 — Deployment readiness

- [ ] Pass the deployment reachability gate for every claimed filtered profile; no inference from encryption, port choice or FEC alone.
- [ ] Stable client/server CLI and relay provisioning instructions, configuration validation and wire-version policy.
- [ ] Credential lifecycle, destination authorization, quotas and bounded resource behavior during hostile or accidental overload.
- [ ] Native Linux/macOS/Windows network acceptance, installation packages and operator metrics.
- [ ] Sustained operation, restart/upgrade/shutdown behavior and reproducible performance acceptance for supported deployment profiles.

**Exit gate:** operators can deploy a documented, authenticated topology and recognize unsupported or degraded conditions without relying on private implementation knowledge.

Automatic shared-bottleneck detection and coupled congestion control are separate research tracks. TUN, mobile packaging and general fragmentation are deferred until a concrete need justifies them. A native HTTPS stream fallback or a datagram-preserving mask moves into the deployment track when reachability requires it, with separate latency and overhead acceptance. REALITY/XHTTP inform those trade-offs; Xray integration and protocol compatibility are outside the project scope. The controlled-network baseline cannot substitute for deployment-specific reachability acceptance.
