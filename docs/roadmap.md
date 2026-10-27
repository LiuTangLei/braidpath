# Roadmap

The initial implementation prioritizes latency and useful throughput, with BBR as the default runtime congestion controller. CPU-efficiency tuning comes later and is not an acceptance gate for the current increment; correctness and bounded queue/memory behavior remain required.

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
- [x] Add authenticated session joins, path generations and opt-in bounded source-port rejoin; generation replay and old-handler cleanup are validated.
- [x] Add opt-in adaptive startup/outage reconnection, bounded retry concurrency/backoff, a highest-generation replay guard and explicit fresh-session replacement after server expiry.
- [ ] Add reliable control-operation replay across surviving paths where later reliable operations require it.
- [x] Add a round-robin scheduler, bounded queues, per-path transport observations and per-direction aggregate pacing.
- [x] Add opt-in authenticated receiver feedback with bounded per-path gap and delay-change estimates.
- [x] Add opt-in quality weights with nonzero probe shares; keep round robin as the default pending paired field comparisons.
- [x] Charge weighted service to actual admitted bytes, including fallback paths; failed attempts spend no service credit.
- [x] Add explicit per-direction bottleneck-group caps, defaulting to one group per configured interface, with probes/feedback/repair included in the same budgets.
- [ ] Demonstrate shared-bottleneck competition fairness; group caps alone do not complete this gate.
- [ ] Validate 1×1 → 1×3 → 2×1 → 2×3, including single-interface operation, relay-only operation and path/relay outages.

**Exit gate:** native captures prove both directions use the requested interface/entrance; queues and state remain bounded; the multi-entrance shared-bottleneck competition test passes for the enabled policy. Datagram loss during outage remains visible.

**Do not advance if:** path identity collapses at a relay, binding silently uses another route, or multiple entrances merely win by increasing their share of a common bottleneck. Keep one active data path per affected group while resolving it.

## M3 — Budgeted recovery and measured scheduling

- [x] Enforce bounded repair credit on actually admitted original HTTP-datagram bytes; pre-admission expiry cannot mint credit, and repairs prefer another eligible path when available.
- [x] Preserve each original's local ingress deadline across input/symbol queues, use local age alone at adaptive admission, bound per-flow/repair queues, and separate receiver repair waiting from unseen-original validity.
- [x] Add an opt-in per-path adaptive operational allowance with current local RTT, finalized interval loss, receiver byte rates and actual-admission accounting; growth requires an exercised allowance and application-limited samples do not become capacity ceilings.
- [x] Keep fresh paths eligible during ordinary congestion, retain learned pace across same-generation stale intervals, and use bounded recovery trials followed by lower-gain exploration near retained delivery; a new generation resets its controller.
- [x] Add independent authenticated idle probes, positive-delivery health freshness separate from all-loss report freshness, bounded early exclusion of sampled zero-delivery paths, and aggregate/group feedback reservation.
- [x] Preserve pending drain restoration across RTT/control-tick boundaries; add deterministic observation-gap, all-loss alternate-path report, drift, repeated-evidence, overhead and delayed-feedback capacity-step regressions.
- [x] Integrate admitted-byte utilization against the rates active within each control window; separate immediate safety brakes from persistent caution qualified at the first pressure observation, with cold-pause/delayed-loss, changing-allowance and loss-only regressions.
- [ ] Validate qualified RTT-baseline refresh and permanent capacity changes over long runs: continuous light service may retire a stable offset, while local backlog or blocked transport must preserve pressure; retained delivery can still motivate bounded upward trials after a permanent reduction.
- [ ] Validate pressure-episode retirement against further delayed-loss patterns: a new clear finalized interval currently has no sequence watermark proving that all losses preceding the episode boundary have finalized.
- [ ] Accept adaptive scheduling against round robin, the quality baseline and the best single path under a matched total budget. Sustained clean → congested → recovered operation, deadline success and unconditional tails must pass in both directions before changing a default.
- [ ] Compare XOR with small-block multi-erasure coding only in a later coding phase; Reed–Solomon and sliding-window work are deferred until a demonstrated loss/recovery limitation justifies them.
- [ ] Complete sparse/bursty traffic, correlated losses, unequal RTTs and packet-packing acceptance. Implemented idle probes and queue limits do not by themselves pass these scenario gates.
- [ ] Add delayed copies only as a separately measured, budgeted policy.
- [ ] Meet the applicable datagram, capacity, fairness and resource gates in both directions; record negative scenarios locally too.

**Exit gate:** useful delivery improves in the stated scenarios within the same total resource envelope. The selected default remains simple when an optimization fails its gate.

**Boundary:** lower mean RTT or a higher FEC recovery count alone does not establish lower application tail latency. The 20 ms local sender target is separate from the prospective mixed-flow 100 ms application round-trip screen: at least 95% on-time delivery in clean/recovered windows, 90% in the impaired window including transition, and 90% of matched-baseline target goodput in clean/recovered windows. This validation objective is not a hard cross-host SLA or an acceptance result.

**Current increment:** adaptive mode is experimental and opt-in. Round robin, XOR block size 4, 3 ms block closing and the existing 30% repair setting remain unchanged defaults. The source implements the mechanisms above; no sustained WAN, capacity-aggregation or deployment result is implied by a checked implementation item.

## M4 — Reliable flows and application adapters

### v0.5.8 — Fixed-target TCP mesh entry (experimental development)

- Expose the existing fixed-target aggregate TCP engine through `mesh-server
  --tcp-target` and `mesh-client --tcp-listen`.
- Reuse standard member discovery, exit binding, relay leases and path health;
  advertise the optional `fixed-tcp-stream-v2` capability without the target address.
- Keep fixed destinations separate from addressed proxy permission. Preserve
  existing UDP/proxy CLI defaults and congestion, repair and scheduling behavior.
- Cover bootstrap-through-another-member, one target socket, half-close, relay
  interruption and graceful lease cleanup with real loopback processes. WAN
  small-request latency and application TLS acceptance remain deployment checks.

### v0.5.7 — Transfer attribution (experimental development)

- Group native path and application counters on common sampling boundaries,
  including startup, idle baselines, path replacements and the final tail.
- Diagnose receive/send queue pressure and TCP extension deltas without modifying
  services, global limits, nstat history or the original low-latency chain.
- Reject incomplete legacy windows instead of understating startup loss or
  overstating byte efficiency. Record the target and connection mode explicitly.
- Keep congestion, FEC, repair and scheduling behavior from v0.5.6. Fixed-source
  evidence determines subsequent throughput changes; browser acceptance is separate.

### v0.5.6 — Shared-uplink upload control (experimental development)

- Match finalized loss to bounded, generation-scoped admission cohorts, so
  block-upload idle gaps cannot teach a random-loss floor or collapse a cap.
- Require binding trial evidence, preserve short idle gaps, and wait for fresh
  feedback after growth. Native common-loss hints only protect early service;
  receiver/finalized feedback still owns aggregate cap and floor decisions.
- Expose sender path/guard/FEC decisions and add a block/receipt upload workload
  to the shared-policer laboratory. Keep failed and intermediate measurements.
- Respect the local DATAGRAM send-buffer capacity when advertising record size.
- Public-network upload/download and low-stall acceptance remain pending.

### v0.5.5 — Native transport pressure (experimental development)

- Distinguish an occupied application pacing allowance from native QUIC
  DATAGRAM buffer pressure so the local allowance does not inhibit its own
  recovery. Keep writer admission, queued-excess and congestion safety checks.
- Publish writer backlog and native DATAGRAM space in existing server path logs.
- Regression covers paced-only occupancy and genuinely full native buffers;
  manual throughput acceptance remains pending.

### v0.5.4 — Negotiated reliable record sizing (experimental development)

- Negotiate larger TCP records while preserving legacy peer and raw UDP limits.
- Fit records to connected paths' current QUIC DATAGRAM budgets, including HTTP,
  measurement and FEC overhead; split oversized retained repairs after a smaller
  budget, preserving byte offsets, FIN and stale-callback safety.
- Bound large-record decoder state by 8 MiB and expose segment-size/split counters.
- Limit native fast recovery to measured congestion delivery; ordinary monitored
  growth and the existing congestion brakes remain active.
- Integrity, failure recovery and resource tests pass. WAN gain and browser
  acceptance remain distinct from implementation and deployment status.

### v0.5.3 - Symmetric reliable receive bursts (experimental development)

- Match reliable server receive queues to the existing bounded client queue;
  keep raw UDP latency queues and all sender admission limits unchanged.
- Include session identity, application pacing, byte progress and receiver
  overflow counters in ordinary status observations. Detailed debug snapshots
  remain optional; idle stream progress does not generate extra rows.
- Regression covers a four-reader burst, finite queue capacity, ordered draining,
  channel closure and preservation of the raw UDP queue budget. Browser speed
  and stability still require separate acceptance.

### v0.5.2 — Reused-session recovery and bounded hole probes (experimental development)

- Restart an idle reliable path from its original native window when new demand
  arrives under clear current conditions; retain tested loss ceilings and all
  admission budgets.
- Probe persistent bulk SACK head holes with one bounded extra copy per RTT;
  cancel resolved holes and preserve the original loss timer after a probe drop.
- Qualify shared loss using measured active paths, while requiring corroboration
  from at least two routes in a multi-route session.
- After a binding cut reduces loss but changes its startup delivery reference,
  permit one fresh, bounded follow-up trial rather than immediately reopening
  at the old peak. Preserve post-cut watermark and two-cohort validation.
- Add debug pacing decisions and bounded per-exit diagnostic snapshots outside
  network workers. Controlled transfer and browser acceptance remain separate.

### v0.5.1 — Correct measurement and coordinated recovery (experimental development)

- Keep high-rate reordered measurement symbols in a fixed-capacity tagged bitmap;
  expose sequence-pressure finalizations separately from the normal loss grace.
- Keep native-window recovery within active loss trials and learned pace ceilings.
- Judge shared-loss trials using receiver-clock byte progress. Delayed finalized
  loss is not multiplied by current local admissions to infer delivery; changing
  or incomplete windows cannot establish a random-loss floor.
- FEC strength and wire profiles are unchanged. Throughput and stability remain
  subject to separate bounded WAN acceptance; no release claim follows from tests.

### v0.5.0 — Aggregate DATAGRAM TCP (experimental development)

- [x] Keep leaderless mesh membership, authentication, exit selection and one
  SOCKS5 listener per exit; move TCP payload to the aggregate DATAGRAM engine.
  Each application connection uses one target TCP socket, with byte-offset SACK,
  fine-grained cross-path repair and receiver-feedback-driven automatic FEC.
- [x] Introduce ALPN `braidpath-stream/2` and capability `proxy-stream-v2`.
  Both endpoints require an upgrade. Retire the former TCP record-RPC profile
  and its rolling compatibility path; native SOCKS UDP keeps `braidpath-proxy/1`
  and no FEC. No user-facing transport switch is added.
- [x] Share TCP admission and retained-data budgets across all sessions: 256
  flows, separate 32 MiB TX/RX shared credit, and a 128 KiB progress reserve per
  flow and direction. Retain existing host rate and DNS-worker limits.
- [x] Preserve remote destination errors and the real SOCKS bound address;
  enforce cancellation, half-close, explicit session termination and old-generation
  isolation. Bound replay controls and closed-stream history independently of
  output backpressure.
- [x] Validate byte integrity, disrupted-path recovery, cancellation and resource
  reclamation through the integrated frontend; remove obsolete TCP RPC state.
- [x] Pass the registered paired single-path WAN gate for goodput, longest stalls
  and variation. Native allowance renewal avoids a second startup bottleneck;
  bounded RTT-probe pauses avoid treating native flight drains as new capacity.
- [x] Bound retained-credit and out-of-order range metadata across sessions;
  preserve hole progress and reclaim drained caches.
- [ ] Measure useful multipath gain separately from single-path transport
  performance; no linear scaling is assumed. Complete deployment acceptance.

### Earlier proxy iterations — historical, superseded TCP architecture

The entries below record completed earlier implementations. Their per-path
reliable-stream/record-RPC TCP behavior is superseded by v0.5.0. They do not
describe the current TCP profile or provide current WAN acceptance evidence.

- [x] v0.4.3: replace adjacent-ACK BBR sampling with per-packet flight delivery
  context, retain application-limited samples correctly, and correct initial RTT
  probing, queue-drain phase advancement and ACK-burst window aging. Inline
  snapshots are bounded and released with native packet recovery. Proxy clients
  return to BBR. Download scheduling combines concurrent payloads in one path
  service window instead of measuring each request's fraction of capacity;
  short buffered bursts cannot replace the sustained estimate. Deterministic
  regressions cover compressed/reordered ACKs, stretched ACKs, idle restart,
  concurrent service, source pauses, cancellation and path replacement. Optional
  paths prepare authenticated connections in the background; an unresponsive cold
  relay cannot hold downloads while a ready path is available. A regression
  covers delivery, target-free preparation and shutdown cleanup. These
  implementation checks do not establish a WAN throughput or stability gain.

- [x] v0.4.2: account for queued download work before a response arrives, so
  expected-arrival scheduling sees requests awaiting connection/stream admission
  and reply headers. A withheld-response regression covers admission-time
  accounting and cancellation cleanup. Active proxy transports expose bounded
  native counters at info level for matched single-connection investigations.
  The bundled BBR maximum-bandwidth filter now ages lower delivery samples;
  deterministic regressions cover peak expiry and application-limited sampling.
  Proxy uploads use CUBIC after bounded sender-loss comparisons; the mesh-server
  download policy and UDP-tunnel default remain BBR. This is a directional
  congestion policy, not a claim of a universal WAN speed gain.
- [x] v0.4.1: fix aggregate TCP admission and scheduling. Exhausted exit upload
  memory or handler slots return a retryable busy reply instead of resetting the
  flow or failing the path; the upload record at the delivery cursor and one
  download record per flow have reserved credit; download blocks are charged by
  size. Exit capacity is 256 aggregate flows. Fixed-stride download lanes are
  replaced by contiguous ranges assigned by expected arrival, latency-first
  future-data waits, and record-level head re-requests on another path. Proxy
  paths report health to entrance selection. Local tests cover busy replies,
  head admission, stalled consumers, 96 idle flows, head re-requests during a
  blackhole and relay replacement; WAN speedup is not yet measured.
- [x] v0.4.0: replace per-flow single-path proxy TCP with sequenced record RPCs
  over multiple cooperating server paths to one selected exit and one target TCP
  socket. Separate acceptance, delivery progress and control quotas; bound record
  replay/reassembly; preserve half-close; quarantine and probe stalled paths.
  Focused tests cover upload/download relay loss, recovery, reset, shutdown and
  abandoned-flow resource reclamation. WAN speedup requires a matched single-TCP
  measurement; independent concurrent flows do not establish this gate.
- [x] v0.3.5: scale Quinn's stream span limit with the flow-control-bounded
  unread extent, so loss holes in a 16 MiB proxy window are not treated as a gap
  flood. Gap-flood rejection is retained at the same density. Proxy sockets also
  request larger send buffers, and granted sizes, rejected spans and local UDP
  send errors are logged by default. Local regressions pass; WAN upload is not
  yet re-verified.
- [x] v0.3.4: prevent contiguous mixed-size stream backlogs from triggering
  Quinn's fragment guard, retaining the real gap limit and flow-control budgets.
  Proxy endpoints request larger UDP receive buffers within OS limits.
- [x] v0.3.3: 10 Gbit/s default operational ceiling, larger authenticated proxy
  flow-control windows, and rate-proportional burst credit for high-rate traffic.
  Focused local regression checks pass; this does not establish WAN throughput.
- [x] v0.3.2: authenticated QUIC TCP/UDP proxy with local SOCKS5, fixed exits,
  concurrent use of selected exits, remote DNS, half-close and bounded cleanup.
  This uses QUIC's native reliable streams; application-level multipath FEC
  reliability remains the separate work below. See [proxy operation](mesh.md).
- [x] Selective application ACKs, bounded retransmission and receiver credit over DATAGRAMs, without synthesizing QUIC ACKs for FEC recovery.
- [x] Per-flow offsets, reassembly bounds, FIN/final-offset acknowledgment, reset and half-close.
- [x] Preserve reliable-flow acknowledgment/reassembly state across surviving-path changes; terminate old flows explicitly when a new aggregate session generation is required.
- [x] UDP forwarding to a fixed target with negotiated messages up to 4,096 bytes, bounded fragmentation/reassembly and whole-message input admission.
- [x] TCP forwarding on the reliable-flow service.
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
