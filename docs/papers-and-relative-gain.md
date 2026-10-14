# Paper-backed next stage: substantial benefit over the best single connection

## Revised goal

The current user priority is a substantial improvement over a **strong, matched
single-connection control**, not an unconditional 300 Mbps number. Preserve past
300 Mbps results and failures; do not retroactively change their registrations.
For future experiments, propose 1.5x unique application goodput as an initial
engineering target, 2x as an aspirational outcome where resource diversity
permits it, with no worse full-population interaction completion and P95.
Those ratios are engineering choices, not literature guarantees or measurements.
The existing deadline requirement is not waived by relaxing absolute throughput.
Register an explicit minimum on-time fraction (proposed 95% at 200 ms RTT for
the interaction screen); RTT still does not certify the single-way deadline.

RFC 6356 section 2 sets the basic multipath objective of not performing worse
than the best available single path, together with resource-use constraints.
A shared saturated resource can prevent a large bandwidth gain; in that case
evaluate reduced completion failures/tail delay separately rather than declaring
bandwidth aggregation successful. Compare both directions independently.

## Reading notes and what is transferable

### S-EDPF: Low Delay Random Linear Coding and Scheduling Over Multiple Interfaces

Garcia-Saavedra, Karzand and Leith; arXiv preprint 2015, IEEE Transactions on
Mobile Computing journal version 2017, DOI 10.1109/TMC.2017.2686379.

Source read: https://arxiv.org/pdf/1507.08499 (v1, 12 pages).

The scheduler considers random path delay and in-order delivery, jointly with
streaming network coding. The important distinction from our last small-packet
heuristic is that a small mean arrival-time improvement is not the same as lower
expected ordered completion. The paper models prior outstanding packets, not
only the next packet's two alternative delays. Its streaming-code construction
also couples which information to protect with available path opportunities.

Candidate transfer: a bounded per-flow outstanding/decoding-state model and
delay-distribution estimates; separately test choosing an original versus an
innovative repair on a given send opportunity. Do not equate repair arrival with
new useful delivery. The paper assumes no within-path reordering, bounded delay
and locally regular service; some controlled evaluations fix windows to isolate
scheduling. Our public Internet tests retain native congestion control, so its
reported gains cannot be imported as predictions. Our unordered UDP adapter
must not acquire global stream head-of-line blocking merely to mimic its model.

### FlEC: Enhancing QUIC With Application-Tailored Reliability Mechanisms

Michel, Cohen, Malak, De Coninck, Medard and Bonaventure; IEEE/ACM Transactions
on Networking, 31(2), 606–619, April 2023; DOI 10.1109/TNET.2022.3195611.

Paper: https://arxiv.org/pdf/2208.07741
Author implementation: https://github.com/francoismichel/flec

FlEC separates bulk transfer, receive-buffer-limited transfer and deadline-bound
messages. It exposes application information to recovery/stream scheduling and
does not hide transport loss from congestion control. In its bulk use case,
selectively protecting tail flights can avoid spending repair bandwidth on
losses that retransmission would resolve before download completion.

Candidate transfer: explicit message/flow requirements instead of treating every
128-byte packet as urgent, bounded repair budgets chosen by remaining usefulness,
and distinct bulk/interactive policies. It is a PQUIC/picoquic-based stream/FEC
framework, not a drop-in Quinn DATAGRAM plugin. Its ns-3 DCE evaluation runs real
code on simulated links; this is not measured throughput on our WAN topology.
The author repo exposes simple_fec and loss_monitor plus three use-case plugins.
Inspect license and exact revisions before porting code; no code copied here.

### Joint Scheduling and Coding For Low In-Order Delivery Delay Over Lossy Paths With Delayed Feedback

Garrido, Leith and Aguero; 2018 preprint, IEEE/ACM Transactions on Networking
journal version 2019. Source read: https://arxiv.org/pdf/1804.04921 (v2).

The paper models a receiver-side deficit/virtual queue and predicts its state
while feedback is in flight, then chooses information or coded transmissions.
Prediction mistakes have a real throughput cost when redundant repairs replace
information. This is a principled alternative to repeatedly reacting to the
same stale loss sample or holding a fixed repair fraction regardless of need.

Candidate transfer: bounded, timestamped receiver decoding deficit, separated
from sender socket backlog and from recovered-original path quality. Protect
against old-session/replayed reports and cap coding work. Its tractable analysis
has simplified erasure/feedback assumptions, including lossless feedback in the
base model; real missing, bursty and reordered feedback needs explicit tests.

### ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths

Lim, Nahum, Towsley and Gibbens; ACM CoNEXT 2017;
DOI 10.1145/3143361.3143376.
Paper: https://www.repository.cam.ac.uk/bitstreams/9f216be1-4124-4f10-bbad-137e912cc7ff/download

ECF includes queued work and congestion-window information, rather than RTT
alone, to avoid making a fast path idle while a small tail waits on a slow one.
It may wait for a fast path when that finishes earlier, but can use slow paths
when enough work exists to benefit. It is not a rule to always prefer the lowest
RTT, and not a rationale for globally holding every datagram for a fast path.

Candidate transfer: workload-size-aware completion estimates and fast-path
utilization measurements. TCP window/reassembly effects differ from our current
unreliable datagram service, so do not use MPTCP head-of-line savings to explain
our existing raw-datagram missing records. ECF is most relevant to future reliable
per-flow transfer and to bounded bulk chunk assignment.

### Shared-bottleneck work: MPTCP-SBD and SmartSBD

Ferlin et al., Revisiting Congestion Control for Multipath TCP with Shared
Bottleneck Detection, IEEE INFOCOM 2016, DOI 10.1109/INFOCOM.2016.7524599.
Author abstract/bibliography:
https://davidahayes.owlstown.net/publications/35045-revisiting-congestion-control-for-multipath-tcp-with-shared-bottleneck-detection
The original PDF endpoint was unavailable during this reading; only its author
abstract/metadata were inspected. Do not describe it as a full-text replication.

Dong et al., SmartSBD: Smart shared bottleneck detection for efficient multipath
congestion control over heterogeneous networks, Computer Networks 237 (2023),
110047; DOI 10.1016/j.comnet.2023.110047.
Full paper read: https://people.cs.vt.edu/penggao/papers/smartsbd-comnet23.pdf

Both distinguish shared and non-shared bottlenecks rather than coupling every
path equally. SmartSBD uses trained features/classification; that does not make
it automatically calibrated for our hosts, relays, carrier or loss patterns.
Candidate transfer: explicit bottleneck hypotheses, bounded paired interventions
and uncertainty, not an immediate ML dependency or deletion of safety budgets.
Failure correlation and resource-sharing correlation remain different objects.

## Why the rejected runtime was not a reproduction of these papers

The last default-off frontier candidate only changes existing small-lane path
preference when a point delay estimate improves by 2 ms without worse recent
marginal loss. It does not introduce a stochastic ordered-completion objective,
receiver coding deficit, application message deadlines, or a shared-resource
controller. Its failed WAN screen rejects that candidate; it neither validates
nor refutes the above papers. Existing failed run records remain unchanged.

## Required controls for the next independent registration

| Control | Purpose |
| --- | --- |
| One connection on each available route, run separately | Identify strongest matched single route, not just direct or a weak route |
| Several connections on one selected route | Separate connection-count effects from route diversity |
| Multiple routes, no active redundancy | Measure path aggregation before coding effects |
| Same topology plus one declared coding/scheduling treatment | Attribute recovery or scheduling gains separately |
| Minimal equivalent native QUIC DATAGRAM single connection | Guard against an artificially weak overlay single-path reference |

The native-only comparison may differ in overlay policy and therefore belongs
to a separately declared implementation-cost experiment, not the strict
same-policy topology gate below. Report both; never select the weaker baseline.
Reliable TCP/HTTP is a separate service and cannot be ranked against dropped UDP
records as if both completed the same operation.

Use identical total (not per-connection multiplied) limits, hardware, crypto,
payload, warmup/cold-start policy, generator/sink, flow count and coding policy
within a topology comparison. Record unique bytes and actual source spans;
missing requests remain in all-population completion/P95. Keep same-route parallel
connections in the report even when they explain much of the benefit. Do not sum
isolated route rates to claim capacity if those routes share a bottleneck.

Choose the reference from all predeclared single modes, not from whichever makes
the candidate look best. Initial complete mirrored rounds can screen; confidence
in repeatability needs additional independently registered paired runs as in
validation.md. No completed workload is re-run simply to improve its result.

## Implemented acceptance helper

`bench/relative_gain.py` evaluates predeclared normalized observations. The
collector must independently validate source/receiver samples and byte identity
before invoking it; the function is not a raw-data authenticity proof.

It requires one-route/one-connection singles for every candidate route, complete
registered windows, at least two windows per mode, equal conditions and full
request populations. It compares pooled goodput (`sum unique bytes / sum actual
source spans`) against the **maximum** pooled single-mode goodput. Same-route
multi-connection gain is reported separately; it does not prove physical path
independence. No 300 Mbps absolute gate is used for this new target.

If P95 is unresolved because requests are missing, it is not treated as zero or
as an infinity/infinity improvement. Throughput can pass its own target while
joint-quality acceptance remains unproven. Synthetic unit fixtures only test
these rules; they are not measured network results. The legacy campaign adapter
explicitly diagnoses old four-path on/off tests as missing single controls.

## Implementation order

First collect matched single-path and same-route-multiconnection references with
the rejected timing feature off. Inspect actual wire supply and gate ownership.
Then compare a data-carrying second route to a repair/backup role at the same
resource budget, with per-flow/packet reliability semantics made explicit.
Only after those observations choose whether to prototype bounded stochastic
completion scheduling, delayed-deficit repair control, or shared-resource
allocation. Do not introduce all three into one unidentifiable candidate.

References for transport boundaries:
https://www.rfc-editor.org/rfc/rfc6356.html#section-2
https://www.rfc-editor.org/rfc/rfc9221.html#section-5
https://www.rfc-editor.org/rfc/rfc9265
