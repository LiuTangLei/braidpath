# Reverse-path feedback and request delivery: next controlled study

## Why this question follows the earlier work

A download is not a one-directional resource consumer. Native QUIC creates ACK
traffic on the receiver-to-sender path, independently of application DATAGRAM
admission. Its byte and packet costs belong in the resource model. A sparse
request can share that direction with confirmation traffic for a large download.

This is a hypothesis to test, not proof that ACKs caused a particular failure.
An ACK-frame counter is not an ACK-only packet count: ACKs can share packets with
application/control frames. Cumulative endpoint UDP bytes include setup, drain
and other frames. Final counters cannot identify the in-window peak or assign
bytes to individual frames. QUIC-declared lost packets are not the missing
application request count. Preserve these populations separately.

The working draft for QUIC ACK Frequency discusses CPU cost and constrained
reverse links, and warns that unilateral ACK reduction can harm congestion
control and loss recovery. Custura et al.'s study similarly
compares acknowledgement policies and their throughput/CPU implications across
link characteristics. These motivate an experiment; they do not certify this
project's bottleneck or promise their reported gains here.

## Evidence ladder

1. Close a request-ID ledger: issued, observed at the server application adapter,
   forwarded there, and received back at the client. The first missing boundary
   is an application observation, not a physical drop location.
2. Verify that the client actually admitted the corresponding originals and
   inspect per-path native DATAGRAM frame counters at both peers. Recheck all
   source files against the original collected hashes.
3. Keep native ACK frame counts, outer UDP counts/bytes and available socket
   observations separate. Kernel drop snapshots are PID/inode scoped; one-second
   observations and missing coverage cannot prove zero kernel drops.
4. Before a network treatment, capture phase-aligned counters, actual offered
   traffic, all request slots, pacing/queue state and endpoint CPU. Include a
   clean single-route case as well as concurrent bulk/interactive traffic.
5. Test a bounded sender-requested ACK policy against a registered matched
   control. Check actual peer negotiation, completion, unconditional latency,
   unique goodput, native loss/ECN recovery, CPU and reverse traffic. Never accept
   reduced ACK counts alone as successful service improvement.

## Implemented laboratory surface

The loopback-only `native_host_reference` example now has `--ack-profile
unchanged|every-eight`. The default leaves the existing configuration intact.
The experimental profile asks the peer to ACK by eight ack-eliciting packets,
requests a maximum ACK delay of 10 ms, and retains a nonzero reordering trigger
of two. These are requested settings, subject to peer negotiation/clamping; they
are not a promise to emit exactly one ACK per eight packets. Native BBR, TLS,
loss recovery, path MTU and queue/resource bounds remain active.

A real-pair unit test verifies both peers send and receive ACK_FREQUENCY frames,
retains payload integrity and checks that the unchanged profile emits no such
request. This is negotiation/correctness evidence only: no public-network gain
or local throughput improvement is claimed for this profile. Production
`transport::config` and all production command-line options are unchanged.

The three experimental settings form one bounded profile, not a one-parameter
causal isolation. A later frequency-only ablation should also include an
explicit ACK-every-two control with the **same** delay/reordering settings, so
changes from extension negotiation or reordering handling are not mistaken for
a frequency effect. Start with only the downstream sender requesting changes
at its peer; a symmetric request is a separate treatment.

The pinned Quinn documentation says its implementation follows the fourth
ACK-Frequency draft. This is not a claim of compatibility with the much newer
working-group draft revision. Verify interoperability using the pinned pair,
not a guessed wire format or unsupported latest-protocol claim.

## Progress and uncompleted prerequisites

The host reference and offline ledger tools are implemented and locally tested.
They are not a deployed Linux/public reference, a production ACK policy, or a
solution to shared bottlenecks. Public topologies and run records stay in local
ignored evidence directories. No benchmark should bypass the existing
production protection or replay completed workloads to select a good outcome.

## Primary sources

- QUIC ACK Frequency working draft, motivation and congestion/loss-recovery considerations:
  https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-14
- Custura et al., *Reducing the acknowledgement frequency in IETF QUIC*:
  https://onlinelibrary.wiley.com/doi/full/10.1002/sat.1466
- Quinn 0.11.12 AckFrequencyConfig semantics and implementation version:
  https://docs.rs/quinn/0.11.12/quinn/struct.AckFrequencyConfig.html
- RFC 9221, DATAGRAM congestion control, ACKs and application-delivery distinction:
  https://www.rfc-editor.org/rfc/rfc9221.html
