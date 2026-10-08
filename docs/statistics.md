# Runtime statistics

Client, server and relay accept `--stats-file PATH` for final JSON, `--stats-jsonl PATH` for optional cumulative periodic JSON lines, and `--stats-interval-ms N` (default 1,000; bounds 10–60,000). Create the output directory first; keep private topology and run records under ignored `local/`.

For example, append these flags to a runtime command:

```sh
--stats-file local/run/client.json \
--stats-jsonl local/run/client.jsonl --stats-interval-ms 250
```

Orderly Ctrl-C/SIGINT shutdown and ordinary command errors emit a final snapshot. SIGKILL, process crashes and filesystem failures cannot guarantee a final file. Periodic output is flushed at each snapshot; readers must ignore an incomplete last line. Files are replaced on each invocation, and final JSON and JSONL must have distinct paths.

## Schema and readiness

Schema version 1 contains `role`, `process_id`, a random process-stable `instance_id`, `sample_unix_ms`, `elapsed_ms`, `final`, `outcome` (`running`, `stopped`, `error`), `error`, `bounds`, and `stats`. Samples are cumulative; use counter differences over a selected interval. `elapsed_ms` uses a monotonic local clock. Samples from separate machines are not clock-synchronized.

`stats.ready`, `listener_bound`, `target_configured` and integer `configured_paths` support readiness without parsing logs. A client reports its requested interface/entrance pair count; server and relay report zero. Starting and readiness changes trigger immediate JSONL snapshots in addition to periodic snapshots. For a relay, ready means its front socket is bound and its fixed target is configured; it does not establish target reachability. Each entry of `stats.paths` is keyed by `session_id/path_id`, includes `authenticated`, `request_stream_id`, `sending_direction`, and `quinn.closed`; the latter identifies a closed connection. Check the expected unique path IDs, a common session ID and the current process instance before beginning a run.

`stats.shutdown_complete` and `drain_incomplete` describe application task/queue cleanup, not delivery of all packets already submitted to Quinn. Remaining owned input/event/symbol queues are counted as shutdown drops. If cleanup times out, `drain_incomplete` is true and complete conservation assertions must be refused. Even an orderly stop can discard Quinn/kernel/network in-flight packets; these cannot be classified as application queue drops.

## Scopes and units

`stats.directions` contains aggregate `client_to_server` and `server_to_client` counters. `stats.sessions[session_id][direction]` contains the same counters for one session plus bounded logical-ID windows. On the client, application ingress is a local UDP receive and UDP target delivery is return traffic handed to that local application's socket. On the server, application ingress is a reply received from its fixed UDP target and UDP delivery is forward traffic handed to that target. Successful UDP sends report kernel acceptance, not remote application receipt.

The direction object's `records` and `symbols` are separate layers:

- Application record ingress, oversized/flow/unavailable drops, event queue admission/rejection, sender input queue admission/rejection, consumed/encoding counts and each queue's shutdown cancellation counts.
- Generated original/repair symbols, skipped repair budget, bounded symbol queue admission/full drops, expiry and shutdown drops, and original/repair admissions to Quinn.
- Received original packets (including duplicates), repair symbol arrivals, uniquely decoded original records, FEC recovery, deduplication, stale/invalid symbol drops and UDP send acceptance/failure.

The sender input queue contains records; the pending queue contains original or repair symbols. On the client there is one ingress/sender input queue, so successful `ingress_queue_enqueued` and `sender_queue_enqueued` describe the same admission. Server target replies first enter the session event queue, then the sender input queue; `ingress_shutdown_dropped` and `input_shutdown_dropped` refer to distinct queues. Received aggregate symbols share a bounded event queue and `receiver_queue_*` counters count symbols rather than logical records. Full and closed queue rejections are reported separately.

`expiry_wait` and `admitted_wait` contain count, total/max milliseconds and a nine-bucket histogram with upper bounds `[1, 5, 10, 25, 50, 100, 250, 1000, infinity]` ms. Original waiting time begins at application receive, including any input queue wait. Repair waiting begins when that symbol is generated. Existing expiry decisions still use the pending queue's existing creation time; measurement does not change the expiry or scheduling policy.

`stats.paths` records original/repair Quinn admission, buffer-full and send-error **attempts**, received HTTP datagrams, receiver queue rejection, decoder outcomes and UDP target acceptance/failure. Recovery is attributed to the path whose arrival triggered recovery, not the unknown path of the missing original. Pre-path application/input/pending queues have aggregate scope: no fabricated path assignment is made before scheduling.

Each path's `quinn` contains cumulative `lost_packets`, `congestion_events`, `sent_packets`, UDP transmit/receive datagram and byte counts, HTTP DATAGRAM frame counts, latest minimum/smoothed RTT, congestion window and closed status. Sending congestion/loss applies to `sending_direction`; UDP receive counts apply to the reverse direction. Initial RTT values can be estimates before enough acknowledgments exist. One QUIC packet can contain several frames, and a UDP datagram can bundle QUIC packets. Control/ACK/handshake traffic is included in QUIC/UDP counts. **QUIC lost packets, HTTP datagram symbols and logical record loss are not interchangeable.**

`send_buffer_full_attempts` counts an unsuccessful path capacity check. The aggregate symbol remains queued for retry or later expiry; an attempt is not an additional drop. These counters measure pressure without changing the existing sender admission policy.

Relay direction counters use UDP datagrams, with received/queued/forwarded counts and bytes. Drop reasons distinguish unauthorized source, oversize, deterministic impairment, rate budget, mapping limits/errors/closed queues, queue capacity, socket send errors/cancellation, expired mapping queues and shutdown. `--drop-every` impairs forward ciphertext datagrams only, including handshake/control packets; a counter cannot identify their encrypted record contents.

## Bounded logical reconciliation

Each session/direction optionally exposes `generated_record_ids`, `quinn_admitted_record_ids`, `locally_dropped_original_ids` and `udp_delivered_record_ids`. Each contains `highest_id`, `floor_id` and `recent`; IDs below its floor have been retired. At most 8,192 IDs are retained in each window. These windows are absent from aggregate direction totals because IDs restart at each session. Statistics retain at most 128 session scopes and 128 connection/path scopes; omitted scopes are counted explicitly. Complete per-session/path assertions must be refused if scopes were omitted or the compared ID range falls below any relevant window floor. Production-long sessions require interval/window reconciliation rather than a whole-session ID claim.

After a fixed observation/drain period, FEC0 can reconcile admitted original IDs with delivered IDs and explicitly named `not_received_after_drain` IDs. This last set is observed non-delivery, **not an identified cause or a locally recorded queue drop**; it can include external loss, peer rejection and transport/kernel in-flight data. FEC can recover a record whose original symbol was locally dropped before Quinn admission; therefore with FEC enabled, reconcile generated IDs and recovered delivery too, and do not assume delivered IDs are a subset of original Quinn admissions. Local original-symbol drop IDs can overlap records delivered through FEC.

Useful independent invariants after completed application cleanup include:

```text
originals_generated = originals_enqueued + originals_queue_full_dropped
repairs_generated = repairs_enqueued + repairs_queue_full_dropped + repairs_budget_skipped
originals_enqueued = originals_quinn_admitted + originals_expired_dropped + originals_shutdown_dropped
repairs_enqueued = repairs_quinn_admitted + repairs_expired_dropped + repairs_shutdown_dropped
sender_queue_enqueued = sender_input_consumed + input_shutdown_dropped
relay.received = relay.forwarded + classified_relay_drops
```

During a run, add the still-queued/in-flight amount at each layer; periodic snapshots are not a transaction across all layer updates. Application conservation additionally includes pre-queue rejection and encoding failure. Logical records and repair symbols must not be added together. Captures, raw sequence probes and paired endpoint snapshots are required to locate external loss and queue growth.

`tests/stats.rs` exercises exact raw UDP sequence loss under relay impairment, real HTTP/3/FEC0 queue expiry and layered/ID reconciliation, immediate JSON readiness, graceful cleanup, and ordinary-error final JSON. Run records are temporary or local; they are not performance evidence for a remote route. Receiver feedback and path rejoin remain later roadmap work.
