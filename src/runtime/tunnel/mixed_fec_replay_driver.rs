// Shared deterministic input driver. Included only by #[cfg(test)] modules.
// No endpoint, socket, OS traffic, clock sleep, or throughput measurement occurs.
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize)]
struct InputRecord {
    id: u64,
    flow: u32,
    kind: String,
    size: usize,
    at_ms: u64,
}
#[derive(Clone, Deserialize)]
struct CaseSpec {
    name: String,
    run_id_hex: String,
    records: Vec<InputRecord>,
    original_erasure_ids: Vec<u64>,
    original_service_from_ms: u64,
    repair_service_from_ms: u64,
    expected_missing: BTreeMap<String, Vec<u64>>,
    expected_repairs: BTreeMap<String, RepairCounts>,
}
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize, PartialEq)]
struct RepairCounts {
    generated: u64,
    admitted: u64,
    budget_skipped: u64,
    expired: u64,
}
#[derive(Deserialize)]
struct ReplayClock {
    tick_ms: u64,
    block_ms: u64,
    sender_ttl_ms: u64,
    receiver_repair_wait_ms: u64,
    virtual_one_way_ms: u64,
    application_deadline_ms: u64,
    case_cutoff_ms: u64,
}
#[derive(Deserialize)]
struct ReplaySpec {
    clock: ReplayClock,
    cases: Vec<CaseSpec>,
}
struct DriverSymbol {
    data: Bytes,
    small: bool,
}
struct Arrival {
    at_ms: u64,
    http: Bytes,
    original_id: Option<u64>,
    block: Option<u64>,
}
fn payload(input: &InputRecord, run_hex: &str) -> Vec<u8> {
    assert_eq!(run_hex.len(), 32);
    assert!(input.size >= 36);
    let kind = if input.kind == "bulk" { 3u8 } else { 2u8 };
    let mut value = Vec::with_capacity(input.size);
    value.extend_from_slice(b"BPP2");
    value.extend_from_slice(&[kind, 0, 0, 0]);
    for pair in run_hex.as_bytes().chunks_exact(2) {
        value.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    value.extend_from_slice(&u32::try_from(input.id).unwrap().to_be_bytes());
    value.extend_from_slice(&i64::try_from(input.at_ms * 1_000_000).unwrap().to_be_bytes());
    value.resize(input.size, ((input.id + u64::from(kind)) % 251) as u8);
    value
}
fn symbol_identity(data: &[u8]) -> (Option<u64>, Option<u64>) {
    assert!(data.len() >= wire::HEADER);
    let id = (data[3] != 1).then(|| Record::decode_identity(&data[wire::HEADER..]).unwrap().1);
    let block = (data[3] != 2).then(|| u64::from_be_bytes(data[4..12].try_into().unwrap()));
    (id, block)
}
fn event(
    events: &mut Vec<Value>,
    at_ms: u64,
    stage: &str,
    pending: &outbound::Pending,
    members: &BTreeMap<u64, Vec<u64>>,
    mode: &str,
    epoch: Instant,
) {
    events.push(json!({
        "event_sequence": events.len() + 1,
        "virtual_ms": at_ms,
        "created_virtual_ms": pending.created.saturating_duration_since(epoch).as_millis(),
        "ingress_age_ms": at_ms.saturating_sub(pending.created.saturating_duration_since(epoch).as_millis() as u64),
        "stage": stage,
        "record_id": pending.record_id,
        "flow": pending.flow,
        "block": pending.block,
        "symbol_type": if pending.record_id.is_some() {"original"} else {"repair"},
        "wire_index_or_count": pending.data[12],
        "codec_lane": replay_lane(mode, pending),
        "block_member_ids_at_event": pending.block.and_then(|b| members.get(&b)),
        "wire_bytes": pending.data.len(),
        "http_stream0_bytes_if_wrapped": wire::http_datagram(0, &pending.data).unwrap().len(),
        "scope": "plaintext virtual replay; no Quinn admission and no encrypted packet"
    }));
}
fn generated(
    symbols: Vec<DriverSymbol>,
    created: Instant,
    now_ms: u64,
    policy: &Policy,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    scope: &Scope,
    members: &mut BTreeMap<u64, Vec<u64>>,
    events: &mut Vec<Value>,
    counts: &mut RepairCounts,
    mode: &str,
    epoch: Instant,
) {
    for symbol in symbols {
        let (record_id, block) = symbol_identity(&symbol.data);
        if let (Some(id), Some(block)) = (record_id, block) {
            let set = members.entry(block).or_default();
            assert!(!set.contains(&id), "an encoder generated an original twice");
            set.push(id);
        }
        if record_id.is_none() {
            counts.generated += 1;
        } else {
            let record = Record::decode(&symbol.data[wire::HEADER..]).unwrap();
            assert_eq!(&record.payload[..4], b"BPP2");
            assert_eq!(u64::from(u32::from_be_bytes(record.payload[24..28].try_into().unwrap())), record.id);
        }
        let repair = record_id.is_none();
        replay_enqueue(symbol, created, queue, blocks, policy, scope);
        // Generated output is observed at the actual queued item; queue overflow
        // is separately checked through the real enqueue counters below.
        let pending = queue.front(repair).expect("bounded fixture enqueue").clone();
        // With this finite immediate-drain fixture, the generated item may sit
        // behind the single held deadline item only in its isolated TTL case.
        assert_eq!(pending.record_id, record_id);
        assert_eq!(pending.block, block);
        event(events, now_ms, "generated_and_enqueued", &pending, members, mode, epoch);
    }
}
fn replay_case(mode: &str, case: &CaseSpec, clock: &ReplayClock) -> Value {
    let policy = replay_policy(mode, clock.block_ms, clock.sender_ttl_ms);
    policy.validate().unwrap();
    let epoch = Instant::now();
    let mut encoder = replay_encoder(&policy);
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope(&format!("fixed-replay-{}", case.name), stats::FORWARD);
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    let mut budget = outbound::RepairBudget::new(policy.redundancy);
    let mut members = BTreeMap::new();
    let mut events = Vec::new();
    let mut repair_counts = RepairCounts::default();
    let mut arrivals = Vec::<Arrival>::new();
    let mut original_admitted = BTreeSet::new();
    let mut artificially_erased = BTreeSet::new();
    let mut original_expired = BTreeSet::new();
    let mut wire_original = 0usize;
    let mut wire_repair = 0usize;
    let mut http_original = 0usize;
    let mut http_repair = 0usize;
    let expected_payloads: BTreeMap<u64, Vec<u8>> = case.records.iter()
        .map(|input| (input.id, payload(input, &case.run_id_hex))).collect();
    let mut receiver = Receiver::with_repair_wait(Duration::from_millis(clock.receiver_repair_wait_ms));
    let mut delivered = BTreeMap::<u64, u64>::new();
    let mut deliveries = Vec::new();
    let selected: BTreeSet<_> = case.original_erasure_ids.iter().copied().collect();
    assert_eq!(selected.len(), case.original_erasure_ids.len());
    assert!(selected.iter().all(|id| expected_payloads.contains_key(id)));
    for ms in (0..=clock.case_cutoff_ms).step_by(clock.tick_ms as usize) {
        let now = epoch + Duration::from_millis(ms);
        for input in case.records.iter().filter(|input| input.at_ms == ms) {
            let record = Record { id: input.id, flow: input.flow, payload: expected_payloads[&input.id].clone() };
            let encoded = replay_encode(&mut encoder, &record, &policy, now);
            generated(encoded, now, ms, &policy, &mut queue, &mut blocks, &scope,
                      &mut members, &mut events, &mut repair_counts, mode, epoch);
        }
        let due = replay_flush_due(&mut encoder, now);
        generated(due, now, ms, &policy, &mut queue, &mut blocks, &scope,
                  &mut members, &mut events, &mut repair_counts, mode, epoch);
        for expired in queue.expire(now, Duration::from_millis(clock.sender_ttl_ms)) {
            account_expired(&expired, now, &scope);
            if let Some(id) = expired.record_id {
                original_expired.insert(id);
            } else {
                repair_counts.expired += 1;
                if let Some(block) = expired.block { blocks.remove(&block); }
            }
            event(&mut events, ms, "ingress_ttl_expired", &expired, &members, mode, epoch);
        }
        for repair in [false, true] {
            let service_from = if repair { case.repair_service_from_ms } else { case.original_service_from_ms };
            if ms < service_from { continue; }
            while let Some(front) = queue.front(repair).cloned() {
                if repair && front.block.is_some_and(|block| queue.block_pending(block)) {
                    break;
                }
                let http = wire::http_datagram(0, &front.data).unwrap();
                let allowed = !repair || repair_allowed(&policy, &budget, &blocks, &front, http.len());
                if !allowed {
                    let skipped = queue.pop(true).unwrap();
                    repair_counts.budget_skipped += 1;
                    replay_budget_skipped(&policy, &skipped, &scope);
                    event(&mut events, ms, "repair_budget_skipped", &skipped, &members, mode, epoch);
                    if let Some(block) = skipped.block { blocks.remove(&block); }
                    continue;
                }
                let admitted = queue.pop(repair).unwrap();
                replay_budget_admitted(&policy, &mut budget, &mut blocks, &admitted, http.len(), &scope);
                if let Some(id) = admitted.record_id {
                    assert!(original_admitted.insert(id));
                    wire_original += admitted.data.len();
                    http_original += http.len();
                    if let Some(block) = admitted.block {
                        blocks.get_mut(&block).expect("admitted original block").paths |= 1;
                    }
                } else {
                    repair_counts.admitted += 1;
                    wire_repair += admitted.data.len();
                    http_repair += http.len();
                    if let Some(block) = admitted.block { blocks.remove(&block); }
                }
                event(&mut events, ms, "virtual_admitted", &admitted, &members, mode, epoch);
                if let Some(id) = admitted.record_id.filter(|id| selected.contains(id)) {
                    artificially_erased.insert(id);
                    event(&mut events, ms, "fixed_logical_original_erased", &admitted, &members, mode, epoch);
                } else {
                    arrivals.push(Arrival { at_ms: ms + clock.virtual_one_way_ms, http,
                        original_id: admitted.record_id, block: admitted.block });
                }
            }
        }
        for arrival in arrivals.iter().filter(|arrival| arrival.at_ms == ms) {
            let before_recovered = receiver.recovered;
            let records = receiver.receive(wire::http_payload(&arrival.http, 0).unwrap(), now).unwrap();
            let recovered = receiver.recovered - before_recovered;
            assert!(recovered <= 1);
            for record in records {
                assert_eq!(record.payload, expected_payloads[&record.id], "payload integrity");
                assert!(delivered.insert(record.id, ms).is_none(), "duplicate business delivery");
                let input = case.records.iter().find(|input| input.id == record.id).unwrap();
                deliveries.push(json!({
                    "record_id": record.id, "flow": record.flow, "kind": input.kind,
                    "payload_bytes": record.payload.len(), "virtual_delivered_ms": ms,
                    "virtual_one_way_ms": ms - input.at_ms,
                    "within_200ms": ms - input.at_ms <= clock.application_deadline_ms,
                    "recovered": arrival.original_id != Some(record.id),
                    "trigger_original_id": arrival.original_id, "trigger_block": arrival.block
                }));
            }
        }
    }
    let missing: Vec<_> = case.records.iter().map(|record| record.id)
        .filter(|id| !delivered.contains_key(id)).collect();
    let mut actual_scope = None;
    metrics.state(|state| { actual_scope = Some(state.sessions[&scope.session][stats::FORWARD].clone()); });
    let direction = actual_scope.unwrap();
    let expected_counts = &case.expected_repairs[mode];
    let expected_missing = &case.expected_missing[mode];
    let errors = [
        (missing == *expected_missing, "unexpected full-denominator missing ID set"),
        (repair_counts == *expected_counts, "unexpected generated/admitted/skipped/expired repair counts"),
        (original_admitted.len() == case.records.len(), "not all fixture originals admitted"),
        (original_expired.is_empty(), "unexpected original expiry"),
        (artificially_erased == selected, "logical original erasure action set changed"),
        (queue.is_empty(), "symbol queue not fully settled"),
        (direction.symbols.originals_queue_full_dropped == 0, "original queue overflow"),
        (direction.symbols.repairs_queue_full_dropped == 0, "repair queue overflow"),
        (direction.symbols.originals_generated == case.records.len() as u64, "real encoder original count mismatch"),
        (direction.symbols.repairs_generated == repair_counts.generated, "real enqueue repair count mismatch"),
        (direction.symbols.repairs_expired_dropped == repair_counts.expired, "real expiry count mismatch"),
        (receiver.invalid == 0, "receiver invalid input"),
        (receiver.duplicates == 0, "receiver duplicate symbols or business IDs"),
        (deliveries.iter().all(|row| row["within_200ms"] == true), "delivered fixture record missed deadline"),
    ].into_iter().filter_map(|(passed, label)| (!passed).then_some(label)).collect::<Vec<_>>();
    let byte_ledger: Vec<Value> = ["generated_and_enqueued", "virtual_admitted", "repair_budget_skipped", "ingress_ttl_expired", "fixed_logical_original_erased"]
        .into_iter().map(|stage| {
            let selected_events: Vec<_> = events.iter().filter(|row| row["stage"] == stage).collect();
            json!({"stage":stage,"symbols":selected_events.len(),
                "encoded_wire_bytes":selected_events.iter().map(|row| row["wire_bytes"].as_u64().unwrap()).sum::<u64>(),
                "http_stream0_bytes_if_wrapped":selected_events.iter().map(|row| row["http_stream0_bytes_if_wrapped"].as_u64().unwrap()).sum::<u64>()})
        }).collect();
    json!({
        "mode": mode, "case": case.name, "full_planned_records": case.records.len(),
        "source": case.records.iter().map(|input| json!({"record_id":input.id,"flow":input.flow,
            "kind":input.kind,"size":input.size,"at_ms":input.at_ms})).collect::<Vec<_>>(),
        "originals_virtual_admitted": original_admitted, "originals_expired": original_expired,
        "fixed_logical_original_erasure_ids": artificially_erased,
        "repairs": repair_counts, "expected_repairs": expected_counts,
        "delivered_records": delivered.len(), "missing_ids": missing, "expected_missing_ids": expected_missing,
        "deliveries": deliveries, "symbol_membership": members, "events": events, "byte_ledger":byte_ledger,
        "wire_bytes": {"scope":"Exact bytes emitted by real plaintext wire encoder and HTTP mapping; no QUIC/IP/UDP overhead",
            "original_wire_admitted":wire_original,"repair_wire_admitted":wire_repair,
            "original_http_datagram_admitted":http_original,"repair_http_datagram_admitted":http_repair},
        "receiver": {"original_packets":receiver.original_packets,"repair_packets":receiver.repair_packets,
            "original_deliveries":receiver.originals,"recovered_deliveries":receiver.recovered,
            "duplicates":receiver.duplicates,"invalid":receiver.invalid,"stale":receiver.stale},
        "real_enqueue_expiry_metrics": direction.symbols,
        "virtual_admission_scope":"No call to send_datagram and no OutPath/Quinn endpoint. Real budget predicate/debit, encoder, outbound Queue, ingress expiry accounting, HTTP mapping and Receiver are used.",
        "errors": errors, "passed": errors.is_empty()
    })
}
#[test]
fn fixed_logical_erasure_replay() {
    let spec: ReplaySpec = serde_json::from_str(include_str!("mixed_fec_replay_spec.json")).unwrap();
    assert_eq!(spec.clock.tick_ms, 1);
    let mut results = Vec::new();
    for mode in replay_modes() {
        for case in &spec.cases {
            results.push(replay_case(mode, case, &spec.clock));
        }
    }
    let failed = results.iter().filter(|result| result["passed"] != true).count();
    let output = json!({
        "schema_version": 1, "driver":"shared deterministic logical replay",
        "real_runtime_identity":replay_implementation_identity(),
        "business_network_datagrams":0, "quinn_endpoints_created":0,
        "modes":replay_modes(), "subcases":results.len(), "failed_subcases":failed,
        "results":results,
        "scope":"Mechanism evidence only; this is not a packet network, pacing benchmark, or native loss/performance result."
    });
    eprintln!("MIXED_FEC_REPLAY_JSON={}", serde_json::to_string(&output).unwrap());
    assert_eq!(failed, 0, "prospective replay expectations failed; retain complete JSON evidence");
}
