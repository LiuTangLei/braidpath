use super::*;

fn policy() -> Policy {
    Policy {
        game_mode: true,
        native_return: false,
        max_message_bytes: 4096,
        streams: false,
        proxy: false,
        adaptive: true,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 3,
        group_rates: [100_000_000; MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: automatic_fec::AUTO,
        fec_repairs: 1,
        small_fec_bytes: 0,
        mixed_fec: false,
        redundancy: 30,
        rate: 100_000_000,
        block_ms: 1,
        queue_ms: 3,
    }
}

#[test]
fn game_mode_rejects_unknown_or_duplicate_negotiation() {
    let mut h = http::HeaderMap::new();
    assert!(!game_mode_header(&h).unwrap());
    h.insert("braidpath-game-mode", "1".parse().unwrap());
    assert!(game_mode_header(&h).unwrap());
    h.append("braidpath-game-mode", "1".parse().unwrap());
    assert!(game_mode_header(&h).is_err());
    h.clear();
    h.insert("braidpath-game-mode", "2".parse().unwrap());
    assert!(game_mode_header(&h).is_err());
}

#[test]
fn game_udp_and_fragments_have_immediate_protection_without_waiting_for_a_block() {
    let now = Instant::now();
    let p = policy();
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    let mut receiver = Receiver::configured(Duration::from_millis(100), true);
    for (id, (flow, size)) in [(2, 128), (2, 800), (messages::FLAG | 2, 1000)]
        .into_iter()
        .enumerate()
    {
        let record = Record {
            flow,
            id: id as u64,
            payload: vec![id as u8; size],
        };
        let symbols = encoder.encode(&record, now).unwrap();
        assert_eq!(symbols.len(), 2, "one original and one immediate repair");
        assert!(symbols.iter().all(|s| s.small));
        let recovered = receiver.receive(&symbols[1].data, now).unwrap();
        assert_eq!(
            recovered.len(),
            1,
            "repair alone recovers an erased original"
        );
        assert_eq!(recovered[0].payload, record.payload);
        assert_eq!(recovered[0].flow, flow);
        assert!(
            receiver.receive(&symbols[0].data, now).unwrap().is_empty(),
            "late original must not reach the destination twice"
        );
    }
    assert!(
        encoder
            .flush_due(now + Duration::from_millis(10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn game_udp_classification_preserves_tcp_and_normal_mode() {
    let mut p = policy();
    assert!(p.gaming_datagram(Some(associate::FLAG | 1)));
    assert!(!p.gaming_datagram(Some(stream::data_flow(1))));
    assert!(!p.gaming_datagram(Some(stream::ack_flow(1))));
    p.game_mode = false;
    assert!(!p.gaming_datagram(Some(2)));
    let record = Record {
        flow: 2,
        id: 0,
        payload: vec![7; 800],
    };
    let symbols = coding::RecordEncoder::new(&p)
        .unwrap()
        .encode(&record, Instant::now())
        .unwrap();
    assert_eq!(
        symbols.len(),
        1,
        "normal clean UDP does not gain a forced copy"
    );
    assert!(!symbols[0].small);
}
