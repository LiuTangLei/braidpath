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
        latency_target_ms: 20,
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
        queue_ms: 20,
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
        assert_eq!(symbols.len(), 4, "one original and three immediate repairs");
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
        for symbol in &symbols[2..] {
            assert!(receiver.receive(&symbol.data, now).unwrap().is_empty());
        }
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

#[test]
fn game_copy_waits_for_rate_credit_ahead_of_superseding_ack_copies() {
    let now = Instant::now();
    let p = policy();
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    encoder.set_fec(4).unwrap();
    let metrics = stats::Metrics::new("server");
    let scope = metrics.scope("game-copy-budget", stats::RETURN);
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    for record in [
        Record {
            flow: stream::ack_flow(1),
            id: 1,
            payload: stream::Frame::Ack(stream::Ack {
                cumulative: 0,
                limit: stream::INITIAL_WINDOW,
                duplicate_bytes: 0,
                ranges: vec![],
            })
            .encode(),
        },
        Record {
            flow: 2,
            id: 2,
            payload: vec![7; 1000],
        },
    ] {
        for symbol in encoder.encode(&record, now).unwrap() {
            enqueue_coded_symbol(
                symbol,
                now,
                &mut queue,
                &mut blocks,
                Some(&p),
                &scope,
                &mut None,
            );
        }
    }
    while let Some(original) = queue.pop(false) {
        let meta = blocks.get_mut(&original.block.unwrap()).unwrap();
        meta.paths = 1;
        meta.small_repair_reserved = meta.small_repair_limit;
    }
    let ack_block = queue.front(true).unwrap().block;
    let mut normal = p.clone();
    normal.game_mode = false;
    assert!(!prioritize_game_repair(&mut queue, &normal, &blocks));
    assert_eq!(queue.front(true).unwrap().block, ack_block);
    let count = queue.len();
    assert!(prioritize_game_repair(&mut queue, &p, &blocks));
    let game = queue.front(true).unwrap();
    assert_ne!(game.block, ack_block);
    assert!(
        game.flow.is_none() && p.gaming_symbol(game),
        "copies retain Game route selection without an original record flow"
    );
    let frame = repair_frame_floor(&p, game);
    let mut budget = outbound::RepairBudget::new(p.redundancy);
    budget.enable_small_rate(4_000_000);
    budget.refill_small(1_000_000);
    budget.small_repair_admitted(2100);
    assert!(
        !repair_allowed(&p, &budget, &blocks, game, frame),
        "priority cannot bypass the copy-rate cap"
    );
    assert_eq!(
        queue.len(),
        count,
        "waiting retains the existing bounded queue"
    );
    budget.refill_small(1_002_000);
    assert!(repair_allowed(
        &p,
        &budget,
        &blocks,
        queue.front(true).unwrap(),
        frame
    ));
    queue.expire(now + p.admission_lifetime(), p.admission_lifetime());
    assert!(
        queue.is_empty(),
        "the existing deadline still expires every copy"
    );
}

#[test]
fn normal_udp_reassembly_keeps_arrival_skew_separate_from_send_deadline() {
    let mut p = policy();
    p.game_mode = false;
    p.queue_ms = 20;
    p.latency_target_ms = 20;
    let now = Instant::now();
    let mut next = 0;
    let payload = vec![13; 1200];
    let mut parts = messages::split(associate::FLAG | 1, &mut next, payload.clone(), 4096).unwrap();
    let mut receiver = messages::Reassembly::new(4096, p.reassembly_lifetime());
    assert!(receiver.receive(parts.next().unwrap(), now).is_none());
    let (packet, _) = receiver
        .receive(parts.next().unwrap(), now + Duration::from_millis(80))
        .expect("a slower path must still complete the UDP packet");
    assert_eq!(packet.flow, associate::FLAG | 1);
    assert_eq!(packet.payload, payload);
}
