use super::*;
use std::{
    collections::BTreeSet,
    sync::atomic::AtomicUsize,
    task::{Wake, Waker},
};

struct Pair {
    _identity: tempfile::TempDir,
    _server: quinn::Endpoint,
    _client: quinn::Endpoint,
    outgoing: quinn::Connection,
    incoming: quinn::Connection,
}

impl Pair {
    async fn connect() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let server = transport::server(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            transport::Congestion::Bbr,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client = transport::client_bound(
            address,
            &identity.join("cert.pem"),
            None,
            transport::Congestion::Bbr,
            Some("127.0.0.1:0".parse().unwrap()),
        )
        .unwrap();
        let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        Self {
            _identity: temp,
            _server: server,
            _client: client,
            outgoing: outgoing.unwrap(),
            incoming: incoming.unwrap(),
        }
    }

    fn path(&self) -> OutPath {
        OutPath {
            id: 0,
            group: 2,
            conn: self.outgoing.clone(),
            stream: 0,
            quality: Arc::new(Mutex::new(quality::State::new(7))),
            capacity_probe: Arc::new(Mutex::new(capacity_probe::State::new(7))),
            capacity_probe_enabled: false,
            epoch: Instant::now(),
            probe_reply: Arc::new(Mutex::new(None)),
        }
    }

    async fn receive(&self) -> Bytes {
        timeout(Duration::from_secs(3), self.incoming.read_datagram())
            .await
            .unwrap()
            .unwrap()
    }

    async fn assert_quiet(&self) {
        assert!(
            timeout(Duration::from_millis(30), self.incoming.read_datagram())
                .await
                .is_err(),
            "a cancelled/expired attempt or duplicate entered the real connection",
        );
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

const FILLER: &[u8; 1100] = &[0xa5; 1100];

fn block_and_poll(
    pair: &Pair,
    wait: &mut WaitingSend,
    paths: &Paths,
    lifetime: Duration,
) -> Arc<Wakes> {
    // This current-thread runtime cannot drive QUIC between the fill and poll.
    pair.outgoing
        .send_datagram(Bytes::from_static(FILLER))
        .unwrap();
    assert!(pair.outgoing.datagram_send_buffer_space() < wait.prepared.data.len());
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    assert!(
        wait.poll(
            &mut TaskContext::from_waker(&waker),
            paths,
            lifetime,
            |_, _, _| true,
        )
        .is_pending()
    );
    assert!(
        paths.try_lock().is_ok(),
        "Pending must release the membership mutex"
    );
    assert!(wait.prepared.path.quality.try_lock().is_ok());
    wakes
}

fn policy() -> Policy {
    Policy {
        adaptive: false,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 20,
        group_rates: [10_000_000; MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: 2,
        redundancy: 100,
        rate: 10_000_000,
        block_ms: 25,
        queue_ms: 1000,
    }
}

fn record(id: u64) -> Record {
    Record {
        flow: 1,
        id,
        payload: vec![id as u8; MAX_PAYLOAD],
    }
}

struct Accounting {
    policy: Policy,
    scope: Scope,
    queue: outbound::Queue,
    blocks: BTreeMap<u64, BlockSend>,
    budget: outbound::RepairBudget,
    scheduler: scheduler::Scheduler,
    controllers: [adaptive::PathController; MAX_PATHS],
    pacer: outbound::Pacer,
    groups: [outbound::Pacer; MAX_PATHS],
    business: Option<outbound::BusinessPacer>,
    cursor: usize,
    repair_turn: bool,
    epoch: Instant,
}

impl Accounting {
    fn new() -> Self {
        let policy = policy();
        let mut pacer = outbound::Pacer::new(policy.rate, 9600);
        pacer.refill(1_000_000);
        let groups = std::array::from_fn(|_| {
            let mut pacer = outbound::Pacer::new(policy.rate, 9600);
            pacer.refill(1_000_000);
            pacer
        });
        Self {
            scope: stats::Metrics::new("client").scope("ready-test", stats::FORWARD),
            queue: outbound::Queue::default(),
            blocks: BTreeMap::new(),
            budget: outbound::RepairBudget::new(policy.redundancy),
            scheduler: scheduler::Scheduler::default(),
            controllers: std::array::from_fn(|_| {
                adaptive::PathController::new(policy.rate, policy.latency_target_ms)
            }),
            pacer,
            groups,
            business: None,
            cursor: 0,
            repair_turn: false,
            epoch: Instant::now(),
            policy,
        }
    }

    fn enqueue(&mut self, data: Bytes, at: Instant) {
        enqueue_symbol(data, at, &mut self.queue, &mut self.blocks, &self.scope);
    }

    fn prepare(&self, path: &OutPath, repair: bool) -> PreparedSend {
        let front = self.queue.front(repair).unwrap().clone();
        let measured = path
            .quality
            .lock()
            .unwrap()
            .wrap(&front.data, quality_time(path));
        PreparedSend {
            path: path.clone(),
            generation: 7,
            data: wire::http_datagram(path.stream, &measured).unwrap(),
            used: front
                .block
                .and_then(|b| self.blocks.get(&b))
                .map_or(0, |b| b.paths),
            front,
            repair,
            candidates: vec![(path.id, 1)],
            feedback_reserve: 0,
            group_reserve: 0,
        }
    }

    fn commit(&mut self, prepared: &PreparedSend, at: Instant, next_cursor: usize) {
        SendAccounting {
            policy: &self.policy,
            metrics: &self.scope,
            queue: &mut self.queue,
            blocks: &mut self.blocks,
            budget: &mut self.budget,
            scheduler: &mut self.scheduler,
            controllers: &mut self.controllers,
            pacer: &mut self.pacer,
            groups: &mut self.groups,
            business: &mut self.business,
            paths: std::slice::from_ref(&prepared.path),
            cursor: &mut self.cursor,
            repair_turn: &mut self.repair_turn,
            epoch: self.epoch,
        }
        .commit(Admission {
            path: &prepared.path,
            front: &prepared.front,
            candidates: &prepared.candidates,
            repair: prepared.repair,
            used: prepared.used,
            frame_bytes: prepared.data.len(),
            next_cursor,
            at,
        });
    }

    fn direction(&self) -> stats::Direction {
        let mut value = None;
        self.scope.metrics.state(|s| {
            value = Some(s.sessions[&self.scope.session][stats::FORWARD].clone());
        });
        value.unwrap()
    }

    fn assert_no_admission(&self, path: &OutPath, queued: usize) {
        let d = self.direction();
        assert_eq!(d.symbols.originals_quinn_admitted, 0);
        assert_eq!(d.symbols.repairs_quinn_admitted, 0);
        assert_eq!(d.symbols.admitted_wait.count, 0);
        assert!(d.quinn_admitted_record_ids.recent.is_empty());
        assert_eq!(self.queue.len(), queued);
        assert!(!self.budget.can_repair(1));
        assert!(self.pacer.available(9600));
        assert!(self.groups[usize::from(path.group)].available(9600));
        assert_eq!(path.quality.lock().unwrap().snapshot.sent_symbols, 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn quinn_readiness_wakes_without_input_or_timer_and_commits_each_symbol_once() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let mut accounting = Accounting::new();
    let mut encoder = Encoder::new(2, Duration::from_millis(25)).unwrap();
    let at = Instant::now();
    for id in [1, 2] {
        for shard in encoder.push(&record(id).encode().unwrap(), at).unwrap() {
            accounting.enqueue(wire::shard(shard), at);
        }
    }
    let mut original_bytes = 0;
    let mut repair_bytes = 0;
    let mut admitted_symbol_bytes = 0;
    for (number, repair) in [false, false, true].into_iter().enumerate() {
        let mut wait = WaitingSend::new(accounting.prepare(&path, repair));
        let wakes = block_and_poll(&pair, &mut wait, &paths, Duration::from_secs(1));
        if number == 0 {
            accounting.assert_no_admission(&path, 3);
        }
        assert_eq!(pair.receive().await.as_ref(), FILLER);
        assert!(
            wakes.0.load(Ordering::Relaxed) > 0,
            "Quinn did not wake its registered waiter"
        );
        let ready = timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                wait.poll(cx, &paths, Duration::from_secs(1), |attempt, _, _| {
                    let cost = attempt.data.len() + 80;
                    accounting.pacer.available(cost)
                        && accounting.groups[usize::from(path.group)].available(cost)
                        && (!repair || accounting.budget.can_repair(attempt.data.len()))
                })
            }),
        )
        .await
        .unwrap();
        let SendReadiness::Admitted { at, next_cursor } = ready else {
            panic!("{ready:?}")
        };
        let prepared = wait.cancel();
        let frame_bytes = prepared.data.len();
        admitted_symbol_bytes += prepared.front.data.len() as u64;
        accounting.commit(&prepared, at, next_cursor);
        assert_eq!(pair.receive().await, prepared.data);
        if repair {
            repair_bytes += frame_bytes;
        } else {
            original_bytes += frame_bytes;
        }
        let spent = original_bytes + repair_bytes + (number + 1) * 80;
        assert!(accounting.pacer.available(9600 - spent));
        assert!(!accounting.pacer.available(9601 - spent));
        assert!(accounting.groups[2].available(9600 - spent));
        assert!(!accounting.groups[2].available(9601 - spent));
        assert!(
            accounting.groups[1].available(9600),
            "unselected group was charged"
        );
        assert_eq!(
            path.quality.lock().unwrap().snapshot.sent_symbols,
            number as u64 + 1
        );
    }
    assert!(accounting.queue.is_empty());
    assert!(accounting.blocks.is_empty());
    let remaining_credit = original_bytes - repair_bytes;
    assert!(accounting.budget.can_repair(remaining_credit));
    assert!(!accounting.budget.can_repair(remaining_credit + 1));
    let d = accounting.direction();
    assert_eq!(d.symbols.originals_quinn_admitted, 2);
    assert_eq!(d.symbols.repairs_quinn_admitted, 1);
    assert_eq!(
        d.symbols.originals_quinn_admitted_bytes,
        original_bytes as u64
    );
    assert_eq!(d.symbols.repairs_quinn_admitted_bytes, repair_bytes as u64);
    assert_eq!(d.symbols.repair_no_diverse_path, 1);
    assert_eq!(d.symbols.admitted_wait.count, 3);
    assert_eq!(d.quinn_admitted_record_ids.recent, BTreeSet::from([1, 2]));
    assert_eq!(
        path.quality.lock().unwrap().snapshot.sent_bytes,
        admitted_symbol_bytes
    );
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_pending_wait_does_not_send_or_mint_credit_and_can_be_reselected() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let mut accounting = Accounting::new();
    accounting.enqueue(wire::plain(&record(1)).unwrap(), Instant::now());
    let mut wait = WaitingSend::new(accounting.prepare(&path, false));
    block_and_poll(&pair, &mut wait, &paths, Duration::from_secs(1));
    let prepared = wait.cancel();
    accounting.assert_no_admission(&path, 1);
    assert_eq!(pair.receive().await.as_ref(), FILLER);
    pair.assert_quiet().await;
    accounting.assert_no_admission(&path, 1);
    // A later actor turn can reselect the same still-queued original exactly once.
    let mut wait = WaitingSend::new(prepared);
    let ready = poll_fn(|cx| wait.poll(cx, &paths, Duration::from_secs(1), |_, _, _| true)).await;
    let SendReadiness::Admitted { at, next_cursor } = ready else {
        panic!("{ready:?}")
    };
    let prepared = wait.cancel();
    accounting.commit(&prepared, at, next_cursor);
    assert_eq!(pair.receive().await, prepared.data);
    assert_eq!(accounting.direction().symbols.originals_quinn_admitted, 1);
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_ready_buffer_cannot_send_past_the_adaptive_20ms_limit_with_a_100ms_queue() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let mut accounting = Accounting::new();
    accounting.policy.adaptive = true;
    accounting.policy.queue_ms = 100;
    accounting.policy.latency_target_ms = 20;
    let lifetime = accounting.policy.admission_lifetime();
    assert_eq!(lifetime, Duration::from_millis(20));
    let created = Instant::now();
    accounting.enqueue(wire::plain(&record(1)).unwrap(), created);
    let mut wait = WaitingSend::new(accounting.prepare(&path, false));
    block_and_poll(&pair, &mut wait, &paths, lifetime);
    assert_eq!(pair.receive().await.as_ref(), FILLER);
    tokio::time::sleep_until((created + Duration::from_millis(25)).into()).await;
    assert!(pair.outgoing.datagram_send_buffer_space() >= wait.prepared.data.len());
    let ready = poll_fn(|cx| wait.poll(cx, &paths, lifetime, |_, _, _| true)).await;
    assert!(matches!(ready, SendReadiness::Expired));
    wait.cancel();
    accounting.assert_no_admission(&path, 1);
    let now = Instant::now();
    for pending in accounting.queue.expire(now, lifetime) {
        account_expired(&pending, now, &accounting.scope);
    }
    let d = accounting.direction();
    assert_eq!(d.symbols.originals_expired_dropped, 1);
    assert_eq!(d.symbols.originals_quinn_admitted, 0);
    assert_eq!(d.locally_dropped_original_ids.recent, BTreeSet::from([1]));
    assert!(accounting.queue.is_empty());
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn removal_or_generation_change_invalidates_a_pending_wait_before_ready_send() {
    let pair = Pair::connect().await;
    for removed in [false, true] {
        let path = pair.path();
        let paths = Arc::new(Mutex::new(vec![path.clone()]));
        let mut accounting = Accounting::new();
        accounting.enqueue(wire::plain(&record(1)).unwrap(), Instant::now());
        let mut wait = WaitingSend::new(accounting.prepare(&path, false));
        block_and_poll(&pair, &mut wait, &paths, Duration::from_secs(1));
        if removed {
            paths.lock().unwrap().clear();
        } else {
            path.quality.lock().unwrap().snapshot.generation += 1;
        }
        assert_eq!(pair.receive().await.as_ref(), FILLER);
        assert!(pair.outgoing.datagram_send_buffer_space() >= wait.prepared.data.len());
        let ready =
            poll_fn(|cx| wait.poll(cx, &paths, Duration::from_secs(1), |_, _, _| true)).await;
        assert!(matches!(ready, SendReadiness::PathChanged));
        wait.cancel();
        accounting.assert_no_admission(&path, 1);
        pair.assert_quiet().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ready_poll_rechecks_current_group_budget_before_entering_quinn() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let mut accounting = Accounting::new();
    accounting.enqueue(wire::plain(&record(1)).unwrap(), Instant::now());
    let mut wait = WaitingSend::new(accounting.prepare(&path, false));
    block_and_poll(&pair, &mut wait, &paths, Duration::from_secs(1));
    assert_eq!(pair.receive().await.as_ref(), FILLER);
    let exhausted_group = outbound::Pacer::new(64_000, 2400);
    let ready = poll_fn(|cx| {
        wait.poll(cx, &paths, Duration::from_secs(1), |attempt, _, _| {
            exhausted_group.available(attempt.data.len() + 80)
        })
    })
    .await;
    assert!(matches!(ready, SendReadiness::GateChanged));
    wait.cancel();
    accounting.assert_no_admission(&path, 1);
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn sender_actor_drains_multiple_flows_once_and_stops_cleanly() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path]));
    let mut policy = policy();
    policy.fec = 0;
    policy.receiver_feedback = false;
    policy.quality_schedule = false;
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("actor-test", stats::FORWARD);
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stopped) = watch::channel(false);
    for id in 0..128 {
        let mut record = record(id);
        record.flow = (id % 8) as u32 + 1;
        assert!(
            tx.try_send(QueuedRecord {
                record,
                created: Instant::now()
            })
            .is_ok()
        );
    }
    let task = tokio::spawn(sender(rx, paths, policy, stopped, scope, None));
    let mut received = BTreeSet::new();
    let mut decoder = Receiver::default();
    timeout(Duration::from_secs(3), async {
        while received.len() < 128 {
            let data = pair.incoming.read_datagram().await.unwrap();
            for record in decoder
                .receive(wire::http_payload(&data, 0).unwrap(), Instant::now())
                .unwrap()
            {
                assert!(received.insert(record.id), "duplicate application record");
            }
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    metrics.state(|s| {
        let d = &s.sessions["actor-test"][stats::FORWARD];
        assert_eq!(d.records.sender_input_consumed, 128);
        assert_eq!(d.symbols.originals_generated, 128);
        assert_eq!(d.symbols.originals_quinn_admitted, 128);
        assert_eq!(d.symbols.originals_expired_dropped, 0);
        assert_eq!(d.symbols.originals_queue_full_dropped, 0);
        assert_eq!(d.symbols.originals_shutdown_dropped, 0);
        assert_eq!(d.symbols.admitted_wait.count, 128);
    });
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn event_observation_036_notifies_only_the_owner_on_accepted_wire_evidence() {
    fn notified(notify: &Notify) -> bool {
        let waker = Waker::from(Arc::new(Wakes::default()));
        let mut future = Box::pin(notify.notified());
        future
            .as_mut()
            .poll(&mut TaskContext::from_waker(&waker))
            .is_ready()
    }
    let pair = Pair::connect().await;
    let path0 = pair.path();
    let mut path1 = pair.path();
    path1.id = 1;
    let paths = Arc::new(Mutex::new(vec![path0.clone(), path1.clone()]));
    let scope = stats::Metrics::new("client").scope("event-observation", stats::FORWARD);
    let owner = Notify::new();
    let other_sender = Notify::new();
    let mut peer0 = quality::State::new(7);
    let mut peer1 = quality::State::new(7);
    let reports = quality::control_v2(&[peer0.report(0, 1000), peer1.report(1, 1000)]);
    assert!(
        measured_payload(&paths, 0, &reports, true, &scope, Some(&owner))
            .unwrap()
            .is_none()
    );
    assert!(notified(&owner));
    assert!(!notified(&owner), "one frame is one coalesced notification");
    assert!(!notified(&other_sender));
    assert!(paths.try_lock().is_ok());
    assert!(path0.quality.try_lock().is_ok());
    assert_eq!(path0.quality.lock().unwrap().snapshot.controls_received, 1);
    assert_eq!(path1.quality.lock().unwrap().snapshot.controls_received, 1);
    assert!(
        measured_payload(&paths, 0, &reports, true, &scope, Some(&owner))
            .unwrap()
            .is_none()
    );
    assert!(!notified(&owner), "replayed reports are not new evidence");
    assert!(measured_payload(&paths, 0, b"BQ2C", true, &scope, Some(&owner)).is_err());
    assert!(!notified(&owner));

    // Generate positive delivery feedback from actual admitted symbol bytes.
    let data = wire::plain(&record(1)).unwrap();
    let sent = {
        let mut state = path0.quality.lock().unwrap();
        let sent = state.wrap(&data, 0);
        state.admitted(data.len());
        sent
    };
    peer0.receive(&sent, 1500).unwrap();
    let delivery = quality::control_v2(&[peer0.delivery_report(0, 2000)]);
    measured_payload(&paths, 0, &delivery, true, &scope, Some(&owner)).unwrap();
    assert!(notified(&owner));
    assert!(!notified(&owner));
    let mut stale = peer0.delivery_report(0, 3000);
    stale.generation += 1;
    measured_payload(
        &paths,
        0,
        &quality::control_v2(&[stale]),
        true,
        &scope,
        Some(&owner),
    )
    .unwrap();
    assert!(
        !notified(&owner),
        "wrong-generation feedback does not notify"
    );

    let request = quality::Probe {
        generation: 7,
        nonce: 77,
        response: false,
    };
    measured_payload(
        &paths,
        0,
        &quality::probe(&request),
        true,
        &scope,
        Some(&owner),
    )
    .unwrap();
    assert!(!notified(&owner), "a peer request is not a measured reply");
    assert_eq!(
        path0.probe_reply.lock().unwrap().as_ref().unwrap().nonce,
        77
    );
    let reply = quality::Probe {
        response: true,
        ..request
    };
    assert!(
        measured_payload(
            &paths,
            0,
            &quality::probe(&reply),
            true,
            &scope,
            Some(&owner)
        )
        .is_err()
    );
    assert!(!notified(&owner), "an unsolicited reply is rejected");
    path0
        .quality
        .lock()
        .unwrap()
        .probe_admitted(77, quality_time(&path0));
    measured_payload(
        &paths,
        0,
        &quality::probe(&reply),
        true,
        &scope,
        Some(&owner),
    )
    .unwrap();
    assert!(notified(&owner));
    assert!(!notified(&owner));
    assert_eq!(path0.quality.lock().unwrap().snapshot.replies_received, 1);
    assert!(
        measured_payload(
            &paths,
            0,
            &quality::probe(&reply),
            true,
            &scope,
            Some(&owner)
        )
        .is_err()
    );
    assert!(!notified(&owner), "the valid nonce can notify only once");

    let incoming = peer1.wrap(&data, 0);
    peer1.admitted(data.len());
    assert!(
        measured_payload(&paths, 1, &incoming, true, &scope, Some(&owner))
            .unwrap()
            .is_some()
    );
    assert!(
        !notified(&owner),
        "business reception does not notify this sender"
    );
    let fixed = quality::control_v2(&[peer1.report(1, 4000)]);
    measured_payload(&paths, 1, &fixed, true, &scope, None).unwrap();
    assert!(!notified(&owner));
    assert!(
        !notified(&other_sender),
        "quality-only mode has no observation owner"
    );
}

#[test]
fn capacity_probe_policy_requires_negotiated_adaptive_fec0_and_bounded_allowance() {
    let mut configured = policy();
    configured.capacity_probe_bps = configured.rate / 20;
    assert!(configured.validate().is_err());
    configured.adaptive = true;
    assert!(configured.validate().is_err());
    configured.fec = 0;
    assert!(configured.validate().is_ok());
    configured.capacity_probe_bps += 1;
    assert!(configured.validate().is_err());
    configured.capacity_probe_bps = 0;
    assert!(configured.validate().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn capacity_frames_are_negotiated_and_never_refresh_business_delivery() {
    let pair = Pair::connect().await;
    let mut path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let scope = stats::Metrics::new("client").scope("capacity-probe", stats::FORWARD);
    let mut peer = capacity_probe::State::new(7);
    let frame = peer.prepare(1000);
    peer.admitted();
    assert!(measured_payload(&paths, 0, &frame, true, &scope, None).is_err());
    path.capacity_probe_enabled = true;
    *paths.lock().unwrap() = vec![path.clone()];
    assert!(
        measured_payload(&paths, 0, &frame, true, &scope, None)
            .unwrap()
            .is_none()
    );
    // Replay is idempotent in the independent bounded window.
    assert!(
        measured_payload(&paths, 0, &frame, true, &scope, None)
            .unwrap()
            .is_none()
    );
    let measured = path
        .capacity_probe
        .lock()
        .unwrap()
        .snapshot(quality_time(&path));
    assert_eq!(measured.received.received_bytes, 972);
    let business = path.quality.lock().unwrap();
    assert_eq!(business.snapshot.sent_symbols, 0);
    assert_eq!(business.snapshot.received.received_bytes, 0);
    assert_eq!(business.snapshot.sender_estimate.received_bytes, 0);
    assert_eq!(business.snapshot.controls_received, 0);
}

#[test]
fn guided_recovery_requires_measurement_and_original_only_negotiation() {
    let mut p = policy();
    p.probe_guided_recovery = true;
    assert!(p.validate().is_err());
    p.adaptive = true;
    p.fec = 0;
    p.capacity_probe_bps = p.rate / 20;
    assert!(p.validate().is_err());
    p.redundancy = 0;
    assert!(p.validate().is_ok());
    p.capacity_probe_bps = 0;
    assert!(p.validate().is_err());
}
