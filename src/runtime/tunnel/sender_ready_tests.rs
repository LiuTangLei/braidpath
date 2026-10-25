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
        Self::connect_with_send_buffer(transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES).await
    }

    async fn connect_with_send_buffer(datagram_send_buffer_bytes: usize) -> Self {
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
        let client = transport::client_bound_with_datagram_buffer(
            address,
            &identity.join("cert.pem"),
            None,
            transport::Congestion::Bbr,
            Some("127.0.0.1:0".parse().unwrap()),
            datagram_send_buffer_bytes,
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
            writer: writer::Writer::spawn(&self.outgoing),
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

fn block_and_poll(wait: &mut WaitingSend, paths: &Paths, lifetime: Duration) -> Arc<Wakes> {
    // This current-thread runtime cannot run the writer or drive QUIC between
    // the fill and poll.
    assert!(wait.prepared.path.writer.send(Bytes::from_static(FILLER)));
    assert!(!wait.prepared.path.writer.admits(wait.prepared.data.len()));
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
        max_message_bytes: 1000,
        streams: false,
        proxy: false,
        fec_repairs: 1,
        adaptive: false,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 20,
        group_rates: [10_000_000; MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: 2,
        small_fec_bytes: 0,
        mixed_fec: false,
        redundancy: 100,
        rate: 10_000_000,
        block_ms: 25,
        queue_ms: 1000,
    }
}

#[tokio::test]
async fn reliable_auto_fec_uses_native_service_without_a_udp_default_change() {
    for reliable in [true, false] {
        let pair = Pair::connect().await;
        let paths = Arc::new(Mutex::new(vec![pair.path()]));
        let mut policy = policy();
        policy.adaptive = true;
        policy.proxy = reliable;
        policy.fec = automatic_fec::AUTO;
        policy.redundancy = 30;
        let metrics = stats::Metrics::new("client");
        metrics.register(
            "native-service-default",
            0,
            2,
            stats::FORWARD,
            &pair.outgoing,
        );
        let scope = metrics.scope("native-service-default", stats::FORWARD);
        let (_tx, rx) = mpsc::channel(QUEUE);
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(sender(rx, paths, policy, stopped, scope, None));
        let sample = timeout(Duration::from_secs(2), async {
            loop {
                let mut sample = None;
                metrics.state(|state| {
                    sample = state.paths.values().find_map(|path| path.adaptive.clone());
                });
                if let Some(sample) = sample {
                    break sample;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(sample.last_control.native_service_guard_enabled, reliable);
        assert_eq!(
            sample.native_service_recoveries, 0,
            "no native allowance may be borrowed without positive business feedback"
        );
    }
}

fn record(id: u64) -> Record {
    Record {
        flow: 1,
        id,
        payload: vec![id as u8; MAX_PAYLOAD],
    }
}

thread_local! {
    static PRIME_FULL_INPUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXHAUST_INPUT_GROUPS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Set up the exact full-queue transition inside the real actor, after selection
// of its Input event. No executor race or timer delay decides whether it is full.
pub(super) fn prime_full_input_turn(
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    metrics: &Scope,
    pacer: &mut outbound::Pacer,
    groups: &mut [outbound::Pacer; MAX_PATHS],
) {
    if !PRIME_FULL_INPUT.with(|prime| prime.replace(false)) {
        return;
    }
    assert!(queue.is_empty());
    for id in 0..outbound::PER_FLOW_LIMIT as u64 {
        enqueue_symbol(
            wire::plain(&record(id)).unwrap(),
            Instant::now(),
            queue,
            blocks,
            metrics,
        );
    }
    // Ordinary earned budget, using the actual Pacer implementation. The first
    // actor turn now has service available; no production token grant is added.
    pacer.refill(1_000_000);
    let exhaust = EXHAUST_INPUT_GROUPS.with(|value| value.replace(false));
    for group in groups {
        group.refill(1_000_000);
        if exhaust {
            while group.available(1) {
                group.spend(1);
            }
        }
    }
}

// Receiving the first 64 records does not imply the actor has polled the
// deferred 65th record's readiness future. Model a legal scheduler suspension
// at that exact boundary instead of relying on wall-clock load to hit it.
// Force that one candidate through readiness: an immediately writable native
// buffer can otherwise expire it in the same drain turn, bypassing this gate.
#[derive(Default)]
struct DeferredExpiryGate {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
thread_local! {
    static DEFERRED_EXPIRY_GATE: std::cell::RefCell<Option<Arc<DeferredExpiryGate>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn defer_expiry_candidate(record_id: Option<u64>) -> bool {
    record_id == Some(64) && DEFERRED_EXPIRY_GATE.with(|cell| cell.borrow().is_some())
}
pub(super) async fn hold_deferred_expiry(deferred: bool) {
    if deferred {
        let gate = DEFERRED_EXPIRY_GATE.with(|cell| cell.borrow_mut().take());
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.resume.notified().await;
        }
    }
}

async fn full_input_turn_services_old_records(expires: bool, settle: bool) {
    let pair = Pair::connect().await;
    let paths = Arc::new(Mutex::new(vec![pair.path()]));
    let mut policy = policy();
    policy.fec = 0;
    policy.redundancy = 0;
    policy.receiver_feedback = false;
    policy.quality_schedule = false;
    policy.rate = 125_000_000;
    policy.group_rates = [policy.rate; MAX_PATHS];
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("full-input", stats::FORWARD);
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stopped) = watch::channel(false);
    let created = Instant::now() - Duration::from_millis(20);
    if expires {
        // Reuse the real admission clock hook: old heads remain within their
        // unchanged 1000ms lifetime, but this older Input expires at the API.
        ADMISSION_CLOCK_FIXED.with(|clock| clock.set(Some(created + Duration::from_millis(1001))));
    }
    tx.try_send(QueuedRecord {
        record: record(64),
        created,
        hold: None,
    })
    .unwrap();
    let gate = expires.then(|| Arc::new(DeferredExpiryGate::default()));
    DEFERRED_EXPIRY_GATE.with(|cell| *cell.borrow_mut() = gate.clone());
    PRIME_FULL_INPUT.with(|prime| prime.set(true));
    let task = tokio::spawn(sender(rx, paths, policy, stopped, scope, None));
    let mut received = BTreeSet::new();
    let mut decoder = Receiver::default();
    while received.len() < outbound::PER_FLOW_LIMIT {
        for record in decoder
            .receive(
                wire::http_payload(&pair.receive().await, 0).unwrap(),
                Instant::now(),
            )
            .unwrap()
        {
            assert!(received.insert(record.id));
        }
    }
    metrics.state(|s| {
        let d = &s.sessions["full-input"][stats::FORWARD];
        assert_eq!(
            d.symbols.originals_queue_full_dropped, 0,
            "a serviceable old head must free an existing slot before rejecting this Input"
        );
    });
    while !expires && received.len() < outbound::PER_FLOW_LIMIT + 1 {
        for record in decoder
            .receive(
                wire::http_payload(&pair.receive().await, 0).unwrap(),
                Instant::now(),
            )
            .unwrap()
        {
            assert!(received.insert(record.id));
        }
    }
    if let Some(gate) = gate {
        timeout(Duration::from_secs(2), gate.reached.notified())
            .await
            .unwrap();
        metrics.state(|s| {
            let d = &s.sessions["full-input"][stats::FORWARD];
            assert_eq!(d.symbols.originals_quinn_admitted, 64);
            assert_eq!(
                d.symbols.originals_expired_dropped, 0,
                "delivery of old records must not be mistaken for deferred-input settlement"
            );
        });
        if !settle {
            stop.send(true).unwrap();
        }
        gate.resume.notify_one();
        if settle {
            timeout(Duration::from_secs(2), async {
                loop {
                    let mut expired = false;
                    metrics.state(|s| {
                        expired = s.sessions["full-input"][stats::FORWARD]
                            .symbols
                            .originals_expired_dropped
                            == 1
                    });
                    if expired {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("deferred input never settled at its fixed admission deadline");
        }
    }
    stop.send(true).unwrap();
    task.await.unwrap();
    ADMISSION_CLOCK_FIXED.with(|clock| clock.set(None));
    assert_eq!(received, (0..if expires { 64 } else { 65 }).collect());
    metrics.state(|s| {
        let d = &s.sessions["full-input"][stats::FORWARD];
        assert_eq!(d.symbols.originals_generated, 65);
        assert_eq!(
            d.symbols.originals_quinn_admitted,
            if expires { 64 } else { 65 }
        );
        assert_eq!(d.symbols.originals_expired_dropped, u64::from(expires && settle));
        assert_eq!(d.symbols.originals_shutdown_dropped, u64::from(expires && !settle));
        if expires && !settle {
            eprintln!("controlled scheduler suspension: generated=65 admitted=64 expired=0 shutdown=1; the former test stopped before deferred expiry settled");
        }
        if !expires {
            assert!(
                d.symbols.admitted_wait.max_ms >= 20.0,
                "preserve the new record's ingress clock"
            );
        }
    });
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_input_turn_services_old_records_before_rejecting_new_original() {
    full_input_turn_services_old_records(false, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_input_turn_cannot_revive_deferred_record_past_its_ingress_deadline() {
    full_input_turn_services_old_records(true, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn stopping_before_deferred_input_settles_is_shutdown_not_deadline_failure() {
    full_input_turn_services_old_records(true, false).await;
}

async fn full_input_turn_with_blocked_group(new_flow: u32) {
    let pair = Pair::connect().await;
    let paths = Arc::new(Mutex::new(vec![pair.path()]));
    let mut policy = policy();
    policy.fec = 0;
    policy.redundancy = 0;
    policy.receiver_feedback = false;
    policy.quality_schedule = false;
    policy.rate = 125_000_000;
    policy.group_rates = [64_000; MAX_PATHS];
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("blocked-full-input", stats::FORWARD);
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stopped) = watch::channel(false);
    let mut input = record(64);
    input.flow = new_flow;
    if new_flow != 1 {
        input.payload.resize(128, 0);
    }
    tx.try_send(QueuedRecord {
        record: input,
        created: Instant::now(),
        hold: None,
    })
    .unwrap();
    PRIME_FULL_INPUT.with(|prime| prime.set(true));
    EXHAUST_INPUT_GROUPS.with(|value| value.set(true));
    let mut task = Box::pin(sender(rx, paths, policy, stopped, scope, None));
    poll_fn(|cx| {
        assert!(task.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    metrics.state(|s| {
        assert_eq!(
            s.sessions["blocked-full-input"][stats::FORWARD]
                .records
                .sender_input_consumed,
            1,
            "full bulk flow must not pause actor input"
        )
    });
    stop.send(true).unwrap();
    task.await;
    metrics.state(|s| {
        let d = &s.sessions["blocked-full-input"][stats::FORWARD];
        let same_flow = u64::from(new_flow == 1);
        assert_eq!(d.symbols.originals_generated, 65);
        assert_eq!(d.symbols.originals_queue_full_dropped, same_flow);
        assert_eq!(d.symbols.originals_quinn_admitted, 0);
        assert_eq!(d.symbols.originals_shutdown_dropped, 65 - same_flow);
        assert_eq!(d.symbols.originals_expired_dropped, 0);
        assert_eq!(d.symbols.originals_ingress_expired_dropped, 0);
    });
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_input_turn_keeps_original_limit_when_all_paths_are_budget_blocked() {
    full_input_turn_with_blocked_group(1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn full_input_turn_does_not_defer_small_record_from_another_flow() {
    full_input_turn_with_blocked_group(2).await;
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
        self.commit_on_paths(
            prepared,
            at,
            next_cursor,
            std::slice::from_ref(&prepared.path),
        );
    }

    fn commit_on_paths(
        &mut self,
        prepared: &PreparedSend,
        at: Instant,
        next_cursor: usize,
        paths: &[OutPath],
    ) {
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
            paths,
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
async fn plain_interactive_waits_for_fast_credit_instead_of_entering_a_slow_queue() {
    let fast = Pair::connect().await;
    let slow = Pair::connect().await;
    let path0 = fast.path();
    let mut path1 = slow.path();
    path1.id = 1;
    path1.quality.lock().unwrap().snapshot.sender_estimate = quality::Estimate {
        updated_us: Some(0),
        delay_variation_ms: 500.0,
        ..Default::default()
    };
    let paths = [path0, path1];
    let mut policy = policy();
    policy.adaptive = true;
    policy.fec = 0;
    policy.redundancy = 0;
    policy.small_fec_bytes = 0;
    let mut controllers = std::array::from_fn(|_| adaptive::PathController::new(policy.rate, 20));
    controllers[0].admitted(0, 2400);
    let mut front = outbound::Pending {
        data: Bytes::from(vec![7; 100]),
        created: Instant::now(),
        record_id: Some(1),
        flow: Some(stream::data_flow(1)),
        block: None,
        small: false,
        hold: None,
    };
    let eligible = [(0, 1), (1, 1)];
    let timely = latency_candidates(
        eligible.to_vec(),
        &paths,
        &front,
        false,
        &policy,
        Duration::ZERO,
    );
    assert!(
        business_ready_candidates(&timely, &paths, &mut controllers, 0, 100, 0.0, None).is_empty(),
        "a momentary fast-path pacing gap must not route an interactive record into 500 ms of queue"
    );
    assert_eq!(
        business_ready_candidates(&timely, &paths, &mut controllers, 10_000, 100, 10.0, None),
        vec![(0, 1)],
        "the fast path admits the record after normal token refill"
    );
    assert_eq!(
        latency_candidates(
            eligible[1..].to_vec(),
            &paths,
            &front,
            false,
            &policy,
            Duration::ZERO
        ),
        vec![(1, 1)],
        "an ineligible fast path cannot suppress the remaining live route"
    );
    front.data = Bytes::from(vec![7; 1000]);
    let gauge = Arc::new(outbound::Gauge::default());
    front.hold = Some(gauge.hold(1, 0, 1, 1000, true));
    assert_eq!(
        latency_candidates(
            eligible.to_vec(),
            &paths,
            &front,
            false,
            &policy,
            Duration::ZERO
        ),
        eligible,
        "large startup chunks keep every route even while their stream has little outstanding data"
    );
    front.hold = None;
    front.data = Bytes::from(vec![7; 100]);
    front.flow = Some(1);
    assert_eq!(
        latency_candidates(
            eligible.to_vec(),
            &paths,
            &front,
            false,
            &policy,
            Duration::ZERO
        ),
        eligible,
        "ordinary UDP keeps its work-conserving ready-path selection"
    );
    front.flow = Some(stream::data_flow(1));
    front.block = Some(1);
    policy.small_fec_bytes = 128;
    assert_eq!(
        latency_candidates(
            eligible.to_vec(),
            &paths,
            &front,
            false,
            &policy,
            Duration::ZERO
        ),
        eligible,
        "the opt-in small-record FEC policy keeps its separate loss and readiness rules"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn adaptive_small_readiness_ignores_fast_peer_without_current_packet_credit() {
    let fast = Pair::connect().await;
    let slow = Pair::connect().await;
    let path0 = fast.path();
    let mut path1 = slow.path();
    path1.id = 1;
    path1.quality.lock().unwrap().snapshot.sender_estimate = quality::Estimate {
        updated_us: Some(0),
        delay_variation_ms: 500.0,
        ..Default::default()
    };
    let paths = Arc::new(Mutex::new(vec![path0.clone(), path1.clone()]));
    let mut accounting = Accounting::new();
    accounting.policy.adaptive = true;
    accounting.policy.fec = 0;
    accounting.policy.redundancy = 0;
    accounting.policy.small_fec_bytes = 128;
    accounting.policy.latency_target_ms = 1000;
    accounting.controllers = std::array::from_fn(|_| {
        adaptive::PathController::new(accounting.policy.rate, accounting.policy.latency_target_ms)
    });
    // Keep controller time fixed so executor scheduling cannot refill the fast
    // peer's credit while the real Quinn driver drains the other connection.
    accounting.controllers[0].admitted(0, 2400);
    assert!(accounting.controllers[0].decision(0).eligible);
    let created = Instant::now();
    let mut encoder = Encoder::new(1, Duration::from_millis(25)).unwrap();
    let small = Record {
        flow: 2,
        id: 1,
        payload: vec![7; 128],
    };
    for symbol in encode_record(&small, &mut encoder, &accounting.policy, created).unwrap() {
        accounting.enqueue(symbol, created);
    }
    let prepared = accounting.prepare(&path1, false);
    assert_eq!(
        business_ready_candidates(
            &[(0, 1), (1, 1)],
            &paths.lock().unwrap(),
            &mut accounting.controllers,
            0,
            prepared.front.data.len() + quality::HEADER,
            0.0,
            None,
        ),
        vec![(1, 1)],
        "the immediate drain can only select the slower, credited path"
    );
    let lifetime = accounting.policy.admission_lifetime();
    let mut wait = WaitingSend::new(prepared);
    let wakes = block_and_poll(&mut wait, &paths, lifetime);
    let waker = Waker::from(wakes.clone());
    let mut allowed = |attempt: &PreparedSend, now: Instant, paths: &[OutPath]| {
        attempt.small_delivery_allowed(
            &accounting.policy,
            paths,
            &mut accounting.controllers,
            0,
            now.saturating_duration_since(attempt.front.created),
        )
    };
    let blocked = wait.poll(
        &mut TaskContext::from_waker(&waker),
        &paths,
        lifetime,
        &mut allowed,
    );
    assert!(
        blocked.is_pending(),
        "an eligible peer without this packet's credit must not invalidate the prepared path: {blocked:?}"
    );
    assert_eq!(slow.receive().await.as_ref(), FILLER);
    assert!(wakes.0.load(Ordering::Relaxed) > 0);
    let ready = timeout(
        lifetime,
        poll_fn(|cx| wait.poll(cx, &paths, lifetime, &mut allowed)),
    )
    .await
    .unwrap();
    let SendReadiness::Admitted { at, next_cursor } = ready else {
        panic!("{ready:?}")
    };
    let prepared = wait.cancel();
    accounting.commit_on_paths(&prepared, at, next_cursor, &paths.lock().unwrap());
    assert_eq!(slow.receive().await, prepared.data);
    assert_eq!(accounting.direction().symbols.originals_quinn_admitted, 1);
    assert_eq!(accounting.direction().symbols.repairs_quinn_admitted, 0);
    slow.assert_quiet().await;
    fast.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn small_sender_avoids_measured_late_path_for_both_symbols() {
    assert_eq!(
        small_sender_admissions([0.0, 0.0], [0.0, 500.0]).await,
        [(1, 1), (0, 0)],
        "measured late diversity must not override timely delivery"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn small_sender_preserves_fresh_lower_loss_peer_outside_timing_band() {
    assert_eq!(
        small_sender_admissions([0.3, 0.0], [0.0, 60.0]).await,
        [(0, 1), (1, 0)],
        "a low-ETA path with worse fresh loss must not force both symbols away from the healthier path"
    );
}

async fn small_sender_admissions(losses: [f64; 2], delays: [f64; 2]) -> [(u64, u64); 2] {
    let fast = Pair::connect().await;
    let slow = Pair::connect().await;
    let path0 = fast.path();
    let mut path1 = slow.path();
    path1.id = 1;
    for (index, path) in [&path0, &path1].into_iter().enumerate() {
        let received = ((1.0 - losses[index]) * 100.0).round() as u64;
        path.quality.lock().unwrap().snapshot.sender_estimate = quality::Estimate {
            expected: 100,
            received,
            lost: 100 - received,
            loss_rate: losses[index],
            updated_us: Some(0),
            delivered_updated_us: Some(0),
            delay_variation_ms: delays[index],
            ..Default::default()
        };
    }
    let paths = Arc::new(Mutex::new(vec![path0, path1]));
    let mut policy = policy();
    policy.fec = 0;
    policy.redundancy = 0;
    policy.small_fec_bytes = 128;
    policy.queue_ms = 100;
    let metrics = stats::Metrics::new("client");
    metrics.register("small-delivery", 0, 0, stats::FORWARD, &fast.outgoing);
    metrics.register("small-delivery", 1, 0, stats::FORWARD, &slow.outgoing);
    let scope = metrics.scope("small-delivery", stats::FORWARD);
    let (tx, rx) = mpsc::channel(4);
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(sender(rx, paths, policy, stopped, scope, None));
    tx.send(QueuedRecord {
        record: Record {
            flow: 2,
            id: 1,
            payload: vec![7; 128],
        },
        created: Instant::now(),
        hold: None,
    })
    .await
    .unwrap();
    let complete = timeout(Duration::from_millis(200), async {
        loop {
            let mut done = false;
            metrics.state(|s| {
                done = s
                    .sessions
                    .get("small-delivery")
                    .and_then(|directions| directions.get(stats::FORWARD))
                    .is_some_and(|d| d.symbols.repairs_quinn_admitted == 1);
            });
            if done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    stop.send(true).unwrap();
    task.await.unwrap();
    assert!(complete.is_ok(), "both small symbols must remain live");
    let mut admitted = [(0, 0); 2];
    metrics.state(|s| {
        for (id, value) in admitted.iter_mut().enumerate() {
            let path = &s.paths[&format!("small-delivery/{id}")];
            *value = (path.quinn_admitted_originals, path.quinn_admitted_repairs);
        }
    });
    admitted
}

#[tokio::test(flavor = "current_thread")]
async fn same_path_small_copy_waits_for_quinn_packetization() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let before = pair.outgoing.stats();
    let original = Bytes::from_static(b"small-original");
    let copy = Bytes::from_static(b"small-copy");
    assert!(path.writer.send(original.clone()));
    // Without a yield, both frames would still fit the same QUIC/UDP packet.
    assert!(!small_delivery::copy_ready(&path, 1));
    assert!(
        small_delivery::copy_ready(&path, 2),
        "another path does not wait"
    );
    assert_eq!(
        pair.outgoing.stats().frame_tx.datagram,
        before.frame_tx.datagram
    );
    assert_eq!(pair.receive().await, original);
    assert!(small_delivery::copy_ready(&path, 1));
    assert!(path.writer.send(copy.clone()));
    assert_eq!(pair.receive().await, copy);
    let after = pair.outgoing.stats();
    assert_eq!(after.frame_tx.datagram - before.frame_tx.datagram, 2);
    assert!(after.udp_tx.datagrams - before.udp_tx.datagrams >= 2);
}

#[tokio::test(flavor = "current_thread")]
async fn small_quality_guard_requires_fresh_loss_evidence_on_real_paths() {
    let fast = Pair::connect().await;
    let slow = Pair::connect().await;
    let mut path0 = fast.path();
    let mut path1 = slow.path();
    path1.id = 1;
    let remaining = Duration::from_millis(100);
    for (label, losses, expected, ages, updated, expected_mask) in [
        (
            "fresh better peer",
            [0.3, 0.0],
            [100, 100],
            [0, 0],
            [true, true],
            3,
        ),
        (
            "equal fresh loss",
            [0.2, 0.2],
            [100, 100],
            [0, 0],
            [true, true],
            1,
        ),
        (
            "all bad retain the timing anchor",
            [1.0, 1.0],
            [100, 100],
            [0, 0],
            [true, true],
            1,
        ),
        (
            "unknown timing anchor",
            [0.3, 0.0],
            [100, 100],
            [0, 0],
            [false, true],
            1,
        ),
        (
            "insufficient anchor evidence",
            [0.3, 0.0],
            [15, 100],
            [0, 0],
            [true, true],
            1,
        ),
        (
            "insufficient peer evidence",
            [0.3, 0.0],
            [100, 15],
            [0, 0],
            [true, true],
            1,
        ),
        (
            "stale anchor evidence",
            [0.3, 0.0],
            [100, 100],
            [4, 0],
            [true, true],
            1,
        ),
        (
            "cold paths remain live",
            [0.0, 0.0],
            [0, 0],
            [0, 0],
            [false, false],
            3,
        ),
    ] {
        for (index, path) in [&mut path0, &mut path1].into_iter().enumerate() {
            path.epoch = Instant::now() - Duration::from_secs(ages[index]);
            path.quality.lock().unwrap().snapshot.sender_estimate = quality::Estimate {
                expected: expected[index],
                loss_rate: losses[index],
                updated_us: updated[index].then_some(0),
                delay_variation_ms: if index == 0 { 0.0 } else { 60.0 },
                ..Default::default()
            };
        }
        assert_eq!(
            small_delivery::mask(&[path0.clone(), path1.clone()], 3, remaining, 100, 0),
            expected_mask,
            "{label}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn small_timing_recovers_from_stale_feedback_and_keeps_cold_paths_live() {
    let fast = Pair::connect().await;
    let slow = Pair::connect().await;
    let path0 = fast.path();
    let mut path1 = slow.path();
    path1.id = 1;
    let remaining = Duration::from_millis(100);
    assert_eq!(
        small_delivery::mask(&[path0.clone(), path1.clone()], 3, remaining, 100, 0),
        3
    );
    path1.quality.lock().unwrap().snapshot.sender_estimate = quality::Estimate {
        updated_us: Some(0),
        delay_variation_ms: 500.0,
        ..Default::default()
    };
    assert_eq!(
        small_delivery::mask(&[path0.clone(), path1.clone()], 3, remaining, 100, 0),
        1
    );
    path1.epoch = Instant::now() - Duration::from_secs(4);
    assert_eq!(
        small_delivery::mask(&[path0.clone(), path1.clone()], 3, remaining, 100, 0),
        3
    );
    // An unavailable best path cannot prevent the remaining live path serving.
    assert_eq!(
        small_delivery::mask(&[path0, path1], 2, remaining, 100, 0),
        2
    );
}

#[tokio::test(flavor = "current_thread")]
async fn quality_only_bulk_unready_path_cannot_steal_later_small_requests() {
    bulk_unready_path_cannot_steal_later_small_requests(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn adaptive_bulk_unready_path_cannot_steal_later_small_requests() {
    bulk_unready_path_cannot_steal_later_small_requests(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn writer_backlog_excludes_the_pace_budget() {
    for buffer in [
        transport::MAX_DATAGRAM_SEND_BUFFER_BYTES,
        transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
    ] {
        let pair = Pair::connect_with_send_buffer(buffer).await;
        // Quinn's usable capacity includes its datagram accounting overhead;
        // the writer must respect that capacity even when the pace is faster.
        let capacity = pair.outgoing.datagram_send_buffer_space();
        assert!(capacity >= 1100);
        if buffer == transport::MAX_DATAGRAM_SEND_BUFFER_BYTES {
            assert!(capacity >= 1800);
        } else {
            assert!(capacity < 1800);
        }
        let path = pair.path();
        // No await: the current-thread runtime cannot drain the writer.
        path.writer.set_pace(8_800_000);
        assert!(path.writer.send(Bytes::from(vec![0xa5; 900])));
        assert!(path.writer.send(Bytes::from(vec![0xa5; 900])));
        assert_eq!(path.writer.held(), 1800);
        assert_eq!(path.writer.backlog(), 700, "beyond the 1100-byte budget");
        path.writer.set_pace(80_000_000);
        assert_eq!(
            path.writer.backlog(),
            1800usize.saturating_sub(10_000.min(capacity)),
            "the 1 ms pace budget is capped by actual Quinn capacity",
        );
    }
}

async fn bulk_unready_path_cannot_steal_later_small_requests(adaptive: bool) {
    let fast = Pair::connect().await;
    let blocked = Pair::connect().await;
    let path0 = fast.path();
    let mut path1 = blocked.path();
    path1.id = 1;
    let paths = [path0.clone(), path1.clone()];
    let mut accounting = Accounting::new();
    accounting.policy.adaptive = adaptive;
    if adaptive {
        accounting.business = Some(outbound::BusinessPacer::new(
            accounting.policy.rate,
            accounting.policy.group_rates,
            2400,
        ));
        update_business_pacer(&mut accounting.business, &paths, &accounting.controllers, 0);
    }
    let created = Instant::now();
    accounting.enqueue(wire::plain(&record(1)).unwrap(), created);
    let mut prepared = accounting.prepare(&path0, false);
    prepared.candidates = vec![(0, 4), (1, 1)];
    // No await between filling path 1 and committing: the current-thread
    // runtime cannot drain either path. Its 1100-byte budget still takes a
    // small symbol but no bulk.
    path1.writer.set_pace(8_800_000);
    assert!(path1.writer.send(Bytes::from(vec![0xa5; 900])));
    let small_bytes = 183;
    assert!(path1.writer.admits(small_bytes));
    assert!(!path1.writer.admits(prepared.data.len()));
    if adaptive {
        assert_eq!(
            business_ready_candidates(
                &prepared.candidates,
                &paths,
                &mut accounting.controllers,
                accounting.epoch.elapsed().as_micros() as u64,
                prepared.front.data.len() + quality::HEADER,
                created.elapsed().as_secs_f64() * 1000.0,
                None,
            ),
            prepared.candidates,
            "both business allowances are ready; only Quinn blocks the bulk peer"
        );
    }
    let at = send_datagram_before_deadline(
        &path0,
        prepared.data.clone(),
        created,
        Duration::from_secs(1),
    )
    .unwrap()
    .unwrap();
    assert!(!path0.writer.admits(prepared.data.len()));
    accounting.commit_on_paths(&prepared, at, 1, &paths);
    // The actual admitted path still pays its share after filling its buffer;
    // the blocked peer must not acquire phantom bulk debt against small work.
    assert_eq!(
        accounting
            .scheduler
            .order(&prepared.candidates, small_bytes)[0],
        0
    );
    assert_eq!(accounting.direction().symbols.originals_quinn_admitted, 1);
    assert!(accounting.queue.is_empty());
    assert_eq!(fast.receive().await, prepared.data);
}

#[test]
fn small_record_fec_is_immediate_independent_of_bulk_and_keeps_ingress_deadline() {
    let created = Instant::now();
    let mut accounting = Accounting::new();
    accounting.policy.fec = 0;
    accounting.policy.small_fec_bytes = 128;
    accounting.policy.redundancy = 0;
    let mut encoder = Encoder::new(1, Duration::from_millis(3)).unwrap();
    let small = Record {
        flow: 2,
        id: 1,
        payload: vec![7; 128],
    };
    let symbols = encode_record(&small, &mut encoder, &accounting.policy, created).unwrap();
    assert_eq!(
        symbols.len(),
        2,
        "a small request needs its own immediate repair"
    );
    for symbol in symbols {
        accounting.enqueue(symbol, created);
    }
    let bulk = record(2);
    let bulk_symbols = encode_record(&bulk, &mut encoder, &accounting.policy, created).unwrap();
    assert_eq!(
        bulk_symbols,
        vec![wire::plain(&bulk).unwrap()],
        "bulk must remain FEC0"
    );
    accounting.enqueue(bulk_symbols[0].clone(), created);
    let original = accounting.queue.pop(false).unwrap();
    let repair = accounting.queue.front(true).unwrap();
    assert_eq!(repair.block, original.block);
    assert!(
        !accounting.queue.block_pending(repair.block.unwrap()),
        "unrelated bulk must not hold small repair"
    );
    assert_eq!(repair.created, created);
    assert!(
        !accounting.budget.can_repair(repair.data.len()),
        "generation must not mint repair credit"
    );
    let expired = accounting.queue.expire(
        created + Duration::from_millis(100),
        Duration::from_millis(100),
    );
    assert_eq!(expired.len(), 2);
    assert!(accounting.queue.is_empty());
}

#[test]
fn independent_small_fec_erasure_grid_recovers_once_within_original_window() {
    let created = Instant::now();
    let mut policy = policy();
    policy.fec = 0;
    policy.small_fec_bytes = 128;
    let mut encoder = Encoder::new(1, Duration::from_millis(3)).unwrap();
    let record = Record {
        flow: 2,
        id: 1,
        payload: vec![9; 128],
    };
    let symbols = encode_record(&record, &mut encoder, &policy, created).unwrap();
    assert_eq!(symbols.len(), 2);
    // Exact 5x5 erasure grid: each transmission is erased in one of five
    // positions, independently. This proves codec behavior, not WAN delivery.
    let mut delivered = 0;
    for original_draw in 0..5 {
        for repair_draw in 0..5 {
            let mut receiver = Receiver::with_repair_wait(Duration::from_millis(100));
            let mut records = Vec::new();
            if repair_draw != 0 {
                records.extend(
                    receiver
                        .receive(&symbols[1], created + Duration::from_millis(60))
                        .unwrap(),
                );
            }
            if original_draw != 0 {
                records.extend(
                    receiver
                        .receive(&symbols[0], created + Duration::from_millis(61))
                        .unwrap(),
                );
            }
            assert!(
                records.len() <= 1,
                "repair-first/late original must be deduplicated"
            );
            if !records.is_empty() {
                assert_eq!(records[0], record);
                delivered += 1;
            }
        }
    }
    assert_eq!(delivered, 24, "both-erased is the only unrecoverable pair");
}

#[test]
fn small_fec_policy_rejects_mixed_repair_or_capacity_probe_budgets() {
    let mut policy = policy();
    policy.small_fec_bytes = 128;
    assert!(policy.validate().is_err());
    policy.fec = 0;
    assert!(policy.validate().is_err());
    policy.redundancy = 0;
    assert!(policy.validate().is_ok());
    policy.small_fec_bytes = 1001;
    assert!(policy.validate().is_err());
    policy.small_fec_bytes = 128;
    policy.adaptive = true;
    policy.capacity_probe_bps = 64_000;
    assert!(policy.validate().is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn mixed_small_copy_uses_its_own_bounded_admission_credit_on_wider_http_stream() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let mut repair_path = path.clone();
    repair_path.stream = 1_u64 << 40;
    let mut accounting = Accounting::new();
    accounting.policy.fec = 4;
    accounting.policy.small_fec_bytes = 128;
    accounting.policy.mixed_fec = true;
    accounting.policy.redundancy = 30;
    accounting.budget = outbound::RepairBudget::new(30);
    let created = Instant::now();
    let mut encoder = coding::RecordEncoder::new(&accounting.policy).unwrap();
    let small = Record {
        flow: 2,
        id: 1,
        payload: vec![7; 128],
    };
    for symbol in encoder.encode(&small, created).unwrap() {
        enqueue_encoded(
            symbol,
            created,
            &mut accounting.queue,
            &mut accounting.blocks,
            &accounting.policy,
            &accounting.scope,
        );
    }
    let repair = accounting.prepare(&repair_path, true);
    assert!(!repair_allowed(
        &accounting.policy,
        &accounting.budget,
        &accounting.blocks,
        &repair.front,
        repair.data.len(),
    ));
    let original = accounting.prepare(&path, false);
    assert_eq!(repair.data.len(), original.data.len() + 9);
    assert_eq!(
        accounting
            .direction()
            .symbols
            .mixed_small_repair_reserved_bytes,
        0
    );
    let at = send_datagram_before_deadline(
        &path,
        original.data.clone(),
        created,
        Duration::from_secs(1),
    )
    .unwrap()
    .unwrap();
    accounting.commit(&original, at, 0);
    assert_eq!(pair.receive().await, original.data);
    assert_eq!(
        accounting
            .direction()
            .symbols
            .mixed_small_repair_reserved_bytes,
        repair.data.len() as u64,
    );
    assert!(repair_allowed(
        &accounting.policy,
        &accounting.budget,
        &accounting.blocks,
        &repair.front,
        repair.data.len(),
    ));
    assert!(!repair_allowed(
        &accounting.policy,
        &accounting.budget,
        &accounting.blocks,
        &repair.front,
        repair.data.len() + 1,
    ));
    assert!(
        !accounting.budget.can_repair(1),
        "small must not earn bulk credit"
    );
    let shared = Arc::new(Mutex::new(vec![repair_path.clone()]));
    let mut wait = WaitingSend::new(accounting.prepare(&repair_path, true));
    block_and_poll(&mut wait, &shared, Duration::from_secs(1));
    assert_eq!(pair.receive().await.as_ref(), FILLER);
    let ready = timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            wait.poll(cx, &shared, Duration::from_secs(1), |attempt, _, _| {
                repair_allowed(
                    &accounting.policy,
                    &accounting.budget,
                    &accounting.blocks,
                    &attempt.front,
                    attempt.data.len(),
                )
            })
        }),
    )
    .await
    .unwrap();
    let SendReadiness::Admitted { at, .. } = ready else {
        panic!("{ready:?}")
    };
    let repair = wait.cancel();
    accounting.commit(&repair, at, 0);
    assert_eq!(pair.receive().await, repair.data);
    assert!(!repair_allowed(
        &accounting.policy,
        &accounting.budget,
        &accounting.blocks,
        &repair.front,
        repair.data.len(),
    ));
    let symbols = accounting.direction().symbols;
    assert_eq!(symbols.mixed_small_repairs_quinn_admitted, 1);
    assert_eq!(
        symbols.mixed_small_repair_admitted_bytes,
        repair.data.len() as u64
    );
    assert_eq!(symbols.mixed_bulk_original_admitted_bytes, 0);
    assert_eq!(symbols.mixed_bulk_repair_admitted_bytes, 0);
    let spent = original.data.len() + repair.data.len() + 160;
    assert!(accounting.pacer.available(9600 - spent));
    assert!(!accounting.pacer.available(9601 - spent));
    assert!(!accounting.groups[2].available(9601 - spent));
}

#[tokio::test(flavor = "current_thread")]
async fn cold_small_copy_is_authorized_only_by_its_actual_original_admission() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let mut accounting = Accounting::new();
    accounting.policy.fec = 0;
    accounting.policy.small_fec_bytes = 128;
    accounting.policy.redundancy = 0;
    accounting.budget = outbound::RepairBudget::new(0);
    let created = Instant::now();
    let small = Record {
        flow: 2,
        id: 1,
        payload: vec![7; 128],
    };
    let mut encoder = Encoder::new(1, Duration::from_millis(3)).unwrap();
    for symbol in encode_record(&small, &mut encoder, &accounting.policy, created).unwrap() {
        accounting.enqueue(symbol, created);
    }
    let repair = accounting.prepare(&path, true);
    assert!(!repair_allowed(
        &accounting.policy,
        &accounting.budget,
        &accounting.blocks,
        &repair.front,
        repair.data.len()
    ));
    let original = accounting.prepare(&path, false);
    let at = send_datagram_before_deadline(
        &path,
        original.data.clone(),
        created,
        Duration::from_secs(1),
    )
    .unwrap()
    .unwrap();
    accounting.commit(&original, at, 0);
    assert!(
        repair_allowed(
            &accounting.policy,
            &accounting.budget,
            &accounting.blocks,
            &repair.front,
            repair.data.len()
        ),
        "one small copy must not wait for unrelated bulk credit"
    );
    assert!(
        !accounting.budget.can_repair(repair.data.len()),
        "the percentage budget remains empty"
    );
    assert_eq!(pair.receive().await, original.data);
    let shared = Arc::new(Mutex::new(vec![path.clone()]));
    let mut wait = WaitingSend::new(accounting.prepare(&path, true));
    block_and_poll(&mut wait, &shared, Duration::from_secs(1));
    assert_eq!(pair.receive().await.as_ref(), FILLER);
    let ready = timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            wait.poll(cx, &shared, Duration::from_secs(1), |attempt, _, _| {
                repair_allowed(
                    &accounting.policy,
                    &accounting.budget,
                    &accounting.blocks,
                    &attempt.front,
                    attempt.data.len(),
                ) && accounting.pacer.available(attempt.data.len() + 80)
                    && accounting.groups[2].available(attempt.data.len() + 80)
            })
        }),
    )
    .await
    .unwrap();
    let SendReadiness::Admitted { at, .. } = ready else {
        panic!("{ready:?}")
    };
    let repair = wait.cancel();
    accounting.commit(&repair, at, 0);
    assert!(
        !repair_allowed(
            &accounting.policy,
            &accounting.budget,
            &accounting.blocks,
            &repair.front,
            repair.data.len()
        ),
        "successful copy consumes its one-original authorization"
    );
    assert_eq!(accounting.direction().symbols.repairs_quinn_admitted, 1);
    assert_eq!(pair.receive().await, repair.data);
    let spent = original.data.len() + repair.data.len() + 160;
    assert!(accounting.pacer.available(9600 - spent));
    assert!(!accounting.pacer.available(9601 - spent));
    assert!(!accounting.groups[2].available(9601 - spent));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_admission_rechecks_ingress_deadline_after_preparation() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let mut accounting = Accounting::new();
    let created = Instant::now();
    let lifetime = Duration::from_millis(100);
    // Both classes inherit the original's ingress time, even after preparation.
    accounting.enqueue(wire::plain(&record(1)).unwrap(), created);
    let mut encoder = Encoder::new(1, Duration::from_millis(25)).unwrap();
    let repair = encoder
        .push(&record(2).encode().unwrap(), created)
        .unwrap()
        .pop()
        .unwrap();
    accounting.enqueue(wire::shard(repair), created);
    let prepared: Vec<_> = [false, true]
        .into_iter()
        .map(|repair| accounting.prepare(&path, repair))
        .collect();
    let cached_preflight = created;
    assert!(cached_preflight.saturating_duration_since(created) < lifetime);
    for attempt in prepared {
        assert!(path.writer.admits(attempt.data.len()));
        // Advance only the final admission clock, simulating time spent preparing
        // or waiting for locks after the cached preflight, without wall-clock sleep.
        ADMISSION_CLOCK_OVERRIDE.with(|clock| clock.set(Some(created + lifetime)));
        assert!(
            send_datagram_before_deadline(&path, attempt.data, attempt.front.created, lifetime,)
                .is_none(),
            "an expired prepared frame must never enter a ready Quinn buffer"
        );
        let expired = accounting.queue.pop(attempt.repair).unwrap();
        account_expired(&expired, created + lifetime, &accounting.scope);
    }
    accounting.assert_no_admission(&path, 0);
    let counts = accounting.direction().symbols;
    assert_eq!(counts.originals_expired_dropped, 1);
    assert_eq!(counts.repairs_expired_dropped, 1);
    assert_eq!(counts.expiry_wait.count, 2);
    let fresh = wire::http_datagram(0, &wire::plain(&record(3)).unwrap()).unwrap();
    assert!(
        send_datagram_before_deadline(
            &path,
            fresh.clone(),
            Instant::now(),
            Duration::from_secs(1),
        )
        .unwrap()
        .is_ok()
    );
    assert_eq!(pair.receive().await, fresh);
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn ready_admission_rechecks_deadline_after_control_gate() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let mut accounting = Accounting::new();
    accounting.enqueue(wire::plain(&record(1)).unwrap(), Instant::now());
    let mut prepared = accounting.prepare(&path, false);
    prepared.front.created = Instant::now();
    let lifetime = Duration::from_millis(100);
    let expired_at = prepared.front.created + lifetime;
    assert!(path.writer.admits(prepared.data.len()));
    let mut wait = WaitingSend::new(prepared);
    let mut gate_checked = false;
    let readiness = poll_fn(|cx| {
        wait.poll(cx, &paths, lifetime, |_, _, _| {
            gate_checked = true;
            ADMISSION_CLOCK_OVERRIDE.with(|clock| clock.set(Some(expired_at)));
            true
        })
    })
    .await;
    assert!(
        gate_checked,
        "the initial age check must pass before the gate"
    );
    assert!(matches!(readiness, SendReadiness::Expired));
    wait.cancel();
    accounting.assert_no_admission(&path, 1);
    pair.assert_quiet().await;
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
        let wakes = block_and_poll(&mut wait, &paths, Duration::from_secs(1));
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
    block_and_poll(&mut wait, &paths, Duration::from_secs(1));
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
    block_and_poll(&mut wait, &paths, lifetime);
    assert_eq!(pair.receive().await.as_ref(), FILLER);
    tokio::time::sleep_until((created + Duration::from_millis(25)).into()).await;
    assert!(wait.prepared.path.writer.admits(wait.prepared.data.len()));
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
        block_and_poll(&mut wait, &paths, Duration::from_secs(1));
        if removed {
            paths.lock().unwrap().clear();
        } else {
            path.quality.lock().unwrap().snapshot.generation += 1;
        }
        assert_eq!(pair.receive().await.as_ref(), FILLER);
        assert!(wait.prepared.path.writer.admits(wait.prepared.data.len()));
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
    block_and_poll(&mut wait, &paths, Duration::from_secs(1));
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
async fn sender_feedback_stats_publish_on_tick_and_final_not_each_input() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let mut policy = policy();
    policy.fec = 0;
    policy.redundancy = 0;
    policy.receiver_feedback = true;
    policy.quality_schedule = false;
    policy.rate = 400_000_000;
    policy.group_rates = [policy.rate; MAX_PATHS];
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("stats-publication-test", stats::FORWARD);
    metrics.register(
        "stats-publication-test",
        0,
        0,
        stats::FORWARD,
        &pair.outgoing,
    );
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stopped) = watch::channel(false);
    tokio::time::pause();
    QUALITY_STATS_PUBLICATIONS.with(|count| count.set(0));
    let task = tokio::spawn(sender(rx, paths, policy, stopped, scope, None));
    tokio::task::yield_now().await;
    // Drive only setup timer-wheel readiness; the measured Input batch stays frozen.
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..256 {
        tokio::task::yield_now().await;
        if QUALITY_STATS_PUBLICATIONS.with(|count| count.get()) > 0 {
            break;
        }
    }
    let initial = QUALITY_STATS_PUBLICATIONS.with(|count| count.get());
    assert!(initial > 0, "setup tick must publish before the batch");
    let frozen_time = tokio::time::Instant::now();
    for id in 0..100 {
        tx.try_send(QueuedRecord {
            record: record(id),
            created: Instant::now(),
            hold: None,
        })
        .unwrap();
    }
    let mut consumed = 0;
    for _ in 0..2048 {
        tokio::task::yield_now().await;
        metrics.state(|s| {
            consumed = s.sessions["stats-publication-test"][stats::FORWARD]
                .records
                .sender_input_consumed;
        });
        if consumed == 100 {
            break;
        }
    }
    assert_eq!(consumed, 100, "the actual actor consumed every input");
    assert_eq!(tokio::time::Instant::now(), frozen_time);
    let after_inputs = QUALITY_STATS_PUBLICATIONS.with(|count| count.get());
    eprintln!("initial_publications={initial} after_100_inputs={after_inputs}");
    assert_eq!(
        after_inputs, initial,
        "input/readiness must not publish stats"
    );
    // A pending update must still appear in final stats even without another Tick.
    path.quality.lock().unwrap().snapshot.controls_received += 1;
    stop.send(true).unwrap();
    task.await.unwrap();
    assert_eq!(
        QUALITY_STATS_PUBLICATIONS.with(|count| count.get()),
        initial + 1
    );
    let expected = path.quality.lock().unwrap().snapshot.clone();
    metrics.state(|s| {
        let actual = s.paths["stats-publication-test/0"]
            .receiver_feedback
            .as_ref()
            .unwrap();
        assert_eq!(actual.sent_symbols, expected.sent_symbols);
        assert_eq!(actual.sent_bytes, expected.sent_bytes);
        assert_eq!(actual.controls_received, expected.controls_received);
    });
    tokio::time::resume();
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
                created: Instant::now(),
                hold: None,
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
        let frontier = d.sender_frontier.as_ref().expect("final sender census");
        assert!(!frontier.enabled);
        let immediate: u64 = frontier
            .paths
            .iter()
            .map(|p| p.small.api_admitted + p.other.api_admitted)
            .sum();
        assert_eq!(
            immediate + frontier.readiness_admitted,
            d.symbols.originals_quinn_admitted + d.symbols.repairs_quinn_admitted
        );
        assert_eq!(frontier.small_rank_changes, 0);
    });
    pair.assert_quiet().await;
}

#[tokio::test(flavor = "current_thread")]
async fn automatic_blocked_copy_cannot_starve_later_originals() {
    // A cold automatic small record carries one copy. On a single path the
    // copy waits until the original leaves Quinn's queue, which cannot happen
    // inside one drain pass; the bulk originals behind it must still be sent.
    let pair = Pair::connect().await;
    let paths = Arc::new(Mutex::new(vec![pair.path()]));
    let mut policy = policy();
    policy.fec = automatic_fec::AUTO;
    policy.redundancy = 30;
    policy.queue_ms = 300;
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("blocked-copy", stats::FORWARD);
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(sender(rx, paths, policy, stopped, scope, None));
    // Earn small-copy credit before the records arrive.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut small = record(0);
    small.flow = 2;
    small.payload.truncate(64);
    let records: Vec<_> = std::iter::once(small).chain((1..=8).map(record)).collect();
    for record in records {
        tx.try_send(QueuedRecord {
            record,
            created: Instant::now(),
            hold: None,
        })
        .unwrap();
    }
    let started = Instant::now();
    let admitted = || {
        let mut n = 0;
        metrics.state(|s| {
            n = s
                .sessions
                .get("blocked-copy")
                .and_then(|d| d.get(stats::FORWARD))
                .map_or(0, |d| d.symbols.originals_quinn_admitted);
        });
        n
    };
    timeout(Duration::from_secs(3), async {
        while admitted() < 9 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(150),
        "originals waited behind a blocked copy for {:?}",
        started.elapsed()
    );
    stop.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    metrics.state(|s| {
        let d = &s.sessions["blocked-copy"][stats::FORWARD];
        assert_eq!(d.symbols.originals_quinn_admitted, 9);
        assert_eq!(d.symbols.originals_expired_dropped, 0);
    });
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

#[tokio::test]
async fn business_only_feedback_does_not_renew_independent_probe_evidence() {
    let pair = Pair::connect().await;
    let mut path = pair.path();
    path.capacity_probe_enabled = true;
    let paths = Arc::new(Mutex::new(vec![path.clone()]));
    let scope = stats::Metrics::new("client").scope("selective-feedback", stats::FORWARD);
    let mut body_receiver = capacity_probe::State::new(7);
    let frame = {
        let mut sender = path.capacity_probe.lock().unwrap();
        let frame = sender.prepare(0);
        sender.admitted();
        frame
    };
    body_receiver.receive(&frame, 1000).unwrap();
    let mut business_peer = quality::State::new(7);
    let combined = capacity_probe::control(
        &[business_peer.report(0, 1000)],
        &[body_receiver.report(0, quality::ReportKind::Full, 1000)],
    );
    measured_payload(&paths, 0, &combined, true, &scope, None).unwrap();
    let before = path
        .capacity_probe
        .lock()
        .unwrap()
        .snapshot(quality_time(&path));
    assert_eq!(before.sender_estimate.received_bytes, 972);
    assert!(before.sender_estimate.delivered_updated_us.is_some());
    let business_only = quality::control_v2(&[business_peer.delivery_report(0, 2000)]);
    measured_payload(&paths, 0, &business_only, true, &scope, None).unwrap();
    let after = path
        .capacity_probe
        .lock()
        .unwrap()
        .snapshot(quality_time(&path));
    assert_eq!(
        serde_json::to_value(&before.sender_estimate).unwrap(),
        serde_json::to_value(&after.sender_estimate).unwrap()
    );
    assert_eq!(before.controls_received, after.controls_received);
    assert_eq!(path.quality.lock().unwrap().snapshot.controls_received, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn native_sender_records_bbr_startup_budget_and_delivers_the_original() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let paths = Arc::new(Mutex::new(vec![path]));
    let mut policy = policy();
    policy.adaptive = true;
    policy.fec = 0;
    policy.redundancy = 0;
    policy.latency_target_ms = 100;
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("native-startup-test", stats::FORWARD);
    metrics.register("native-startup-test", 0, 0, stats::FORWARD, &pair.outgoing);
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stopped) = watch::channel(false);
    tx.try_send(QueuedRecord {
        record: record(1),
        created: Instant::now(),
        hold: None,
    })
    .unwrap();
    let task = tokio::spawn(sender(rx, paths, policy.clone(), stopped, scope, None));
    let mut quality = quality::State::new(7);
    let mut decoder = Receiver::default();
    timeout(Duration::from_secs(3), async {
        loop {
            let frame = pair.incoming.read_datagram().await.unwrap();
            let payload = wire::http_payload(&frame, 0).unwrap();
            if payload.starts_with(b"BQ1D") {
                let data = quality.receive(payload, 0).unwrap();
                assert_eq!(
                    decoder.receive(data, Instant::now()).unwrap(),
                    vec![record(1)]
                );
                break;
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
        let d = &s.sessions["native-startup-test"][stats::FORWARD];
        assert_eq!(d.symbols.originals_quinn_admitted, 1);
        let snapshot = s.paths.values().find_map(|p| p.adaptive.as_ref()).unwrap();
        let seed = snapshot
            .rate_changes
            .iter()
            .find(|change| matches!(change.reason, adaptive::RateReason::NativeStartup))
            .unwrap();
        let cwnd = seed.control.native_startup_cwnd_bytes.unwrap();
        let rtt = seed.control.native_startup_rtt_us.unwrap();
        assert!(cwnd > 0 && rtt > 0);
        assert_eq!(
            seed.pacing_bps,
            (u128::from(cwnd) * 8_000_000 / u128::from(rtt)).min(u128::from(policy.rate)) as u64
        );
    });
}

#[tokio::test(flavor = "current_thread")]
async fn writer_control_prepend_preserves_byte_accounting() {
    let pair = Pair::connect().await;
    let path = pair.path();
    path.writer.set_pace(80_000_000);
    let writer = path.writer.clone();
    writer::test_before_pop(move || {
        assert!(writer.send_first(Bytes::from_static(b"ctl")));
    });
    assert!(path.writer.send(Bytes::from(vec![0xa5; 900])));
    assert_eq!(pair.receive().await.as_ref(), b"ctl");
    assert_eq!(pair.receive().await.len(), 900);
    assert_eq!(
        path.writer.held(),
        0,
        "drained writer byte count must not wrap"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn writer_queue_accounting_release_wakes_admission() {
    let pair = Pair::connect().await;
    let path = pair.path();
    let (entered, release) = writer::test_after_send();
    assert!(path.writer.send(Bytes::from(vec![0xa5; 900])));
    entered.await.unwrap();
    assert_eq!(pair.receive().await.len(), 900);
    // Quinn is empty, but the transferring item is still counted by Writer.
    assert!(!path.writer.admits(900));
    let mut admitted = Box::pin(path.writer.admitted(900));
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = std::task::Context::from_waker(&waker);
    assert!(admitted.as_mut().poll(&mut cx).is_pending());
    release.send(()).unwrap();
    timeout(Duration::from_secs(1), async {
        while !path.writer.admits(900) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(path.writer.admits(900));
    assert!(
        admitted.as_mut().poll(&mut cx).is_ready(),
        "writer freed its last queued bytes after Quinn's drain notification; the waiter must wake and finish"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn native_liveness_hints_track_real_data_and_ack_progress() {
    let pair = Pair::connect().await;
    let before = pair.outgoing.liveness_hint();
    for _ in 0..16 {
        pair.outgoing
            .send_datagram(Bytes::from_static(b"liveness"))
            .unwrap();
    }
    for _ in 0..16 {
        assert_eq!(&pair.receive().await[..], b"liveness");
    }
    timeout(Duration::from_secs(3), async {
        loop {
            let (acks, eliciting) = pair.outgoing.liveness_hint();
            if acks > before.0 && eliciting >= before.1 + 16 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real ACK and sent frames must reach the published hints");
    let (acks, eliciting) = pair.outgoing.liveness_hint();
    let actual = pair.outgoing.stats();
    assert!(acks <= actual.frame_rx.acks);
    assert!(eliciting <= actual.frame_tx.datagram + actual.frame_tx.stream + actual.frame_tx.ping);
}
