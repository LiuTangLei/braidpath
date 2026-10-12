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
        small_fec_bytes: 0,
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
async fn quality_only_bulk_unready_path_cannot_steal_later_small_requests() {
    let fast = Pair::connect().await;
    let blocked = Pair::connect().await;
    let path0 = fast.path();
    let mut path1 = blocked.path();
    path1.id = 1;
    let paths = [path0.clone(), path1.clone()];
    let mut accounting = Accounting::new();
    let created = Instant::now();
    accounting.enqueue(wire::plain(&record(1)).unwrap(), created);
    let mut prepared = accounting.prepare(&path0, false);
    prepared.candidates = vec![(0, 4), (1, 1)];
    // No await between filling Quinn and committing: the current-thread driver
    // cannot drain either buffer. Path 1 can accept a small symbol but no bulk.
    blocked
        .outgoing
        .send_datagram(Bytes::from(vec![0xa5; 900]))
        .unwrap();
    let small_bytes = 183;
    assert!(path1.conn.datagram_send_buffer_space() >= small_bytes);
    assert!(path1.conn.datagram_send_buffer_space() < prepared.data.len());
    let at = send_datagram_before_deadline(
        &path0.conn,
        prepared.data.clone(),
        created,
        Duration::from_secs(1),
    )
    .unwrap()
    .unwrap();
    assert!(path0.conn.datagram_send_buffer_space() < prepared.data.len());
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
        &path.conn,
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
    block_and_poll(&pair, &mut wait, &shared, Duration::from_secs(1));
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
        assert!(pair.outgoing.datagram_send_buffer_space() >= attempt.data.len());
        // Advance only the final admission clock, simulating time spent preparing
        // or waiting for locks after the cached preflight, without wall-clock sleep.
        ADMISSION_CLOCK_OVERRIDE.with(|clock| clock.set(Some(created + lifetime)));
        assert!(
            send_datagram_before_deadline(
                &pair.outgoing,
                attempt.data,
                attempt.front.created,
                lifetime,
            )
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
            &pair.outgoing,
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
    assert!(pair.outgoing.datagram_send_buffer_space() >= prepared.data.len());
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
