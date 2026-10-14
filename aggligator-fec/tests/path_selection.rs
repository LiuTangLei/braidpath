#[path = "../src/path.rs"]
mod path;

use std::time::Duration;

#[test]
fn late_probe_timeout_preserves_newer_success() {
    let mut scheduler=path::PathScheduler::new(1).unwrap();
    scheduler.observe(0,Duration::from_millis(100),Duration::from_millis(400));
    scheduler.timeout(0,Duration::from_millis(600));
    assert_eq!(scheduler.best(Duration::from_millis(600)),Some(0));
    assert_eq!(scheduler.best(Duration::from_secs(2)),None);
}

#[test]
fn transpacific_retry_budget_exceeds_its_round_trip() {
    let mut scheduler=path::PathScheduler::new(1).unwrap();
    for i in 0..30 {
        scheduler.observe(0,Duration::from_millis(320),Duration::from_millis(i*100));
    }
    let delay=scheduler.retry_delay(Duration::from_millis(2900));
    assert!(delay>=Duration::from_millis(340));
    assert!(delay<Duration::from_millis(400));
}

#[test]
fn independent_uplinks_aggregate_without_counting_relays_as_extra_bandwidth(){
    let mut scheduler=path::PathScheduler::new(32).unwrap();
    scheduler.set_access_weights(vec![30,10]).unwrap();
    for i in 0..20{
        let now=Duration::from_millis(i*100);
        scheduler.observe(0,Duration::from_millis(30),now);
        scheduler.observe(1,Duration::from_millis(35),now); // Same WAN, not another 30Mbps.
        scheduler.observe(8,Duration::from_millis(50),now);
    }
    let now=Duration::from_millis(1900);let mut counts=[0usize;4];
    for _ in 0..400{let lane=scheduler.select(now).unwrap();counts[lane/8]+=1;assert!(lane==0||lane==8);}
    assert_eq!(counts,[300,100,0,0]);
    scheduler.set_enabled(0,false);scheduler.set_enabled(1,false);
    for _ in 0..50{assert_eq!(scheduler.select(now),Some(8));}
    scheduler.set_enabled(0,true);scheduler.observe(0,Duration::from_millis(30),now);
    assert!((0..100).any(|_|scheduler.select(now)==Some(0)));
}

#[test]
fn low_latency_path_wins() {
    let mut scheduler = path::PathScheduler::new(3).unwrap();
    let base = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(100), base);
    scheduler.observe(1, Duration::from_millis(180), base);
    scheduler.observe(2, Duration::from_millis(210), base);

    assert_eq!(scheduler.best(base), Some(0));
    assert_eq!(scheduler.select(base), Some(0));
}

#[test]
fn near_equal_paths_share_weight() {
    let mut scheduler = path::PathScheduler::new(3).unwrap();
    let base = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(100), base);
    scheduler.observe(1, Duration::from_millis(103), base);
    scheduler.observe(2, Duration::from_millis(400), base);

    let snapshots = scheduler.snapshots(base);
    let live = snapshots.iter().filter(|s| s.live).collect::<Vec<_>>();
    assert_eq!(live.len(), 3);
    assert!(live[0].weight > 0);
    assert!(live[1].weight > 0);
    assert_eq!(live[2].weight, 0);
    assert!(matches!(scheduler.select(base), Some(0) | Some(1)));
}

#[test]
fn constant_now_cycles_across_near_equal_paths() {
    let mut scheduler = path::PathScheduler::new(3).unwrap();
    let base = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(100), base);
    scheduler.observe(1, Duration::from_millis(101), base);
    scheduler.observe(2, Duration::from_millis(500), base);

    let picks = (0..64)
        .map(|_| scheduler.select(base).unwrap())
        .collect::<Vec<_>>();
    assert!(picks.iter().all(|pick| matches!(pick, 0 | 1)));
    assert!(picks.contains(&0));
    assert!(picks.contains(&1));
}

#[test]
fn degradation_shifts_preferred_path() {
    let mut scheduler = path::PathScheduler::new(2).unwrap();
    let start = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(100), start);
    scheduler.observe(1, Duration::from_millis(102), start);

    let later = Duration::from_millis(500);
    scheduler.observe(0, Duration::from_millis(400), later);
    scheduler.observe(1, Duration::from_millis(105), later);

    assert_eq!(scheduler.best(later), Some(1));
}

#[test]
fn repair_never_uses_a_slow_alternative_just_because_it_is_the_only_alternative() {
    let mut scheduler=path::PathScheduler::new(3).unwrap();
    let now=Duration::ZERO;
    scheduler.observe(0,Duration::from_millis(100),now);
    scheduler.observe(1,Duration::from_millis(400),now);
    scheduler.observe(2,Duration::from_millis(500),now);
    for _ in 0..100 {assert_eq!(scheduler.repair(now,0),Some(0));}
    scheduler.set_enabled(0,false);
    assert_ne!(scheduler.repair(now,0),Some(0));
    scheduler.set_enabled(0,true);
    assert!(!scheduler.snapshots(now)[0].live);
}

#[test]
fn repair_falls_back_when_alternative_is_too_slow() {
    let mut scheduler = path::PathScheduler::new(2).unwrap();
    let base = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(100), base);
    scheduler.observe(1, Duration::from_millis(3000), base);

    assert_eq!(scheduler.repair(base, 1), Some(0));
}

#[test]
fn timeout_disables_and_recovery_reuses_healthy_path() {
    let mut scheduler = path::PathScheduler::new(3).unwrap();
    let base = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(90), base);
    scheduler.observe(1, Duration::from_millis(95), base);
    scheduler.observe(2, Duration::from_millis(250), base);

    let refresh = Duration::from_millis(500);
    scheduler.observe(1, Duration::from_millis(96), refresh);
    scheduler.timeout(0, Duration::from_millis(750));

    assert_eq!(scheduler.best(Duration::from_millis(750)), Some(1));
    assert_eq!(scheduler.repair(Duration::from_millis(750), 0), Some(1));

    let fresh = Duration::from_millis(1400);
    scheduler.observe(0, Duration::from_millis(92), fresh);
    assert_eq!(scheduler.best(fresh), Some(0));
}

#[test]
fn all_dead_paths_return_none() {
    let mut scheduler = path::PathScheduler::new(2).unwrap();
    let base = Duration::from_millis(0);
    scheduler.observe(0, Duration::from_millis(80), base);
    scheduler.observe(1, Duration::from_millis(85), base);

    scheduler.timeout(0, Duration::from_secs(2));
    scheduler.timeout(1, Duration::from_secs(2));

    assert_eq!(scheduler.best(Duration::from_secs(2)), None);
    assert_eq!(scheduler.select(Duration::from_secs(2)), None);
    assert_eq!(scheduler.repair(Duration::from_secs(2), 0), None);
}

#[test]
fn malformed_indices_and_times_do_not_panic() {
    let mut scheduler = path::PathScheduler::new(2).unwrap();
    let now = Duration::from_secs(1);

    scheduler.observe(99, Duration::from_millis(10), now);
    scheduler.observe(0, Duration::ZERO, now);
    scheduler.observe(0, Duration::from_secs(90), now);
    scheduler.observe(1, Duration::from_millis(50), now - Duration::from_millis(1));
    scheduler.timeout(99, now);

    let _ = scheduler.best(now);
    let _ = scheduler.select(now);
    let _ = scheduler.repair(now, 99);
    let _ = scheduler.snapshots(now);
}

#[test]
fn fast_but_lossy_originals_lose_to_slightly_slower_reliable_path() {
    let mut scheduler=path::PathScheduler::new(2).unwrap();
    let now=Duration::from_secs(1);
    for _ in 0..30 {
        scheduler.observe(0,Duration::from_millis(110),now);
        scheduler.observe(1,Duration::from_millis(125),now);
    }
    assert_eq!(scheduler.best(now),Some(0));
    scheduler.observe_delivery(0,64,6,now);
    scheduler.observe_delivery(1,64,0,now);
    assert_eq!(scheduler.best(now),Some(1));
    assert!((0..128).any(|_|scheduler.select(now)==Some(1)));
    assert_eq!(scheduler.snapshots(now)[0].delivery_samples,64);
    // Payload recovery matters: successful pings alone must not erase this signal.
    for _ in 0..20 {scheduler.observe(0,Duration::from_millis(110),now);}
    assert_eq!(scheduler.best(now),Some(1));
    for _ in 0..12 {scheduler.observe_delivery(0,64,0,now);}
    assert_eq!(scheduler.best(now),Some(0));
}

#[test]
fn old_delivery_deficits_do_not_permanently_blacklist_a_recovered_path() {
    let mut scheduler=path::PathScheduler::new(2).unwrap();
    let now=Duration::ZERO;
    for _ in 0..30 {
        scheduler.observe(0,Duration::from_millis(100),now);
        scheduler.observe(1,Duration::from_millis(120),now);
    }
    scheduler.observe_delivery(0,64,32,now);
    assert_eq!(scheduler.best(now),Some(1));
    let later=Duration::from_secs(90);
    scheduler.observe(0,Duration::from_millis(100),later);
    scheduler.observe(1,Duration::from_millis(120),later);
    assert_eq!(scheduler.best(later),Some(0));
    scheduler.observe_delivery(0,0,1,later);
    scheduler.observe_delivery(99,1,1,later);
    assert_eq!(scheduler.snapshots(later)[0].delivery_samples,64);
}
