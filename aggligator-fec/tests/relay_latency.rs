#![cfg(feature = "runtime")]
use aggligator_fec::multiplex::{RelayTable, LANES, MAX_FLOWS};
use std::{net::{IpAddr, SocketAddr}, time::{Duration, Instant}};

fn packet(flow: u64, kind: u8) -> Vec<u8> {
    let mut bytes = b"AFM3".to_vec(); bytes.extend(flow.to_be_bytes()); bytes.push(0);
    bytes.extend(b"AFL1"); bytes.push(kind); bytes.extend((flow + 10_000).to_be_bytes());
    match kind {
        9 => bytes.extend(b"FECSTREAM2"),
        2 | 3 | 11 => bytes.extend(1u64.to_be_bytes()),
        7 => { bytes.extend(1u64.to_be_bytes()); bytes.push(1); },
        _ => bytes.push(42),
    }
    bytes
}
fn peers() -> (SocketAddr, SocketAddr, [IpAddr; 1]) {
    ("127.0.0.1:9000".parse().unwrap(), "127.0.0.1:9001".parse().unwrap(), ["127.0.0.1".parse().unwrap()])
}
fn latency_table() -> RelayTable {
    let mut table = RelayTable::default(); table.set_low_latency(true); table
}

#[test]
fn fifteen_hundred_short_sessions_retire_with_a_fixed_two_second_replay_window() {
    let (master, client, allowed) = peers(); let start = Instant::now();
    let mut table = latency_table();
    for flow in 1..=1500 {
        let at = start + Duration::from_millis(flow * 10);
        assert_eq!(table.route(&packet(flow, 9), client, master, &allowed, at), Some(master));
        assert_eq!(table.route(&packet(flow, 11), master, master, &allowed, at), Some(client));
        assert_eq!(table.route(&packet(flow, 11), client, master, &allowed, at), Some(master));
        assert!(table.len() <= 201, "completed sessions accumulated until the old 60s TTL");
    }
    // Valid late FINs still route during the entire replay window. They must
    // not move its deadline forward or retain the association indefinitely.
    let late = start + Duration::from_millis(16_900);
    assert_eq!(table.route(&packet(1500, 7), client, master, &allowed, late), Some(master));
    assert_eq!(table.route(&packet(1500, 11), master, master, &allowed, late), Some(client));
    let expired = start + Duration::from_millis(17_001);
    table.prune(expired, &allowed);
    assert!(table.is_empty());
    assert_eq!(table.route(&packet(1500, 7), client, master, &allowed, expired), None);
    assert_eq!(table.route(&packet(1500, 1), master, master, &allowed, expired), None);
}

#[test]
fn one_sided_fin_ack_never_retires_a_live_half_closed_stream() {
    let (master, client, allowed) = peers(); let start = Instant::now(); let mut table = latency_table();
    assert_eq!(table.route(&packet(1, 9), client, master, &allowed, start), Some(master));
    assert_eq!(table.route(&packet(1, 7), client, master, &allowed, start), Some(master));
    assert_eq!(table.route(&packet(1, 11), master, master, &allowed, start), Some(client));
    // A malformed, wrong-session or wrong-source FIN_ACK cannot supply the
    // missing direction and start retirement of a legitimate half-close.
    let mut malformed = packet(1, 11); malformed.pop();
    assert_eq!(table.route(&malformed, client, master, &allowed, start), Some(master));
    let mut wrong_session = packet(1, 11); wrong_session[25] ^= 1;
    assert_eq!(table.route(&wrong_session, client, master, &allowed, start), None);
    assert_eq!(table.route(&packet(1, 11), "127.0.0.1:9999".parse().unwrap(), master, &allowed, start), None);
    for tick in 1..=24 {
        let at = start + Duration::from_millis(tick * 500);
        assert_eq!(table.route(&packet(1, 2), client, master, &allowed, at), Some(master));
        assert_eq!(table.route(&packet(1, 11), master, master, &allowed, at), Some(client));
        assert_eq!(table.route(&packet(1, 1), master, master, &allowed, at), Some(client));
        table.prune(at, &allowed); assert_eq!(table.len(), 1);
    }
}

#[test]
fn pressure_reclaims_only_the_oldest_stale_route_and_ping_can_reassociate_it() {
    let (master, client, allowed) = peers(); let start = Instant::now(); let mut table = latency_table();
    let capacity = (MAX_FLOWS * LANES) as u64;
    for flow in 1..=capacity {
        assert_eq!(table.route(&packet(flow, 9), client, master, &allowed, start), Some(master));
    }
    let recent = start + Duration::from_secs(1);
    assert_eq!(table.route(&packet(capacity + 1, 9), client, master, &allowed, recent), None,
        "a full fresh table must keep its live associations");
    let pressure = start + Duration::from_millis(3001);
    assert_eq!(table.route(&packet(1, 2), client, master, &allowed, pressure), Some(master));
    assert_eq!(table.route(&packet(capacity + 1, 9), client, master, &allowed, pressure), Some(master));
    assert_eq!(table.len(), capacity as usize);
    assert_eq!(table.route(&packet(1, 1), master, master, &allowed, pressure), Some(client), "fresh warm route was evicted");
    assert_eq!(table.route(&packet(2, 1), client, master, &allowed, pressure), None, "oldest stale route was not reclaimed");
    // Recovery is a real association boundary: DATA racing the next probe can
    // be lost, but the admitted session's PING establishes its mapping again.
    assert_eq!(table.route(&packet(2, 2), client, master, &allowed, pressure), Some(master));
    assert_eq!(table.route(&packet(2, 1), client, master, &allowed, pressure), Some(master));
    assert_eq!(table.route(&packet(2, 3), master, master, &allowed, pressure), Some(client));
    assert_eq!(table.len(), capacity as usize);
    table.prune(pressure, &[]); assert!(table.is_empty(), "revoked clients retained relay associations");
}

#[test]
fn balanced_table_keeps_its_sixty_second_lifetime_and_fresh_capacity_policy() {
    let (master, client, allowed) = peers(); let start = Instant::now(); let mut table = RelayTable::default();
    let capacity = (MAX_FLOWS * LANES) as u64;
    for flow in 1..=capacity {
        assert_eq!(table.route(&packet(flow, 9), client, master, &allowed, start), Some(master));
        assert_eq!(table.route(&packet(flow, 11), client, master, &allowed, start), Some(master));
        assert_eq!(table.route(&packet(flow, 11), master, master, &allowed, start), Some(client));
    }
    let later = start + Duration::from_secs(4); table.prune(later, &allowed);
    assert_eq!(table.len(), capacity as usize);
    assert_eq!(table.route(&packet(capacity + 1, 9), client, master, &allowed, later), None);
    assert_eq!(table.route(&packet(1, 1), master, master, &allowed, later), Some(client));
}
