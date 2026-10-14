#![cfg(feature="runtime")]
use aggligator_fec::multiplex::{self,RelayTable};
use std::time::{Duration,Instant};
fn packet(flow:u64,lane:u8,sid:u64,kind:u8)->Vec<u8>{
    let mut p=b"AFM3".to_vec();p.extend(flow.to_be_bytes());p.push(lane);p.extend(b"AFL1");p.push(kind);p.extend(sid.to_be_bytes());
    if kind==9{p.extend(b"FECSTREAM2");}else if kind==2{p.extend(123u64.to_be_bytes());}p
}
#[test]
fn relay_separates_flows_lanes_and_allows_only_matching_session_nat_rebind(){
    let main="127.0.0.1:10000".parse().unwrap();let a="127.0.0.1:10001".parse().unwrap();let b="127.0.0.1:10002".parse().unwrap();let c="127.0.0.1:10003".parse().unwrap();
    let allowed=["127.0.0.1".parse().unwrap()];let now=Instant::now();let mut table=RelayTable::default();
    let p=packet(1,0,11,9);let q=packet(1,8,11,9);let r=packet(2,0,22,9);
    assert_eq!(table.route(&p,a,main,&allowed,now),Some(main));assert_eq!(table.route(&q,b,main,&allowed,now),Some(main));assert_eq!(table.route(&r,c,main,&allowed,now),Some(main));
    assert_eq!(table.route(&p,main,main,&allowed,now),Some(a));assert_eq!(table.route(&q,main,main,&allowed,now),Some(b));assert_eq!(table.route(&r,main,main,&allowed,now),Some(c));
    assert_eq!(table.route(&packet(1,0,999,9),c,main,&allowed,now),None);
    assert_eq!(table.route(&packet(1,0,11,1),c,main,&allowed,now),None);
    assert_eq!(table.route(&packet(1,0,11,2),c,main,&allowed,now),Some(main));
    assert_eq!(table.route(&p,main,main,&allowed,now),Some(c));
    assert_eq!(table.route(&p,"127.0.0.2:10001".parse().unwrap(),main,&allowed,now),None);
    table.prune(now+Duration::from_secs(61),&allowed);assert!(table.is_empty());
}
#[test]
fn malformed_mux_headers_are_rejected_before_session_allocation(){
    assert!(multiplex::decode(&packet(0,0,1,9)).is_none());assert!(multiplex::decode(&packet(1,32,1,9)).is_none());
    let good=packet(1,31,2,9);assert!(multiplex::decode(&good).is_some());
    for n in 0..26{assert!(multiplex::decode(&good[..n]).is_none());}
    let mut bad=good.clone();bad[13]=0;assert!(multiplex::decode(&bad).is_none());
    assert!(multiplex::decode(&vec![0;1700]).is_none());
}
