use aggligator_fec::{Config,Decoded,Decoder,Encoder,Error,Frame};
use std::{collections::BTreeMap,time::Duration};

fn config(k:usize,m:usize)->Config {
    Config {data_shards:k,repair_shards:m,max_payload:1100,max_decode_blocks:64,
        max_block_delay:Duration::from_millis(2)}
}
fn data(i:usize)->Vec<u8> { vec![(i+1) as u8;1+i*7] }
fn block(k:usize,m:usize)->Vec<Frame> {
    let mut enc=Encoder::new(config(k,m)).unwrap();
    (0..k).flat_map(|i|enc.push(data(i),Duration::ZERO).unwrap()).collect()
}
fn collect(out:Vec<Decoded>,received:&mut BTreeMap<u64,Vec<u8>>) {
    for item in out {
        if let Some(old)=received.insert(item.seq,item.payload.clone()) { assert_eq!(old,item.payload); }
    }
}

#[test]
fn all_erasure_subsets_up_to_two_of_six() {
    let frames=block(4,2);
    assert_eq!(frames.len(),6);
    for lost in 0u32..64 {
        if lost.count_ones()>2 {continue;}
        for reversed in [false,true] {
            let mut dec=Decoder::new(config(4,2)).unwrap();
            let mut received=BTreeMap::new();
            let mut indices:Vec<_>=(0..6).collect();
            if reversed {indices.reverse();}
            for i in indices {
                if lost&(1<<i)==0 {
                    let wire=frames[i].encode().unwrap();
                    let frame=Frame::decode(&wire,1100).unwrap();
                    collect(dec.input(&frame).unwrap(),&mut received);
                }
            }
            assert_eq!(received.len(),4,"lost={lost:b},reverse={reversed}");
            for i in 0..4 {assert_eq!(received[&(i as u64)],data(i));}
        }
    }
}

#[test]
fn originals_are_not_held_for_a_block() {
    let mut enc=Encoder::new(config(8,4)).unwrap();
    let out=enc.push(vec![7;100],Duration::ZERO).unwrap();
    assert!(matches!(out.as_slice(),[Frame::Source {..}]));
    let mut dec=Decoder::new(config(8,4)).unwrap();
    assert_eq!(dec.input(&out[0]).unwrap()[0].payload,vec![7;100]);
    assert!(enc.poll(Duration::from_micros(1999)).unwrap().is_empty());
    let parity=enc.poll(Duration::from_millis(2)).unwrap();
    assert!(matches!(parity.as_slice(),[Frame::Repair {data:1,parity:1,..}]));
    // A sole interactive packet can be reconstructed without waiting for a later write.
    let mut lost_original=Decoder::new(config(8,4)).unwrap();
    let repaired=lost_original.input(&parity[0]).unwrap();
    assert_eq!(repaired.len(),1);
    assert!(repaired[0].recovered);
    assert_eq!(repaired[0].payload,vec![7;100]);
}

#[test]
fn shortened_blocks_preserve_sequence_and_ratio() {
    let cfg=config(8,4);
    let mut enc=Encoder::new(cfg.clone()).unwrap();
    let mut dec=Decoder::new(cfg).unwrap();
    let mut output=BTreeMap::new();
    for i in 0..3 {enc.push(data(i),Duration::ZERO).unwrap();}
    let repairs=enc.flush().unwrap();
    assert_eq!(repairs.len(),2); // ceil(3*4/8), not four full-size repairs.
    assert!(matches!(repairs[0],Frame::Repair {data:3,parity:2,..}));
    let source=Frame::Source {block:0,base:0,index:2,payload:data(2)};
    collect(dec.input(&source).unwrap(),&mut output);
    for r in repairs {collect(dec.input(&r).unwrap(),&mut output);}
    assert_eq!(output.len(),3);
    let next=enc.push(data(3),Duration::from_millis(10)).unwrap();
    assert!(matches!(next[0],Frame::Source {block:1,base:3,index:0,..}));
    collect(dec.input(&next[0]).unwrap(),&mut output);
    assert_eq!(output[&3],data(3));
}

#[test]
fn expired_block_is_closed_before_the_next_source() {
    let mut enc=Encoder::new(config(8,4)).unwrap();
    enc.push(vec![1],Duration::ZERO).unwrap();
    let out=enc.push(vec![2],Duration::from_millis(3)).unwrap();
    assert!(matches!(out.as_slice(),[
        Frame::Repair {block:0,data:1,parity:1,..},Frame::Source {block:1,base:1,index:0,..}]));
}

#[test]
fn no_fec_does_not_invent_repairs() {
    let mut enc=Encoder::new(config(8,0)).unwrap();
    for i in 0..32 {
        let out=enc.push(data(i),Duration::from_millis(i as u64)).unwrap();
        assert!(matches!(out.as_slice(),[Frame::Source {..}]));
    }
    assert!(enc.flush().unwrap().is_empty());
}

#[test]
fn duplicates_are_safe_and_permit_ack_repetition() {
    let frames=block(4,2);
    let mut dec=Decoder::new(config(4,2)).unwrap();
    let first=dec.input(&frames[0]).unwrap();
    let duplicate=dec.input(&frames[0]).unwrap();
    assert_eq!(first,duplicate);
    let mut received=BTreeMap::new();
    for frame in frames.iter().rev().chain(frames.iter()) {
        collect(dec.input(frame).unwrap(),&mut received);
    }
    assert_eq!(received.len(),4);
}

#[test]
fn cache_eviction_is_bounded_and_does_not_break_late_arq_sources() {
    let cfg=Config {max_decode_blocks:2,..config(1,1)};
    let mut enc=Encoder::new(cfg.clone()).unwrap();
    let mut dec=Decoder::new(cfg).unwrap();
    let mut old=None;
    for i in 0..100 {
        let frames=enc.push(vec![i as u8],Duration::ZERO).unwrap();
        if i==0 {old=Some(frames[0].clone());}
        for frame in frames {dec.input(&frame).unwrap();}
        assert!(dec.buffered_blocks()<=2);
    }
    // FEC retention is not an application replay/order window.
    let retried=dec.input(&old.unwrap()).unwrap();
    assert_eq!(retried[0].seq,0);
    assert_eq!(retried[0].payload,[0]);
    assert!(dec.buffered_blocks()<=2);
}

#[test]
fn bad_metadata_cannot_poison_a_live_block() {
    let frames=block(4,2);
    let mut dec=Decoder::new(config(4,2)).unwrap();
    dec.input(&frames[0]).unwrap();
    assert_eq!(dec.input(&Frame::Source {block:0,base:0,index:0,payload:vec![99]}),Err(Error::ConflictingFrame));
    assert_eq!(dec.input(&Frame::Source {block:0,base:123,index:1,payload:vec![99]}),Err(Error::ConflictingFrame));
    assert!(dec.input(&Frame::Repair {block:0,base:0,data:2,parity:2,index:0,symbol:vec![0;12]}).is_err());
    let mut received=BTreeMap::new();
    for i in [0,3,4,5] {collect(dec.input(&frames[i]).unwrap(),&mut received);}
    assert_eq!(received.len(),4);
    for i in 0..4 {assert_eq!(received[&(i as u64)],data(i));}
}

#[test]
fn insufficient_symbols_do_not_manufacture_delivery() {
    let frames=block(4,2);
    let mut dec=Decoder::new(config(4,2)).unwrap();
    let mut received=BTreeMap::new();
    for i in [0,4,5] {collect(dec.input(&frames[i]).unwrap(),&mut received);}
    assert_eq!(received.len(),1);
    // Packet-level ARQ adds only the missing source, enabling remaining FEC.
    collect(dec.input(&frames[1]).unwrap(),&mut received);
    assert_eq!(received.len(),4);
}

#[test]
fn one_whole_path_can_be_erased_from_eight_plus_eight() {
    let frames=block(8,8);
    for failed in 0..3 {
        let mut dec=Decoder::new(config(8,8)).unwrap();
        let mut received=BTreeMap::new();
        for (i,frame) in frames.iter().enumerate() {
            if i%3!=failed {collect(dec.input(frame).unwrap(),&mut received);}
        }
        assert_eq!(received.len(),8,"failed path {failed}");
    }
}

#[test]
fn source_and_repair_wire_roundtrip_and_limits() {
    for frame in block(4,2) {
        let wire=frame.encode().unwrap();
        assert_eq!(Frame::decode(&wire,1100).unwrap(),frame);
        for len in 0..wire.len() {assert!(Frame::decode(&wire[..len],1100).is_err());}
        let mut extra=wire.clone();extra.push(0);
        assert!(Frame::decode(&extra,1100).is_err());
        let mut wrong=wire.clone();wrong[0]^=1;
        assert!(Frame::decode(&wrong,1100).is_err());
        let mut wrong=wire.clone();wrong[4]=255;
        assert!(Frame::decode(&wrong,1100).is_err());
    }
    assert!(Frame::Source {block:0,base:u64::MAX,index:1,payload:vec![1]}.encode().is_err());
    assert!(Frame::Repair {block:0,base:0,data:0,parity:1,index:0,symbol:vec![0;2]}.encode().is_err());
    assert!(Frame::Repair {block:0,base:0,data:8,parity:4,index:4,symbol:vec![0;2]}.encode().is_err());
    assert!(Frame::Source {block:0,base:0,index:0,payload:vec![0;1401]}.encode().is_err());
}

#[test]
fn extreme_configurations_fail_without_overflow() {
    for bad in [Config {data_shards:0,..Config::default()},Config {data_shards:usize::MAX,..Config::default()},
        Config {repair_shards:usize::MAX,..Config::default()},Config {max_payload:usize::MAX,..Config::default()},
        Config {max_decode_blocks:usize::MAX,..Config::default()},Config {max_decode_blocks:0,..Config::default()},
        Config {max_block_delay:Duration::ZERO,..Config::default()}] {
        assert!(Encoder::new(bad.clone()).is_err());
        assert!(Decoder::new(bad).is_err());
    }
}

#[test]
fn empty_payload_and_largest_payload_recover() {
    let cfg=config(2,2);
    let mut enc=Encoder::new(cfg.clone()).unwrap();
    enc.push(vec![],Duration::ZERO).unwrap();
    let out=enc.push(vec![77;1100],Duration::ZERO).unwrap();
    let mut dec=Decoder::new(cfg).unwrap();
    let mut received=BTreeMap::new();
    for frame in out.iter().filter(|f|matches!(f,Frame::Repair {..})) {
        collect(dec.input(frame).unwrap(),&mut received);
    }
    assert_eq!(received[&0],Vec::<u8>::new());
    assert_eq!(received[&1],vec![77;1100]);
}

#[test]
fn clock_and_payload_validation_preserve_pending_block() {
    let mut enc=Encoder::new(config(4,2)).unwrap();
    enc.push(vec![9],Duration::from_millis(10)).unwrap();
    assert_eq!(enc.poll(Duration::from_millis(9)),Err(Error::TimeWentBackwards));
    assert!(enc.push(vec![0;1200],Duration::from_millis(100)).is_err());
    assert!(matches!(enc.poll(Duration::from_millis(12)).unwrap()[0],Frame::Repair {base:0,data:1,..}));
}
