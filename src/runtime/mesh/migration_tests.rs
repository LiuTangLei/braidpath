use super::*;

fn node(id: &str, port: u16, incarnation: u64) -> Node {
    Node {
        id: id.into(),
        address: SocketAddr::from(([127, 0, 0, 1], port)),
        incarnation,
    }
}

fn exchange(sender: &Node, nodes: Vec<Node>) -> Exchange {
    Exchange {
        sender: sender.clone(),
        nodes,
    }
}

#[tokio::test]
async fn address_incarnation_supersedes_live_old_record_and_rejects_stale_gossip() {
    let temp = tempfile::tempdir().unwrap();
    let state = tests::state(temp.path());
    let original = node("moving", 10001, 0);
    let moved = node("moving", 10002, 1);
    let other = node("other", 10003, 0);
    state
        .merge(exchange(&original, vec![]), true)
        .await
        .unwrap();
    state.merge(exchange(&other, vec![]), true).await.unwrap();
    // The new persisted address need not wait for old gossip to stop refreshing
    // the previous record's liveness.
    state.merge(exchange(&moved, vec![]), true).await.unwrap();
    assert!(state.known().contains(&moved));
    assert!(!state.known().contains(&original));
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert!(saved.contains(&moved));

    // A stale hint neither replaces nor refreshes the record. This remains true
    // after the replacement is no longer heard, and after a membership restart.
    state.peers.lock().unwrap().get_mut("moving").unwrap().heard = Instant::now() - LIVE_FOR;
    let heard = state.peers.lock().unwrap()["moving"].heard;
    state
        .merge(exchange(&other, vec![original.clone()]), true)
        .await
        .unwrap();
    assert_eq!(state.peers.lock().unwrap()["moving"].heard, heard);
    assert!(
        state
            .merge(exchange(&original, vec![]), true)
            .await
            .is_err()
    );
    let restart = tests::state(temp.path());
    restart
        .merge(exchange(&restart.own, saved), false)
        .await
        .unwrap();
    assert!(
        restart
            .merge(exchange(&original, vec![]), true)
            .await
            .is_err()
    );
    assert!(restart.known().contains(&moved));

    let inconsistent = node("moving", 10004, 1);
    assert!(
        state
            .merge(exchange(&inconsistent, vec![]), true)
            .await
            .is_err()
    );
    let stolen = node("moving", other.address.port(), 2);
    assert!(state.merge(exchange(&stolen, vec![]), true).await.is_err());
    // A different node can use the released address, but old gossip must not
    // bring the original identity back there or remove its successor.
    let successor = node("successor", original.address.port(), 0);
    state
        .merge(exchange(&successor, vec![]), true)
        .await
        .unwrap();
    state
        .merge(exchange(&other, vec![original]), true)
        .await
        .unwrap();
    assert!(state.known().contains(&successor));
    assert!(state.known().contains(&moved));
}

#[tokio::test]
async fn forgotten_incarnation_blocks_old_address_until_hint_expiry() {
    let temp = tempfile::tempdir().unwrap();
    let state = tests::state(temp.path());
    let current = node("moving", 10002, 1);
    let old = node("moving", 10001, 0);
    let live = node("live", 10003, 0);
    state.merge(exchange(&current, vec![]), true).await.unwrap();
    state.merge(exchange(&live, vec![]), true).await.unwrap();
    state.peers.lock().unwrap().get_mut("moving").unwrap().heard = Instant::now() - FORGET_AFTER;
    state.forget_departed().await.unwrap();
    assert!(!state.known().contains(&current));
    assert!(state.merge(exchange(&old, vec![]), true).await.is_err());
    state
        .merge(exchange(&live, vec![old.clone()]), true)
        .await
        .unwrap();
    assert!(!state.known().contains(&old));
    state.merge(exchange(&current, vec![]), true).await.unwrap();
    assert!(state.reconnect.lock().unwrap().is_empty());

    state.peers.lock().unwrap().remove("moving");
    *state.reconnect.lock().unwrap() = vec![hints::Hint {
        node: current,
        forgotten_unix: hints::now_unix() - hints::HINT_TTL.as_secs(),
    }];
    state.merge(exchange(&old, vec![]), true).await.unwrap();
}
