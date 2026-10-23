//! Keep a few existing channel slots available to the negotiated small lane.
//! This is admission isolation, not a larger queue or a bandwidth reservation.
use super::Policy;
use crate::runtime::QUEUE;
use tokio::sync::mpsc::{Sender, error::TrySendError};

const SMALL_SLOTS: usize = QUEUE / 16;

/// Reserve the complete message before publishing any fragment. A rejected
/// reservation returns every permit, including the small-message reserve.
pub(super) fn reserve<T>(
    tx: &Sender<T>,
    count: usize,
    bulk: bool,
) -> Result<tokio::sync::mpsc::PermitIterator<'_, T>, TrySendError<()>> {
    let permits = tx.try_reserve_many(count)?;
    if bulk && tx.capacity() < SMALL_SLOTS {
        return Err(TrySendError::Full(()));
    }
    Ok(permits)
}

pub(super) fn small_threshold(policy: &Policy) -> usize {
    if policy.adaptive && policy.mixed_fec {
        usize::from(policy.small_fec_bytes)
    } else {
        0
    }
}

pub(super) fn try_send<T>(
    tx: &Sender<T>,
    item: T,
    payload_bytes: usize,
    small_threshold: usize,
) -> Result<(), TrySendError<T>> {
    if small_threshold == 0 || payload_bytes <= small_threshold {
        return tx.try_send(item);
    }
    // Take a real permit before checking the remaining capacity. Concurrent
    // producers cannot all spend the last bulk slot based on the same preview.
    let permit = match tx.try_reserve() {
        Ok(permit) => permit,
        Err(TrySendError::Full(())) => return Err(TrySendError::Full(item)),
        Err(TrySendError::Closed(())) => return Err(TrySendError::Closed(item)),
    };
    if tx.capacity() < SMALL_SLOTS {
        return Err(TrySendError::Full(item));
    }
    permit.send(item);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_fifo_admission_loses_small_requests_while_reserved_admission_keeps_them() {
        let (old, _old_rx) = tokio::sync::mpsc::channel(QUEUE);
        let (new, _new_rx) = tokio::sync::mpsc::channel(QUEUE);
        for id in 0..QUEUE {
            old.try_send(id).unwrap();
            let _ = try_send(&new, id, 1000, 128);
        }
        assert!(matches!(old.try_send(999), Err(TrySendError::Full(999))));
        try_send(&new, 999, 128, 128).unwrap();
        assert_eq!(new.max_capacity(), old.max_capacity());
        assert_eq!(new.capacity(), SMALL_SLOTS - 1);
    }

    #[test]
    fn full_bulk_backlog_leaves_small_slots_without_growing_the_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(QUEUE);
        for id in 0..QUEUE - SMALL_SLOTS {
            try_send(&tx, id, 1000, 128).unwrap();
        }
        assert!(matches!(
            try_send(&tx, 999, 1000, 128),
            Err(TrySendError::Full(999))
        ));
        assert_eq!(tx.capacity(), SMALL_SLOTS, "rejected bulk permit returned");
        for id in QUEUE - SMALL_SLOTS..QUEUE {
            try_send(&tx, id, 128, 128).unwrap();
        }
        assert!(matches!(
            try_send(&tx, 999, 128, 128),
            Err(TrySendError::Full(999))
        ));
        assert_eq!(tx.capacity(), 0);
        for id in 0..QUEUE {
            assert_eq!(rx.try_recv().unwrap(), id, "existing FIFO order unchanged");
        }
        assert_eq!(tx.capacity(), QUEUE);
        try_send(&tx, 1001, 1000, 128).unwrap();
        assert_eq!(rx.try_recv().unwrap(), 1001);
    }

    #[test]
    fn disabled_or_all_small_traffic_retains_the_entire_existing_capacity() {
        for (payload, threshold) in [(1000, 0), (128, 128), (0, 128)] {
            let (tx, _rx) = tokio::sync::mpsc::channel(QUEUE);
            for id in 0..QUEUE {
                try_send(&tx, id, payload, threshold).unwrap();
            }
            assert!(matches!(
                try_send(&tx, 999, payload, threshold),
                Err(TrySendError::Full(999))
            ));
        }
    }

    #[test]
    fn closed_channels_preserve_the_closed_error_and_the_rejected_item() {
        for (payload, threshold) in [(1000, 128), (128, 128), (1000, 0)] {
            let (tx, rx) = tokio::sync::mpsc::channel(QUEUE);
            drop(rx);
            assert!(matches!(
                try_send(&tx, 999, payload, threshold),
                Err(TrySendError::Closed(999))
            ));
            assert_eq!(tx.capacity(), QUEUE);
        }
    }

    #[test]
    fn concurrent_bulk_producers_cannot_consume_the_small_reserve() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(QUEUE);
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let tx = tx.clone();
                scope.spawn(move || {
                    for id in 0..256 {
                        let _ = try_send(&tx, (worker, id), 1000, 128);
                    }
                });
            }
        });
        assert!(tx.capacity() >= SMALL_SLOTS);
        let mut received = 0;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        assert!(received > 0 && received <= QUEUE - SMALL_SLOTS);
        assert_eq!(tx.capacity(), QUEUE);
    }
}
