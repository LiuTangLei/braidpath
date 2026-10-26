//! Reliable record negotiation and the current path's exact DATAGRAM budget.
use super::{MAX_PAYLOAD, quality, wire};
use crate::runtime::MAX_STREAM_PAYLOAD;
use anyhow::{Result, ensure};
use http::HeaderMap;

pub(super) const HEADER: &str = "braidpath-stream-payload";

pub(super) fn negotiate(headers: &HeaderMap, reliable: bool) -> Result<usize> {
    let mut values = headers.get_all(HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(MAX_PAYLOAD);
    };
    ensure!(
        reliable && values.next().is_none(),
        "invalid stream payload negotiation"
    );
    let maximum: usize = value.to_str()?.parse()?;
    ensure!(
        (MAX_PAYLOAD..=MAX_STREAM_PAYLOAD).contains(&maximum),
        "unsupported stream payload size"
    );
    Ok(maximum)
}

pub(super) fn wire_limit(payload: usize, feedback: bool) -> usize {
    wire::HEADER + 12 + payload + 2 + if feedback { quality::HEADER } else { 0 }
}

pub(super) fn record_limit(
    datagram: usize,
    stream: u64,
    feedback: bool,
    negotiated: usize,
) -> usize {
    // Quinn's limit already excludes QUIC framing and packet encryption. HTTP
    // mapping, measurement, record, coding and parity length are ours to pay.
    let overhead = wire::http_datagram_overhead(stream).unwrap_or(9) + wire_limit(0, feedback);
    datagram.saturating_sub(overhead).min(negotiated)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_is_explicit_bounded_and_legacy_compatible() {
        let mut headers = HeaderMap::new();
        assert_eq!(negotiate(&headers, true).unwrap(), 1000);
        for value in ["999", "1401", "x"] {
            headers.insert(HEADER, value.parse().unwrap());
            assert!(negotiate(&headers, true).is_err());
        }
        headers.insert(HEADER, "1400".parse().unwrap());
        assert_eq!(negotiate(&headers, true).unwrap(), 1400);
        assert!(negotiate(&headers, false).is_err());
        headers.append(HEADER, "1000".parse().unwrap());
        assert!(negotiate(&headers, true).is_err());
    }
    #[test]
    fn every_envelope_and_mtu_change_is_paid_before_segmentation() {
        for stream in [0, 256, 65536, 1 << 34] {
            for feedback in [false, true] {
                for mtu in [1100, 1160, 1420, 1450] {
                    let limit = record_limit(mtu, stream, feedback, 1400);
                    assert!(limit <= 1400);
                    assert!(
                        wire_limit(limit, feedback) + wire::http_datagram_overhead(stream).unwrap()
                            <= mtu
                    );
                    assert_eq!(record_limit(mtu, stream, feedback, 1000), limit.min(1000));
                }
            }
        }
        assert_eq!(record_limit(20, 0, true, 1400), 0);
    }
}
