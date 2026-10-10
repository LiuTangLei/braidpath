//! Service rates from matching cumulative receiver endpoints.
//!
//! Short byte reports may confirm startup progress. Capacity memory and drain
//! hints instead need an interval long enough not to promote a brief burst.
use super::FRESH_US;

const SAMPLE_US: u64 = 500_000;

#[derive(Clone, Copy, Debug)]
pub(super) struct Sample {
    pub(super) bps: f64,
    pub(super) span_us: u64,
    /// Local arrival of the completed receiver interval, not its start time.
    pub(super) observed_us: u64,
}

#[derive(Clone, Copy)]
struct Endpoint {
    number: u64,
    receiver_us: u64,
    bytes: u64,
    observed_us: u64,
}

#[derive(Clone, Default)]
pub(super) struct Window {
    cursor: Option<Endpoint>,
    latest: Option<Endpoint>,
    sample: Option<Sample>,
}

impl Window {
    pub(super) fn observe(
        &mut self,
        number: u64,
        receiver_us: Option<u64>,
        bytes: u64,
        now_us: u64,
    ) -> bool {
        let Some(receiver_us) = receiver_us else {
            return false;
        };
        let current = Endpoint {
            number,
            receiver_us,
            bytes,
            observed_us: now_us,
        };
        if self.latest.is_some_and(|latest| {
            number <= latest.number
                || receiver_us <= latest.receiver_us
                || bytes < latest.bytes
                || now_us < latest.observed_us
        }) {
            return false;
        }
        let gap = self.latest.is_some_and(|latest| {
            receiver_us - latest.receiver_us > FRESH_US || now_us - latest.observed_us > FRESH_US
        });
        self.latest = Some(current);
        let Some(previous) = self.cursor else {
            // No byte/time delta exists before the first real endpoint.
            self.cursor = Some(current);
            return false;
        };
        let span_us = receiver_us - previous.receiver_us;
        if gap || span_us > FRESH_US || now_us - previous.observed_us > FRESH_US {
            self.cursor = Some(current);
            self.sample = None;
            return false;
        }
        if span_us < SAMPLE_US {
            return false;
        }
        self.cursor = Some(current);
        self.sample = Some(Sample {
            bps: (bytes - previous.bytes) as f64 * 8_000_000.0 / span_us as f64,
            span_us,
            observed_us: now_us,
        });
        true
    }

    pub(super) fn latest(&self, now_us: u64) -> Option<Sample> {
        self.sample.and_then(|sample| {
            (now_us >= sample.observed_us && now_us - sample.observed_us <= FRESH_US)
                .then_some(sample)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_019_aggregates_matching_endpoints_and_keeps_zero_service() {
        let mut window = Window::default();
        let epoch = 100_000_000;
        assert!(!window.observe(1, Some(epoch), 10_000, 0));
        for (step, bytes) in [(1, 11_000), (2, 11_000), (3, 13_000), (4, 14_000)] {
            assert!(!window.observe(
                step + 1,
                Some(epoch + step * 100_000),
                bytes,
                step * 100_000
            ));
            assert!(window.latest(step * 100_000).is_none());
        }
        assert!(window.observe(6, Some(epoch + 500_000), 15_000, 500_000));
        let sample = window.latest(500_000).unwrap();
        assert_eq!(sample.span_us, 500_000);
        assert_eq!(sample.bps, 80_000.0);

        for step in 6..10 {
            assert!(!window.observe(
                step + 1,
                Some(epoch + step * 100_000),
                15_000,
                step * 100_000
            ));
        }
        assert!(window.observe(11, Some(epoch + 1_000_000), 15_000, 1_000_000));
        assert_eq!(window.latest(1_000_000).unwrap().bps, 0.0);
        assert_eq!(window.latest(1_000_000).unwrap().span_us, 500_000);
    }

    #[test]
    fn service_019_rejects_intermediate_regression_and_reanchors_after_a_gap() {
        let mut window = Window::default();
        assert!(!window.observe(1, None, 1_000, 0));
        assert!(!window.observe(1, Some(1_000_000), 1_000, 0));
        assert!(!window.observe(2, Some(1_100_000), 1_200, 100_000));
        assert!(!window.observe(2, Some(1_200_000), 1_500, 200_000));
        assert!(!window.observe(3, Some(1_050_000), 1_500, 200_000));
        assert!(!window.observe(3, Some(1_200_000), 1_199, 200_000));
        assert!(!window.observe(3, Some(1_200_000), 1_500, 50_000));
        assert!(window.observe(3, Some(1_500_000), 2_000, 500_000));
        assert_eq!(window.latest(500_000).unwrap().bps, 16_000.0);
        assert!(window.latest(499_999).is_none());
        assert!(window.latest(500_000 + FRESH_US).is_some());
        assert!(window.latest(500_001 + FRESH_US).is_none());

        let after_gap = 500_001 + FRESH_US;
        assert!(!window.observe(4, Some(1_000_000 + after_gap), 9_000, after_gap));
        assert!(window.latest(after_gap).is_none());
        assert!(window.observe(5, Some(1_500_000 + after_gap), 9_500, after_gap + 500_000));
        let sample = window.latest(after_gap + 500_000).unwrap();
        assert_eq!(sample.span_us, 500_000);
        assert_eq!(sample.bps, 8_000.0);
    }
}
