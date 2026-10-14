//! Laboratory-only peer requests. No change to production transport defaults.
use braidpath::runtime::transport;
use clap::ValueEnum;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum AckProfile {
    #[default]
    Unchanged,
    EveryTwo,
    EveryEight,
}

impl AckProfile {
    /// (ack-eliciting threshold, requested maximum delay ms, reordering threshold).
    pub fn request(self) -> Option<(u32, u64, u32)> {
        match self {
            Self::Unchanged => None,
            Self::EveryTwo => Some((1, 10, 2)),
            Self::EveryEight => Some((7, 10, 2)),
        }
    }
}

pub fn reference_transport(profile: AckProfile) -> quinn::TransportConfig {
    let mut transport = transport::config(transport::Congestion::Bbr);
    transport.datagram_send_buffer_size(9600);
    if let Some((threshold, delay, reorder)) = profile.request() {
        let mut request = quinn::AckFrequencyConfig::default();
        request.ack_eliciting_threshold(threshold.into());
        request.max_ack_delay(Some(Duration::from_millis(delay)));
        request.reordering_threshold(reorder.into());
        transport.ack_frequency_config(Some(request));
    }
    transport
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matched_profiles_change_only_threshold_and_default_stays_unchanged() {
        assert_eq!(AckProfile::Unchanged.request(), None);
        assert_eq!(AckProfile::EveryTwo.request(), Some((1, 10, 2)));
        assert_eq!(AckProfile::EveryEight.request(), Some((7, 10, 2)));
    }
}
