//! Laboratory adapter for shared opt-in peer requests. Defaults stay unchanged.
use braidpath::runtime::transport;
pub use transport::AckRequest as AckProfile;

pub fn reference_transport(profile: AckProfile) -> quinn::TransportConfig {
    let mut transport = transport::config(transport::Congestion::Bbr);
    transport.datagram_send_buffer_size(9600);
    profile.apply(&mut transport);
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
