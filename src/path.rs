//! A path is a local interface paired with a server entrance.

/// Application-assigned identity. Multiple paths can share physical bottlenecks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId {
    pub interface: u16,
    pub entrance: u16,
}

/// Enumerate candidate paths. Reachability and route diversity require live probes.
/// One interface and one entrance are valid; an empty side produces no paths.
pub fn candidates(interfaces: u16, entrances: u16) -> impl Iterator<Item = PathId> {
    (0..interfaces).flat_map(move |interface| {
        (0..entrances).map(move |entrance| PathId {
            interface,
            entrance,
        })
    })
}
