//! One bounded trial slot. Only fresh delivery evidence can justify promotion.
use super::entrances::{ClientLease, PathHealth};
use super::*;
const COOLDOWN: Duration = Duration::from_secs(30);
const TRIAL: Duration = Duration::from_secs(8);

struct Trial {
    candidate: String,
    incumbent: Node,
    score: f64,
    started: Instant,
}
pub(super) struct Explorer {
    trial: Option<Trial>,
    ready: Instant,
    pub(super) preferred: Option<String>,
    cursor: usize,
}
impl Default for Explorer {
    fn default() -> Self {
        Self {
            trial: None,
            ready: Instant::now() + COOLDOWN,
            preferred: None,
            cursor: 0,
        }
    }
}
impl Explorer {
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }
    /// Return a lease to retire before attempting another. The selected direct
    /// exit is never retired; at least one connected path must remain.
    pub(super) fn advance(
        &mut self,
        nodes: &[Node],
        selected: &Node,
        leases: &BTreeMap<String, ClientLease>,
        health: &PathHealth,
        limit: usize,
        now: Instant,
    ) -> Option<String> {
        if now.saturating_duration_since(health.checked) >= Duration::from_secs(2) {
            return None;
        }
        if let Some(trial) = &self.trial {
            if now.saturating_duration_since(trial.started) < TRIAL {
                return None;
            }
            let trial = self.trial.take().expect("trial");
            self.ready = now + COOLDOWN;
            self.preferred = None;
            let candidate = leases.get(&trial.candidate);
            let promoted = candidate
                .and_then(|lease| {
                    health
                        .samples
                        .iter()
                        .find(|s| s.address == lease.reply.address)
                })
                .and_then(|s| s.score())
                .is_some_and(|score| score < trial.score * 0.8);
            let other_live = health.addresses.iter().any(|address| {
                *address == selected.address
                    || leases.iter().any(|(id, lease)| {
                        *id != trial.candidate && lease.reply.address == *address
                    })
            });
            if promoted || !other_live || !nodes.contains(&trial.incumbent) {
                return None;
            }
            self.preferred = Some(trial.incumbent.id);
            return Some(trial.candidate);
        }
        if now < self.ready || limit < 3 || leases.len() != limit - 1 {
            return None;
        }
        let live = health
            .addresses
            .iter()
            .filter(|address| {
                **address == selected.address
                    || leases.values().any(|l| l.reply.address == **address)
            })
            .count();
        if live < 2 {
            return None;
        }
        let worst = leases
            .values()
            .filter_map(|lease| {
                health
                    .samples
                    .iter()
                    .find(|s| s.address == lease.reply.address)
                    .and_then(|s| s.score())
                    .map(|score| (lease, score))
            })
            .max_by(|a, b| a.1.total_cmp(&b.1));
        let (worst, score) = worst?;
        let candidates: Vec<_> = nodes
            .iter()
            .filter(|n| n.id != selected.id && !leases.contains_key(&n.id))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let candidate = candidates[self.cursor % candidates.len()];
        self.cursor = self.cursor.wrapping_add(1);
        self.preferred = Some(candidate.id.clone());
        self.trial = Some(Trial {
            candidate: candidate.id.clone(),
            incumbent: worst.node.clone(),
            score,
            started: now,
        });
        Some(worst.node.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::entrances::PathSample;
    use super::*;
    fn node(id: usize) -> Node {
        Node {
            id: id.to_string(),
            address: SocketAddr::from(([127, 0, 0, 1], 10000 + id as u16)),
            incarnation: 1,
        }
    }
    fn lease(node: Node) -> ClientLease {
        ClientLease {
            reply: RelayReply {
                lease: "0".repeat(32),
                address: node.address,
            },
            node,
            renewed: Instant::now(),
        }
    }
    #[test]
    fn ninth_candidate_gets_a_bounded_trial_and_requires_fresh_improvement() {
        let nodes: Vec<_> = (0..9).map(node).collect();
        let mut leases: BTreeMap<_, _> = nodes[1..8]
            .iter()
            .map(|n| (n.id.clone(), lease(n.clone())))
            .collect();
        let now = Instant::now();
        let mut health = PathHealth {
            checked: now,
            addresses: nodes[..8].iter().map(|n| n.address).collect(),
            samples: nodes[1..8]
                .iter()
                .enumerate()
                .map(|(i, n)| PathSample {
                    address: n.address,
                    group: 0,
                    delivered: true,
                    rtt_ms: 10.0 + i as f64 * 10.0,
                    loss: 0.0,
                })
                .collect(),
        };
        let mut explorer = Explorer {
            ready: now,
            ..Default::default()
        };
        let retired = explorer
            .advance(&nodes, &nodes[0], &leases, &health, 8, now)
            .unwrap();
        assert_eq!(retired, "7");
        assert_eq!(explorer.preferred.as_deref(), Some("8"));
        leases.remove(&retired);
        leases.insert("8".into(), lease(nodes[8].clone()));
        health.checked = now + TRIAL;
        health.samples.push(PathSample {
            address: nodes[8].address,
            group: 0,
            delivered: false,
            rtt_ms: 1.0,
            loss: 0.0,
        });
        // Low RTT alone cannot displace established delivery.
        assert_eq!(
            explorer
                .advance(&nodes, &nodes[0], &leases, &health, 8, now + TRIAL)
                .as_deref(),
            Some("8")
        );
        assert_eq!(explorer.preferred.as_deref(), Some("7"));
        assert!(
            explorer
                .advance(&nodes, &nodes[0], &leases, &health, 8, now + TRIAL)
                .is_none()
        );
        leases.remove("8");
        leases.insert("7".into(), lease(nodes[7].clone()));
        let next = now + TRIAL + COOLDOWN;
        health.checked = next;
        assert_eq!(
            explorer
                .advance(&nodes, &nodes[0], &leases, &health, 8, next)
                .as_deref(),
            Some("7")
        );
        leases.remove("7");
        leases.insert("8".into(), lease(nodes[8].clone()));
        health.samples.last_mut().unwrap().delivered = true;
        health.checked = next + TRIAL;
        assert!(
            explorer
                .advance(&nodes, &nodes[0], &leases, &health, 8, next + TRIAL)
                .is_none()
        );
        assert!(explorer.preferred.is_none());
        assert_eq!(leases.len() + 1, 8);
    }
    #[test]
    fn no_trial_without_fresh_quality_or_when_only_one_path_survives() {
        let nodes: Vec<_> = (0..4).map(node).collect();
        let leases = BTreeMap::from([
            ("1".into(), lease(nodes[1].clone())),
            ("2".into(), lease(nodes[2].clone())),
        ]);
        let now = Instant::now();
        let mut health = PathHealth {
            checked: now,
            addresses: vec![nodes[1].address],
            samples: vec![PathSample {
                address: nodes[1].address,
                group: 0,
                delivered: true,
                rtt_ms: 99.0,
                loss: 0.0,
            }],
        };
        let mut explorer = Explorer {
            ready: now,
            ..Default::default()
        };
        assert!(
            explorer
                .advance(&nodes, &nodes[0], &leases, &health, 3, now)
                .is_none()
        );
        health.addresses.push(nodes[0].address);
        assert!(
            explorer
                .advance(
                    &nodes,
                    &nodes[0],
                    &leases,
                    &health,
                    3,
                    now + Duration::from_secs(3)
                )
                .is_none()
        );
    }
}
