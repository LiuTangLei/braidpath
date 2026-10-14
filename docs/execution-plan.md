# Execution plan: useful gain over the strongest single connection

## Objective and decision rule

The user has replaced an absolute throughput target with a relative objective:
aggregation must be substantially more useful than a matched single connection.
Use 1.5x unique application goodput as the first engineering target and 2x as an
aspiration when independently usable resources permit it. Neither is a promise.
Keep full-population interaction completion and latency alongside throughput.
An experiment can complete successfully while its candidate fails acceptance.

The previously rejected frontier preference remains disabled. Historical
registrations, failures and results must not be relabelled under the new goal.
Network identities, concrete topology, results, credentials and progress records
remain in ignored `local/`; this file describes methods and implementation order.

## Milestones

| Stage | Work | Completion evidence | Decision after completion |
| --- | --- | --- | --- |
| P0: freeze scope | Record objective, failed candidates, protected services and resource limits | Versioned plan and resumable local checkpoint | Begin P1 without another approval loop |
| P1: topology baselines | Implement and run matched singles, same-route parallel and true multipath with active redundancy off | Frozen mode/order manifest; exact endpoint identities; raw cohort validation; complete accounting and cleanup | Locate the strongest single and quantify current aggregation gain, even when negative |
| P2: service identification | Separate host/reference cost, native-equivalent carrier cost and sustained offered-rate response; instrument limiting gates | Host and native references plus bounded actual-supply interventions, with cold and warm profiles separated | Choose the measured binding limitation, not the most frequent counter alone |
| P3: one mechanism | Modify bulk allocation, controller responsibility or deadline/repair decisions, one independently registered treatment at a time | Unit/integration tests and deterministic counterexamples; default-off runtime candidate | Advance only to a same-condition controlled comparison |
| P4: confirm useful gain | Compare held-out strongest single, matching same-route parallel and candidate; test both directions and meaningful loss regimes | Full planned windows, unique-byte goodput, finite usable tails, no hidden missing population or increased budget | Accept, reject, or explicitly leave unresolved; do not cherry-pick |
| P5: operational integration | Validate the actual reliable service separately, lifecycle, resource bounds, documentation and rollback | End-to-end completion and integrity, stable resource use and relevant release checks | Promote only the validated scope, never substitute datagram success for TCP/HTTP success |

P1 has two separate meanings: the measurement collector can be complete while
performance is unacceptable. Likewise, a short cold-start diagnostic is not a
steady-state capacity measurement or the P4 release gate.

## First P1 campaign

Use one frozen binary, unchanged native congestion control, equal total/group
budgets, equal source packet sizes/rates, identical queue deadlines and telemetry.
Disable mixed FEC, small copies, active repair and the rejected preference in all
modes. Keep feedback and the existing adaptive sender identical across modes.

Predeclare every available route as a one-route/one-connection control. Include
one fixed route with the same connection count as the true multipath mode; this
is not assumed to be the strongest parallel-route control. Use a mirrored order
with two windows per mode. A subsequent held-out comparison must use the strongest
route selected from this discovery phase, without substituting old windows.

The first profile is an explicitly short cold-session workload, not a warm
capacity sweep: no application warmup, a finite source interval, the same
request/response probe in every mode, complete missing slots and fixed drain.
All requested paths must authenticate before releasing work. Route identity,
number of unique connections, native source sockets and the actual client argv
must agree; command-line labels alone do not establish the topology.

Raw collection must verify source/receiver run IDs, original sequence slots,
timestamps, integrity counters, source pacing, exact process identities, final
snapshots and the collection hash chain. It must preserve protection failure
even if some completed windows can be read. Lack of a native-equivalent reference
or a warm profile must remain visible rather than weakening that later gate.

## Progress and recovery

Each work segment records completed work, evidence paths, exact commit, current
blocked items and the next executable action in a local checkpoint. Do not leave
an unowned load generator running at the end of a work segment. Record and await
all started finite operations or stop and verify their exact owned resources.

Preserve the current fail-closed production observer, observation deadlines,
heartbeat, finite process lifetimes, resource caps and exact-identity cleanup.
Before a new campaign, verify preparation, tests, fresh production identities
and a finite read-only observer pilot. Observation failure stops business work;
it is not permission to weaken protection or repeatedly retry a completed load.

If a candidate fails, retain its evidence and advance to the next justified
mechanism, not a parameter sweep intended to find a better-looking window.
Do not push, replace production or publish a release merely because a milestone
document was completed. Measurements, implementation and release state are
separate claims.
