# Experimental sender-frontier runtime

`--frontier-scheduler` is a local, default-off client/server experiment, not a
new wire protocol or a release recommendation. Set it separately on each
endpoint to study both sending directions. It applies only with adaptive
scheduling and the explicitly configured small-FEC lane. A packet's size is
not a general declaration of application priority.

Both on and off modes evaluate the same shadow proposal. Among the existing
allowed small-lane paths, the candidate may promote an alternative only when:

* its current local delay estimate is at least 2 ms lower than the old first
  path, with fresh observed path-symbol loss no worse than that old path;
* the path presently has API space, legal frame size and the existing
  aggregate/group/business and repair allowances;
* it belongs to the same used/unused repair-diversity tier as the old first path.

Unknown/stale/nonfinite estimates do not authorize a change. The existing
small-lane delay estimate includes propagation RTT/2, the maximum of RTT excess
and receiver transit variation, and a local queued-byte service heuristic.
It is not a synchronized one-way deadline bound, a capacity estimate or a
guarantee of lower future loss. The 2 ms difference is hysteresis, NOT an
intentional delay: originals/copies are not held back to create it.

All normal gates run again after the preference, immediately before Quinn
admission. The scheduler cannot create pacing tokens, increase queues, extend
deadlines, add copies, change coding, bypass native congestion control, or make
an ineligible route eligible. Bulk weighted scheduling and original flow order
are unchanged. Copy diversity remains the existing preference, not proof of
independent failures.

The owning session/direction publishes `sender_frontier`. It includes fixed
eight-path, small/other counters for rejected eligibility/allowance, aggregate
and group budgets, business aggregate/group budgets, repair credit, copy
readiness, frame size, API buffer/error and immediate admissions. Separate
readiness counters account for deferred admissions and invalidation/failure.
These are repeated path previews/attempts, not unique-record counts or time
fractions. Earlier filters can prevent later gates from being examined. Repair
queue promotion and control/probe traffic are outside the main-attempt census.
The counters do not reveal native bytes-in-flight or prove the ultimate cause
of a local gate. Never attribute every local drop to CPU or to network loss.

Compare identical binaries, shadow-off vs enabled, with equal telemetry and
registered input, limits, source clocks and complete request populations.
The field test retains native QUIC congestion control and the existing
fail-closed production monitor. A successful loopback test or better partial
window is not WAN acceptance. Neither this stage nor its counters implement
automatic resource grouping, active marginal-capacity pulses, sliding-window
FEC or a reliable HTTP/TCP adapter.

See [the research direction](delivery-frontier.md). QUIC DATAGRAM remains
congestion controlled and transport acceptance/ACKs do not guarantee application
delivery (RFC 9221 sections 5.2–5.4).
