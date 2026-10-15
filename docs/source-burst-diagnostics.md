# Source burst attribution

`bench.source_burst` reads the full original source sample population without
modifying pacing or pass criteria. It reports source inter-send gaps, bounded
top-gap evidence and half-open rolling input populations at100us/1ms/1.6ms/5ms.
This makes a uniform mean rate distinguishable from gaps followed by bursts.
Burst pressure alone is not proof of a tunnel loss or of its cause.

The existing source uses Tokio `Interval` with `MissedTickBehavior::Delay`.
The pinned runtime can release sub-threshold overdue ticks immediately even
with `Delay`. Deterministic tests exercise that actual source helper: a2ms
advance at40000pps releases80 ticks without a new clock wait, while a10ms
advance reanchors the following schedule. These are timer semantics, not
measurements of operating-system wakeup latency. The source timing is unchanged.

`python3 -m bench.source_observer_study` executes a registered off/on/on/off
raw-UDP loopback diagnostic with the same binary and source timing. Each window
has400000 original1000B datagrams at40000pps,200ms deadline and3s drain. The
collector samples at5ms, at most16 tasks and10000 rows, recording its own work
time. It is a specifically described Python observer, not assumed identical to
another collector implementation. Use only in a dedicated network-none container
with `BRAIDPATH_SOURCE_STUDY=1` and explicit resource limits.

Source qualification still uses the existing95% whole-source and one-second
cohort floor. Qualification failures remain evidence; lifecycle failure stops
later windows. The runner makes no causal attribution or performance promotion.
Do not change `Delay` to `Burst`, extend queue deadlines, increase queue memory
or raise sending allowances based on the average source rate alone.

Study records and local conclusions belong in ignored `local/`. Further tunnel
comparison requires qualified contemporaneous single-path, same-path multiple
connection and multipath controls, with consistent budgets and full populations.
