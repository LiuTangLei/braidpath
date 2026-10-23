# Source burst attribution

`bench.source_burst.burst_summary` reads the full original source sample
population without changing samples or pass criteria. It reports source inter-send gaps, bounded
top-gap evidence and half-open rolling input populations at100us/1ms/1.6ms/5ms.
This makes a uniform mean rate distinguishable from gaps followed by bursts.
Burst pressure alone is not proof of a tunnel loss or of its cause.

The source uses Tokio `Interval` with `MissedTickBehavior::Delay`. The pinned
runtime can release sub-threshold overdue ticks immediately even with `Delay`.
From v0.2.1, the source reanchors after at most 64 overdue ticks: a controlled
2 ms stall at 40,000 pps has 80 scheduled packets due, but only 64 can catch up
before another timer wait. A 10 ms stall also reanchors. The reset count appears
in source pacing diagnostics. These are timer semantics, not measurements of
operating-system wakeup latency or proof of uniform source spacing.

`python3 -m bench.source_observer_study` executes a registered off/on/on/off
raw-UDP loopback diagnostic with the same binary and source timing. Each window
has400000 original1000B datagrams at40000pps,200ms deadline and3s drain. The
collector samples at5ms, at most16 tasks and10000 rows, recording its own work
time. It is a specifically described Python observer, not assumed identical to
another collector implementation. Use only in a dedicated network-none container
with `BRAIDPATH_SOURCE_STUDY=1` and explicit resource limits.

`--study flush` is a separate fixed on/off/off/on diagnostic for per-row file
flushes. All four arms retain5ms collection and the same64KiB file buffer; only
explicit flushing of each row varies. All buffered data is flushed on close.
It does not change any tunnel or socket queue, source timer, production monitor
or default collector behavior. It records the timestamp and work of the most
expensive collection/write event without retaining an unbounded event history.

Steady-source qualification requires the existing 95% whole-source and
one-second cohort floor plus rolling 100 µs, 1 ms, 1.6 ms and 5 ms peaks of at
most twice the nominal count (a minimum allowance of two packets). A correct
average does not excuse a large catch-up burst. Deliberate burst workloads need
their own declared contract and cannot claim steady-source acceptance.
Qualification failures remain evidence; lifecycle failure stops later windows.
The runner makes no causal attribution or performance promotion.
Do not change `Delay` to `Burst`, extend queue deadlines, increase queue memory
or raise sending allowances based on the average source rate alone.

Study records and local conclusions belong in ignored `local/`. Further tunnel
comparison requires qualified contemporaneous single-path, same-path multiple
connection and multipath controls, with consistent budgets and full populations.
