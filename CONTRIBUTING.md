# Contributing

Please discuss major protocol or algorithm changes in an issue first. Small fixes
and focused tests can go directly to a pull request.

Run the formatter, Clippy and tests listed in the README. Changes to FEC or the
future session layer must exercise loss, reordering and duplication, including
the failure boundary rather than only successful recovery.

Performance claims need reproducible settings, baselines, both directions,
completion rates and actual overhead. Separate simulation from live measurements.
Keep test records, run results, and historical experiment notes local (for example,
in the ignored `local/` or `results/` directory). Commit automated test code and
validation methods, not test reports. Do not commit secrets, private infrastructure
details or raw captures.

Contributions are accepted under Apache-2.0. Preserve the source and license of
any incorporated third-party code. This repository is not a compatibility fork.
