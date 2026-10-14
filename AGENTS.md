# Branch working agreements

- This is the dedicated low-latency TCP forwarding branch in the BraidPath repository.
- Keep its runtime independent of the throughput main branch and of the retired repository.
- Preserve authentication, reliable delivery, HTTP request non-replay and half-close behavior.
- Keep topology, credentials and measured run records in ignored local/; do not publish them.
- Use UTC and bounded tests. Do not repeat completed workloads to obtain a better result.
- Do not change production services as a side effect of builds or tests.
