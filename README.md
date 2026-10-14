# BraidPath — dedicated low-latency branch

This `low-latency` branch contains the independent, persistent-session multipath
TCP forwarding implementation. `main` contains the separate high-throughput
HTTP/3 datagram implementation. They are alternative source trees, not two
protocols that can be mixed within one session.

The existing `agg-fec-tunnel` executable name is retained for configuration and
service compatibility. All workspace packages, the lockfile and license notices
needed for its build are present here; the retired repository is not required.

```sh
cargo +1.97.0 build --release --locked -p aggligator-fec --features managed --bin agg-fec-tunnel
cargo +1.97.0 test --locked -p aggligator-fec --all-features --all-targets
python3 -B aggligator-fec/tests/cli_contract.py
python3 -B aggligator-fec/tests/http_latency.py --quick --profile latency --output local/http-smoke.json
```

Use `target/release/agg-fec-tunnel --help` for init/join/run/check commands.
The `latency` profile keeps pre-handshaken sessions ready, immediately replicates
data over live paths and maintains independent reliable state for each TCP flow.
The existing managed configuration format, wire protocol and executable name
are unchanged by this repository migration. A server restart does not replay
already-sent application requests onto a new backend connection.

This is a source relocation, not a production rollout or a new performance claim.
Shared-link bandwidth and retransmissions still constrain throughput and latency.
Control-plane TLS is not a claim that the UDP data plane encrypts application
traffic; retain inner application encryption and the existing source restrictions.

## Provenance

Runtime snapshot: `d815f23d023302845b48e4a4bc4acf5f5fdf22d5` of the retired
latency implementation. Runtime Rust sources and Cargo.lock are copied without
changes. Upstream Apache-2.0 LICENSE/NOTICE attribution is retained. This branch
starts a clean publication history: private node-specific deployment scripts,
credentials and historic measurement reports are not imported into Git history.
The full source archive, deployment helpers, source hashes and migration checks
are retained locally alongside the throughput repository's ignored evidence.
