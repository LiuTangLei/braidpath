# Fast warmup without pretending it is free capacity

The finite study tests a 3-second full-supply prefix, followed immediately by
the same 10-second business source. One continuous flow and the same authenticated
QUIC connections span both phases. No reconnect, artificial congestion-window
increase, disabled congestion control, raised queue cap or extra repair is used.
The reference begins business immediately. This measures the practical prefix
trade-off, not a perfect separation of connection age from transmitted training.

Both modes retain the existing overlay adaptive controller and native BBR. The
code already seeds a new eligible path's allowance from actual native cwnd/RTT;
the 256kbps constructor value is not its permanent startup ceiling. Native keepalive
is configured, but that does not guarantee a continuously warm bandwidth estimate.

Full supply means a source offered 40,000 x 1000-byte UDP messages per second.
Actual transport admission and wire transmission remain gated. A 3-second prefix
offers 120,000 extra messages (120MB before transport headers) per warm run. It
does not prove that the network transmitted those bytes or attained steady state.
Echo probes run from the first source interval; warmup losses and delays are not
hidden. Actual connection UDP-byte totals are kept separate from payload counts.

The first test pairs a single route selected before this study from the prior
survey with four-route aggregation. Both topologies have cold and warm cases,
two windows each in a fixed mirrored order. The selected route is not relabelled
as the currently strongest single route. This is not release acceptance or a
substitute for the pending native-equivalent and host references.

The canonical phase boundary is a registered source sequence index, not an
observed best-looking start time. Late prefix arrivals never earn business byte
credit. The suffix always retains all configured 400,000 bulk and 200 echo slots.
Reports show prefix, suffix, complete run, and suffix bytes divided by total time
including prefix. Full-population RTT tails retain missing requests.

The frozen native source records per-message UNIX send timestamps and a complete
monotonic source span. Phase spans use same-source timestamps only after a
nonregression and full-span agreement check (max 10ms or 0.5%). This is explicitly
not proof against every small interior clock correction, or cross-host one-way
deadline timing. Echo RTT is recomputed from its own monotonic send/receive pair.
Bulk and echo each have their own registered prefix; their clocks are not claimed
to be synchronized. Warm readiness is not assumed merely because 3 seconds elapsed.

The follow-up source-clock-only preparation does not require a cross-host SSH
clock-bracketing probe: no primary metric consumes a cross-host offset. Its local
timing-scope marker explicitly records that no remote clock bound exists, while
the same production observer and source-clock validation remain mandatory. If a
previous preparation fails, it remains failed. Newly registered unfinished cases
must not replay completed traffic or silently merge different preparations into
one successful historical campaign. Comparisons still require their declared
window population; single observations are descriptive only.

First judge each topology's warm/cold suffix gain and deadline cost. An acceptable
candidate must not regress completion or a comparable finite P95; missing tails
cannot pass. Then report same-study warm multipath versus the preselected warm
single, without stitching in older results. Whole-run cost remains visible even
if suffix throughput improves. Do not prolong a failed prefix or repeat completed
workloads to find a favorable warmup duration.

This study implements measurement and finite preparation, not an automatic
production preheater. A later runtime startup accelerator requires separate
admission/queue evidence, cooldown, state-expiry and rollback validation.

## Primary technical context

- RFC 9002 sections 7.7-7.8: pacing and under-utilized congestion windows.
  https://www.rfc-editor.org/rfc/rfc9002.html
- BBR working draft (not evidence that the pinned Quinn BBR is BBRv3): model
  learning from delivery and restarting after idle are separate from keepalive.
  https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-06
- Rapid Start is an expired individual Internet-Draft, not a deployed or accepted project
  feature. Its more aggressive startup still uses pacing and congestion handling.
  https://datatracker.ietf.org/doc/html/draft-kazuho-ccwg-rapid-start-02
