"""Packet-timing diagnostics and the explicit steady-source qualification envelope.

All original samples remain in the analysis. A burst count is input pressure,
not proof that the tunnel dropped those packets or that a timer caused a gap.
"""
from collections import Counter
import heapq
import math


def rolling_peaks(times, pps):
    """Bounded-window source pressure; callers choose their declared acceptance policy."""
    rolling = {}
    for width in (100, 1000, 1600, 5000):
        left = maximum = best_left = best_right = 0
        for right, at in enumerate(times):
            # Half-open [first, first+width): a boundary packet starts a new span.
            while at - times[left] >= width:
                left += 1
            size = right-left+1
            if size > maximum:
                maximum, best_left, best_right = size, left, right
        rolling[str(width)] = dict(max_packets=maximum, first_seq=best_left,
            last_seq=best_right, nominal_packets=pps*width/1e6)
    return rolling


def steady_source_peaks(times, pps):
    """The registered steady-workload envelope; burst workloads use a separate contract."""
    peaks = rolling_peaks(times, pps)
    for peak in peaks.values():
        limit = max(2, math.ceil(peak["nominal_packets"] * 2))
        peak.update(maximum_allowed_packets=limit, qualified=peak["max_packets"] <= limit)
    return dict(pacing_policy="steady", micro_window_maximum_nominal_multiple=2,
                micro_window_minimum_packet_allowance=2, rolling_windows_us=peaks,
                qualified=bool(times) and all(peak["qualified"] for peak in peaks.values()))


def burst_summary(samples, pps):
    if not isinstance(pps, int) or not 1 <= pps <= 40000:
        raise ValueError('registered pps must be 1..40000')
    if not 2 <= len(samples) <= 1000000:
        raise ValueError('timing diagnosis needs 2..1000000 original slots')
    times = []
    for seq, sample in enumerate(samples):
        at = sample.get('send_unix_us')
        if sample.get('seq') != seq or not isinstance(at, int):
            raise ValueError('full ordered source sequence and integer timestamps required')
        if times and at < times[-1]:
            raise ValueError('source clock regressed')
        times.append(at)
    bounds = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 50000]
    histogram = [0] * (len(bounds) + 1)
    peaks = []
    for seq in range(1, len(times)):
        gap = times[seq] - times[seq-1]
        bucket = next((i for i, bound in enumerate(bounds) if gap <= bound), len(bounds))
        histogram[bucket] += 1
        item = (gap, seq, times[seq-1], times[seq])
        if len(peaks) < 16:
            heapq.heappush(peaks, item)
        elif item > peaks[0]:
            heapq.heapreplace(peaks, item)
    rolling = rolling_peaks(times, pps)
    bins = Counter((at-times[0])//1000 for at in times)
    gaps = [b-a for a, b in zip(times, times[1:])]
    ordered = sorted(gaps)
    quantile = lambda p: ordered[max(0, math.ceil(p*len(ordered))-1)]
    return dict(population=len(samples), registered_pps=pps,
        gap_us=dict(p50=quantile(.5), p95=quantile(.95), p99=quantile(.99), maximum=max(gaps)),
        gap_histogram_upper_us=bounds+[None], gap_histogram_counts=histogram,
        rolling_windows_us=rolling, aligned_1ms_max_packets=max(bins.values()),
        first_240ms_packets=sum(v for k, v in bins.items() if k < 240),
        largest_gaps=[dict(gap_us=g, following_seq=s, previous_send_unix_us=a,
            following_send_unix_us=b) for g, s, a, b in sorted(peaks, reverse=True)],
        clock='source wall microseconds; verify monotonic aggregate independently',
        causal_claim=False, changes_pacing_or_acceptance=False)
