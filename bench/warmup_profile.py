"""Finite continuous-connection warmup profiles and honest phase accounting.

No sockets or runtime changes. Warmup is the registered prefix of one continuous
source, not a second connection. Report its time, bytes, failures and complete-run
cost separately from the business suffix. No prefix byte earns business credit.
"""
import math

from bench.delivery_frontier import EvidenceError, finite, integer
from bench.topology_results import samples_summary


def make_plan(single_route, aggregate_routes):
    routes = list(aggregate_routes)
    if len(routes) != 4 or len(set(routes)) != 4 or single_route not in routes:
        raise EvidenceError('one preselected single among exactly four distinct routes required')
    if any(not isinstance(r, str) or not r or len(r) > 64 for r in routes):
        raise EvidenceError('short nonempty route identifiers required')
    modes = {}
    for name, selected in [('single', [single_route]), ('aggregate', routes)]:
        for treatment, warm in [('cold', 0), ('warm', 3)]:
            modes[name + '_' + treatment] = {
                'routes': selected, 'entrances': selected, 'connections': len(selected),
                'adaptive_sender': True, 'warmup_seconds': warm,
                'warmup_bulk_records': warm * 40_000, 'warmup_echo_requests': warm * 20,
                'bulk_count': (warm + 10) * 40_000, 'echo_count': (warm + 10) * 20,
                'business_bulk_records': 400_000, 'business_echo_requests': 200,
            }
    order_names = ['single_cold', 'single_warm', 'aggregate_warm', 'aggregate_cold',
                   'aggregate_cold', 'aggregate_warm', 'single_warm', 'single_cold']
    order = [{'window': 'window_' + chr(97 + i), 'mode': name}
             for i, name in enumerate(order_names)]
    return {
        'schema_version': 1, 'phase': 'P2_fast_warmup_same_connection',
        'modes': modes, 'order': order,
        'batches': [{'name': 'batch_' + chr(97 + i), 'windows': order[4*i:4*i+4]} for i in range(2)],
        'source': {'bulk_pps': 40_000, 'echo_pps': 20, 'datagram_bytes': 1000,
                   'net_payload_bytes': 964, 'echo_bytes': 128, 'drain_ms': 3000},
        'limits': {'aggregate_bps': 500_000_000, 'group_bps': 500_000_000,
                   'queue_ms': 100, 'latency_target_ms': 100, 'datagram_send_buffer_bytes': 9600,
                   'maximum_windows': 8, 'nominal_total_source_seconds': 92,
                   'maximum_extra_warmup_payload_bytes_per_warm_window': 120_000_000,
                   'fec': 0, 'small_fec_bytes': 0, 'redundancy_percent': 0,
                   'frontier_scheduler': False, 'no_retries': True},
        'warmup_gate': {'minimum_business_goodput_ratio': 1.1,
                        'no_worse_on_time_fraction': True, 'no_worse_finite_p95': True},
        'user_quality_target': {'minimum_on_time_fraction': .95,
                                'aggregation_ratio_to_selected_single': 1.5},
        'scope': '3s paced source-prefix diagnosis; not guaranteed instant warmup or steady-state capacity',
        'selected_single_is_current_best_proven': False,
        'native_equivalent_reference_completed': False,
        'warmup_cwnd_override': False, 'production_automation': False,
    }


def _latency(values):
    if not values:
        return {'requests': 0, 'received': 0, 'on_time': 0, 'on_time_fraction': None,
                'missing': 0, 'late': 0, 'p95_ms': None, 'p95_status': 'no_population'}
    ranked = sorted(math.inf if v is None else finite(v, 'RTT') for v in values)
    received = sum(v is not None for v in values)
    on_time = sum(v is not None and v <= 200 for v in values)
    p95 = ranked[math.ceil(len(values) * .95) - 1]
    return {'requests': len(values), 'received': received, 'on_time': on_time,
            'on_time_fraction': on_time / len(values), 'missing': len(values) - received,
            'late': received - on_time, 'p95_ms': None if math.isinf(p95) else p95,
            'p95_status': 'unresolved_missing_population' if math.isinf(p95) else 'finite'}


def analyze(source, received, echo, source_report, receive_report, echo_report, case, spec):
    full_spec = {**spec, 'bulk_count': case['bulk_count'], 'echo_count': case['echo_count']}
    checked = samples_summary(source, received, echo, source_report, receive_report, echo_report, full_spec)
    split = integer(case['warmup_bulk_records'], 'warmup records')
    echo_split = integer(case['warmup_echo_requests'], 'warmup requests')
    if split + case['business_bulk_records'] != len(source) or echo_split + case['business_echo_requests'] != len(echo):
        raise EvidenceError('warmup/business partition does not exactly cover the source')
    pps = integer(spec['bulk_pps'], 'bulk pps')
    if not pps:
        raise EvidenceError('positive source rate required')
    stamps = [integer(row['send_unix_us'], 'source timestamp') for row in source]
    if any(b < a for a, b in zip(stamps, stamps[1:])):
        raise EvidenceError('source wall clock regressed')
    measured_span = checked['actual_source_span_seconds']
    wall_span = (stamps[-1] - stamps[0]) / 1e6
    # The frozen native generator has per-record wall stamps and one monotonic
    # complete-source span. Reject disagreement. This cannot certify the absence
    # of every small interior clock adjustment or cross-host one-way timing.
    tolerance = max(.01, measured_span * .005)
    if abs(wall_span - measured_span) > tolerance:
        raise EvidenceError('source wall interval disagrees with monotonic full-source span')
    end_us = stamps[0] + measured_span * 1e6
    if end_us < stamps[-1]:
        # Small floating/recording differences use one nominal final slot;
        # never silently shorten a phase ending before its final send.
        end_us = stamps[-1] + 1e6 / pps

    def phase(begin, end, ebegin, eend):
        if begin == end:
            span = 0.
        else:
            stop = stamps[end] if end < len(stamps) else end_us
            span = (stop - stamps[begin]) / 1e6
            if span <= 0:
                raise EvidenceError('nonpositive measured source phase')
            if (end-begin) * spec['datagram_bytes'] * 8 / span < pps * spec['datagram_bytes'] * 8 * .95:
                raise EvidenceError('individual phase source pacing below95percent')
        n = sum(row['receive_unix_us'] is not None for row in received[begin:end])
        return {'first_seq': begin, 'exclusive_end_seq': end, 'source_records': end-begin,
                'delivered_records': n, 'missing_records': end-begin-n,
                'source_span_seconds': span, 'offered_datagram_bytes': (end-begin)*spec['datagram_bytes'],
                'unique_net_payload_bytes': n*spec['net_payload_bytes'],
                'goodput_mbps': n*spec['net_payload_bytes']*8/span/1e6 if span else None,
                'echo': _latency(checked['request_rtt_ms'][ebegin:eend])}
    prefix = phase(0, split, 0, echo_split)
    business = phase(split, len(source), echo_split, len(echo))
    entire = phase(0, len(source), 0, len(echo))
    if prefix['delivered_records'] + business['delivered_records'] != checked['unique_delivered']:
        raise EvidenceError('prefix incorrectly counted as business payload')
    if abs(prefix['source_span_seconds'] + business['source_span_seconds'] - entire['source_span_seconds']) > 1e-8:
        raise EvidenceError('time partition does not close')
    rtts = checked['request_rtt_ms']
    cohorts = []
    ep = spec['echo_pps']
    for i, start in enumerate(range(0,len(source),pps)):
        stop = min(start+pps,len(source))
        segment = phase(start,stop,i*ep,min((i+1)*ep,len(rtts)))
        segment['source_second_cohort'] = i
        cohorts.append(segment)
    return {'warmup':prefix,'business':business,'complete_run':entire,
            'business_goodput_charging_prefix_time_mbps':business['unique_net_payload_bytes']*8/entire['source_span_seconds']/1e6,
            'one_second_source_cohorts':cohorts,
            'clock_check':{'full_monotonic_span_seconds':measured_span,'full_wall_span_seconds':wall_span,
                           'allowed_difference_seconds':tolerance,
                           'phase_rate_basis':'same-source wall timestamp boundaries checked against full monotonic span',
                           'cross_host_absolute_deadline_proven':False},
            'echo_prefix_is_own_source_prefix':True,
            'bulk_echo_prefix_clocks_synchronized':False,
            'steady_state_or_ready_after3s_proven':False}


def pool(phases):
    phases = list(phases)
    if not phases:
        raise EvidenceError('no phase population')
    span = sum(p['source_span_seconds'] for p in phases)
    if span <= 0:
        raise EvidenceError('cannot pool zero phase time')
    n = sum(p['unique_net_payload_bytes'] for p in phases)
    requests = sum(p['echo']['requests'] for p in phases)
    on_time = sum(p['echo']['on_time'] for p in phases)
    # Do not average per-window P95. Caller pools raw RTT slots for a quantile.
    return {'goodput_mbps':n*8/span/1e6,'unique_net_payload_bytes':n,'source_span_seconds':span,
            'requests':requests,'on_time':on_time,'on_time_fraction':on_time/requests if requests else None,
            'missing':sum(p['echo']['missing'] for p in phases),
            'p95_ms':None,'p95_requires_raw_rtt_pool':True}
