"""Full-population arithmetic for the bounded recovery/frontier field screen.

This is not a statistical estimator or a capacity claim. The caller separately
verifies frozen inputs, raw identities, source qualification and owned cleanup.
"""
import math


def _number(value, name, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(name + ' must be finite numeric evidence')
    if value < 0 or (positive and value == 0):
        raise ValueError(name + ' is outside its valid range')
    return value


def quantile(rtts, population, fraction):
    if not isinstance(population, int) or isinstance(population, bool) or population <= 0:
        raise ValueError('population must be a positive integer')
    if len(rtts) > population or not 0 < fraction <= 1:
        raise ValueError('invalid quantile population')
    values = sorted(_number(v, 'RTT') for v in rtts)
    index = math.ceil(population * fraction) - 1
    return values[index] if index < len(values) else 'infinity'


def pool(windows):
    if not windows:
        raise ValueError('no complete windows')
    seen, rtts = set(), []
    delivered_bytes = 0
    span = 0.0
    population = on_time = received = 0
    qualified = True
    for row in windows:
        label = row['window']
        if label in seen:
            raise ValueError('a completed window cannot be counted twice')
        seen.add(label)
        count, samples = row['requests'], row['echo_samples']
        if type(count) is not int or count <= 0 or len(samples) != count:
            raise ValueError('incomplete request population')
        if [r.get('seq') for r in samples] != list(range(count)):
            raise ValueError('missing, duplicate or unordered request slots')
        for sample in samples:
            rtt = sample.get('rtt_ms')
            if rtt is None:
                if sample.get('receive_unix_us') is not None:
                    raise ValueError('received request lacks monotonic RTT')
                continue
            _number(rtt, 'RTT')
            if sample.get('send_unix_us') is None or sample.get('receive_unix_us') is None:
                raise ValueError('RTT is missing request identity timestamps')
            rtts.append(rtt)
            received += 1
            on_time += rtt <= 200
        population += count
        n = row['unique_bytes']
        if type(n) is not int or n < 0:
            raise ValueError('unique payload bytes must be a nonnegative integer')
        delivered_bytes += n
        span += _number(row['source_span_seconds'], 'source span', positive=True)
        qualified &= row['source_qualified'] is True
    return {'windows': [r['window'] for r in windows], 'goodput_mbps': delivered_bytes * 8 / span / 1e6,
            'requests': population, 'received': received, 'on_time': on_time,
            'missing': population - received, 'late': received - on_time,
            'on_time_fraction': on_time / population,
            'p95_ms': quantile(rtts, population, .95), 'p99_ms': quantile(rtts, population, .99),
            'source_qualified': qualified}


def contrast(candidate, reference):
    c, r = candidate['p95_ms'], reference['p95_ms']
    finite_c = isinstance(c, (int, float)) and not isinstance(c, bool) and math.isfinite(c)
    finite_r = isinstance(r, (int, float)) and not isinstance(r, bool) and math.isfinite(r)
    rate = _number(reference['goodput_mbps'], 'reference goodput')
    gain = _number(candidate['goodput_mbps'], 'candidate goodput')
    return {'goodput_ratio': gain / rate if rate > 0 else None,
            'goodput_strictly_higher': gain > rate,
            'on_time_gain_percentage_points': 100 * (candidate['on_time_fraction'] - reference['on_time_fraction']),
            'completion_no_worse': candidate['on_time_fraction'] >= reference['on_time_fraction'],
            'p95_strictly_lower': finite_c and (r == 'infinity' or (finite_r and c < r))}


def screen(candidate, references, *, execution_complete, cleanup_confirmed, frontier_changes):
    comparisons = {name: contrast(candidate, row) for name, row in references.items()}
    passed = (execution_complete is True and cleanup_confirmed is True
              and candidate['source_qualified'] is True and len(candidate['windows']) == 2
              and type(frontier_changes) is int and frontier_changes > 0
              and bool(references)
              and all(row['source_qualified'] is True and len(row['windows']) == 2 for row in references.values())
              and all(c['goodput_strictly_higher'] and c['completion_no_worse'] and c['p95_strictly_lower']
                      for c in comparisons.values()))
    return {'passed': passed, 'comparisons': comparisons, 'frontier_changes': frontier_changes,
            'statistical_acceptance': False, 'capacity_acceptance': False, 'production_promoted': False}
