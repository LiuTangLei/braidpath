"""Finite 80Mbps actual-HTTP/3 local reference, not a synthetic-link calibration.

One off/on pair tests the source/adapter/HTTP3 pipeline before any WAN use.
All original payloads and all interaction slots count; no successful-only P95.
No network topology or credentials are published by this helper.
"""
import argparse
import json
from pathlib import Path
import platform
import subprocess

from bench.host_reference import digest, run_window, save_new


def adaptive_snapshots(value):
    """Inspect serialized runtime evidence without assuming a session layout."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'adaptive' and isinstance(child, dict):
                yield child
            else:
                yield from adaptive_snapshots(child)
    elif isinstance(value, list):
        for child in value:
            yield from adaptive_snapshots(child)


def check(row, enabled):
    phase = row['phase']['business']
    echo = phase['echo']
    ledger = row['pipeline_ledger']
    reasons = []
    if phase['source_records'] != 100000 or phase['delivered_records'] != 100000:
        reasons.append('incomplete original population')
    if phase['goodput_mbps'] < 77.12 * .95:
        reasons.append('actual source/delivery rate below the registered 95% floor')
    if echo['requests'] != 200 or echo['received'] != 200 or echo['on_time'] != 200:
        reasons.append('incomplete full-deadline request population')
    if any(ledger[k] != 100000 for k in ['source_sent', 'adapter_bulk_received', 'adapter_bulk_forwarded']):
        reasons.append('source/adapter pipeline gap')
    for role in ['client', 'server']:
        stats = row['endpoint_stats'][role]['stats']
        paths = list(stats['paths'].values())
        if len(paths) != 1 or not all(p['authenticated'] for p in paths):
            reasons.append(role + ': authenticated single path missing')
        adaptive = list(adaptive_snapshots(stats))
        if not adaptive or any(a['last_control']['native_service_guard_enabled'] != enabled for a in adaptive):
            reasons.append(role + ': native service flag not observed at runtime')
    return dict(passed=not reasons, reasons=reasons, native_service_guard=enabled,
                goodput_mbps=phase['goodput_mbps'], bulk_delivered=phase['delivered_records'],
                bulk_population=100000, echo_on_time=echo['on_time'], echo_population=200,
                echo_p95_ms=echo['p95_ms'])


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(argv)
    binary, bundle, root = a.binary.resolve(), a.bundle.resolve(), a.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    sha = digest(binary)
    save_new(root/'registration.json', dict(binary_sha256=sha, platform=platform.platform(),
        order=[False, True], profile='native-service-80', total_group_cap_bps=125000000,
        unchanged_native_bbr=True, unchanged_ack=True, no_retries=True,
        windows=2, source_seconds_per_window=10, no_synthetic_link=True,
        prior_synthetic_timing_failures_preserved=True, public_network_operations=0))
    subprocess.run([str(binary), 'init', '--dir', str(root/'identity'), '--name', 'localhost'],
                   check=True, capture_output=True, timeout=10)
    checks, error = [], None
    try:
        for i, enabled in enumerate([False, True]):
            if digest(binary) != sha:
                raise ValueError('binary changed after registration')
            row = run_window(root/('window_'+chr(97+i)), 'overlay_adaptive', binary,
                binary, bundle, root/'identity', service_profile='native-service-80',
                native_service_guard=enabled)
            checked = check(row, enabled)
            checks.append(checked)
            print(json.dumps(checked), flush=True)
    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    value = dict(passed=error is None and len(checks)==2 and all(c['passed'] for c in checks),
                 checks=checks, error=error, completed_windows=len(checks),
                 scope='80Mbps no-simulator actual HTTP3 pipeline, not WAN capacity or aggregation acceptance',
                 synthetic_timer_qualified=False, public_network_operations=0)
    save_new(root/'readiness.json', value)
    print(json.dumps(value, indent=2), flush=True)
    return 0 if value['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
