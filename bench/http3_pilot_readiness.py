"""Fixed 16Mbps real-HTTP/3 loopback readiness, with no modeled link or delay.

This is a new functional scope, not a relaxation or replacement of failed
simulator timing calibration. It never contacts remote machines. All processes
are owned by host_reference and stopped before a readiness result is written.
"""
import argparse
import json
from pathlib import Path
import platform
import signal
import subprocess
import time

from bench.host_reference import digest, read, reference_profile, run_window, save_new

PROFILES = ('every-two', 'every-eight')


def check_window(row, profile):
    case, source, rate = reference_profile(profile)
    phase = row['phase']['business']
    pipeline = row['pipeline_ledger']
    reasons = []
    if phase['source_records'] != case['bulk_count'] or phase['delivered_records'] != case['bulk_count']:
        reasons.append('full original population not delivered')
    echo = phase['echo']
    if echo['requests'] != case['echo_count'] or echo['received'] != case['echo_count'] or echo['on_time'] != case['echo_count']:
        reasons.append('full request deadline population not delivered')
    if pipeline['source_sent'] != case['bulk_count'] or pipeline['adapter_bulk_received'] != case['bulk_count'] or pipeline['adapter_bulk_forwarded'] != case['bulk_count']:
        reasons.append('source/adapter pipeline has a gap')
    for role in ['client', 'server']:
        endpoint = row['endpoint_stats'][role]
        stats = endpoint['stats']
        paths = list(stats['paths'].values())
        if len(paths) != 1 or not all(p['authenticated'] for p in paths):
            reasons.append(role + ': real single authenticated path missing')
            continue
        q = paths[0]['quinn']
        expected_tx = role == 'server'
        if (q['ack_frequency_frames_tx'] > 0) != expected_tx or (q['ack_frequency_frames_rx'] > 0) == expected_tx:
            reasons.append(role + ': actual ACK request direction differs')
        if endpoint.get('error') is not None or not stats['shutdown_complete'] or stats['drain_incomplete']:
            reasons.append(role + ': endpoint shutdown is incomplete')
    return {'profile': profile, 'passed': not reasons, 'reasons': reasons,
            'bulk_delivered': phase['delivered_records'], 'bulk_population': case['bulk_count'],
            'echo_on_time': echo['on_time'], 'echo_population': case['echo_count'],
            'echo_p95_ms': echo['p95_ms'], 'goodput_mbps': phase['goodput_mbps'],
            'nominal_datagram_bps': source['bulk_pps'] * source['datagram_bytes'] * 8,
            'total_group_cap_bps': rate, 'raw_hashes': row['raw_hashes'],
            'purpose': 'unimpaired real HTTP/3 functional readiness; not a performance comparison'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    binary, bundle, root = args.binary.resolve(), args.bundle.resolve(), args.output.resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    helpers = ('mixed_adapter.py', 'bpp2_echo.py', 'probe_identity.py')
    for name in helpers:
        if not (bundle / name).is_file():
            raise FileNotFoundError(bundle / name)
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parent.parent
    registration = {'profiles': list(PROFILES), 'case': reference_profile(PROFILES[0])[0],
                    'source': reference_profile(PROFILES[0])[1], 'rate_cap_bps': 50000000,
                    'binary_sha256': digest(binary),
                    'source_sha256': {name: digest(repo / name) for name in [
                        'bench/host_reference.py', 'bench/http3_pilot_readiness.py',
                        'bench/topology_results.py', 'bench/warmup_profile.py']},
                    'helper_sha256': {name: digest(bundle / name) for name in helpers},
                    'platform': platform.platform(), 'created_unix_ns': time.time_ns(),
                    'maximum_windows': 2, 'no_retries': True, 'loopback_only': True,
                    'synthetic_link_present': False, 'failed_5ms_model_qualification_preserved': True,
                    'high_load_qualification_passed': False, 'new_network_capacity_claim': False}
    save_new(root / 'registration.json', registration)
    checks, error = [], None
    def interrupt(signum, frame):
        raise KeyboardInterrupt('readiness owner interrupted')
    previous = {s: signal.signal(s, interrupt) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        subprocess.run([str(binary), 'init', '--dir', str(root / 'identity'), '--name', 'localhost'],
                       capture_output=True, check=True, timeout=10)
        for index, profile in enumerate(PROFILES):
            if digest(binary) != registration['binary_sha256']:
                raise ValueError('binary changed after readiness registration')
            row = run_window(root / ('window_' + chr(97 + index)), 'overlay_adaptive',
                             binary, binary, bundle, root / 'identity', pilot_ack=profile)
            checked = check_window(row, profile)
            checks.append(checked)
            print(json.dumps({k: v for k, v in checked.items() if k != 'raw_hashes'}), flush=True)
            if not checked['passed']:
                raise RuntimeError('readiness failed; remaining profile not run')
    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
    value = {'passed': error is None and len(checks) == len(PROFILES) and all(c['passed'] for c in checks),
             'error': error, 'completed_windows': len(checks), 'checks': checks,
             'registration_sha256': digest(root / 'registration.json'),
             'scope': 'functional real HTTP/3 source/adapter/endpoint readiness, no delay simulator',
             'simulation_timing_qualified': False, 'high_load_qualified': False,
             'public_network_workloads': 0, 'production_actions': 0}
    save_new(root / 'readiness.json', value)
    print(json.dumps({k: v for k, v in value.items() if k != 'checks'}, indent=2), flush=True)
    return 0 if value['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
