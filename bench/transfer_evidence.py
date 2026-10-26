"""Offline, common-window transfer accounting. Never launches traffic.

New grouped sender frames share all path and application counter boundaries.
Legacy per-connection logs must enclose the requested window on every path;
missing startup/tail samples are reported explicitly, never hidden in a total.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re

COUNTERS = ('sent_packets', 'lost_packets', 'udp_tx_bytes', 'udp_rx_bytes')
FIELD = re.compile(r'([a-z_]+)=("[^"]*"|\S+)')


def timestamp(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp()


def read_lines(path):
    path = Path(path)
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt') as stream:
        yield from stream


def proc_counters(text, family='TcpExt'):
    """Parse paired proc headers without nstat's mutable history file."""
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith(family + ':')]
    if len(rows) != 2 or len(rows[0]) != len(rows[1]):
        return None
    try:
        return dict(zip(rows[0], map(int, rows[1])))
    except ValueError:
        return None


def counter_delta(before, after):
    if before is None or after is None or before.keys() != after.keys():
        return None
    if any(after[k] < before[k] for k in before):
        return None
    return {k: after[k] - before[k] for k in before}


def legacy_samples(lines, exit_name=None):
    series = defaultdict(list)
    for line in lines:
        if 'proxy transport counters' not in line:
            continue
        fields = dict(FIELD.findall(line))
        if exit_name is not None and fields.get('exit', '').strip('"') != exit_name:
            continue
        if 'connection' not in fields or not all(k in fields for k in COUNTERS):
            continue
        try:
            sample = {k: int(fields[k]) for k in COUNTERS}
            sample['unix'] = timestamp(line.split()[0])
        except (ValueError, IndexError):
            continue
        series[fields['connection']].append(sample)
    return dict(series)


def enclose(series, start, end, expected_connections):
    """No interpolation and no baselines taken after the transfer has started."""
    rows, complete = [], bool(expected_connections)
    for connection in expected_connections:
        points = sorted(series.get(connection, []), key=lambda p: p['unix'])
        before = next((p for p in reversed(points) if p['unix'] <= start), None)
        after = next((p for p in points if p['unix'] >= end), None)
        row = {'connection': connection, 'complete': False}
        if before is None or after is None:
            row['missing'] = 'startup' if before is None else 'tail'
            complete = False
        else:
            delta = counter_delta({k: before[k] for k in COUNTERS},
                                  {k: after[k] for k in COUNTERS})
            if delta is None:
                row['missing'] = 'counter_reset'
                complete = False
            else:
                row.update(complete=True, start_unix=before['unix'], end_unix=after['unix'],
                           padding_before_seconds=start - before['unix'],
                           padding_after_seconds=after['unix'] - end, counters=delta)
        rows.append(row)
    totals = None
    if complete:
        totals = {k: sum(row['counters'][k] for row in rows) for k in COUNTERS}
        totals['quinn_declared_loss_fraction'] = (totals['lost_packets'] / totals['sent_packets']
                                                if totals['sent_packets'] else None)
    return {'coverage_complete': complete, 'paths': rows, 'totals': totals,
            'scope': 'enclosing per-connection intervals; includes boundary traffic',
            'application_to_udp_ratio': None,
            'ratio_note': 'Application counters do not share these exact legacy boundaries.'}


def grouped_frames(lines):
    decoder = json.JSONDecoder()
    for line in lines:
        if 'transfer snapshot' not in line or 'frame=' not in line:
            continue
        try:
            frame, _ = decoder.raw_decode(line.split('frame=', 1)[1])
            if frame.get('schema') != 1:
                continue
            frame['unix'] = timestamp(line.split()[0])
            yield frame
        except (ValueError, IndexError, AttributeError):
            continue


def frame_delta(before, after):
    """Compute all ratios on one unchanged session, direction and path set."""
    if any(before.get(k) != after.get(k) for k in ['schema', 'session', 'direction']):
        return {'complete': False, 'reason': 'session_or_direction_changed'}
    elapsed = after['sample_us'] - before['sample_us']
    if elapsed <= 0:
        return {'complete': False, 'reason': 'clock_not_advanced'}
    key = lambda p: (p['path'], p['connection'], p['generation'])
    left = {key(p): p for p in before['paths']}
    right = {key(p): p for p in after['paths']}
    if not left or left.keys() != right.keys():
        return {'complete': False, 'reason': 'path_generation_changed'}
    paths = []
    for identity, first in left.items():
        delta = counter_delta({k: first[k] for k in COUNTERS},
                              {k: right[identity][k] for k in COUNTERS})
        if delta is None:
            return {'complete': False, 'reason': 'native_counter_reset'}
        paths.append({'path': identity[0], 'counters': delta,
                      'pacing_bps': right[identity]['pacing_bps'],
                      'writer_backlog_bytes': right[identity]['writer_backlog_bytes'],
                      'last_rate_change': right[identity].get('last_rate_change')})
    totals = {k: sum(p['counters'][k] for p in paths) for k in COUNTERS}
    totals['quinn_declared_loss_fraction'] = (totals['lost_packets'] / totals['sent_packets']
                                            if totals['sent_packets'] else None)
    first, last = before.get('streams'), after.get('streams')
    streams = None
    # Only cumulative stream fields may be subtracted. Active gauges can fall.
    if first and last:
        fields = ['bytes_from_application', 'bytes_to_application', 'retransmitted_bytes']
        streams = counter_delta({k: first[k] for k in fields}, {k: last[k] for k in fields})
    ratio = None
    if streams is not None and totals['udp_tx_bytes']:
        ratio = streams['bytes_from_application'] / totals['udp_tx_bytes']
    return {'complete': True, 'elapsed_seconds': elapsed / 1e6, 'paths': paths,
            'totals': totals, 'streams': streams,
            'stream_gauges_end': {k:last[k] for k in ['send_retained_bytes','send_unsent_bytes',
                'send_window_blocked_streams','receive_buffered_bytes','receive_out_of_order_bytes']
                if last and k in last},
            'application_to_udp_ratio_estimate': ratio,
            'stream_sample_age_us': [before.get('streams_sample_age_us'), after.get('streams_sample_age_us')],
            'ratio_note': 'Stream snapshots are asynchronously published; age and inflight queues can skew short intervals. Prefer quiescent start/tail frames. UDP bytes exclude IP/UDP headers.'}


def tcp_sockets(text):
    """Read each owned ss block separately, retaining the socket identity."""
    import hashlib
    blocks = []
    for line in text.splitlines():
        m = re.match(r'^(?:tcp\s+)?(ESTAB|CLOSE-WAIT|FIN-WAIT-1|FIN-WAIT-2|SYN-SENT)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)', line)
        if m:
            blocks.append([m, line])
        elif blocks:
            blocks[-1][1] += ' ' + line.strip()
    result = []
    for m, block in blocks:
        inode = re.search(r'\bino:(\d+)', block)
        identity = m[4] + ' ' + m[5] + ' ' + (inode[1] if inode else '')
        row = {'socket': hashlib.sha256(identity.encode()).hexdigest()[:16],
               'recvq': int(m[2]), 'sendq': int(m[3]), 'peer_port': m[5].rsplit(':', 1)[-1]}
        for field in ['bytes_received', 'bytes_acked', 'bytes_sent', 'bytes_retrans']:
            value = re.search(r'\b' + field + r':(\d+)', block)
            row[field] = int(value[1]) if value else None
        for field in ['busy', 'rwnd_limited']:
            value = re.search(r'\b' + field + r':([\d.]+)(us|ms|s)', block)
            row[field + '_us'] = (float(value[1]) * {'us':1, 'ms':1000, 's':1e6}[value[2]]
                                     if value else None)
        memory = re.search(r'skmem:\(([^)]+)\)', block)
        fields = dict(re.findall(r'([a-z]+)(\d+)', memory[1])) if memory else {}
        row['socket_drops'] = int(fields['d']) if 'd' in fields else None
        result.append(row)
    return result


def tcp_timeline(samples, offset=0.0, frames=(), target_port=None):
    previous = {}
    prior_ext = None
    prior_host_at = None
    host_rows = []
    frames = sorted((f for f in frames if f['direction'] == 'server_to_client'), key=lambda f:f['unix'])
    cursor, nearest = 0, None
    rows = []
    for sample in samples:
        if sample.get('kind') != 'sample':
            continue
        at = sample['unix'] - offset
        while cursor < len(frames) and frames[cursor]['unix'] <= at:
            nearest = frames[cursor]; cursor += 1
        frame = nearest if nearest and at - nearest['unix'] <= 2 else None
        ext = proc_counters(sample.get('netstat', ''))
        ext_delta = counter_delta(prior_ext, ext)
        prior_ext = ext
        if prior_host_at is not None:
            host_rows.append({'end_utc':datetime.fromtimestamp(at, timezone.utc).isoformat(),
                              'elapsed_seconds':at-prior_host_at,'tcp_ext_delta':ext_delta})
        prior_host_at = at
        for socket in tcp_sockets(sample.get('tcp', '')):
            if target_port is not None and socket['peer_port'] != str(target_port):
                continue
            before = previous.get(socket['socket'])
            previous[socket['socket']] = (at, socket)
            if before is None or at <= before[0]:
                continue
            elapsed = at - before[0]
            old = before[1]
            def delta(field):
                a, b = old.get(field), socket.get(field)
                return b - a if a is not None and b is not None and b >= a else None
            received, acked = delta('bytes_received'), delta('bytes_acked')
            busy, rwnd = delta('busy_us'), delta('rwnd_limited_us')
            rwnd_fraction = rwnd / busy if busy and rwnd is not None else None
            candidates = []
            if rwnd_fraction is not None and rwnd_fraction >= .1:
                candidates.append('target_receive_window')
            if socket['recvq'] >= 1024*1024:
                candidates.append('tunnel_backpressure')
            if delta('socket_drops'):
                candidates.append('exit_socket_drop')
            if frame:
                gauge = frame.get('streams') or {}
                queued = gauge.get('local_sender_queued_bytes')
                retained = gauge.get('send_retained_bytes')
                writer = sum(p['writer_backlog_bytes'] for p in frame['paths'])
                if queued is not None and (queued >= 4*1024*1024 or writer >= 65536):
                    candidates.append('tunnel_backpressure')
                if gauge.get('send_window_blocked_streams', 0) > 0:
                    candidates.append('stream_receive_window')
                if retained is not None and retained >= 4*1024*1024:
                    candidates.append('tunnel_backpressure')
                if (received and socket['recvq'] < 65536 and writer == 0 and queued == 0
                        and retained is not None and retained < 1024*1024):
                    candidates.append('upstream_supply')
            rows.append({'end_utc':datetime.fromtimestamp(at, timezone.utc).isoformat(),
                         'socket':socket['socket'], 'elapsed_seconds':elapsed,
                         'receive_mbps':received*8/elapsed/1e6 if received is not None else None,
                         'acked_mbps':acked*8/elapsed/1e6 if acked is not None else None,
                         'recvq':socket['recvq'], 'sendq':socket['sendq'],
                         'rwnd_limited_fraction':rwnd_fraction,
                         'socket_drop_delta':delta('socket_drops'),
                         'candidate_causes':sorted(set(candidates)) or ['undetermined'],
                         'attribution_note':'Sampled evidence, not proof of a remote server or physical-link limit.'})
    return {'socket_intervals':rows, 'host_intervals':host_rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--legacy-start', help='UTC ISO timestamp; requires legacy-end/connections')
    parser.add_argument('--legacy-end')
    parser.add_argument('--connection', action='append', default=[])
    parser.add_argument('--exit')
    parser.add_argument('--tcp-samples', type=Path)
    parser.add_argument('--clock-alignment', type=Path)
    parser.add_argument('--host')
    parser.add_argument('--target-port', type=int)
    args = parser.parse_args(argv)
    from bench.run import private_path, save
    private_path(args.output)
    offset, alignment = 0.0, None
    if args.clock_alignment or args.host:
        if not args.clock_alignment or not args.host:
            parser.error('host and clock-alignment must be supplied together')
        alignment = json.loads(args.clock_alignment.read_text())[args.host]
        offset = alignment['remote_minus_mac_seconds']
    if args.legacy_start:
        if not args.legacy_end or not args.connection:
            parser.error('legacy accounting requires end and every expected connection')
        series = legacy_samples(read_lines(args.log), args.exit)
        for points in series.values():
            for point in points: point['unix'] -= offset
        result = enclose(series, timestamp(args.legacy_start), timestamp(args.legacy_end), args.connection)
        frames = []
    else:
        frames = list(grouped_frames(read_lines(args.log)))
        sessions = defaultdict(list)
        for frame in frames:
            frame['unix'] -= offset
            sessions[(frame['session'], frame['direction'])].append(frame)
        result = {'sessions': [{'session': session, 'direction': direction,
                   'intervals': [dict(end_utc=datetime.fromtimestamp(b['unix'], timezone.utc).isoformat(),
                                      **frame_delta(a, b)) for a, b in zip(values, values[1:])]}
                  for (session, direction), values in sessions.items()]}
    if args.tcp_samples:
        if alignment is None:
            parser.error('TCP attribution needs its host clock alignment')
        result['tcp_timeline'] = tcp_timeline(
            (json.loads(line) for line in args.tcp_samples.open()), offset, frames, args.target_port)
    result['clock_alignment'] = alignment
    save(args.output, result)


if __name__ == '__main__':
    main()
