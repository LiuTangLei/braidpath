"""Read-only raw collector adapter for a predeclared multi-batch topology survey.

Reads stopped-job artifacts and verifies their original hash inventories. It
never launches sockets, executes source files, retries workloads or upgrades a
short cold-start survey to a steady-state/native-equivalent capacity claim.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from bench.delivery_frontier import EvidenceError, closed_endpoint, finite, integer, read_json, record_ledger
from bench.relative_gain import evaluate


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def samples_summary(source, received, echo, source_report, receive_report, echo_report, spec):
    """Validate complete original slots and independently recompute echo RTT."""
    count, ecount = spec['bulk_count'], spec['echo_count']
    if len(source) != count or len(received) != count or len(echo) != ecount:
        raise EvidenceError('missing configured raw sample slots')
    if source_report['requested_count'] != count or receive_report['requested_count'] != count or echo_report['requested_count'] != ecount:
        raise EvidenceError('report population changed')
    if source_report['sent'] != count or echo_report['sent'] != ecount:
        raise EvidenceError('source did not send the full configured cohort')
    if source_report['run_id'] != receive_report['run_id']:
        raise EvidenceError('source and receiver run IDs differ')
    for report in [source_report, receive_report, echo_report]:
        if report.get('outcome') != 'ok' or report.get('final') is not True:
            raise EvidenceError('nonfinal or unsuccessful application report')
        if report.get('corrupt') != 0 or report.get('duplicate') != 0:
            raise EvidenceError('corrupt or duplicate application data')
    delivered = 0
    for i, (a, b) in enumerate(zip(source, received)):
        if a['seq'] != i or b['seq'] != i:
            raise EvidenceError('missing, duplicate or reordered sequence slots')
        integer(a['send_unix_us'], 'original source timestamp')
        if b['receive_unix_us'] is not None:
            integer(b['receive_unix_us'], 'receive timestamp')
            if b['send_unix_us'] != a['send_unix_us'] or b.get('missing') is not False:
                raise EvidenceError('received original has wrong source identity or missing flag')
            delivered += 1
        elif b.get('missing') is not True:
            raise EvidenceError('missing original was not recorded missing')
    if delivered != receive_report['received']:
        raise EvidenceError('received count disagrees with raw original slots')
    rtts = []
    for i, row in enumerate(echo):
        if row['seq'] != i:
            raise EvidenceError('echo sequence slots differ')
        integer(row['send_unix_us'], 'echo source wall timestamp')
        sent = integer(row['send_monotonic_ns'], 'echo source monotonic timestamp')
        if row.get('receive_monotonic_ns') is None:
            if row.get('rtt_ms') is not None or row.get('receive_unix_us') is not None or row.get('missing') is not True:
                raise EvidenceError('missing echo contains completed timing')
            rtts.append(None)
        else:
            end = integer(row['receive_monotonic_ns'], 'echo receive monotonic timestamp')
            if end < sent or row.get('receive_unix_us') is None or row.get('missing') is not False:
                raise EvidenceError('invalid completed echo timing')
            rtt = (end - sent) / 1_000_000
            if not math.isclose(finite(row['rtt_ms'], 'reported RTT'), rtt, rel_tol=1e-9, abs_tol=1e-7):
                raise EvidenceError('reported echo RTT differs from same-clock timestamps')
            rtts.append(rtt)
    if sum(rtt is not None for rtt in rtts) != echo_report['received']:
        raise EvidenceError('echo report disagrees with raw slots')
    for report, pps, size in [(source_report,spec['bulk_pps'],spec['datagram_bytes']),
                              (echo_report,spec['echo_pps'],spec['echo_bytes'])]:
        if finite(report['actual_offered_load_bps'], 'source pacing') < pps * size * 8 * .95:
            raise EvidenceError('source pacing below fixed 95 percent floor')
    span = finite(source_report['send_span_seconds'], 'source span')
    if span <= 0:
        raise EvidenceError('missing source span')
    return {'unique_delivered': delivered, 'request_rtt_ms': rtts, 'actual_source_span_seconds': span}


def topology_census(client, server, client_argv, expected_entrances):
    tx, sid = closed_endpoint(client, 'client')
    peer, psid = closed_endpoint(server, 'server')
    if sid != psid:
        raise EvidenceError('endpoint sessions differ')
    n = len(expected_entrances)
    values = [client_argv[i+1] for i, value in enumerate(client_argv[:-1]) if value == '--entrance']
    if values != expected_entrances:
        raise EvidenceError('actual client destinations differ from planned topology')
    out = {}
    for role, stats in [('client',tx),('server',peer)]:
        paths = sorted(stats['paths'].values(), key=lambda p:p['path_id'])
        if len(paths) != n or [p['path_id'] for p in paths] != list(range(n)):
            raise EvidenceError('missing or extra actual connection paths')
        if len({p['connection_id'] for p in paths}) != n or not all(p['authenticated'] for p in paths):
            raise EvidenceError('duplicate or unauthenticated connections')
        if any(p.get('total_generations') != 1 for p in paths):
            raise EvidenceError('path generation changed during short topology window')
        if role == 'client':
            if any(not isinstance(p.get('local_socket'),str) or not p['local_socket'] for p in paths):
                raise EvidenceError('actual client source sockets missing')
            if len({p['local_socket'] for p in paths}) != n:
                raise EvidenceError('parallel connections did not use independent source sockets')
            if [p['peer_socket'] for p in paths] != expected_entrances:
                raise EvidenceError('observed peer routes differ from command line')
        for direction in stats['sessions'][sid].values():
            if direction['symbols']['repairs_generated'] != 0:
                raise EvidenceError('uncoded control generated repairs')
            f = direction.get('sender_frontier')
            if f and (f['enabled'] or f['small_rank_changes']):
                raise EvidenceError('rejected frontier treatment was enabled')
        out[role] = {'connections':n, 'per_path':[{
            'id':p['path_id'], 'originals_api_admitted':p['quinn_admitted_originals'],
            'quinn_udp_bytes_tx':p['quinn']['udp_bytes_tx'],
            'quinn_udp_bytes_rx':p['quinn']['udp_bytes_rx']} for p in paths]}
    return out


def audit(plan_path, batch_paths):
    inputs = {}
    def read(path): return read_json(path, inputs)
    plan = read(plan_path)
    batch_paths = [Path(p).resolve() for p in batch_paths]
    if len(batch_paths) != len(plan['batches']) or len(set(batch_paths)) != len(batch_paths):
        raise EvidenceError('missing, extra or duplicate registered batches')
    records, details, batches = [], [], []
    for batch_spec, root in zip(plan['batches'], batch_paths):
        registration = root/'registration.json'
        if not registration.exists():
            batches.append({'batch':batch_spec['name'],'status':'not_started'})
            continue
        reg = read(registration)
        if digest(registration) != (root/'registration.sha256').read_text().strip():
            raise EvidenceError('frozen registration changed')
        for name, expected in reg['files_sha256'].items():
            p = root/name
            if digest(p) != expected:
                raise EvidenceError('frozen input changed: ' + str(p))
        if read(root/'topology-plan.json') != plan:
            raise EvidenceError('batch substituted another survey plan')
        if [(r['window'],r['variant']) for r in reg['conditions']['order']] != [(r['window'],r['mode']) for r in batch_spec['windows']]:
            raise EvidenceError('batch window order differs from master plan')
        topology = read(root/'topology.private.json')
        if digest(root/'topology.private.json') != plan['common']['host_fixture']:
            raise EvidenceError('host fixture changed')
        wrapper = read(root/'wrapper-completion.json')
        protected = wrapper['status']=='complete' and wrapper['continuous_protection_passed'] is True
        batches.append({'batch':batch_spec['name'],'status':wrapper['status'],'protected':protected})
        for item in batch_spec['windows']:
            w = root/item['window']
            if not (w/'metrics.json').exists():
                continue
            mode = plan['modes'][item['mode']]
            completion = read(w/'completion.json')
            if completion['error'] is not None or completion['cleanup_errors'] != [] or completion['cleanup_unconfirmed'] != []:
                raise EvidenceError('completed metrics have unclean window lifecycle')
            jobs = read(w/'jobs.json')
            if len({j['role'] for j in jobs}) != len(jobs):
                raise EvidenceError('duplicate role identity')
            jobs = {j['role']:j for j in jobs}
            for role, job in jobs.items():
                collection = w/'two-phase-cleanup/collection'/role
                proof = read(collection/'collection-completion.json')
                for key in ['all_hashes_verified','remote_inventory_stable','launch_identity_verified','exit_identity_verified','exact_process_inactive']:
                    if proof.get(key) is not True:
                        raise EvidenceError('incomplete collector proof: '+role+'/'+key)
                if proof.get('outcome') != 'ok' or proof.get('ssh_returncode') != 0:
                    raise EvidenceError('collector did not finish')
                inventory = read(collection/'inventory-after.json')
                if inventory['pid'] != job['pid'] or inventory['unit'] != job['unit'] or inventory['alive'] is not False:
                    raise EvidenceError('collector/job identity differs')
                for entry in inventory['files']:
                    name = entry['name']
                    if Path(name).name != name or name in ('.','..'):
                        raise EvidenceError('artifact name escapes role')
                    path = w/role/name
                    if path.is_symlink() or path.stat().st_size != entry['size'] or digest(path) != entry['sha256']:
                        raise EvidenceError('collected raw artifact hash differs')
                launch = read(w/role/'launch.json')
                if launch != inventory['launch'] or launch['pid'] != job['pid']:
                    raise EvidenceError('launch metadata changed')
            for role in ['client','server']:
                argv = jobs[role]['argv']
                if argv[0] != reg['variants']['baseline']['remote_binary']:
                    raise EvidenceError('unexpected endpoint binary')
                if '--frontier-scheduler' in argv or '--mixed-fec' in argv or '--adaptive-fec-retention' in argv:
                    raise EvidenceError('unexpected runtime treatment')
            av = jobs['client']['argv']
            for flag, value in [('--fec','0'),('--small-fec-bytes','0'),('--redundancy-percent','0'),
                                ('--rate-bps','500000000'),('--group-rate-bps','0:500000000')]:
                if av.count(flag) != 1 or av[av.index(flag)+1] != value:
                    raise EvidenceError('wrong matched client policy: '+flag)
            client, server = read(w/'client/stats.json'), read(w/'server/stats.json')
            for role, snapshot in [('client',client),('server',server)]:
                if snapshot['process_id'] != jobs[role]['pid']:
                    raise EvidenceError('endpoint stats PID differs from launch')
            census = topology_census(client,server,av,[topology['paths'][p]['entrance'] for p in mode['entrances']])
            reports = {role:read(w/role/'result.json') for role in ['source','bulk','interactive']}
            for role, report in reports.items():
                if report['pid'] != jobs[role]['pid'] or report['run_id'] != jobs[role]['run_id']:
                    raise EvidenceError('application report identity changed')
            sample = {role:read(w/role/'samples.json')['samples'] for role in reports}
            result = samples_summary(sample['source'],sample['bulk'],sample['interactive'],
                                     reports['source'],reports['bulk'],reports['interactive'],plan['source'])
            old = read(w/'metrics.json')
            if old['bulk']['unique_delivered'] != result['unique_delivered']:
                raise EvidenceError('raw reader and campaign delivery totals disagree')
            record = {'window':item['window'],'mode':item['mode'],'common':plan['common'],
                      'actual_source_span_seconds':result['actual_source_span_seconds'],
                      'unique_application_payload_bytes':result['unique_delivered']*plan['common']['payload_bytes'],
                      'offered_application_payload_bytes':plan['source']['bulk_count']*plan['common']['payload_bytes'],
                      'configured_requests':plan['source']['echo_count'],'request_rtt_ms':result['request_rtt_ms'],
                      'protected':protected,'cohort_complete':True}
            records.append(record)
            details.append({'window':item['window'],'mode':item['mode'],'topology':census,
                            'record_ledger':record_ledger(server['stats']['directions']['server_to_client']),
                            'bulk':old['bulk'],'interactive':old['interactive']})
    result = evaluate(plan, records)
    return {'result':result,'batches':batches,'normalized_records':records,'windows':details,
            'all_registered_artifact_hashes_verified':True,'raw_cohorts_and_connection_topology_verified':True,
            'native_reference_completed':False,'steady_state_confirmed':False,'release_acceptance':False,
            'completed_windows':len(records),'planned_windows':len(plan['order']),'input_sha256':inputs,
            'scope':'cold topology discovery; no cross-regime or reliable-service claim','network_actions':0}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',type=Path,required=True);p.add_argument('--batch',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise FileExistsError('preserve previous evidence')
    value=audit(a.plan,a.batch)
    with a.output.open('x') as f:json.dump(value,f,indent=2,allow_nan=False);f.write('\n')
    print(json.dumps({'completed_windows':value['completed_windows'],'planned_windows':value['planned_windows'],
                      'result':value['result']},indent=2,allow_nan=False))


if __name__=='__main__':main()
