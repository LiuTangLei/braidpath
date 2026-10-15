"""Finite loopback-only host/QUIC reference. Production services are never addressed.

Run on an isolated test host with --bundle (frozen helper directory), --binary,
--native and a new --output under an explicitly chosen test directory. Full raw
samples are retained. No sysctl, qdisc, firewall, service or network-wide changes.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import signal
import socket
import subprocess
import sys
import time
import uuid

from bench.warmup_profile import analyze, pool

MODES = ('udp', 'native_thin', 'native_matched', 'overlay_native', 'overlay_adaptive')
CASE = dict(warmup_bulk_records=120000, warmup_echo_requests=60,
            bulk_count=520000, echo_count=260, business_bulk_records=400000,
            business_echo_requests=200, warmup_seconds=3)
SOURCE = dict(bulk_pps=40000, echo_pps=20, datagram_bytes=1000,
              net_payload_bytes=964, echo_bytes=128, drain_ms=3000)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def save_new(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def read(path):
    return json.loads(Path(path).read_text())


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return '127.0.0.1:' + str(sock.getsockname()[1])


def wait_ready(process, file, *, paths=None, limit=8):
    until = time.monotonic() + limit
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError('process exited before readiness: ' + str(file))
        try:
            if paths is None:
                value = read(file)
                if value.get('ready') is True and value.get('pid') == process.pid:
                    return value
            else:
                text = Path(file).read_text()
                for line in reversed(text.splitlines()):
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    live = value['stats']['paths']
                    if len(live) == paths and all(p['authenticated'] for p in live.values()):
                        return value
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.025)
    raise TimeoutError('finite host-reference readiness: ' + str(file))


def stage_fields(closed):
    c = closed['counters']
    return (c['udp_received'] == c['oversize']+c['flow_full']+c['input_enqueued']+c['input_full']
            and c['input_enqueued'] == c['encoded']+c['input_shutdown']
            and c['encoded'] == c['queue_full']+c['expired']+c['queued_shutdown']+c['api_admitted']+c['api_error']
            and c['carrier_received'] == c['invalid']+c['target_delivered']+c['target_error'])


class Owned:
    """Only process groups created by this owner; never arbitrary PID matching."""
    def __init__(self, directory):
        self.directory = directory
        self.children = []
        self.cleanup = []

    def launch(self, role, argv):
        folder = self.directory/role
        folder.mkdir()
        with (folder/'stdout.log').open('x') as out, (folder/'stderr.log').open('x') as err:
            child = subprocess.Popen([str(x) for x in argv], stdout=out, stderr=err,
                                     start_new_session=True,
                                     env={**os.environ, 'RUST_LOG':'braidpath=info'})
        self.children.append((role, child))
        save_new(folder/'launch.json', dict(role=role,pid=child.pid,process_group=child.pid,
            argv=[str(x) for x in argv],started_unix_ns=time.time_ns(),
            linux_start_ticks=Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
                if Path('/proc/'+str(child.pid)+'/stat').exists() else None))
        return child

    def stop_all(self):
        for role, child in self.children:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
        for role, child in self.children:
            forced = False
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                forced = True
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
            item = dict(role=role,pid=child.pid,returncode=child.returncode,
                        exited=child.poll() is not None,forced_kill=forced)
            self.cleanup.append(item)
            save_new(self.directory/role/'exit.json',item)
        save_new(self.directory/'cleanup.json',self.cleanup)
        if any(r['forced_kill'] for r in self.cleanup):
            raise RuntimeError('forced cleanup required; do not accept reference')


def reference_profile(pilot_ack=None):
    """The optional pilot is a distinct, fixed no-simulator readiness profile."""
    if pilot_ack is None:
        return dict(CASE), dict(SOURCE), 500_000_000
    if pilot_ack not in ('every-two', 'every-eight'):
        raise ValueError('only the two matched directional ACK requests are allowed')
    case = dict(warmup_bulk_records=0, warmup_echo_requests=0,
                bulk_count=20000, echo_count=200, business_bulk_records=20000,
                business_echo_requests=200, warmup_seconds=0)
    return case, {**SOURCE, 'bulk_pps': 2000}, 50_000_000


def run_window(root, mode, binary, native, bundle, identity, *, pilot_ack=None):
    case, source_spec, rate = reference_profile(pilot_ack)
    if pilot_ack is not None and mode != 'overlay_adaptive':
        raise ValueError('public pilot readiness must use the real adaptive HTTP/3 path')
    root.mkdir()
    owner=Owned(root)
    adapter, source_addr, listener, entrance = port(), port(), port(), port()
    run, echo_run = uuid.uuid4().hex, uuid.uuid4().hex
    results_error=None
    usage0=resource.getrusage(resource.RUSAGE_CHILDREN)
    started=time.monotonic()
    save_new(root/'case.json',dict(mode=mode,source=source_spec,case=case,
                                 pilot_ack_request=pilot_ack, rate_cap_bps=rate,
                                 addresses=dict(adapter=adapter,source=source_addr,listener=listener,entrance=entrance)))
    try:
        owner.launch('adapter',[sys.executable,'-B',bundle/'mixed_adapter.py','--listen',adapter,
            '--source',source_addr,'--direction','reverse','--bulk-count',case['bulk_count'],
            '--bulk-run-id',run,'--echo-ids',json.dumps({echo_run:case['echo_count']}),
            '--ready-file',root/'adapter/ready.json','--result-file',root/'adapter/result.json',
            '--lifetime-seconds','90'])
        wait_ready(owner.children[-1][1],root/'adapter/ready.json')
        if mode.startswith('native_'):
            frame=mode.split('_',1)[1]
            for role,listen,peer in [('server',entrance,adapter),('client',listener,entrance)]:
                child=owner.launch(role,[native,'--role',role,'--listen',listen,'--peer',peer,
                    '--identity',identity,'--frame',frame,'--ready-file',root/role/'ready.json',
                    '--stats-file',root/role/'stats.json','--lifetime-seconds','60'])
                wait_ready(child,root/role/'ready.json')
        elif mode.startswith('overlay_'):
            server=owner.launch('server',[binary,'server','--listen',entrance,'--cert',identity/'cert.pem',
                '--key',identity/'key.pem','--token-file',identity/'token','--target',adapter,
                '--max-rate-bps',str(rate),'--datagram-send-buffer-bytes','9600',
                '--stats-file',root/'server/stats.json','--stats-jsonl',root/'server/stats.jsonl','--stats-interval-ms','250',
                *(['--ack-request',pilot_ack] if pilot_ack is not None else [])])
            # Server readiness has no app connection yet; retain finite JSON lifecycle check.
            deadline=time.monotonic()+8
            while True:
                if server.poll() is not None: raise RuntimeError('overlay server exited')
                try:
                    values=[json.loads(s) for s in (root/'server/stats.jsonl').read_text().splitlines()]
                    if any(v['stats']['ready'] for v in values):break
                except (OSError,ValueError,KeyError):pass
                if time.monotonic()>=deadline:raise TimeoutError('overlay server readiness')
                time.sleep(.025)
            args=[binary,'client','--listen',listener,'--entrance',entrance,'--server-name','localhost',
                  '--ca',identity/'cert.pem','--token-file',identity/'token','--fec','0',
                  '--small-fec-bytes','0','--redundancy-percent','0','--receiver-feedback','--quality-schedule',
                  '--rate-bps',str(rate),'--group-rate-bps','0:'+str(rate),
                  '--queue-ms','100','--latency-target-ms','100','--datagram-send-buffer-bytes','9600',
                  '--stats-file',root/'client/stats.json','--stats-jsonl',root/'client/stats.jsonl','--stats-interval-ms','250']
            if mode=='overlay_adaptive':args+=['--adaptive']
            client=owner.launch('client',args)
            wait_ready(client,root/'client/stats.jsonl',paths=1)
        else:
            listener=adapter
        source=owner.launch('source',[binary,'sink','--role','reverse-source','--listen',source_addr,
            '--count',case['bulk_count'],'--pps',source_spec['bulk_pps'],'--size','1000','--deadline-ms','200',
            '--drain-ms','3000','--startup-timeout-ms','30000','--run-id',run,
            '--ready-file',root/'source/ready.json','--result-file',root/'source/result.json',
            '--samples-file',root/'source/samples.json'])
        wait_ready(source,root/'source/ready.json')
        bulk=owner.launch('bulk',[binary,'probe','--mode','receive','--target',listener,
            '--count',case['bulk_count'],'--pps',source_spec['bulk_pps'],'--size','1000','--deadline-ms','200',
            '--drain-ms','3000','--startup-timeout-ms','30000','--run-id',run,
            '--result-file',root/'bulk/result.json','--samples-file',root/'bulk/samples.json'])
        echo=owner.launch('interactive',[sys.executable,'-B',bundle/'bpp2_echo.py','--target',listener,
            '--count',case['echo_count'],'--pps','20','--size','128','--deadline-ms','200',
            '--drain-ms','3000','--startup-timeout-ms','30000','--run-id',echo_run,
            '--result-file',root/'interactive/result.json','--samples-file',root/'interactive/samples.json'])
        until=time.monotonic()+45
        while any(p.poll() is None for p in [source,bulk,echo]):
            if time.monotonic()>=until:raise TimeoutError('host-source observation bound')
            time.sleep(.05)
        if any(p.returncode!=0 for p in [source,bulk,echo]):raise RuntimeError('native source or sink failed')
    except BaseException as exc:
        results_error=type(exc).__name__+': '+str(exc)
    finally:
        # A second interrupt must not skip cleanup of other owned process groups.
        previous={sig:signal.signal(sig,signal.SIG_IGN) for sig in (signal.SIGINT,signal.SIGTERM)}
        try:
            owner.stop_all()
            save_new(root/'lifecycle.json',dict(error=results_error,complete=results_error is None,
                elapsed_seconds=time.monotonic()-started,no_production_actions=True))
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
    if results_error: raise RuntimeError(results_error)
    usage1=resource.getrusage(resource.RUSAGE_CHILDREN)
    reports={role:read(root/role/'result.json') for role in ['source','bulk','interactive']}
    samples={role:read(root/role/'samples.json')['samples'] for role in reports}
    for role in reports:
        assert reports[role]['pid']==read(root/role/'launch.json')['pid']
    phase=analyze(samples['source'],samples['bulk'],samples['interactive'],reports['source'],
        reports['bulk'],reports['interactive'],case,source_spec)
    endpoints={}
    if mode!='udp':
        for role in ['server','client']:
            value=read(root/role/'stats.json')
            if mode.startswith('native_'):
                assert value['final'] and value['outcome']=='ok' and value['source_stage_accounting_closed']
                assert value['pid']==read(root/role/'launch.json')['pid'] and stage_fields(value)
            else:
                assert value['final'] and value.get('error') is None
                assert value['stats']['shutdown_complete'] and not value['stats']['drain_incomplete']
            endpoints[role]=value
    hashes={str(p.relative_to(root)):digest(p) for p in root.glob('*/*') if p.is_file()}
    adapter_result=read(root/'adapter/result.json')
    counters=adapter_result['counters']
    pipeline=dict(source_sent=reports['source']['sent'],adapter_bulk_received=counters['backend_data_received'],
        adapter_bulk_forwarded=counters['bulk_data_forwarded'],application_unique_delivered=reports['bulk']['received'],
        source_to_adapter_missing=reports['source']['sent']-counters['backend_data_received'],
        all_counts_whole_run_including_warmup=True,
        source_to_adapter_gap_is_not_public_network_loss=True)
    assert 0<=pipeline['adapter_bulk_received']<=pipeline['source_sent']
    assert pipeline['adapter_bulk_forwarded']<=pipeline['adapter_bulk_received']
    value=dict(mode=mode,phase=phase,endpoint_stats=endpoints,pipeline_ledger=pipeline,
        child_cpu_seconds=(usage1.ru_utime+usage1.ru_stime)-(usage0.ru_utime+usage0.ru_stime),
        cpu_scope='all child processes in window including source/sink/adapter; not endpoint-only CPU',
        raw_hashes=hashes,no_wire_capacity_claim=True)
    save_new(root/'result.json',value)
    print(json.dumps(dict(window=root.name,mode=mode,business_Mbps=phase['business']['goodput_mbps'],
        business_on_time=phase['business']['echo']['on_time'],business_requests=200,
        child_cpu_seconds=value['child_cpu_seconds'])),flush=True)
    return value


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--native',type=Path,required=True)
    p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--modes',nargs='+',choices=MODES,default=list(MODES))
    p.add_argument('--smoke',action='store_true')
    args=p.parse_args(argv)
    if len(set(args.modes))!=len(args.modes):raise ValueError('duplicate modes')
    for path in [args.binary,args.native]:
        if not path.is_file():raise FileNotFoundError(path)
    args.output.mkdir(parents=True,exist_ok=False)
    root=args.output.resolve();binary=args.binary.resolve();native=args.native.resolve();bundle=args.bundle.resolve()
    order=args.modes if args.smoke else args.modes+args.modes[::-1]
    registration=dict(source=SOURCE,case=CASE,modes=args.modes,order=order,smoke=args.smoke,
        binary_sha256=digest(binary),native_sha256=digest(native),helpers={p.name:digest(p) for p in bundle.glob('*.py')},
        system=platform.platform(),cpu_count=os.cpu_count(),runtime_threads='Tokio default per process, not manually raised',
        python=platform.python_version(),loopback_only=True,network_impairment=False,
        interpretation='host-local cost reference; not WAN capacity, exact H3 equivalence, default candidate or release',
        no_retries=True,maximum_windows=len(order),created_unix_ns=time.time_ns())
    save_new(root/'registration.json',registration)
    subprocess.run([str(binary),'init','--dir',str(root/'identity'),'--name','localhost'],check=True,timeout=10,capture_output=True)
    def stop(signum,frame):raise KeyboardInterrupt('host owner interrupted')
    signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
    rows=[];error=None
    try:
        for i,mode in enumerate(order):
            rows.append(run_window(root/('window_'+chr(97+i)),mode,binary,native,bundle,root/'identity'))
            if i<len(order)-1:time.sleep(1)
    except BaseException as exc:
        error=type(exc).__name__+': '+str(exc)
    by_mode=defaultdict(list)
    for row in rows:by_mode[row['mode']].append(row['phase']['business'])
    summaries={mode:pool(phases) for mode,phases in by_mode.items()}
    # P95 is a quantile of all raw request slots, never an average of window P95s.
    for mode, summary in summaries.items():
        slots=[]
        for i, current in enumerate(order[:len(rows)]):
            if current==mode:
                samples=read(root/('window_'+chr(97+i))/'interactive/samples.json')['samples'][60:]
                slots.extend(math.inf if r['rtt_ms'] is None else r['rtt_ms'] for r in samples)
        slots.sort();p95=slots[math.ceil(len(slots)*.95)-1]
        summary['p95_ms']=None if math.isinf(p95) else p95
        summary['p95_requires_raw_rtt_pool']=False
        summary['p95_status']='unresolved_missing_population' if math.isinf(p95) else 'finite'
    value=dict(complete=error is None and len(rows)==len(order),error=error,completed_windows=len(rows),
               summaries=summaries,registration_sha256=digest(root/'registration.json'),loopback_only=True)
    save_new(root/'completion.json',value);print(json.dumps(value,indent=2),flush=True)
    return 0 if value['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
