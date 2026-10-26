"""Finite read-only capture of owned BraidPath services and local proxy counters.

No website access, test requests, configuration changes or remote files. Private
host configuration, identities, run records and captured data stay in local/.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shlex
import signal
import subprocess
import time
import urllib.request

from bench.run import Remote, ROOT, private_path, save

# The program runs on each selected Linux host and only reads the owned service.
SAMPLER = r'''
import hashlib,json,pathlib,subprocess,sys,time
p=json.loads(sys.argv[1])
pid=int(subprocess.check_output(['systemctl','show',p['unit'],'--property=MainPID','--value'],text=True))
proc=pathlib.Path('/proc')/str(pid)
assert hashlib.sha256((proc/'exe').read_bytes()).hexdigest()==p['sha256'], 'unexpected executable'
start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
def own(text):
 rows=[];keep=False
 for line in text.splitlines():
  if not line.startswith((' ','\t')): keep='pid='+str(pid)+',' in line
  if keep: rows.append(line)
 return '\n'.join(rows)
print(json.dumps({'kind':'ready','unix':time.time(),'pid':pid,'sha256':p['sha256']}),flush=True)
until=time.monotonic()+p['seconds']
while time.monotonic()<until and proc.exists():
 stat=(proc/'stat').read_text()
 if stat.rsplit(')',1)[1].split()[19]!=start: break
 tcp=subprocess.run(['ss','-Htinepm'],capture_output=True,text=True,timeout=4)
 udp=subprocess.run(['ss','-Huanmp'],capture_output=True,text=True,timeout=4)
 print(json.dumps({'kind':'sample','unix':time.time(),'pid':pid,
  'tcp':own(tcp.stdout),'udp':own(udp.stdout),'ss_returncodes':[tcp.returncode,udp.returncode],
  'netstat':pathlib.Path('/proc/net/netstat').read_text(),
  'snmp':pathlib.Path('/proc/net/snmp').read_text(),
  'host_cpu':pathlib.Path('/proc/stat').read_text().splitlines()[0],'process_stat':stat}),flush=True)
 time.sleep(1)
'''


def utc():
    return datetime.now(timezone.utc).isoformat()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['topology', 'build', 'mac-record', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--host', action='append', required=True)
    parser.add_argument('--unit', default='braidpath-mesh.service')
    parser.add_argument('--seconds', type=int, default=1200)
    parser.add_argument('--planned-target', required=True)
    parser.add_argument('--connection-mode', choices=['single', 'multi'], required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.seconds <= 1800:
        parser.error('capture is bounded to 1..1800 seconds')
    if len(set(args.host)) != len(args.host) or len(args.host) > 8:
        parser.error('select up to eight distinct owned hosts')
    for name in ['topology', 'build', 'mac_record', 'output']:
        setattr(args, name, private_path(getattr(args, name)))
    return args


def run(args):
    args.output.mkdir(mode=0o700, exist_ok=False)
    topology = json.loads(args.topology.read_text())
    build = json.loads(args.build.read_text())
    mac = json.loads(args.mac_record.read_text())
    assert all(h in topology['hosts'] for h in args.host), 'unknown host'
    assert mac['binary_sha256'] == build['targets']['mac']['sha256']
    assert 'n' + mac['argv'][0] in subprocess.check_output(
        ['lsof','-a','-p',str(mac['pid']),'-d','txt','-Fn'],text=True).splitlines()
    runtime = ROOT / 'local/runtime/proxy-client'
    # Retain preceding idle baselines as well as the new activity; timestamps
    # distinguish the pre-roll from the requested capture window.
    initial_logs = {n: (runtime/n).stat() for n in ['stdout.log','stderr.log']}
    offsets = {n: max(0, info.st_size - 256*1024) for n,info in initial_logs.items()}
    remote = Remote(topology)
    children, files, clocks, errors = {}, [], {}, []
    started = time.time()
    save(args.output/'registration.json', {
        'utc':utc(), 'version':build['version'], 'commit':build['commit'],
        'duration_seconds':args.seconds, 'hosts':args.host,
        'planned_target':args.planned_target, 'connection_mode':args.connection_mode,
        'metadata_verification':'requested; record actual target/mode with manual results',
        'tcp_extensions_scope':'host cumulative counters; correlate with owned socket samples',
        'no_test_traffic':True,'no_remote_files':True,
        'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    import yaml
    configuration = yaml.safe_load(Path(mac['clash']['credential_source']).read_text())
    headers = {'Authorization':'Bearer '+configuration['secret']} if configuration.get('secret') else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def api(part):
        with opener.open(urllib.request.Request('http://127.0.0.1:9090'+part,headers=headers),timeout=3) as reply:
            return json.load(reply)
    def selectors():
        return {k:v['now'] for k,v in api('/proxies')['proxies'].items()
                if v.get('type')=='Selector' and 'now' in v}
    def stop_handler(_sig, _frame):
        raise KeyboardInterrupt()
    old_handlers = {sig:signal.signal(sig,stop_handler) for sig in [signal.SIGINT,signal.SIGTERM]}
    try:
        save(args.output/'clash-start.private.json', {'utc':utc(),'selectors':selectors()})
        for host in args.host:
            samples=[]
            for _ in range(3):
                before=time.time()
                reply=remote.command(host,['python3','-c',
                    "import time,os,json;print(json.dumps({'unix':time.time(),'clock_ticks':os.sysconf('SC_CLK_TCK')}))"],timeout=10)
                after=time.time();assert reply.returncode==0, 'clock read failed'
                value=json.loads(reply.stdout)
                samples.append({'remote_minus_mac_seconds':value['unix']-(before+after)/2,
                                'uncertainty_seconds':(after-before)/2,'clock_ticks':value['clock_ticks']})
            clocks[host]=min(samples,key=lambda x:x['uncertainty_seconds'])
        save(args.output/'clock-alignment.json',clocks)
        for host in args.host:
            h=topology['hosts'][host]
            out=(args.output/(host+'-sockets.private.jsonl')).open('x')
            err=(args.output/(host+'-sampling.stderr')).open('x');files.extend([out,err])
            payload={'unit':args.unit,'seconds':args.seconds+15,'sha256':build['targets']['linux']['sha256']}
            children[host]=subprocess.Popen(['ssh','-C','-o','BatchMode=yes',*h.get('ssh_options',[]),
                h['ssh'],shlex.join(['python3','-u','-c',SAMPLER,json.dumps(payload)])],stdout=out,stderr=err)
        deadline=time.monotonic()+15
        while True:
            assert all(child.poll() is None for child in children.values()), 'sampler failed'
            if all((args.output/(h+'-sockets.private.jsonl')).stat().st_size for h in children):
                break
            assert time.monotonic()<deadline, 'sampler readiness deadline'
            time.sleep(.1)
        ready={'utc':utc(),'expires_utc':datetime.fromtimestamp(time.time()+args.seconds,timezone.utc).isoformat(),
               'version':build['version'],'mac_pid':mac['pid'],'hosts':args.host,
               'planned_target':args.planned_target,'connection_mode':args.connection_mode,
               'no_test_traffic':True,'no_remote_files':True,'mac_log_offsets':offsets}
        save(args.output/'ready.json',ready);print(json.dumps({'phase':'READY',**ready}),flush=True)
        until=time.monotonic()+args.seconds
        with (args.output/'mac-resources.private.jsonl').open('x') as output, \
             (args.output/'clash-counters.private.jsonl').open('x') as counters:
            while time.monotonic()<until and not (args.output/'stop').exists():
                assert all(child.poll() is None for child in children.values()), 'sampler stopped'
                try:
                    c=api('/connections')
                    counters.write(json.dumps({'utc':utc(),'upload_total':c.get('uploadTotal'),
                        'download_total':c.get('downloadTotal'),'selectors':selectors(),
                        'connections':[{'id':hashlib.sha256(x['id'].encode()).hexdigest()[:16],
                                        'chains':x.get('chains',[]),'upload':x.get('upload',0),
                                        'download':x.get('download',0)} for x in c.get('connections',[])]})+'\n')
                except Exception as error:
                    counters.write(json.dumps({'utc':utc(),'error':type(error).__name__})+'\n')
                counters.flush()
                ps=subprocess.run(['ps','-p',str(mac['pid']),'-o','pid=,time=,rss=,%cpu='],capture_output=True,text=True,timeout=4)
                udp=subprocess.run(['netstat','-s','-p','udp'],capture_output=True,text=True,timeout=4)
                output.write(json.dumps({'utc':utc(),'process':ps.stdout,'global_udp':udp.stdout})+'\n');output.flush()
                time.sleep(1)
    except KeyboardInterrupt:
        errors.append('capture_interrupted')
    except Exception as error:
        errors.append(type(error).__name__+': '+str(error))
        raise
    finally:
        for child in children.values():
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
        for file in files:file.close()
        for name,offset in offsets.items():
            path = runtime/name
            current = path.stat()
            if current.st_ino != initial_logs[name].st_ino or current.st_size < offset:
                errors.append('log_rotated:'+name); offset = 0
            with path.open('rb') as log:
                log.seek(offset)
                data = log.read()
            (args.output/('mac-'+name+'.gz')).write_bytes(gzip.compress(data))
        readbacks={}
        for host in children:
            since=int(started+clocks[host]['remote_minus_mac_seconds'])-35
            q=remote.command(host,['journalctl','-u',args.unit,'--since','@'+str(since),'-o','cat','--no-pager'],timeout=35)
            (args.output/(host+'-journal.private.log.gz')).write_bytes(gzip.compress(q.stdout.encode()))
            readbacks[host]=q.returncode
        save(args.output/'completion.json',{'utc':utc(),'errors':errors,'journal_returncodes':readbacks,
                                          'read_only':True,'no_test_traffic':True,'no_remote_files':True})
        for sig,handler in old_handlers.items():signal.signal(sig,handler)
        print(json.dumps({'phase':'COLLECTED','errors':errors}),flush=True)


if __name__ == '__main__':
    run(parse_args())
