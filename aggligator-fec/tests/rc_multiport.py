#!/usr/bin/env python3
"""RC acceptance: ONE uplink, six TCP ports, concurrent full-process data transfer.
Only loopback sockets and temporary credentials. No remote access or OS changes.
Use --rounds 3 (default); traffic/file sizes are bounded. Every payload is checked.
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import socket
import socketserver
import struct
import tempfile
import threading
import time
from live_run import Node, ROOT
from managed_cli import invoke, free_port

BIN=ROOT/'target/release/agg-fec-tunnel'
PATTERN=bytes(range(251))*256


def exact(sock,n):
    out=bytearray()
    while len(out)<n:
        b=sock.recv(min(65536,n-len(out)))
        if not b:
            raise AssertionError(f'truncated TCP data: {len(out)}/{n}')
        out.extend(b)
    return bytes(out)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=True
    def handle_error(self,request,address):
        # Some clients deliberately send RST. Normal exchanges are checked outside.
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(75)
        role=self.server.role
        if role=='half':
            digest=hashlib.sha256();size=0
            while True:
                b=self.request.recv(65536)
                if not b:break
                digest.update(b);size+=len(b)
                if size>4*1024*1024:return
            self.request.sendall(struct.pack('!Q',size)+digest.digest())
        elif role=='bulk':
            size=struct.unpack('!Q',exact(self.request,8))[0]
            if size>64*1024*1024:return
            self.request.sendall(self.server.prefix)
            left=size
            while left:
                n=min(left,len(PATTERN));self.request.sendall(PATTERN[:n]);left-=n
        else:
            self.request.sendall(self.server.prefix)
            while True:
                b=self.request.recv(65536)
                if not b:break
                self.request.sendall(b)


def connect(address):
    host,port=address.rsplit(':',1)
    return socket.create_connection((host,int(port)),timeout=45)


def echo(address,prefix,payload):
    with connect(address) as s:
        if exact(s,len(prefix))!=prefix:raise AssertionError('wrong TCP target greeting')
        for offset in range(0,len(payload),32768):
            b=payload[offset:offset+32768];s.sendall(b)
            if exact(s,len(b))!=b:raise AssertionError('echo corruption/cross-connection')
        s.shutdown(socket.SHUT_WR)
        if s.recv(1):raise AssertionError('unexpected bytes after EOF')
    return len(payload)*2+len(prefix)


def half(address,payload):
    with connect(address) as s:
        s.sendall(payload);s.shutdown(socket.SHUT_WR)
        expected=struct.pack('!Q',len(payload))+hashlib.sha256(payload).digest()
        if exact(s,len(expected))!=expected:raise AssertionError('half-close response incorrect')
        if s.recv(1):raise AssertionError('half-close trailing data')
    return len(payload)+len(expected)


def bulk(address,prefix,mib):
    size=mib*1024*1024;expected=hashlib.sha256()
    for _ in range(size//len(PATTERN)):expected.update(PATTERN)
    expected.update(PATTERN[:size%len(PATTERN)])
    with connect(address) as s:
        s.sendall(struct.pack('!Q',size));s.shutdown(socket.SHUT_WR)
        if exact(s,len(prefix))!=prefix:raise AssertionError('crossed bulk target')
        digest=hashlib.sha256();left=size
        while left:
            b=s.recv(min(left,65536))
            if not b:raise AssertionError('bulk truncated')
            digest.update(b);left-=len(b)
        if digest.digest()!=expected.digest():raise AssertionError('bulk SHA-256 mismatch')
        if s.recv(1):raise AssertionError('bulk trailing bytes')
    return size+len(prefix)+8


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--rounds',type=int,default=3)
    args=parser.parse_args()
    if not 1<=args.rounds<=5:raise ValueError('rounds must be 1..5')
    jobs={};servers=[];verified=0;interactions=[];started=time.monotonic()
    def service(role,prefix,port=0):
        server=Server(('127.0.0.1',port),Handler);server.role=role;server.prefix=prefix
        threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
        return f'127.0.0.1:{server.server_address[1]}'
    with tempfile.TemporaryDirectory(prefix='agg-rc-acceptance-') as directory:
        d=Path(directory);master=d/'master.json';client=d/'client.json';relay=d/'relay.json'
        try:
            targets={
                'echo-a':service('echo',b'A:'),'echo-b':service('echo',b'B:'),
                'bulk-a':service('bulk',b'DOWN-A:'),'bulk-b':service('bulk',b'DOWN-B:'),
                'half':service('half',b''),'flaky':f'127.0.0.1:{free_port()}',
            }
            command=['init','--state',str(master),'--control',f'127.0.0.1:{free_port()}',
                     '--advertise',f'127.0.0.1:{free_port(socket.SOCK_DGRAM)}',
                     '--wire-mbps','260','--upload-wire-mbps','80']
            for name,address in targets.items():command+=['--forward',name+'='+address]
            invite=json.loads(invoke(command).stdout)['invitation']
            jobs['master']=Node('master',[str(BIN),'run','--state',str(master),'--exit-on-stdin','--lifetime-seconds','160'])
            invoke(['join','--state',str(relay),'--as','relay','--name','rc-relay',
                    '--advertise',f'127.0.0.1:{free_port(socket.SOCK_DGRAM)}'],invite)
            jobs['relay']=Node('relay',[str(BIN),'run','--state',str(relay),'--exit-on-stdin','--lifetime-seconds','160'])
            command=['join','--state',str(client),'--name','rc-single-wan']
            for name in targets:command+=['--forward',name+'=127.0.0.1:0']
            invoke(command,invite)
            for file in (master,relay,client):
                checked=json.loads(invoke(['check','--state',str(file)]).stdout)
                assert checked['event']=='config_valid' and checked['offline_check_only']
                assert not any(key in checked for key in ('private_key','admin','credential','invitation','ticket'))
            jobs['client']=Node('client',[str(BIN),'run','--state',str(client),'--exit-on-stdin','--lifetime-seconds','160'])
            ready=jobs['client'].wait('ready')
            assert ready['uplinks']==1
            addresses={row['service']:row['listen'] for row in ready['forwards']}
            assert len(addresses)==6
            for round_number in range(args.rounds):
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    futures=[]
                    for i in range(6):
                        label='echo-a' if i%2==0 else 'echo-b';prefix=b'A:' if i%2==0 else b'B:'
                        data=bytes([17*round_number+i])*192*1024
                        futures.append(pool.submit(echo,addresses[label],prefix,data))
                    futures+=[pool.submit(half,addresses['half'],bytes([i])*256*1024) for i in (17,35)]
                    futures+=[pool.submit(bulk,addresses['bulk-a'],b'DOWN-A:',32),
                              pool.submit(bulk,addresses['bulk-b'],b'DOWN-B:',32)]
                    verified+=sum(f.result(timeout=40) for f in futures)
                print(json.dumps({'event':'rc_concurrent_round','round':round_number+1,'connections':10,'all_exact':True}),flush=True)
            # A living but quiet interactive TCP socket must survive >20s idle.
            with connect(addresses['echo-a']) as idle:
                assert exact(idle,2)==b'A:'
                idle.sendall(b'before-idle');assert exact(idle,11)==b'before-idle'
                time.sleep(22)
                idle.sendall(b'after-idle');assert exact(idle,10)==b'after-idle'
                verified+=44
            # Deliberately stop reading a large download. Other services must work.
            with connect(addresses['bulk-a']) as slow:
                slow.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
                slow.sendall(struct.pack('!Q',32*1024*1024));assert exact(slow,7)==b'DOWN-A:'
                time.sleep(1)
                for i in range(12):
                    at=time.monotonic();verified+=echo(addresses['echo-b'],b'B:',f'interactive-{i}'.encode());interactions.append(time.monotonic()-at)
            assert max(interactions)<2,'slow reader blocked independent port'
            # Failed targets are isolated; start the SAME target later without restarting tunnel.
            for _ in range(3):
                try:
                    with connect(addresses['flaky']) as broken:
                        broken.sendall(b'x');got=broken.recv(1)
                    assert not got,'unavailable target unexpectedly replied'
                except (ConnectionResetError,BrokenPipeError):pass
            service('echo',b'UP:',int(targets['flaky'].rsplit(':',1)[1]))
            verified+=echo(addresses['flaky'],b'UP:',b'target-recovered')
            # Abrupt resets must release flow IDs/permits instead of filling the 32-flow pool.
            for wave in range(5):
                for _ in range(8):
                    s=connect(addresses['echo-b']);assert exact(s,2)==b'B:'
                    s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));s.close()
                time.sleep(.8)
            time.sleep(1)
            verified+=echo(addresses['echo-a'],b'A:',b'after-40-resets')
            verified+=bulk(addresses['bulk-b'],b'DOWN-B:',1)
            # The successful exchanges have matched completion reports on both peers.
            expected_success=args.rounds*10+12+1+2  # idle and deliberate RST aren't counted as clean FIN.
            deadline=time.monotonic()+8
            while True:
                reports={name:[r for r in jobs[name].records if r.get('event')=='managed_session'] for name in ('master','client')}
                common=set(r['session'] for r in reports['master'])&set(r['session'] for r in reports['client'])
                if len(common)>=expected_success:break
                if time.monotonic()>deadline:raise AssertionError(f'missing end-to-end close reports: {len(common)}/{expected_success}')
                time.sleep(.05)
            assert all(row.process.poll() is None for row in jobs.values())
            result={'event':'rc_multiport_pass','version':invoke(['--version']).stdout.strip(),
                    'ports':6,'independent_uplinks':1,'rounds':args.rounds,'peak_test_concurrency':10,
                    'verified_application_bytes':verified,'matched_clean_session_ids':len(common),
                    'idle_survived_seconds':22,'forced_resets':40,'target_recovered_without_restart':True,
                    'interactive_max_ms_during_slow_reader':max(interactions)*1000,
                    'elapsed_s':time.monotonic()-started}
            print(json.dumps(result),flush=True)
        except Exception:
            print(json.dumps({'event':'rc_multiport_failure','records':{n:node.records[-8:] for n,node in jobs.items()},
                              'stderr':{n:node.errors[-5:] for n,node in jobs.items()}}),flush=True)
            raise
        finally:
            for node in reversed(list(jobs.values())):node.close()
            for server in servers:server.shutdown();server.server_close()
    print(json.dumps({'event':'rc_local_cleanup','processes_closed':True,'temporary_credentials_removed':True}),flush=True)


if __name__=='__main__':main()
