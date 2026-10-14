#!/usr/bin/env python3
"""Local end-to-end CLI test: multiple ports, concurrent flows, two access sockets.
No public servers, system routes, interface changes or persistent credentials.
"""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
from live_run import Node, ROOT
from managed_cli import invoke, free_port, download

BIN=ROOT/'target/release/agg-fec-tunnel'
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data=bytearray()
        while True:
            part=self.request.recv(32768)
            if not part:break
            data.extend(part)
            if len(data)>2*1024*1024:return
        self.request.sendall(self.server.prefix+data)
class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=False

def exchange(address,payload,prefix):
    host,port=address.rsplit(':',1)
    with socket.create_connection((host,int(port)),timeout=15) as s:
        s.sendall(payload);s.shutdown(socket.SHUT_WR);received=bytearray()
        while True:
            b=s.recv(65536)
            if not b:break
            received.extend(b)
    if bytes(received)!=prefix+payload:raise AssertionError('wrong service/data/half-close')
    return len(payload)

def main():
    jobs={};servers=[]
    with tempfile.TemporaryDirectory(prefix='agg-multi-cli-') as d:
        d=Path(d);master=d/'master.json';client=d/'client.json';relay=d/'relay.json'
        try:
            for label in (b'A:',b'B:'):
                server=Server(('127.0.0.1',0),Echo);server.prefix=label
                threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
            http=Node('http',[str(BIN),'http-test','--listen','127.0.0.1:0','--exit-on-stdin','--lifetime-seconds','90']);jobs['http']=http
            address=lambda s:f'127.0.0.1:{s.server_address[1]}'
            args=['init','--state',str(master),'--control',f'127.0.0.1:{free_port()}',
                  '--advertise',f'127.0.0.1:{free_port(socket.SOCK_DGRAM)}',
                  '--forward','alpha='+address(servers[0]),'--forward','beta='+address(servers[1]),
                  '--forward','bulk='+http.wait('ready')['tcp_listen'],
                  '--forward',f'unavailable=127.0.0.1:{free_port()}',
                  '--wire-mbps','50','--upload-wire-mbps','50']
            invitation=json.loads(invoke(args).stdout)['invitation']
            jobs['master']=Node('master',[str(BIN),'run','--state',str(master),'--exit-on-stdin','--lifetime-seconds','90'])
            invoke(['join','--state',str(relay),'--as','relay','--name','relay-test',
                    '--advertise',f'127.0.0.1:{free_port(socket.SOCK_DGRAM)}'],invitation)
            jobs['relay']=Node('relay',[str(BIN),'run','--state',str(relay),'--exit-on-stdin','--lifetime-seconds','90'])
            join=['join','--state',str(client),'--as','client','--name','two-wans',
                  '--uplink','wan_a@127.0.0.1=20/20','--uplink','wan_b@127.0.0.1=30/30']
            for service in ('alpha','beta','bulk','unavailable'):join+=['--forward',service+'=127.0.0.1:0']
            joined=json.loads(invoke(join,invitation).stdout)
            jobs['client']=Node('client',[str(BIN),'run','--state',str(client),'--exit-on-stdin','--lifetime-seconds','90'])
            ready=jobs['client'].wait('ready');forwards={f['service']:f['listen'] for f in ready['forwards']}
            # Both bound TLS connections must coexist instead of replacing each other.
            deadline=time.monotonic()+8
            while True:
                status=json.loads(invoke(['status','--state',str(master)]).stdout)
                member=next(m for m in status['members'] if m['id']==joined['id'])
                if len(member['accesses'])==2:break
                if time.monotonic()>deadline:raise AssertionError('WAN identity registrations did not coexist')
                time.sleep(.05)
            started=time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                futures=[]
                for i in range(8):
                    service='alpha' if i%2==0 else 'beta';prefix=b'A:' if i%2==0 else b'B:'
                    payload=bytes([i])*200_000
                    futures.append(pool.submit(exchange,forwards[service],payload,prefix))
                futures.append(pool.submit(download,forwards['bulk'],4*1024*1024))
                verified=sum(f.result(timeout=25) for f in futures)
            # One configured target being down must not kill other listeners/flows.
            try:
                exchange(forwards['unavailable'],b'x',b'')
                raise AssertionError('unavailable target reported success')
            except (OSError,AssertionError) as e:
                if str(e)=='unavailable target reported success':raise
            verified+=exchange(forwards['alpha'],b'after-target-failure',b'A:')
            # Let a large flow hit downstream backpressure while small requests continue.
            host,port=forwards['bulk'].rsplit(':',1)
            slow=socket.socket();slow.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096);slow.settimeout(5)
            slow.connect((host,int(port)));slow.sendall(b'GET /bytes/33554432 HTTP/1.1\r\nHost: test\r\n\r\n')
            slow.recv(512);time.sleep(.2)
            interactions=[]
            for i in range(12):
                at=time.monotonic();verified+=exchange(forwards['beta'],f'ping-{i}'.encode(),b'B:');interactions.append(time.monotonic()-at)
            slow.close()
            time.sleep(1)
            reports=[r for n in ('client','master') for r in jobs[n].records if r.get('event')=='managed_session']
            if not any(len(r['wan_source_packets'])>=2 and min(r['wan_source_packets'][:2])>0 for r in reports):
                raise AssertionError('no completed stream used both access links')
            if max(interactions)>2:raise AssertionError('slow bulk reader blocked interactive service')
            print(json.dumps({'event':'managed_multi_pass','verified_application_bytes':verified,'concurrent_flows':9,
                'local_ports':4,'independent_uplinks':2,'same_identity_two_tls_registrations':True,
                'both_wans_used_in_one_stream':True,'half_close_and_target_isolation':True,
                'interactive_max_ms_during_slow_reader':max(interactions)*1000,
                'elapsed_s':time.monotonic()-started,'completed_session_reports':len(reports)}))
        except Exception:
            print(json.dumps({'event':'managed_multi_failure','records':{n:node.records[-5:] for n,node in jobs.items()},
                              'errors':{n:node.errors[-5:] for n,node in jobs.items()}}))
            raise
        finally:
            for node in reversed(list(jobs.values())):node.close()
            for server in servers:server.shutdown();server.server_close()

if __name__=='__main__':main()
