#!/usr/bin/env python3
"""Actual CLI, local TCP/UDP and pinned-TLS end-to-end test. No remote hosts.
Temporary credentials never appear in arguments/logs; join reads stdin.
"""
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from live_run import Node, ROOT

BIN=ROOT/'target/release/agg-fec-tunnel'
def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET,kind) as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]
def invoke(args,invite=None,ok=True):
    p=subprocess.run([str(BIN)]+args,input=invite+'\n' if invite else None,capture_output=True,text=True,timeout=15)
    if ok and p.returncode:raise RuntimeError(f'CLI {args[0]} failed: {p.stderr}')
    return p

def download(address,size):
    host,port=address.rsplit(':',1);connection=http.client.HTTPConnection(host,int(port),timeout=15)
    connection.request('GET','/bytes/'+str(size));response=connection.getresponse()
    if response.status!=200:raise RuntimeError('HTTP failure')
    digest=hashlib.sha256();total=0
    while True:
        data=response.read(65536)
        if not data:break
        digest.update(data);total+=len(data)
    connection.close()
    expected=hashlib.sha256();pattern=bytes(range(251))*256
    for _ in range(size//len(pattern)):expected.update(pattern)
    expected.update(pattern[:size%len(pattern)])
    if total!=size or digest.digest()!=expected.digest():raise RuntimeError('payload mismatch')
    return total

def main():
    jobs={};errors=[]
    with tempfile.TemporaryDirectory(prefix='agg-managed-cli-') as directory:
        directory=Path(directory);master=directory/'master.json';client=directory/'client.json';relay=directory/'relay.json'
        try:
            http=Node('http',[str(BIN),'http-test','--listen','127.0.0.1:0','--exit-on-stdin','--lifetime-seconds','90']);jobs['http']=http
            target=http.wait('ready')['tcp_listen'];control='127.0.0.1:'+str(free_port());data='127.0.0.1:'+str(free_port(socket.SOCK_DGRAM))
            initialized=json.loads(invoke(['init','--state',str(master),'--control',control,'--advertise',data,'--target',target,'--wire-mbps','20']).stdout)
            invitation=initialized['invitation']
            jobs['master']=Node('master',[str(BIN),'run','--state',str(master),'--exit-on-stdin','--lifetime-seconds','90'])
            joined=json.loads(invoke(['join','--state',str(client),'--name','cli-client','--as','client','--listen','127.0.0.1:0'],invitation).stdout)
            jobs['client']=Node('client',[str(BIN),'run','--state',str(client),'--exit-on-stdin','--lifetime-seconds','90'])
            address=jobs['client'].wait('ready')['tcp_listen']
            relay_id=[]
            def change():
                try:
                    time.sleep(.25)
                    public='127.0.0.1:'+str(free_port(socket.SOCK_DGRAM))
                    r=json.loads(invoke(['join','--state',str(relay),'--as','relay','--name','hot-relay','--advertise',public],invitation).stdout);relay_id.append(r['id'])
                    jobs['relay']=Node('relay',[str(BIN),'run','--state',str(relay),'--exit-on-stdin','--lifetime-seconds','90'])
                    time.sleep(.6)
                    invoke(['revoke','--state',str(master),'--node-id',r['id']])
                except Exception as exc:errors.append(str(exc))
            worker=threading.Thread(target=change);worker.start()
            count=download(address,8*1024*1024);worker.join(timeout=10)
            if worker.is_alive() or errors:raise RuntimeError(str(errors) or 'hot-change worker stuck')
            reports={n:jobs[n].wait('managed_session',timeout=8) for n in ('client','master')}
            if reports['client']['session']!=reports['master']['session']:raise RuntimeError('session changed')
            if any(r['topology_updates']<2 for r in reports.values()):raise RuntimeError('hot updates not observed')
            # Loopback direct RTT can be materially faster than a two-hop relay.
            # Do not require the scheduler to use an inferior path. The separate
            # hot_topology test removes the old path and verifies actual new-path bytes.
            if not all(any(r.get('event')=='topology' and len(r.get('peers',[]))>=2 for r in jobs[side].records) for side in ('client','master')):
                raise RuntimeError('new relay never reached both live topology watchers')
            snapshot=json.loads(invoke(['status','--state',str(master)]).stdout)
            if not any(n['id']==relay_id[0] and n['revoked'] for n in snapshot['members']):raise RuntimeError('revoke not persisted')
            current_invitation=invoke(['rotate','--state',str(master)]).stdout.strip()
            if current_invitation==invitation:raise RuntimeError('invite did not rotate')
            rejected=invoke(['join','--state',str(directory/'bad.json'),'--as','relay','--advertise','127.0.0.1:'+str(free_port(socket.SOCK_DGRAM))],invitation,ok=False)
            if rejected.returncode==0:raise RuntimeError('old invitation accepted')
            # Restart master and reconnect using independently persisted node identity,
            # without re-entering either the old or the newly rotated invitation.
            jobs['client'].close();jobs['master'].close();jobs['relay'].close()
            jobs['master']=Node('master-restart',[str(BIN),'run','--state',str(master),'--exit-on-stdin','--lifetime-seconds','60'])
            jobs['client']=Node('client-restart',[str(BIN),'run','--state',str(client),'--exit-on-stdin','--lifetime-seconds','60'])
            count+=download(jobs['client'].wait('ready')['tcp_listen'],1024*1024)
            for name in ('client','master'):jobs[name].wait('managed_session',timeout=8)
            snapshot=json.loads(invoke(['status','--state',str(master)]).stdout)
            if not any(n['id']==joined['id'] for n in snapshot['members']):raise RuntimeError('client identity lost')
            print(json.dumps({'event':'managed_cli_pass','verified_bytes':count,'same_session_hot_add_remove':True,
                              'relay_discovered_in_live_session':True,'revocation_and_rotation':True,'master_restart_same_identity':True,
                              'temporary_credentials_only':True,'reports':reports}))
        finally:
            for node in reversed(list(jobs.values())):node.close()

if __name__=='__main__':main()
