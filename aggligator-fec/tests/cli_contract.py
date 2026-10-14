#!/usr/bin/env python3
"""RC CLI contract: help, defaults, safe config inspection, invitation files, signals.
Only temporary local state; no public server or credential is used.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from live_run import ROOT,Node
from managed_cli import free_port

BIN=ROOT/'target/release/agg-fec-tunnel'

def call(args,cwd,ok=True):
    p=subprocess.run([str(BIN)]+args,cwd=cwd,input='',capture_output=True,text=True,timeout=12)
    if ok and p.returncode:raise AssertionError(f'{args[0]}: {p.stderr}')
    if not ok and p.returncode==0:raise AssertionError('invalid CLI unexpectedly succeeded')
    return p


def main():
    with tempfile.TemporaryDirectory(prefix='agg-cli-contract-') as directory:
        d=Path(directory)
        help_root=call(['--help'],d).stdout
        assert '--repair-shards' not in help_root and '多端口' in help_root
        for command in ('init','join','run','check','status','invite','rotate','revoke'):
            assert 'Usage:' in call([command,'--help'],d).stdout
        assert '0.2.0-latency.1' in call(['--version'],d).stdout
        for args in (['run','--forward','a=127.0.0.1:1234'],['init'],['join','--as','relay'],['revoke']):
            call(args,d,ok=False)
        assert not list(d.iterdir()),'invalid command or help wrote files'
        initialized=call(['--json','init','--control',f'127.0.0.1:{free_port()}',
                          '--advertise','127.0.0.1:55529','--forward','web=127.0.0.1:8080'],d)
        data=json.loads(initialized.stdout);state=d/'agg-fec.json';assert state.is_file()
        secret=json.loads(state.read_text())['settings']
        checked=call(['--json','check'],d)
        decoded=json.loads(checked.stdout);assert decoded['event']=='config_valid' and decoded['offline_check_only']
        assert decoded['profile']=='latency' and decoded['warm_sessions']==8
        assert decoded['download_wire_mbps']==80 and decoded['upload_wire_mbps']==80
        for key in ('private_key','invitation','admin'):
            assert secret[key] not in checked.stdout
        before=state.read_bytes()
        call(['init','--control','127.0.0.1:55528','--advertise','127.0.0.1:55529','--target','127.0.0.1:80'],d,ok=False)
        assert state.read_bytes()==before
        os.chmod(state,0o644);call(['check'],d,ok=False);os.chmod(state,0o600)
        invite_file=d/'invite.txt';invite_file.write_text(data['invitation']+'\n');os.chmod(invite_file,0o644)
        bad=call(['join','--state',str(d/'node.json'),'--invite-file',str(invite_file)],d,ok=False)
        assert '600' in bad.stderr
        # SIGTERM is handled by the process and exits cleanly, rather than leaving a listener.
        port=free_port()
        job=Node('signal-test',[str(BIN),'http-test','--listen',f'127.0.0.1:{port}','--lifetime-seconds','15'])
        try:
            job.process.send_signal(signal.SIGTERM)
            assert job.process.wait(timeout=5)==0
        finally:job.close()
    print(json.dumps({'event':'cli_contract_pass','help_commands':8,'default_state':True,
                      'offline_check_redacts_secrets':True,'invalid_options_have_no_side_effects':True,
                      'state_not_overwritten':True,'invite_file_permissions':True,'sigterm_clean_exit':True}))


if __name__=='__main__':main()
