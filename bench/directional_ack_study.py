"""Finite real-QUIC loopback ACK-frequency ablation with synthetic link limits.

No SSH, host sysctls, qdisc, firewall or production service actions. Eight new
fixed windows; no completed-window retries. Not a WAN or multipath benchmark.
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
import subprocess
import time
from bench.lab_health import classify


def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):value.update(block)
    return value.hexdigest()


def save_new(path,value):
    with Path(path).open('x') as stream:
        json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')


def read(path):return json.loads(Path(path).read_text())


def plan():
    order=[]
    for reverse_pps in [0,2000]:
        for profile in ['every-two','every-eight','every-eight','every-two']:
            order.append({'window':'window_'+chr(97+len(order)), 'ack_profile':profile,
                          'reverse_pps':reverse_pps})
    return {'order':order,'bulk_pps':10000,'echo_pps':50,'bulk_payload_bytes':1000,
        'record_overhead_bytes':55,'echo_payload_bytes':128,'warmup_ms':2000,
        'business_ms':8000,'drain_ms':2000,'one_way_delay_ms':20,'link_queue_ms':20,
        'ack_max_delay_ms':10,'ack_reorder_threshold':2,'client_ack_profile':'unchanged',
        'native_transport':'pinned QUIC BBR + TLS; no production policy changes',
        'runtime_threads':4,'maximum_windows':8,'no_retries':True,
        'relay_runtime_threads':2,'relay_executor_isolation':True,
        'socket_receive_bytes':0,'socket_send_bytes':0,
        'nominal_source_seconds':80,'synthetic_link_not_public_network':True,
        'capacity_or_multilink_acceptance':False,
        'hypothesis':'Does a one-direction matched ACK-frequency request reduce reverse packet resource pressure without losing useful service?',
        'screen':{'goodput_min_ratio':.95,'on_time_fraction_no_regression':True,
                  'on_time_fraction_target':.95,'finite_p95_max_ratio':1.05,
                  'reverse_native_packet_max_ratio':.85,'source_pacing_floor':.95},
        'phase_scope':'native counter snapshots are interval evidence, not exact source-cohort wire attribution'}


def latency(samples):
    values=[]
    for s in samples:
        start,end=s['issued_us'],s['received_us']
        if end is not None:
            if start is None or s['admitted_us'] is None or end<start:raise ValueError('response without valid request')
            values.append((end-start)/1000)
        else:values.append(math.inf)
    values.sort()
    p95=values[math.ceil(len(values)*.95)-1]
    return {'population':len(values),'received':sum(math.isfinite(x) for x in values),
            'on_time':sum(x<=200 for x in values),'on_time_fraction':sum(x<=200 for x in values)/len(values),
            'p95_ms':None if math.isinf(p95) else p95}


def native_interval(timeline, warmup_ms, business_ms):
    first=next((s for s in timeline if s['elapsed_us']>=warmup_ms*1000),None)
    last=next((s for s in timeline if s['elapsed_us']>=(warmup_ms+business_ms)*1000),None)
    if first is None or last is None:raise ValueError('missing phase snapshots')
    out={'actual_interval_seconds':(last['elapsed_us']-first['elapsed_us'])/1e6,
         'boundary_tolerance':'first snapshot at/after each source phase boundary; native counts include packets from earlier source cohorts'}
    for endpoint in ['client','server']:
        fields=['udp_packets_tx','udp_packets_rx','udp_bytes_tx','udp_bytes_rx','ack_frames_tx',
                'ack_frames_rx','datagram_frames_tx','datagram_frames_rx','lost_packets',
                'ack_frequency_tx','ack_frequency_rx']
        diff={k:last[endpoint][k]-first[endpoint][k] for k in fields}
        if any(v<0 for v in diff.values()):raise ValueError('native counter regressed')
        out[endpoint]=diff
    return out


def audit_window(directory, registered, settings):
    d=Path(directory);config=read(d/'config.json');result=read(d/'result.json')
    raw=read(d/'samples.json');timeline=read(d/'timeline.json');cleanup=read(d/'cleanup.json')
    expected_profile={'every-two':'EveryTwo','every-eight':'EveryEight'}[registered['ack_profile']]
    if config['ack_profile']!=expected_profile or config['client_profile']!='Unchanged':raise ValueError('wrong direction/profile')
    if config['requested_ack_tuple']!=([1,10,2] if expected_profile=='EveryTwo' else [7,10,2]):raise ValueError('unmatched delay or reorder treatment')
    for key in ['bulk_pps','echo_pps','warmup_ms','business_ms','drain_ms','one_way_delay_ms','link_queue_ms','runtime_threads']:
        if config[key]!=settings[key]:raise ValueError('changed setting: '+key)
    for key in ['relay_runtime_threads','relay_executor_isolation','socket_receive_bytes','socket_send_bytes']:
        if key in settings and config.get(key)!=settings[key]:raise ValueError('changed instrument setting: '+key)
    if config['reverse_pps']!=registered['reverse_pps']:raise ValueError('wrong synthetic link')
    if not cleanup['all_owned_relay_tasks_joined'] or not cleanup['no_remote_actions']:raise ValueError('incomplete cleanup')
    for direction in ['reverse','forward']:
        s=cleanup[direction]
        if s['input_packets']!=s['forwarded_packets']+s['queue_discarded_packets']+s['shutdown_discarded_packets']:raise ValueError('relay census does not close')
        if s['foreign_packets']!=0:raise ValueError('unexpected socket source')
    if cleanup['forward']['queue_discarded_packets']:raise ValueError('unconfigured forward resource limit reached')
    total=(settings['warmup_ms']+settings['business_ms'])*settings['bulk_pps']//1000
    count=(settings['warmup_ms']+settings['business_ms'])*settings['echo_pps']//1000
    split=settings['warmup_ms']*settings['bulk_pps']//1000;esplit=settings['warmup_ms']*settings['echo_pps']//1000
    if len(raw['bulk'])!=total or len(raw['echo'])!=count or raw['bulk_split']!=split or raw['echo_split']!=esplit:raise ValueError('incomplete original population')
    if not result['generator_complete'] or result['generator_pacing_fraction']<.95:raise ValueError('native generator not fully exercised')
    for s in raw['bulk']:
        if s['issued_us'] is None or (s['received_us'] is not None and s['admitted_us'] is None):raise ValueError('missing generation or admission identity')
    for s in raw['echo']:
        if s['issued_us'] is None:raise ValueError('request generator incomplete')
        if s['received_us'] is not None and (s['server_received_us'] is None or s['reply_admitted_us'] is None):raise ValueError('response lacks server observation')
    actual_latency=latency(raw['echo'][esplit:])
    expected_latency=result['business_echo']
    if actual_latency['on_time']!=expected_latency['on_time_200ms'] or actual_latency['received']!=expected_latency['received'] or actual_latency['p95_ms']!=expected_latency['p95_ms']:raise ValueError('latency does not match full raw cohort')
    delivered=sum(s['received_us'] is not None for s in raw['bulk'][split:])
    span=(raw['bulk'][-1]['issued_us']-raw['bulk'][split]['issued_us'])/1e6+1/settings['bulk_pps']
    goodput=delivered*settings['bulk_payload_bytes']*8/span/1e6
    if delivered!=result['business_delivered'] or not math.isclose(goodput,result['business_goodput_mbps'],rel_tol=1e-10):raise ValueError('goodput cohort mismatch')
    if not result['ack_request_confirmed'] or result['client_ack_request_sent']:raise ValueError('wrong ACK negotiation')
    if result['final_counters']['client']['ack_frequency_tx']!=0 or result['final_counters']['server']['ack_frequency_rx']!=0:raise ValueError('client changed ACK policy')
    echo=raw['echo'][esplit:]
    request_missing={'not_admitted':sum(s['admitted_us'] is None for s in echo),
        'admitted_not_observed_at_server':sum(s['admitted_us'] is not None and s['server_received_us'] is None for s in echo),
        'server_received_no_reply_admitted':sum(s['server_received_us'] is not None and s['reply_admitted_us'] is None for s in echo),
        'reply_admitted_not_received':sum(s['reply_admitted_us'] is not None and s['received_us'] is None for s in echo)}
    if sum(request_missing.values())!=len(echo)-actual_latency['received']:raise ValueError('request boundary census does not close')
    socket_evidence=read(d/'sockets.json') if (d/'sockets.json').exists() else None
    measurement_health=classify(result,config,socket_evidence)
    return {**registered,'goodput_mbps':goodput,'delivered_bytes':delivered*settings['bulk_payload_bytes'],
        'measurement_health':measurement_health,
        'actual_business_source_seconds':span,'echo':actual_latency,'request_missing_boundaries':request_missing,
        'native_business_interval':native_interval(timeline,settings['warmup_ms'],settings['business_ms']),
        'relay_complete_census':cleanup,'application_counters':result['application_counters'],
        'maximum_source_generation_lag_us':max(max(0,s['issued_us']-i*1e6/settings['bulk_pps']) for i,s in enumerate(raw['bulk'])),
        'raw_hashes':{p.name:digest(p) for p in d.iterdir() if p.is_file()},
        'source_adapter_gap_eliminated_by_construction':True,
        'condition':'real local QUIC sockets; synthetic packet service/propagation; not WAN'}


def aggregate(rows,settings):
    summaries={};comparisons={}
    grouped=defaultdict(list)
    for row in rows:grouped[(row['reverse_pps'],row['ack_profile'])].append(row)
    for (limit,profile),items in grouped.items():
        span=sum(x['actual_business_source_seconds'] for x in items)
        byte_count=sum(x['delivered_bytes'] for x in items);requests=sum(x['echo']['population'] for x in items)
        native_span=sum(x['native_business_interval']['actual_interval_seconds'] for x in items)
        if native_span<=0:raise ValueError('invalid native counter interval')
        summaries[str(limit)+'/'+profile]={'windows':len(items),'goodput_mbps':byte_count*8/span/1e6,
            'on_time_fraction':sum(x['echo']['on_time'] for x in items)/requests,
            'reverse_native_packets':sum(x['native_business_interval']['client']['udp_packets_tx'] for x in items),
            'reverse_ack_frames':sum(x['native_business_interval']['client']['ack_frames_tx'] for x in items),
            'reverse_native_bytes':sum(x['native_business_interval']['client']['udp_bytes_tx'] for x in items),
            'native_counter_interval_seconds':native_span,
            'reverse_native_packets_per_second':sum(x['native_business_interval']['client']['udp_packets_tx'] for x in items)/native_span,
            'reverse_ack_frames_per_second':sum(x['native_business_interval']['client']['ack_frames_tx'] for x in items)/native_span,
            'p95_ms':None,'p95_requires_raw_pool':True}
    # Pool raw request slots, never per-window P95; caller fills them from known files.
    for limit in [0,2000]:
        control=summaries.get(str(limit)+'/every-two');treatment=summaries.get(str(limit)+'/every-eight')
        if not control or not treatment:continue
        comparisons[str(limit)]={'goodput_ratio':treatment['goodput_mbps']/control['goodput_mbps'],
            'on_time_change_percentage_points':100*(treatment['on_time_fraction']-control['on_time_fraction']),
            'reverse_native_packet_ratio':treatment['reverse_native_packets_per_second']/control['reverse_native_packets_per_second'] if control['reverse_native_packets_per_second'] else None,
            'reverse_ack_frame_ratio':treatment['reverse_ack_frames_per_second']/control['reverse_ack_frames_per_second'] if control['reverse_ack_frames_per_second'] else None,
            'native_ratio_basis':'sum phase counter deltas / sum actual sampled intervals',
            'mechanism_screen_passed':False,'performance_scope':'controlled single-connection model only'}
    return summaries,comparisons


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv);binary=a.binary.resolve();root=a.output.resolve()
    if not binary.is_file():raise FileNotFoundError(binary)
    root.mkdir(parents=True,exist_ok=False);settings=plan()
    repo=Path(__file__).resolve().parent.parent
    sources=['examples/directional_ack_lab.rs','examples/support/ack_policy.rs','examples/support/lab_socket.rs',
             'Cargo.lock','bench/directional_ack_study.py','bench/lab_health.py']
    registration={**settings,'binary_sha256':digest(binary),'source_sha256':{x:digest(repo/x) for x in sources},
        'system':platform.platform(),'cpu_count':os.cpu_count(),'created_unix_ns':time.time_ns()}
    save_new(root/'registration.json',registration)
    active=None;cancelled=False;rows=[];error=None
    def cancel(signum,frame):
        nonlocal cancelled
        cancelled=True
        if active is not None and active.poll() is None:active.send_signal(signal.SIGINT)
    old={sig:signal.signal(sig,cancel) for sig in [signal.SIGINT,signal.SIGTERM]}
    try:
        for item in settings['order']:
            if cancelled:raise KeyboardInterrupt('study cancelled')
            out=root/item['window']
            args=[str(binary),'--output',str(out),'--ack-profile',item['ack_profile'],'--reverse-pps',str(item['reverse_pps'])]
            for name in ['bulk_pps','echo_pps','warmup_ms','business_ms','drain_ms','one_way_delay_ms','link_queue_ms']:
                args+=['--'+name.replace('_','-'),str(settings[name])]
            usage=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic()
            with (root/(item['window']+'.log')).open('x') as log:
                active=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                save_new(root/(item['window']+'-launch.json'),{'pid':active.pid,'argv':args,'started_unix_ns':time.time_ns()})
                try:code=active.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    active.send_signal(signal.SIGINT);active.wait(timeout=5);raise
            after=resource.getrusage(resource.RUSAGE_CHILDREN)
            save_new(root/(item['window']+'-exit.json'),{'pid':active.pid,'returncode':code,'elapsed_seconds':time.monotonic()-start,
                'process_cpu_seconds':after.ru_utime+after.ru_stime-usage.ru_utime-usage.ru_stime,
                'cpu_scope':'single process including both endpoints, generators and relay, not endpoint-only'})
            if code:raise RuntimeError('native lab failed: '+item['window'])
            row=audit_window(out,item,settings);rows.append(row)
            print(json.dumps({k:row[k] for k in ['window','ack_profile','reverse_pps','goodput_mbps','echo','request_missing_boundaries']}),flush=True)
    except BaseException as exc:error=type(exc).__name__+': '+str(exc)
    finally:
        if active is not None and active.poll() is None:
            active.send_signal(signal.SIGINT)
            try:active.wait(timeout=5)
            except subprocess.TimeoutExpired:active.kill();active.wait(timeout=5)
        for sig,handler in old.items():signal.signal(sig,handler)
    summaries,comparisons=aggregate(rows,settings)
    clean_controls=[r for r in rows if r['reverse_pps']==0]
    clean_calibration=(len(clean_controls)==4 and all(r['measurement_health']['clean_reference_passed'] for r in clean_controls))
    application_receivers_healthy=all(r['measurement_health']['consumer_loss_free'] is True
                                    and r['measurement_health']['api_to_native_closed'] is True
                                    and r['measurement_health']['model_timer_fidelity_passed'] is True for r in rows)
    for key,s in summaries.items():
        limit,profile=key.split('/');all_slots=[]
        for row in rows:
            if row['reverse_pps']==int(limit) and row['ack_profile']==profile:
                raw=read(root/row['window']/'samples.json');all_slots+=raw['echo'][raw['echo_split']:]
        s['p95_ms']=latency(all_slots)['p95_ms'];s['p95_requires_raw_pool']=False
    for limit,c in comparisons.items():
        b=summaries[limit+'/every-two'];n=summaries[limit+'/every-eight'];g=settings['screen']
        c['p95_evaluable']=b['p95_ms'] is not None and n['p95_ms'] is not None
        c['clean_reference_calibration_passed']=clean_calibration
        c['application_receiver_and_model_healthy']=application_receivers_healthy
        c['mechanism_screen_passed']=(error is None and clean_calibration and application_receivers_healthy
            and b['windows']==2 and n['windows']==2 and
            c['goodput_ratio']>=g['goodput_min_ratio'] and c['on_time_change_percentage_points']>=0 and
            n['on_time_fraction']>=g['on_time_fraction_target'] and c['p95_evaluable'] and
            n['p95_ms']<=b['p95_ms']*g['finite_p95_max_ratio'] and
            c['reverse_native_packet_ratio'] is not None and c['reverse_native_packet_ratio']<=g['reverse_native_packet_max_ratio'])
    facts={'complete':error is None and len(rows)==len(settings['order']),'error':error,'completed_windows':len(rows),
        'windows':rows,'summary':summaries,'comparisons':comparisons,'planned_windows':8,
        'registration_sha256':digest(root/'registration.json'),'all_owned_processes_stopped':active is None or active.poll() is not None,
        'new_public_network_workloads':0,'linux_user_host_workloads':0,'production_changes':0,
        'scope':'local single-connection mechanism study; not multipath/host-native-equivalence or release validation'}
    save_new(root/'facts.json',facts);print(json.dumps({k:v for k,v in facts.items() if k!='windows'},indent=2),flush=True)
    return 0 if facts['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
