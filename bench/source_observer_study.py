"""One finite raw-source observer off/on/on/off study, isolated loopback only.

This tests the explicitly described Python observer, not an assumed identical
replacement of an earlier Node collector. It changes neither runtime timing nor
queue budgets. Measurement failures remain results; lifecycle failure stops later
windows. No qualified results are selected for publication by this runner.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import uuid

from bench.host_reference import Owned, digest, port, save_new, wait_ready
from bench.netem import source_qualification
from bench.source_burst import burst_summary


class Observer:
    def __init__(self, process, output, enabled, flush_each_sample=True):
        self.process, self.output, self.enabled = process, output, enabled
        self.flush_each_sample = flush_each_sample
        self.stop = threading.Event()
        self.thread = None
        self.status = dict(enabled=enabled, interval_ms=5, max_rows=10000,
                           max_tasks=16, rows=0, errors=[], maximum_collection_ms=0,
                           maximum_total_work_ms=0, dropped_samples=0,
                           flush_each_sample=flush_each_sample, file_buffer_bytes=65536,
                           maximum_work_event=None)

    def start(self):
        if self.enabled:
            self.thread = threading.Thread(target=self.collect, daemon=False)
            self.thread.start()

    def collect(self):
        def text(path):
            try:
                return Path(path).read_text()
            except OSError as error:
                return {'error': type(error).__name__ + ': ' + str(error)}
        with (self.output/'observer.jsonl').open('x', buffering=65536) as stream:
            while not self.stop.is_set() and self.process.poll() is None and self.status['rows'] < 10000:
                begin, wall = time.monotonic_ns(), time.time_ns()
                try:
                    root = Path('/proc')/str(self.process.pid)/'task'
                    tids = sorted(root.iterdir(), key=lambda p: int(p.name))
                    row = dict(begin_monotonic_ns=begin, begin_unix_ns=wall,
                        source_pid=self.process.pid, task_count=len(tids), task_list_truncated=len(tids)>16,
                        cpu_stat=text('/sys/fs/cgroup/cpu.stat'), tasks=[])
                    for path in tids[:16]:
                        row['tasks'].append(dict(tid=int(path.name), schedstat=text(path/'schedstat'),
                                                 wchan=text(path/'wchan')))
                    row['collection_duration_ns'] = time.monotonic_ns()-begin
                    row['source_alive_at_end'] = self.process.poll() is None
                    stream.write(json.dumps(row)+'\n')
                    if self.flush_each_sample:
                        stream.flush()
                    work = time.monotonic_ns()-begin
                    self.status['rows'] += 1
                    self.status['maximum_collection_ms'] = max(self.status['maximum_collection_ms'], row['collection_duration_ns']/1e6)
                    if work/1e6 > self.status['maximum_total_work_ms']:
                        self.status['maximum_total_work_ms'] = work/1e6
                        self.status['maximum_work_event'] = dict(sample_number=self.status['rows']-1,
                            begin_unix_ns=wall, begin_monotonic_ns=begin,
                            collection_duration_ns=row['collection_duration_ns'], total_work_ns=work)
                except (OSError, ValueError) as error:
                    self.status['errors'].append(type(error).__name__+': '+str(error))
                    break
                self.stop.wait(.005)

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                raise RuntimeError('bounded observer did not stop')
        save_new(self.output/'observer-status.json', self.status)


def window(root, binary, enabled, flush_each_sample=True):
    root.mkdir()
    owner, observer = Owned(root), None
    address, run = port(), uuid.uuid4().hex
    common = ['--count','400000','--size','1000','--pps','40000','--deadline-ms','200',
        '--drain-ms','3000','--startup-timeout-ms','15000','--run-id',run,'--transport','raw-udp']
    error = None
    try:
        sink = owner.launch('sink', [binary,'sink','--role','receive','--listen',address,*common,
            '--ready-file',root/'sink/ready.json','--result-file',root/'sink/result.json',
            '--samples-file',root/'sink/samples.json'])
        wait_ready(sink, root/'sink/ready.json', limit=10)
        source = owner.launch('source', [binary,'probe','--mode','send','--target',address,*common,
            '--result-file',root/'source/result.json','--samples-file',root/'source/samples.json'])
        observer = Observer(source, root, enabled, flush_each_sample)
        observer.start()
        source.wait(timeout=40)
        sink.wait(timeout=10)
        if source.returncode or sink.returncode:
            raise RuntimeError('source or sink failed')
    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    finally:
        previous = {s: signal.signal(s, signal.SIG_IGN) for s in [signal.SIGINT, signal.SIGTERM]}
        try:
            try:
                if observer:
                    observer.close()
            finally:
                owner.stop_all()
                save_new(root/'lifecycle.json', dict(error=error, cleanup=owner.cleanup))
        finally:
            for s, handler in previous.items():
                signal.signal(s, handler)
    if error:
        raise RuntimeError(error)
    source = json.loads((root/'source/result.json').read_text())
    sink = json.loads((root/'sink/result.json').read_text())
    samples = json.loads((root/'source/samples.json').read_text())['samples']
    row = dict(window=root.name, observer=enabled, source_pps=40000, count=400000,
        source_raw_mbps=source['actual_offered_load_bps']/1e6,
        source_pacing=source.get('source_pacing'), sink_received=sink['received'],
        sink_corrupt=sink['corrupt'], sink_missing=sink['lost'],
        qualification=source_qualification(samples, source, 400000, 40000),
        burst=burst_summary(samples,40000), observer_status=observer.status,
        runtime_source_changed=False, network_operations_outside_loopback=0)
    save_new(root/'analysis.json',row)
    print(json.dumps({**{k:v for k,v in row.items() if k not in ['burst','qualification','source_pacing']},
        'source_qualified':row['qualification']['source_qualified'],
        'maximum_wake_lateness_ms':row['source_pacing']['max_wake_lateness']['nanoseconds']/1e6,
        'maximum_input_gap_us':row['burst']['gap_us']['maximum']}),flush=True)
    return row


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--study', choices=['presence','flush'], default='presence',
        help='presence toggles5ms collection; flush keeps it enabled and toggles per-row flush only')
    args=parser.parse_args()
    if not Path('/.dockerenv').exists() or os.environ.get('BRAIDPATH_SOURCE_STUDY') != '1':
        parser.error('dedicated network-none test container required')
    root,binary=args.output.resolve(),args.binary.resolve()
    root.mkdir(parents=True,exist_ok=False)
    sha=digest(binary)
    order = [False,True,True,False] if args.study=='presence' else [True]*4
    flush_order = [True]*4 if args.study=='presence' else [True,False,False,True]
    save_new(root/'registration.json',dict(utc=datetime.now(timezone.utc).isoformat(),
        study=args.study,order=order,flush_order=flush_order,
        source_count=400000,source_pps=40000,size_bytes=1000,
        nominal_seconds=10,deadline_ms=200,unchanged_binary_sha256=sha,no_retries=True,
        script_sha256=digest(Path(__file__)), file_buffer_bytes=65536,
        scope='observer attribution, not tunnel acceptance',performance_promotion=False,
        collector='Python bounded per-task schedstat/wchan + cgroup cpu,5ms,16tasks,10000rows'))
    def cancel(signum,frame):
        raise KeyboardInterrupt('source study interrupted')
    for s in [signal.SIGINT,signal.SIGTERM]:signal.signal(s,cancel)
    rows,error=[],None
    try:
        for i,enabled in enumerate(order):
            if digest(binary)!=sha:raise ValueError('frozen binary changed')
            if args.study=='presence':
                rows.append(window(root/('window_'+chr(97+i)),binary,enabled))
            else:
                rows.append(window(root/('window_'+chr(97+i)),binary,enabled,flush_order[i]))
    except BaseException as exc:
        error=type(exc).__name__+': '+str(exc)
    save_new(root/'result.json',dict(error=error,complete=error is None and len(rows)==4,
        windows=rows,causal_conclusion=None,production_actions=0))
    return 0 if error is None else 1


if __name__=='__main__':
    raise SystemExit(main())
