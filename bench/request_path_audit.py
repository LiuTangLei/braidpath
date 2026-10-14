"""Offline request-direction ledger from existing raw echo/adapter identities.

Not a packet capture, link loss estimator, or causal performance comparison.
A gap before the server application adapter includes both endpoint queues and
both possible QUIC/application boundaries; it is not automatically wire loss.
"""
from bench.delivery_frontier import EvidenceError, integer


def request_ledger(echo, adapter, raw):
    run = echo['run_id']
    count = integer(echo['requested_count'], 'requests')
    slots = raw['samples']
    if raw.get('run_id') != run or raw.get('pid') != echo['pid'] or len(slots) != count:
        raise EvidenceError('raw echo identity or population differs')
    if [r['seq'] for r in slots] != list(range(count)):
        raise EvidenceError('missing or duplicate echo slots')
    if echo.get('corrupt') != 0 or echo.get('duplicate') != 0:
        raise EvidenceError('corrupt/duplicate echo must not be reclassified as path loss')
    if adapter['echo_probe_population'].get(run) != count:
        raise EvidenceError('adapter authorized another request population')
    if set(adapter['echo_probe_population']) != {run}:
        raise EvidenceError('this audit requires one echo cohort')
    sent = {r['seq'] for r in slots if r.get('send_monotonic_ns') is not None}
    received = {r['seq'] for r in slots if r.get('receive_monotonic_ns') is not None}
    seen_list = adapter['echo_received_sequences'][run]
    forwarded_list = adapter['echo_forwarded_sequences'][run]
    if len(set(seen_list)) != len(seen_list) or len(set(forwarded_list)) != len(forwarded_list):
        raise EvidenceError('duplicate adapter identity evidence')
    seen, forwarded = set(seen_list), set(forwarded_list)
    if not received <= forwarded <= seen <= sent <= set(range(count)):
        raise EvidenceError('request path identity is not a nested delivery chain')
    if len(sent) != echo['sent'] or len(received) != echo['received']:
        raise EvidenceError('echo counters disagree with raw slots')
    before = sent-seen
    adapter_failed = seen-forwarded
    after = forwarded-received
    unsent = set(range(count))-sent
    assert len(unsent)+len(before)+len(adapter_failed)+len(after)+len(received)==count
    return {'requests':count, 'sent':len(sent), 'received':len(received), 'unsent':len(unsent),
            'not_observed_at_server_application_adapter':len(before),
            'server_adapter_received_but_not_forwarded':len(adapter_failed),
            'forwarded_by_server_adapter_but_not_received_by_client':len(after),
            'missing_total':count-len(received),
            'before_adapter_missing_sequences':sorted(before),
            'after_adapter_missing_sequences':sorted(after),
            'interpretation':'first missing observable application boundary, not physical-link or CPU attribution'}


def bulk_adapter_ledger(source, adapter):
    sent=integer(source['sent'],'source sent')
    count=integer(source['requested_count'],'source count')
    c=adapter['counters']
    received=integer(c['backend_data_received'],'adapter original data received')
    forwarded=integer(c['bulk_data_forwarded'],'adapter original data forwarded')
    if not 0<=forwarded<=received<=sent<=count:
        raise EvidenceError('invalid bulk adapter conservation')
    if adapter['bulk_count'] != count:
        raise EvidenceError('adapter belongs to another bulk population')
    return {'source_requested':count,'source_sent':sent,'adapter_received':received,
            'adapter_forwarded':forwarded,'source_to_adapter_gap':sent-received,
            'adapter_forwarding_gap':received-forwarded,
            'unit':'whole original cohort including any registered warmup, no echo/control bytes'}


def native_direction_census(sender, receiver):
    """Same-path endpoint counters, with frame counts separate from UDP bytes.

    ACK frames may share packets with data; no ACK-byte estimate is manufactured.
    These final counters include startup/drain, not an instantaneous load rate.
    """
    from bench.delivery_frontier import closed_endpoint
    tx, sid = closed_endpoint(sender, 'client')
    rx, other_sid = closed_endpoint(receiver, 'server')
    if sid != other_sid:
        raise EvidenceError('native census endpoint sessions differ')
    paths = {p['path_id']:p for p in rx['paths'].values()}
    if len(paths) != len(rx['paths']) or len(paths) != len(tx['paths']):
        raise EvidenceError('native census path population differs')
    fields = ('udp_datagrams_tx','udp_bytes_tx','ack_frames_tx','http_datagram_frames_tx',
              'ack_frequency_frames_tx','immediate_ack_frames_tx','lost_packets')
    total = {k:0 for k in fields}
    result=[]
    for p in sorted(tx['paths'].values(), key=lambda p:p['path_id']):
        q=paths.get(p['path_id'])
        if q is None or p['total_generations'] != 1 or q['total_generations'] != 1:
            raise EvidenceError('unmatched or regenerated path')
        if not p['authenticated'] or not q['authenticated']:
            raise EvidenceError('unauthenticated path in census')
        values={k:integer(p['quinn'][k],k) for k in fields}
        for k,v in values.items():total[k]+=v
        original_sent=integer(p['quinn_admitted_originals'],'original API admissions')
        original_received=integer(q['original_records_delivered'],'original records delivered')
        if original_received>original_sent:
            raise EvidenceError('peer original delivery exceeds single-generation admissions')
        result.append({'path':p['path_id'],'client_native':values,
            'server_native_udp_datagrams_received':integer(q['quinn']['udp_datagrams_rx'],'UDP datagrams received'),
            'server_native_data_frames_received':integer(q['quinn']['http_datagram_frames_rx'],'data frames received'),
            'server_application_frames_received':integer(q['http_datagrams_received'],'application frames received'),
            'original_api_admitted':original_sent,'original_received':original_received,
            'originals_not_observed_at_server':original_sent-original_received})
    return {'client_native_totals':total,'paths':result,
            'ack_bytes':None,'ack_only_packet_count':None,'caused_request_loss':None,
            'scope':'final cumulative same-generation endpoint counts; ACK frames are not ACK-only packets or bytes'}
