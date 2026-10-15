"""Pure health classification for the instrumented local QUIC laboratory.

No execution, sockets or retrospective rewriting. A lower ACK count is not a
successful mechanism test if the measuring application itself drops received
frames. Snapshot packet gaps remain diagnostics: they are not loss localization.
"""
import math

SOCKET_ROLES = {'server_endpoint', 'client_endpoint', 'relay_front', 'relay_back'}
MAX_CALIBRATION_TIMER_LATENESS_US = 5000


def _number(value, name):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError('finite numeric evidence required: '+name)
    return value


def classify(result, config, sockets):
    reasons=[]
    boundary=result.get('boundary_census')
    if not isinstance(boundary,dict) or set(boundary)!={'server_to_client','client_to_server'}:
        return {'status':'unknown_legacy_measurement','clean_reference_passed':False,
                'consumer_loss_free':None,'reason':['native/application boundary census missing'],
                'network_root_cause_identified':False}
    consumer=True;sender=True
    for direction, values in boundary.items():
        counts={key:_number(values[key],key) for key in ['application_api_admitted',
            'application_datagrams_received','native_datagram_frames_tx','native_datagram_frames_rx',
            'api_admitted_not_native_transmitted','native_received_not_read_by_application','model_queue_discards']}
        if any(type(v) is not int for v in counts.values()):
            raise ValueError('boundary counts must be integers')
        if counts['api_admitted_not_native_transmitted'] != counts['application_api_admitted']-counts['native_datagram_frames_tx']:
            raise ValueError('API/native conservation mismatch')
        if counts['native_received_not_read_by_application'] != counts['native_datagram_frames_rx']-counts['application_datagrams_received']:
            raise ValueError('native/application conservation mismatch')
        if counts['native_received_not_read_by_application']:
            consumer=False;reasons.append(direction+': native receive/application read gap')
        if counts['api_admitted_not_native_transmitted']:
            sender=False;reasons.append(direction+': API admission/native transmit gap')
    if not isinstance(sockets,list) or len(sockets)!=4 or {s['role'] for s in sockets}!=SOCKET_ROLES:
        reasons.append('four-socket evidence missing')
        socket_ok=False
    else:
        socket_ok=True
        requested=config['socket_receive_bytes']
        requested_send=config.get('socket_send_bytes',0)
        for socket in sockets:
            if not socket['address'].startswith('127.0.0.1:') or socket['requested_receive_bytes']!=requested:
                raise ValueError('socket scope or treatment identity changed')
            actual=_number(socket['effective_receive_bytes'],'receive buffer')
            if actual<=0 or (requested and actual<requested):socket_ok=False
            if requested_send:
                if socket.get('requested_send_bytes')!=requested_send:
                    raise ValueError('send-buffer treatment identity changed')
                if _number(socket.get('effective_send_bytes'),'send buffer')<requested_send:socket_ok=False
        if not socket_ok:reasons.append('registered per-socket headroom unavailable')
    echo=result['business_echo']
    echo_complete=echo['population']>0 and echo['received']==echo['population'] and echo['on_time_200ms']==echo['population']
    bulk_complete=result['business_population']>0 and result['business_delivered']==result['business_population']
    if result['business_delivered']>result['business_population'] or echo['received']>echo['population']:
        raise ValueError('delivered population exceeds source')
    queue_clean=all(v==0 for v in result['ending_application_queues'].values())
    generation=result['generator_complete'] is True and _number(result['generator_pacing_fraction'],'source pacing')>=.95
    model_clean=all(d['model_queue_discards']==0 for d in boundary.values())
    timers=result.get('final_counters',{})
    timer_known=all('maximum_timer_lateness_us' in timers.get(d,{}) for d in ['forward','reverse'])
    timer_faithful=timer_known and all(_number(timers[d]['maximum_timer_lateness_us'],'model timer lateness')
                                      <=MAX_CALIBRATION_TIMER_LATENESS_US for d in ['forward','reverse'])
    limited=config['reverse_pps']!=0
    if not echo_complete:reasons.append('business request deadline population incomplete')
    if not bulk_complete:reasons.append('business original population incomplete')
    if not queue_clean:reasons.append('application queues not drained')
    if not generation:reasons.append('source supply incomplete or below registered pacing')
    if not model_clean:reasons.append('synthetic model discarded packets')
    if not timer_faithful:reasons.append('model timer fidelity unknown or exceeded 5ms calibration bound')
    if limited:reasons.append('intentional resource bottleneck is not a clean reference')
    clean=(consumer and sender and socket_ok and echo_complete and bulk_complete and queue_clean
            and generation and model_clean and timer_faithful and not limited)
    return {'status':'clean_reference' if clean else 'not_clean_reference',
            'clean_reference_passed':clean,'consumer_loss_free':consumer,'api_to_native_closed':sender,
            'source_complete':generation,'request_deadlines_complete':echo_complete,
            'business_originals_complete':bulk_complete,'intentional_bottleneck':limited,
            'model_timer_fidelity_passed':timer_faithful,
            'maximum_calibration_timer_lateness_us':MAX_CALIBRATION_TIMER_LATENESS_US,
            'reasons':reasons,'network_root_cause_identified':False,
            'scope':'one fixed finite laboratory cohort, not sustainable capacity, performance comparison, WAN or release acceptance'}
