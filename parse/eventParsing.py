import numpy as np
from graph.Event import Event

lttng_sys_event = ['sys_open','sys_openat','sys_close','sys_read','sys_readv','sys_pread',
    'sys_preadv','sys_write','sys_writev','sys_pwrite','sys_pwritev','sys_clone','sys_fork',
    'sys_execve','sys_accept','sys_connect','sys_recvfrom','sys_recvmsg','sys_sendto','sys_sendmsg',
    'sys_socket','sys_rename','sys_renameat','sys_dup2','sys_chmod','sys_chown','sys_create','sys_pipe','sys_pipe2','sys_setuid',
    'sys_setgid','sys_unlink','sys_unlinkat','sys_unknow','sys_imageload','ipaddr_info','dns_info']

lttng_sched_event = ['sched_switch','sched_process_fork','sched_process_free','sched_process_exec','sched_wakeup_new']

lttng_lttng_event = ['lttng_statedump_start','lttng_statedump_end','lttng_statedump_process_state','lttng_statedump_file_descriptor']

def parse_event_cadets(datum):
    event = {}
    event['uuid'] = datum['uuid']
    event['type'] = datum['type']
    event['properties'] = datum['properties']
    event['timestamp'] = datum['timestampNanos']
    if event['type'] == 'EVENT_UPDATE':
        event['src'] = datum['predicateObject']['com.bbn.tc.schema.avro.cdm18.UUID']
        event['dest'] = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm18.UUID']
    else:
        if isinstance(datum['subject'], dict):
            event['src'] = datum['subject']['com.bbn.tc.schema.avro.cdm18.UUID']
        else:
            event['src'] = -1
        
        if isinstance(datum['predicateObject'], dict):
            event['dest'] = datum['predicateObject']['com.bbn.tc.schema.avro.cdm18.UUID']
        else:
            event['dest'] = -1

        if isinstance(datum['predicateObjectPath'], dict):
            event['obj_path'] = datum['predicateObjectPath']['string']

    if event['type'] == 'EVENT_MODIFY_FILE_ATTRIBUTES':
        if datum['name']['string'] != 'aue_chmod':
            return None
        # print(datum['parameters']['array'][0]['valueBytes']['bytes'])
        event['parameters'] = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
        
    return event

def parse_event_cdm(datum):
    event = {}
    event['uuid'] = datum['uuid']
    event['type'] = datum['type']
    event['properties'] = datum['properties']
    event['timestamp'] = datum['timestampNanos']
    if event['type'] == 'EVENT_UPDATE':
        event['src'] = datum['predicateObject']['com.bbn.tc.schema.avro.cdm18.UUID']
        event['dest'] = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm18.UUID']
    else:
        event['src'] = datum['subject']['com.bbn.tc.schema.avro.cdm18.UUID']
        if isinstance(datum['predicateObject'], dict):
            event['dest'] = datum['predicateObject']['com.bbn.tc.schema.avro.cdm18.UUID']
        else:
            event['dest'] = -1
        
    return event

def parse_event(datum, format='cadets'):
    if format == 'cdm':
        return parse_event_cdm(datum)
    elif format == 'cadets':
        return parse_event_cadets(datum)