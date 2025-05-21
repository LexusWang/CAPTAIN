'''
This script is used to transfer the TRACE data in CDM 18 format 
(used in DARPA Engagement 3) to the standard format.

After the tranlation is finished, the data will be saved in the log.json
file in the output folder.
'''

import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])

from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from parse.cdm18.eventType import SET_UID_SET, cdm_events, READ_SET, WRITE_SET, INJECT_SET, CHMOD_SET, SET_UID_SET, EXECVE_SET, LOAD_SET, CREATE_SET, RENAME_SET, REMOVE_SET, CLONE_SET, MPROTECT_SET, MMAP_SET, UPDATE_SET, EXIT_SET, UNUSED_SET
from parse.utils import memory_protection

def parse_event_trace(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]

    try:
        if datum['type'] in READ_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in WRITE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'write'
        elif datum['type'] in INJECT_SET:
            event.type = 'inject'
        elif datum['type'] in CHMOD_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'chmod'
            event.parameters = int(event.properties['mode'], 8)
        elif datum['type'] in SET_UID_SET:
            assert node_buffer.get(event.src, None)
            if datum['properties']['map']['operation'] == 'setuid':
                event.type = 'set_uid'
                event.src = event.dest
                event.dest = None
                event.parameters = node_buffer.get(event.src, None).owner
            else:
                return None
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'update_process'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            assert node_buffer.get(event.src, None)
            if node_buffer.get(event.dest, None) and node_buffer[event.dest].isFile():
                event.type = 'load'
                event.dest2 = None
            else:
                event.type = 'mmap'
                event.dest = None
                event.dest2 = None
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'create'
        elif datum['type'] in RENAME_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.type = 'rename'
        elif datum['type'] in REMOVE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            assert node_buffer.get(event.src, None)
            event.type = 'mprotect'
            event.dest = None
            event.dest2 = None
            event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in UPDATE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.type = 'update'
        elif datum['type'] in EXIT_SET:
            assert node_buffer.get(event.src, None)
            event.dest = None
            event.type = 'exit'
        else:
            return None
    except AssertionError as ae:
        return None 
    
    return event

def parse_subject_trace(datum, cdm_version=18):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = int(datum['cid'])
        pname_ = datum['properties']['map'].get('name',None)
        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        ppid_ = int(datum['properties']['map']['ppid'])
        if isinstance(datum['cmdLine'],dict):
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = datum['cmdLine']
        subject = Subject(id=datum['uuid'], type = type_, pid = pid_, ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        if isinstance(datum['localPrincipal'],dict):
            subject.owner = datum['localPrincipal']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        else:
            subject.owner = datum['localPrincipal']
        return subject
    elif subject_type == 'SUBJECT_THREAD':
        return None
    elif subject_type == 'SUBJECT_UNIT':
        return None
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        return None
    else:
        return None

def parse_object_trace(datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if isinstance(datum['baseObject']['epoch'], dict):
        object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        # object.subtype = cdm_file_object_type[datum['type']]
        object.subtype = datum['type']
        object.name = datum['baseObject']['properties']['map'].get('path',None)
        object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        return None
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'NetFlowObject':
        try:
            object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
        except TypeError:
            object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
    elif object_type == 'MemoryObject':
        # object.name = 'MEM_{}'.format(datum['memoryAddress'])
        return None
    elif object_type == 'SrcSinkObject':
        return None
        # object.subtype = datum['type']
        # permission = datum['baseObject']['permission']
        # if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
        #     return None
        # else:
        #     print(datum)
    else:
        return None

    return object


def start_experiment(args):
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    ##### Load File Names #####
    # volume_list = [file for file in os.listdir(args.input_data) if file.startswith('.') == False]
    # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
    volume_list = []
    for volume in range(204):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official.json', 'ta1-trace-e3-official.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official.json', f'ta1-trace-e3-official.json.{volume}'))
            
    for volume in range(7):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official-1.json', 'ta1-trace-e3-official-1.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official-1.json', f'ta1-trace-e3-official-1.json.{volume}'))

    last_event_str = ''
    node_buffer = {}
    principals_buffer = {}
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0
    envt_num = 0
    edge_num = 0
    node_num = 0
    
    for volume in volume_list:
        if volume.endswith('118'):
            begin_time = time.time()
        print("Loading {} ...".format(volume))
        with open(volume,'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                envt_num += 1
                if record_type == 'Event':
                    event = parse_event_trace(node_buffer, record_datum, args.cdm_version)
                    if event:
                        if event.type == 'set_uid':
                            event.parameters = int(principals_buffer[event.parameters]['userId'])
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str:
                            last_event_str = event_str
                            edge_num += 1
                            log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                            print(json.dumps(log_datum), file = output_file)
                elif record_type == 'Subject':
                    subject = parse_subject_trace(record_datum,args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                        log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                        print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                elif record_type == 'Principal':
                    record_datum['euid'] = record_datum['properties']['map']['euid']
                    del record_datum['hostId']
                    del record_datum['properties']
                    principals_buffer[record_datum['uuid']] = record_datum
                    log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                    print(json.dumps(log_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_trace(record_datum,record_type)
                    if object:
                        node_buffer[object.id] = object
                        log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                        print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
                    pass
                else:
                    pass

    output_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {:,}".format(node_num))
    print("#Edges: {:,}".format(edge_num))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)
    # parser.add_argument("--volume_num", type=int)
    args = parser.parse_args()

    start_experiment(args)

