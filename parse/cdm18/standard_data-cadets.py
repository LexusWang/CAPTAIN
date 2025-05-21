'''
This script is used to transfer the CADETS data in CDM 18 format 
(used in DARPA Engagement 3) to the standard format.

After the tranlation is finished, the data will be saved in the log.json
file in the output folder.
'''

import json
import os
import argparse
import time
import pdb

import sys
sys.path.extend(['.','..','...'])
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from parse.cdm18.eventType import cdm_events, READ_SET, WRITE_SET, INJECT_SET, CHMOD_SET, SET_UID_SET, EXECVE_SET, LOAD_SET, CREATE_SET, RENAME_SET, REMOVE_SET, CLONE_SET, MPROTECT_SET, MMAP_SET, UPDATE_SET, EXIT_SET, UNUSED_SET
from parse.utils import memory_protection

def parse_event_cadets(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    event.properties = datum['properties']['map']

    ##### Get Related Nodes #####
    if isinstance(datum['subject'], dict):
        event.src = datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    ##### Check if the nodes get updated #####
    node_updates = {}
    if isinstance(datum['predicateObjectPath'], dict):
        event.obj_path = datum['predicateObjectPath']['string']
        if event.dest in node_buffer and node_buffer[event.dest].path != event.obj_path:
            node_buffer[event.dest].name = event.obj_path
            node_buffer[event.dest].path = event.obj_path
            node_updates[event.dest] = {'name':event.obj_path}

    if isinstance(datum['predicateObject2Path'], dict):
        event.obj2_path = datum['predicateObject2Path']['string']
        if event.dest2 in node_buffer and node_buffer[event.dest2].path != event.obj2_path:
            node_buffer[event.dest2].name = event.obj2_path
            node_buffer[event.dest2].path = event.obj2_path
            node_updates[event.dest2] = {'name':event.obj2_path}

    if 'exec' in event.properties:
        if event.src in node_buffer and node_buffer[event.src].processName != event.properties['exec']:
            node_buffer[event.src].processName = event.properties['exec']
            node_updates[event.src] = {'exec':event.properties['exec']}

    ##### Begin Parsing Event Type #####
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
            if datum['name']['string'] == 'aue_chmod':
                assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
                event.type = 'chmod'
                event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
            else:
                return None, node_updates  
        elif datum['type'] in SET_UID_SET:
            if datum['name']['string'] in {'aue_setuid'}:
                assert node_buffer.get(event.src, None)
                event.dest = None
                event.type = 'set_uid'
                event.parameters = int(datum['properties']['map']['arg_uid'])
            else:
                return None, node_updates
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.parameters = datum['properties']['map']['cmdLine']
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            pdb.set_trace()
            return None, node_updates
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            if node_buffer[event.dest].isFile():
                assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
                event.type = 'load'
            else:
                pdb.set_trace()
                event.type = 'mmap'
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            assert datum['name']['string'] not in {'aue_socketpair', 'aue_mkdirat'}
            if node_buffer.get(event.src, None) and node_buffer.get(event.dest, None):
                event.type = 'create'
            else:
                return None, node_updates
        elif datum['type'] in RENAME_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.parameters = datum['predicateObjectPath']['string']
            event.type = 'rename'
        elif datum['type'] in REMOVE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            assert node_buffer.get(event.src, None)
            event.dest == None
            event.type = 'mprotect'
            event.parameters = eval(datum['properties']['map']['arg_mem_flags'])
        elif datum['type'] in UPDATE_SET:
            pdb.set_trace()
            event.type = 'update'
        elif datum['type'] in EXIT_SET:
            assert node_buffer.get(event.src, None)
            event.dest = None
            event.type = 'exit'
        else:
            return None, node_updates
    except AssertionError as ae:
        return None, node_updates
    
    return event, node_updates

def parse_subject_cadets(node_buffer, datum, cdm_version=18):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        pname_ = datum['properties'].get('name', None)
        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            ppid_ = node_buffer[parent_].pid
        cmdLine_ = datum['cmdLine']
        subject = Subject(id=datum['uuid'], type = datum['type'], pid = datum['cid'], ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        subject.owner = datum['localPrincipal']
    elif subject_type in {'SUBJECT_THREAD', 'SUBJECT_UNIT', 'SUBJECT_BASIC_BLOCK'}:
        return None
    else:
        return None
    
    return subject


def parse_object_cadets(datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if object_type == 'FileObject':
        ## We ignore all other types of file
        if datum['type'] != 'FILE_OBJECT_FILE':
            return None
        object.subtype = datum['type']
        ## Usually it is null
        object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'NetFlowObject':
        object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type in {'UnnamedPipeObject', 'RegistryKeyObject', 'PacketSocketObject', 'SrcSinkObject'}:
        return None
    else:
        return None

    return object

def start_experiment(args):
    ## Load File Names
    file_list = ['ta1-cadets-e3-official.json/ta1-cadets-e3-official.json',
                 'ta1-cadets-e3-official.json/ta1-cadets-e3-official.json.1',
                 'ta1-cadets-e3-official.json/ta1-cadets-e3-official.json.2',
                 'ta1-cadets-e3-official-1.json/ta1-cadets-e3-official-1.json',
                 'ta1-cadets-e3-official-1.json/ta1-cadets-e3-official-1.json.1',
                 'ta1-cadets-e3-official-1.json/ta1-cadets-e3-official-1.json.2',
                 'ta1-cadets-e3-official-1.json/ta1-cadets-e3-official-1.json.3',
                 'ta1-cadets-e3-official-1.json/ta1-cadets-e3-official-1.json.4',
                 'ta1-cadets-e3-official-2.json/ta1-cadets-e3-official-2.json',
                 'ta1-cadets-e3-official-2.json/ta1-cadets-e3-official-2.json.1',
                 ]
    volume_list = []
    for file in file_list:
        volume_list.append(os.path.join(args.input_data, file))
    
    ##### Set Up Necessary Data Structure #####

    node_buffer = {}
    last_event_str = ''
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0
    envt_num = 0
    edge_num = 0
    node_num = 0

    begin_time = time.time()
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    for volume in volume_list:
        print(f"Loading {volume} ...")
        with open(volume,'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == "Event":
                    envt_num += 1
                    event, node_updates = parse_event_cadets(node_buffer, record_datum, args.cdm_version)
                    for key, value in node_updates.items():
                        if key in node_set:
                            update_evnt = {'type': 'UPDATE', 'nid': key, 'value': value}
                            log_datum = {'logType':'EVENT', 'logData': update_evnt}
                            print(json.dumps(log_datum), file = output_file)
                    if event:
                        for nid in [event.src, event.dest, event.dest2]:
                            if nid not in node_set:
                                node_set.add(nid)
                                node = node_buffer.get(nid, None)
                                if node:
                                    log_datum = {'logType':'NODE', 'logData': json.loads(node.dumps())}
                                    print(json.dumps(log_datum), file = output_file)
                                    node_num += 1
                        if node_buffer.get(event.src, None):
                            event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                            if event_str != last_event_str:
                                last_event_str = event_str
                                log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                                print(json.dumps(log_datum), file = output_file)
                                edge_num += 1
                elif record_type == 'Subject':
                    subject = parse_subject_cadets(node_buffer, record_datum, args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                elif record_type == 'Principal':
                    record_datum['username'] = record_datum['username']['string']
                    del record_datum['hostId']
                    # del record_datum['properties']
                    log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                    print(json.dumps(log_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_cadets(record_datum, record_type)
                    if object:
                        node_buffer[object.id] = object
                elif record_type == 'Host':
                    node_buffer = {}
                    last_event_str = ''
                    node_set = set()
                    log_datum = {'logType':'CTL_EVENT_REBOOT', 'logData': {}}
                    print(json.dumps(log_datum), file = output_file)
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

    args = parser.parse_args()

    start_experiment(args)
