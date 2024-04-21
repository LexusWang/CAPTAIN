import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from utils.eventClassifier import eventClassifier
from utils.utils import *

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
        # object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
        object.pku_ip = f"{datum['localAddress']}:{datum['localPort']}->{datum['remoteAddress']}:{datum['remotePort']}"
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type in {'UnnamedPipeObject', 'RegistryKeyObject', 'PacketSocketObject', 'SrcSinkObject'}:
        return None
    else:
        return None

    return object

def parse_event_cadets(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
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
            
    # a = node_buffer.get(event.src, None) 
    # b = node_buffer.get(event.dest, None)

    ##### Begin Parsing Event Type #####
    try:
        if datum['type'] in {'EVENT_READ'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in {'EVENT_RECVFROM'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'recvfrom'
        elif datum['type'] in {'EVENT_RECVMSG'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'recvmsg'
        elif datum['type'] in {'EVENT_WRITE'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'write'
        elif datum['type'] in {'EVENT_SENDTO'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'sendto'
        elif datum['type'] in {'EVENT_SENDMSG'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'sendmsg'
        elif datum['type'] in {'EVENT_MODIFY_FILE_ATTRIBUTES'}:
            if datum['name']['string'] == 'aue_chmod':
                assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
                event.type = 'chmod'
                event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
            else:
                return None, node_updates  
        elif datum['type'] in {'EVENT_EXECUTE'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.parameters = datum['properties']['map']['cmdLine']
            node_buffer.get(event.src).cmdLine = datum['properties']['map']['cmdLine']
            event.type = 'execve'
        elif datum['type'] in {'EVENT_CREATE_OBJECT'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            assert datum['name']['string'] not in {'aue_socketpair', 'aue_mkdirat'}
            if node_buffer.get(event.src, None) and node_buffer.get(event.dest, None):
                event.type = 'create'
            else:
                return None, node_updates
        elif datum['type'] in {'EVENT_RENAME'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.parameters = datum['predicateObjectPath']['string']
            event.type = 'rename'
        # elif datum['type'] in REMOVE_SET:
        #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
        #     event.type = 'remove'
        elif datum['type'] in {"EVENT_CLONE"}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in {"EVENT_FORK"}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'fork'
        else:
            return None, node_updates
    except AssertionError as ae:
        return None, node_updates
    
    return event, node_updates


def start_experiment(args):
    # output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')
    train_data_file = open(os.path.join(args.output_data, 'benign.json'), 'w')
    test_data_file = open(os.path.join(args.output_data, 'anomaly.json'), 'w')
    
    ec = eventClassifier(args.ground_truth_file)

    ##### Load File Names #####
    file_list = [
                 'ta1-cadets-e3-official.json/ta1-cadets-e3-official.json',
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

    node_buffer = {}
    last_event_str = ''
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0
    envt_num = 0
    edge_num = 0
    node_num = 0

    begin_time = time.time()

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
                        if key in node_buffer:
                            if 'exec' in value:
                                node_buffer[key].processName = value['exec']
                            elif 'name' in value:
                                node_buffer[key].name = value['name']
                                node_buffer[key].path = value['name']
                            elif 'cmdl' in value:
                                node_buffer[key].cmdLine = value['cmdl']
                            # update_evnt = {'type': 'UPDATE', 'nid': key, 'value': value}
                            # log_datum = {'logType':'EVENT', 'logData': update_evnt}
                            # print(json.dumps(log_datum), file = output_file)
                    if event:
                        # for nid in [event.src, event.dest, event.dest2]:
                        #     if nid not in node_set:
                        #         node_set.add(nid)
                        #         node = node_buffer.get(nid, None)
                        #         if node:
                        #             log_datum = {'logType':'NODE', 'logData': json.loads(node.dumps())}
                        #             print(json.dumps(log_datum), file = output_file)
                        #             node_num += 1
                        if node_buffer.get(event.src, None):
                            event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                            if event_str != last_event_str:
                                last_event_str = event_str
                                pku_event = {"evt.time": event.time, "evt.type": event.type, "evt.num": edge_num}
                                if event.type in {"read", "readv", "write", "writev", "fcntl", "rmdir", "rename", "chmod", "create"}:
                                    pku_event['proc.cmdline'] = f"{node_buffer.get(event.src, None).pid} {node_buffer.get(event.src, None).processName} {node_buffer.get(event.src, None).cmdLine}"
                                    pku_event['fd.name'] = node_buffer.get(event.dest, None).path
                                elif event.type in {"clone", "pipe", "fork"}:
                                    pku_event['proc.pcmdline'] = f"{node_buffer.get(event.src, None).pid} {node_buffer.get(event.src, None).processName} {node_buffer.get(event.src, None).cmdLine}"
                                    pku_event['proc.cmdline'] = f"{node_buffer.get(event.dest, None).pid} {node_buffer.get(event.dest, None).processName} {node_buffer.get(event.dest, None).cmdLine}"
                                elif event.type in {'execve'}:
                                    parent_nid = node_buffer.get(event.src, None).parentNode
                                    if parent_nid:
                                        parent_subject = node_buffer.get(parent_nid, None)
                                    if parent_subject:
                                        pku_event['proc.pcmdline'] = f"{parent_subject.pid} {parent_subject.processName} {parent_subject.cmdLine}"
                                        # if parent_subject.cmdLine:
                                        #     pku_event['proc.pcmdline'] = parent_subject.cmdLine
                                        # else:
                                        #     pku_event['proc.pcmdline'] = parent_subject.processName
                                        
                                    pku_event['proc.cmdline'] = f"{node_buffer.get(event.src, None).pid} {node_buffer.get(event.src, None).processName} {node_buffer.get(event.src, None).cmdLine}"
                                elif event.type in {"sendmsg", "recvmsg", "recvfrom", "send", "sendto"}:
                                    pku_event['proc.cmdline'] = f"{node_buffer.get(event.src, None).pid} {node_buffer.get(event.src, None).processName} {node_buffer.get(event.src, None).cmdLine}"
                                    pku_event['fd.name'] = node_buffer.get(event.dest, None).pku_ip
                                ## The start time of testing is 2018-4-6T00:00:00-04:00
                                if pku_event["evt.time"] < 1522987200*1e9:
                                    output_file = train_data_file
                                else:
                                    output_file = test_data_file
                                    ## Assign is_warn using event labels
                                    # gt = ec.classify(event.id)
                                    # if gt:
                                    #     pku_event['is_warn'] = True
                                    # else:
                                    #     pku_event['is_warn'] = False
                                    
                                    ## Assign is_warn using node labels
                                    if len({event.src, event.type, event.dest} & {'D3822AFC-39AF-11E8-BF66-D9AA8AFF4A69', 'DCBB8D5C-3E7F-11E8-A5CB-3FA3753A265A', '0001A528-3E80-11E8-A5CB-3FA3753A265A', '327621AE-3E80-11E8-A5CB-3FA3753A265A', '47E61FFC-3E80-11E8-A5CB-3FA3753A265A'}) > 0:
                                        print(f'Malicious Node Involves in event: {event.id}')
                                        pku_event['is_warn'] = True
                                    else:
                                        pku_event['is_warn'] = False
                                print(json.dumps(pku_event), file = output_file)
                                edge_num += 1
                elif record_type == 'Subject':
                    subject = parse_subject_cadets(node_buffer, record_datum, args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                elif record_type == 'Principal':
                    pass
                elif record_type.endswith('Object'):
                    object = parse_object_cadets(record_datum, record_type)
                    if object:
                        node_buffer[object.id] = object
                elif record_type == 'Host':
                    pass
                else:
                    pass

    train_data_file.close()
    test_data_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {:,}".format(node_num))
    print("#Edges: {:,}".format(edge_num))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str, default = '../data/raw/')
    parser.add_argument("--output_data", type=str, default = 'data/pku-e3-cadets/')
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--cdm_version", type=int, default = 18)

    args = parser.parse_args()

    start_experiment(args)
