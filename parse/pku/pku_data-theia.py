import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
import pdb
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from parse.cdm18.eventType import EXECVE_SET, SET_UID_SET, lttng_events, cdm_events, standard_events
from parse.cdm18.eventType import READ_SET, WRITE_SET, INJECT_SET, CHMOD_SET, SET_UID_SET, EXECVE_SET, LOAD_SET, CREATE_SET, RENAME_SET, REMOVE_SET, CLONE_SET, MPROTECT_SET, MMAP_SET, UPDATE_SET, EXIT_SET, UNUSED_SET


def parse_event_theia(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    event.properties = datum['properties']['map']

    ##### Get Related Nodes #####
    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]

    ##### Begin Parsing Event Type #####
    try:
        if datum['type'] in {'EVENT_READ'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'read'
            event.dest2 = None
        elif datum['type'] in {'EVENT_RECVFROM'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'recvfrom'
            event.dest2 = None
        elif datum['type'] in {'EVENT_RECVMSG'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'recvmsg'
            event.dest2 = None
        elif datum['type'] in {'EVENT_WRITE'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'write'
            event.dest2 = None
        elif datum['type'] in {'EVENT_SENDTO'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'sendto'
            event.dest2 = None
        elif datum['type'] in {'EVENT_SENDMSG'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'sendmsg'
            event.dest2 = None
        elif datum['type'] in {'EVENT_MODIFY_FILE_ATTRIBUTES'}:
            # if datum['name']['string'] == 'chown':
            #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            #     event.type = 'chown'
            #     event.parameters = (datum['properties']['map']['uid'], datum['properties']['map']['gid'])
            #     event.dest2 = None
            if datum['name']['string'] == 'chmod':
                assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
                event.type = 'chmod'
                event.dest2 = None
                event.parameters = None
            else:
                return None
        # elif datum['type'] in SET_UID_SET:
        #     pdb.set_trace()
        #     assert node_buffer.get(event.src, None)
        #     if datum['properties']['map']['operation'] == 'setuid':
        #         event.type = 'set_uid'
        #         event.src = event.dest
        #         event.dest = None
        #         event.parameters = node_buffer.get(event.src, None).owner
        #     else:
        #         return None
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest, None).isFile()
            event.dest2 = None
            event.type = 'execve'
            event.parameters = datum['properties']['map']['cmdLine']
        # elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
        #     pdb.set_trace()
        #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
        #     event.type = 'execve'
        # elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        #     if datum['name']['string'] == 'mmap':
        #         assert node_buffer.get(event.src, None)
        #         if node_buffer.get(event.dest, None) and node_buffer[event.dest].isFile():
        #             pdb.set_trace()
        #             event.type = 'load'
        #             event.dest2 = None
        #         elif node_buffer.get(event.dest2, None) and node_buffer[event.dest2].isFile():
        #             event.type = 'load'
        #             event.dest = event.dest2
        #             event.dest2 = None
        #         else:
        #             pdb.set_trace()
        #             event.type = 'mmap'
        #             event.dest = None
        #             event.dest2 = None
        #             event.parameters = event.properties['prot'].split('|')
        #     else:
        #         return None
        elif datum['type'] in {'EVENT_CREATE_OBJECT'}:
            pdb.set_trace()
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'create'
            event.dest2 = None
        elif datum['type'] in {'EVENT_RENAME'}:
            pdb.set_trace()
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.type = 'rename'
            event.dest2 = None
        elif datum['type'] in {'EVENT_UNLINK'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.dest2 = None
            event.type = 'remove'
        elif datum['type'] in {"EVENT_CLONE"}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
            event.dest2 = None
        elif datum['type'] in {"EVENT_FORK"}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'fork'
            event.dest2 = None
        # elif datum['type'] in MPROTECT_SET:
        #     if datum['name']['string'] == 'mprotect':
        #         assert node_buffer.get(event.src, None)
        #         event.type = 'mprotect'
        #         event.dest = None
        #         event.dest2 = None
        #         event.parameters = event.properties['prot'].split('|')
        #     else:
        #         return None
        # elif datum['type'] in UPDATE_SET:
        #     pdb.set_trace()
        #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
        #     event.type = 'update'
        # elif datum['type'] in EXIT_SET:
        #     pdb.set_trace()
        #     assert node_buffer.get(event.src, None)
        #     event.dest = None
        #     event.type = 'exit'
        else:
            return None
    except AssertionError as ae:
        return None 
    
    return event

def parse_subject_theia(datum, cdm_version=18):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = int(datum['properties']['map'].get('tgid', None))
        pname_ = datum['properties']['map'].get('path', None)
        ppid_ = None
        if datum['properties']['map'].get('ppid', None):
            ppid_ = int(datum['properties']['map'].get('ppid', None))
        parent_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
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

def parse_object_theia(datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if object_type == 'FileObject':
        object.subtype = datum['type']
        object.name = datum['baseObject']['properties']['map'].get('filename',None)
        object.path = datum['baseObject']['properties']['map'].get('filename', None)
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        return None
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'NetFlowObject':
        object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
        object.pku_ip = f"{datum['localAddress']}:{datum['localPort']}->{datum['remoteAddress']}:{datum['remotePort']}"
    elif object_type == 'MemoryObject':
        return None
    elif object_type == 'SrcSinkObject':
        return None
    else:
        return None

    return object

def start_experiment(args):
    # output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')
    train_data_file = open(os.path.join(args.output_data, 'benign.json'), 'w')
    test_data_file = open(os.path.join(args.output_data, 'anomaly.json'), 'w')

    ##### Load File Names #####
    volume_list = []
    for volume in range(10):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-1r.json', 'ta1-theia-e3-official-1r.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-1r.json', 'ta1-theia-e3-official-1r.json')+f'.{volume}')
    
    volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-3.json', 'ta1-theia-e3-official-3.json'))
    volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-5m.json', 'ta1-theia-e3-official-5m.json'))

    for volume in range(13):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-6r.json', 'ta1-theia-e3-official-6r.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-6r.json', 'ta1-theia-e3-official-6r.json')+f'.{volume}')

    last_event_str = ''
    node_buffer = {}
    principals_buffer = {}
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0
    envt_num = 0
    edge_num = 0
    node_num = 0
    
    begin_time = time.time()
    for volume in volume_list:
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
                    event = parse_event_theia(node_buffer, record_datum, args.cdm_version)
                    if event:
                        if event.type == 'set_uid':
                            event.parameters = int(principals_buffer[event.parameters]['userId'])
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
                            if pku_event["evt.time"] < 1523332800*1e9:
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
                                if len({event.src, event.type, event.dest} & {'80370C6E-1795-D04B-7503-500000000040', '80370C6E-1895-D04B-7503-500000000040', '80370C6E-1995-D04B-7503-500000000040',
                                                                              '80370C6E-6395-D04B-7503-500000000040','80370C6E-6495-D04B-7503-500000000040', '80370C6E-6595-D04B-7503-500000000040', '80370C6E-4C81-8D2B-B0CB-500000000040', '80370C6E-42AD-9299-4497-500000000040',
                                                                              '6818A92B-0000-0000-0000-000000000020', '80370C6E-AAB0-A174-5848-500000000040', '80370C6E-8581-8D2B-B0CB-500000000040', '80370C6E-7BAD-9299-4497-500000000040',
                                                                              'FB1F9E30-0000-0000-0000-000000000020', '80370C6E-64B2-A174-5848-500000000040', '80370C6E-2D96-8D2B-B0CB-500000000040', '80370C6E-4396-8D2B-B0CB-500000000040',
                                                                              '80370C6E-39C2-9299-4497-500000000040', '80370C6E-D2AA-9534-C617-500000000040'}) > 0:
                                    print(f'Malicious Node Involves in event: {event.id}')
                                    pku_event['is_warn'] = True
                                else:
                                    pku_event['is_warn'] = False
                            print(json.dumps(pku_event), file = output_file)
                            edge_num += 1
                            # pdb.set_trace()
                            # log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                            # print(json.dumps(log_datum), file = output_file)
                elif record_type == 'Subject':
                    subject = parse_subject_theia(record_datum,args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                        # log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                        # print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                # elif record_type == 'Principal':
                #     # record_datum['euid'] = record_datum['properties']['map']['euid']
                #     del record_datum['hostId']
                #     # del record_datum['properties']
                #     principals_buffer[record_datum['uuid']] = record_datum
                #     log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                #     print(json.dumps(log_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_theia(record_datum,record_type)
                    if object:
                        node_buffer[object.id] = object
                        # log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                        # print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                # elif record_type == 'Host':
                #     # node_buffer = {}
                #     # last_event_str = ''
                #     # node_set = set()
                #     log_datum = {'logType':'CTL_EVENT_REBOOT', 'logData': {}}
                #     print(json.dumps(log_datum), file = output_file)
                # elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency'}:
                #     pass
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
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--cdm_version", type=int)
    args = parser.parse_args()

    start_experiment(args)

