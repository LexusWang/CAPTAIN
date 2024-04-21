import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
import time
import pdb
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject

def memory_protection(permission: int):
    if permission < 0 or permission > 7:
        raise ValueError("Unvalid permission!!!")
    else:
        if permission == 0:
            return ['PROT_NONE']
        elif permission == 1:
            return ['PROT_EXEC']
        elif permission == 2:
            return ['PROT_WRITE']
        elif permission == 3:
            return ['PROT_WRITE', 'PROT_EXEC']
        elif permission == 4:
            return ['PROT_READ']
        elif permission == 5:
            return ['PROT_READ', 'PROT_EXEC']
        elif permission == 6:
            return ['PROT_READ', 'PROT_WRITE']
        elif permission == 7:
            return ['PROT_READ', 'PROT_WRITE', 'PROT_EXEC']

def parse_event_trace(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]

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
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'chmod'
            event.dest2 = None
            event.parameters = int(event.properties['mode'], 8)
        # elif datum['type'] in SET_UID_SET:
        #     assert node_buffer.get(event.src, None)
        #     if datum['properties']['map']['operation'] == 'setuid':
        #         event.type = 'set_uid'
        #         event.src = event.dest
        #         event.dest = None
        #         event.parameters = node_buffer.get(event.src, None).owner
        #     else:
        #         return None
        # elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
        #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
        #     event.type = 'update_process'
        elif datum['type'] in {'EVENT_LOADLIBRARY'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'execve'
            event.dest2 = None
        # elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        #     assert node_buffer.get(event.src, None)
        #     if node_buffer.get(event.dest, None) and node_buffer[event.dest].isFile():
        #         event.type = 'load'
        #         event.dest2 = None
        #     else:
        #         event.type = 'mmap'
        #         event.dest = None
        #         event.dest2 = None
        #         event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in {'EVENT_CREATE_OBJECT'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'create'
            event.dest2 = None
        elif datum['type'] in {'EVENT_RENAME'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.type = 'rename'
        elif datum['type'] in {'EVENT_UNLINK'}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in {"EVENT_CLONE"}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in {"EVENT_FORK"}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'fork'
        # elif datum['type'] in MPROTECT_SET:
        #     assert node_buffer.get(event.src, None)
        #     event.type = 'mprotect'
        #     event.dest = None
        #     event.dest2 = None
        #     event.parameters = memory_protection(eval(event.properties['protection']))
        # elif datum['type'] in UPDATE_SET:
        #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
        #     event.type = 'update'
        # elif datum['type'] in EXIT_SET:
        #     assert node_buffer.get(event.src, None)
        #     event.dest = None
        #     event.type = 'exit'
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
        if datum['type'] == 'FILE_OBJECT_FILE':
            object.subtype = datum['type']
            object.name = datum['baseObject']['properties']['map'].get('path',None)
            object.path = datum['baseObject']['properties']['map'].get('path', None)
        else:
            return None
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
        if datum.get('remoteAddress') == '':
            datum['remoteAddress'] = 'x.x.x.x'
        object.pku_ip = f"{datum.get('localAddress','unknown')}:{datum.get('localPort', 'unknown')}->{datum.get('remoteAddress', 'unknown')}:{datum.get('remotePort', 'unknown')}"
        try:
            import re
            s = object.pku_ip.strip().encode('ascii', errors='ignore').decode()
            if re.search(r'([0-9\.]*):([0-9]*)->([0-9\.]*):([0-9]*)',s):
                # s = s.replace('/32','')
                split_path = re.split('/|\.|,|:|-|>',s)
                split_path = [item for item in filter(lambda x:x != '',split_path)]
                split_path.pop(4)
                split_path.pop(8)
        except Exception:
            pdb.set_trace()
    elif object_type == 'MemoryObject':
        # object.name = 'MEM_{}'.format(datum['memoryAddress'])
        return None
    elif object_type == 'SrcSinkObject':
        return None
    else:
        return None

    return object

def start_experiment(args):
    train_data_file = open(os.path.join(args.output_data, 'benign.json'), 'w')
    test_data_file = open(os.path.join(args.output_data, 'anomaly.json'), 'w')

    ##### Load File Names #####
    volume_list = []
    for volume in range(204):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official.json', 'ta1-trace-e3-official.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official.json', 'ta1-trace-e3-official.json')+f'.{volume}')
    
    for volume in range(7):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official-1.json', 'ta1-trace-e3-official-1.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-trace-e3-official-1.json', 'ta1-trace-e3-official-1.json')+f'.{volume}')

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
                    event = parse_event_trace(node_buffer, record_datum, args.cdm_version)
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
                                if len({event.src, event.type, event.dest} & {'38E9D7FE-B6CC-64DF-8E8C-419DAF0F65EF','DC9ED747-EF99-64F2-06C2-5FFFC486A4EE','77628A05-FC72-F379-7F62-E56247B5EE83','5392E8E9-B18F-F8DB-1D36-B0C9ABA992FD','41BED274-6761-FF93-4254-9A966671956F','C9FE6BB4-870D-D742-8179-55B42F423770','07B7A85C-8367-6BB7-C9E5-70397F50D45C','190A4CE3-955A-E051-E3D1-5FE0AC85E95C','CAE9180E-98E9-A5FB-A375-E99EAECC8B7C','A494D8CF-50ED-5620-1FBE-07A0EE363991','93E0C854-95A4-FE1B-245B-6E217A409764','96FE4223-D38F-9D49-C00F-D51954FA7DD4','D64910E4-454E-156D-BF13-BC7AD66F7A6A','7E6F9A12-EDFA-C87E-B4D5-DB6C782DC6DC','2A25D735-8DD9-0026-DE60-544F311757AE','ECB97D8D-649C-9FF1-D5FF-F4B39229C1F0','CF66482C-33A3-8DFE-5713-A1BB54C5A7C0','964D9E8C-C3C8-5C07-9B68-3D0D0B590BBC','7169B097-1601-297F-2F6E-CEF5924F1C68','0BF26B23-2DE5-B70A-45F7-64BE377293F3','4687EC2F-9A87-42A2-4EF4-788DC5A9129A','BAD67782-9D71-3549-6673-5A18FE172EA2'}) > 0:
                                    print(f'Malicious Node Involves in event: {event.id}')
                                    pku_event['is_warn'] = True
                                else:
                                    pku_event['is_warn'] = False
                            print(json.dumps(pku_event), file = output_file)
                            edge_num += 1
                elif record_type == 'Subject':
                    subject = parse_subject_trace(record_datum,args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                        # log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                        # print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                # elif record_type == 'Principal':
                #     record_datum['euid'] = record_datum['properties']['map']['euid']
                #     del record_datum['hostId']
                #     del record_datum['properties']
                #     principals_buffer[record_datum['uuid']] = record_datum
                #     log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                #     print(json.dumps(log_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_trace(record_datum,record_type)
                    if object:
                        node_buffer[object.id] = object
                        # log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                        # print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                # elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
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

