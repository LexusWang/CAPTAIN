'''
This script is used to transfer the FiveDirections data in CDM 18 format 
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

from model.captain import CAPTAIN
import pdb
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from parse.cdm18.eventType import cdm_events, READ_SET, WRITE_SET, INJECT_SET, CHMOD_SET, SET_UID_SET, EXECVE_SET, LOAD_SET, CREATE_SET, RENAME_SET, REMOVE_SET, CLONE_SET, MPROTECT_SET, MMAP_SET, UPDATE_SET, EXIT_SET, UNUSED_SET
from parse.utils import memory_protection

def parse_event_fivedirections(self, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    node_updates = {}

    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]

    if isinstance(datum['predicateObjectPath'], dict):
        obj_path = datum['predicateObjectPath']['string']
        if self.Nodes.get(event.dest, None) and self.Nodes[event.dest].path == None:
            self.Nodes[event.dest].name = obj_path
            self.Nodes[event.dest].path = obj_path
            node_updates[event.dest] = {'name': obj_path}

    if isinstance(datum['predicateObject2Path'], dict):
        obj2_path = datum['predicateObject2Path']['string']
        if self.Nodes.get(event.dest2, None) and self.Nodes[event.dest2].path == None:
            self.Nodes[event.dest2].name = obj2_path
            self.Nodes[event.dest2].path = obj2_path
            node_updates[event.dest2] = {'name': obj2_path}

    try:
        if datum['type'] in READ_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in WRITE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            object = self.Nodes.get(event.dest, None)
            if isinstance(object, Object):
                event.type = 'write'
                if object.isIP():
                    event.parameters = {'size':datum['size']}
            else:
                # event.type = 'inject'
                return None, node_updates
        elif datum['type'] in INJECT_SET:
            event.type = 'inject'
        elif datum['type'] in CHMOD_SET:
            # event.type = 'chmod'
            return None, node_updates
        elif datum['type'] in SET_UID_SET:
            # event.type = 'set_uid'
            return None, node_updates
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.parameters = datum['predicateObjectPath']['string']
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'load'
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            if self.Nodes[event.dest].isFile():
                event.type = 'load'
            else:
                event.type = 'mmap'
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'create'
        elif datum['type'] in RENAME_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'rename'
        elif datum['type'] in REMOVE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.parameters = datum['properties']['map']
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            pdb.set_trace()
            event.type = 'mprotect'
            event.parameters = eval(datum['properties']['map']['arg_mem_flags'])
        elif datum['type'] in UPDATE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            pdb.set_trace()
            if self.Nodes.get(event.dest2, None):
                event.type = 'update'
            else:
                return None, node_updates
        elif datum['type'] in EXIT_SET:
            assert self.Nodes.get(event.src, None)
            event.parameters = datum['properties']['map']
            event.type = 'exit'
        else:
            return None, node_updates
    except AssertionError as ae:
        return None, node_updates
    
    return event, node_updates

def parse_subject_fivedirections(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        parent_ = None
        ppid_ = None
        cmdLine_ = None
        pname_ = None
        if datum['parentSubject']:
            parent_ = list(datum['parentSubject'].values())[0]
            ppid_ = self.Nodes[parent_].pid
        if datum['cmdLine']:
            cmdLine_ = datum['cmdLine']['string']
            pname_ = datum['cmdLine']['string']
        subject = Subject(id=datum['uuid'], type = datum['type'], pid = datum['cid'], ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        if isinstance(datum['localPrincipal'], dict):
            subject.owner = datum['localPrincipal']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        else:
            subject.owner = datum['localPrincipal']
    elif subject_type == 'SUBJECT_THREAD':
        pass
    elif subject_type == 'SUBJECT_UNIT':
        pass
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        pass
    else:
        pass
    
    return subject

def parse_object_fivedirections(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    # if isinstance(datum['baseObject']['epoch'], dict):
    #     object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        object.subtype = datum['type']
        if datum['baseObject']['properties']:
            object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'NetFlowObject':
        if datum['remoteAddress'] == '' or datum['remotePort'] == '':
            return None
        else:
            object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        object.subtype = 'RegistryKeyObject'
        object.name = datum['key']
        # object.value = list(datum['value'].values())[0]
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type == 'SrcSinkObject':
        return None
        # object.subtype = datum['type']
        # if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
        #     return None
        # elif object.subtype in {'SRCSINK_DATABASE','SRCSINK_PROCESS_MANAGEMENT'}:
        #     object.name = object.subtype
        # else:
        #     print('New SrcSink Object Type!!!')
        #     print(datum)
    else:
        pass

    return object

def start_experiment(args):
    begin_time = time.time()
    mo = CAPTAIN(0, 0)

    node_file = open(os.path.join(args.output_data, 'nodes.json'), 'w')
    edge_file = open(os.path.join(args.output_data, 'edges.json'), 'w')
    principal_file = open(os.path.join(args.output_data, 'principals.json'), 'w')

    uuid_nid_mapping = {}

    loaded_line = 0
    last_event_str = ''
    volume_list = [file for file in os.listdir(args.input_data) if file.startswith('.') == False]
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[-1]))
    node_set = set()

    envt_num = 0
    edge_num = 0
    node_num = 0
    
    for volume in volume_list:
        print("Loading the {} ...".format(volume))
        with open(os.path.join(args.input_data, volume),'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                if line.endswith(',\n'):
                    line = line[:-2]
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Subject':
                    subject = parse_subject_fivedirections(mo, record_datum, args.cdm_version)
                    if subject:
                        mo.add_subject(subject)
                        uuid_nid_mapping[subject.id] = node_num
                        subject.id = node_num
                        node_num += 1
                elif record_type.endswith('Object'):
                    object = parse_object_fivedirections(mo, record_datum, record_type)
                    if object:
                        mo.add_object(object)
                        uuid_nid_mapping[object.id] = node_num
                        object.id = node_num
                        node_num += 1
                elif record_type == 'Principal':
                    if record_datum['username']:
                        record_datum['username'] = record_datum['username']['string']
                    del record_datum['hostId']
                    del record_datum['properties']
                    print(json.dumps(record_datum), file = principal_file)
                elif record_type == 'TimeMarker':
                    pass
                elif record_type == 'StartMarker':
                    pass
                elif record_type == 'UnitDependency':
                    pass
                elif record_type == 'Host':
                    pass
                else:
                    pass
    
    loaded_line = 0
    for volume in volume_list:
        print("Loading the {} ...".format(volume))
        with open(os.path.join(args.input_data, volume),'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                if line.endswith(',\n'):
                    line = line[:-2]
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Event':
                    envt_num += 1
                    event, node_updates = parse_event_fivedirections(mo, record_datum, args.cdm_version)
                    for key, value in node_updates.items():
                        if key in uuid_nid_mapping:
                            update_evnt = {'type': 'UPDATE', 'nid': uuid_nid_mapping[key], 'value': value}
                            print(json.dumps(update_evnt), file = edge_file)
                    if event:
                        event.src = uuid_nid_mapping.get(event.src, None)
                        event.dest = uuid_nid_mapping.get(event.dest, None)
                        event.dest2 = uuid_nid_mapping.get(event.dest2, None)
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str and event.src != None:
                            last_event_str = event_str
                            print(event.dumps(), file = edge_file)
                            edge_num += 1

    for nid, node in mo.Nodes.items():
        print(node.dumps(), file = node_file)

    node_file.close()
    edge_file.close()
    principal_file.close()
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

