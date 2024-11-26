import json
import os
import argparse
import time
import pdb
import sys
sys.path.extend(['.','..','...'])
from utils.utils import *
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from datetime import datetime

def parse_object_optc(record_datum):
    object_type = record_datum['object']
    if object_type == 'PROCESS':
        object = Subject(id=record_datum['objectID'], type = object_type)
    else:
        object = Object(id=record_datum['objectID'], type = object_type)
    if object_type == 'FLOW':
        object.type = 'NetFlowObject'
        object.subtype = 'FLOW_OPTC'
        if record_datum.get('properties', {}).get('direction', None) == 'inbound':
            object.set_IP(record_datum['properties']['src_ip'], record_datum['properties']['src_port'], None)
        elif record_datum.get('properties', {}).get('direction', None) == 'outbound':
            object.set_IP(record_datum['properties']['dest_ip'], record_datum['properties']['dest_port'], None)
        else:
            return None
    elif object_type == 'PROCESS':
        return None
        # if record_datum['action'] != 'OPEN':
        #     object.type = 'SUBJECT_PROCESS'
        #     object.cmdLine = record_datum['properties'].get('command_line', None)
        # else:
        #     return None
    elif object_type == 'FILE':
        object.type = 'FileObject'
        object.subtype = 'FILE'
        path = record_datum.get('properties',{}).get('file_path', None)
        if path:
            object.name = path
            object.path = path
        else:
            return None
    elif object_type == 'MODULE':
        return None
    elif object_type == 'THREAD':
        return None
    elif object_type == 'REGISTRY':
        return None
    elif object_type == 'TASK':
        return None
    elif object_type == 'SHELL':
        return None
    elif object_type == 'HOST':
        return None
    elif object_type == 'SERVICE':
        return None
    elif object_type == 'USER_SESSION':
        return None
    return object
    
def parse_subject_optc(record_datum):
    pid_ = record_datum['pid']
    ppid_= record_datum['ppid']
    principal_ = record_datum['principal']
    tid_ = record_datum['tid']
    properties = record_datum['properties']
    image_path = record_datum['properties'].get('image_path', None)
    if image_path:
        pname_ = image_path.split('\\')[-1]
    else:
        pname_ = None
    parent_ = None
    cmdLine_ = None
    subject = Subject(id=record_datum['actorID'], type = 'SUBJECT_PROCESS', pid = record_datum['pid'], ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
    return subject

def parse_event_optc(log_data, node_buffer):
    dt = datetime.fromisoformat(log_data['timestamp'])
    ts_nano = int(dt.timestamp()*1e9)
    event = Event(log_data['id'], ts_nano)
    event_type = log_data['action']
    # event.properties = datum['properties']['map']

    if log_data['actorID'] and log_data['actorID'] != '00000000-0000-0000-0000-000000000000':
        event.src = log_data['actorID']
    
    if log_data['objectID'] and log_data['objectID'] != '00000000-0000-0000-0000-000000000000':
        event.dest = log_data['objectID']

    try:
        if log_data['object'] == 'FLOW':
            if event_type in {'MESSAGE'}:
                assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
                if log_data.get('properties', {}).get('direction', None) == 'inbound':
                    event.type = 'read'
                elif log_data.get('properties', {}).get('direction', None) == 'outbound':
                    event.type = 'write'
        elif log_data['object'] == 'FILE':
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            if event_type in {'WRITE'}:
                event.type = 'write'
            elif event_type in {'READ'}:
                event.type = 'read'
            elif event_type in {'CREATE'}:
                event.type = 'create'
            elif event_type in {'DELETE'}:
                event.type = 'remove'
            elif event_type in {'MODIFY'}:
                return None
            elif event_type in {'RENAME'}:
                event.type = 'rename'
                event.parameters = log_data['properties']['new_path']
            else:
                return None
        elif log_data['object'] == 'PROCESS':
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            if event_type in {'CREATE'}:
                event.type = 'clone'
            elif event_type in {'OPEN'}:
                event.type = 'open_process'
            elif event_type in {'TERMINATE'}:
                event.type = 'terminate'
        else:
            return None
    except AssertionError as ae:
        return None
    
    if event.type:
        return event
    else:
        return None

def start_experiment(args):
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    # ##### Load File Names #####
    # volume_list = []
    # for v_index in range(191):
    #     for sv_index in ['', '.1', '.2']:
    #         volume_list.append("ta1-trace-2-e5-official-1.bin.{}.json{}".format(v_index, sv_index))
    # volume_list = volume_list[:-1]

    last_event_str = ''
    node_buffer = {}
    # principals_buffer = {}
    # node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0    
    envt_num = 0
    edge_num = 0
    node_num = 0
    
    # ##### Object Version Control #####
    # object_latest_version = {}

    begin_time = time.time()
    decoder = json.JSONDecoder()
    
    volume_list = ['optc-train.json'] 
    for volume in volume_list:
        print("Loading {} ...".format(volume))
        with open(os.path.join(args.input_data, volume),'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                record_datum = decoder.decode(line)
                record_type = record_datum['action']
                # if record_type == 'Event':
                subject = parse_subject_optc(record_datum)
                if subject and subject.id not in node_buffer:
                    node_buffer[subject.id] = subject
                    log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                    output_file.write(json.dumps(log_datum)+'\n')
                    node_num += 1
                
                object = parse_object_optc(record_datum)
                if object and object.id not in node_buffer:
                    node_buffer[object.id] = object
                    log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                    output_file.write(json.dumps(log_datum)+'\n')
                    node_num += 1
                    
                # if record_datum['principal'] not in principals_buffer:
                #     record_datum['euid'] = record_datum['properties']['map']['euid']
                #     del record_datum['properties']
                #     principals_buffer[record_datum['uuid']] = record_datum
                #     log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                #     output_file.write(json.dumps(log_datum)+'\n')
    
                event = parse_event_optc(record_datum, node_buffer)
                if event:
                    event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                    if event_str != last_event_str:
                        last_event_str = event_str
                        edge_num += 1
                        log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                        output_file.write(json.dumps(log_datum)+'\n')

    output_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(loaded_line))
    print("#Nodes: {:,}".format(node_num))
    print("#Edges: {:,}".format(edge_num))
    
    
def main():
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str, default = '/home/lwk0770/projects/data/optc')
    parser.add_argument("--output_data", type=str, default = 'data/optc')
    args = parser.parse_args()

    start_experiment(args)


if __name__ == '__main__':
    # import cProfile
    # cProfile.run("main()")
    main()
