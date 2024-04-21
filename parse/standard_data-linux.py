import json
from json.decoder import JSONDecodeError
import os
import argparse
import time
from utils.utils import *
import time
import pdb

def start_experiment(args):
    begin_time = time.time()

    node_file = open(os.path.join(args.output_data, 'nodes.json'), 'w')
    edge_file = open(os.path.join(args.output_data, 'edges.json'), 'w')
    principal_file = open(os.path.join(args.output_data, 'principals.json'), 'w')

    uuid_nid_mapping = {}
    principal_dict = {}
    principal_name = set()
    node_dict = {}
    file_uuid_mapping = {}

    loaded_line = 0
    last_event_str = ''
    volume_list = [file for file in os.listdir(args.input_data) if file.startswith('.') == False]
    volume_list = sorted(volume_list)
    
    envt_num = 0
    edge_num = 0
    nodes_num = 0
    
    for volume in volume_list:
        print("Loading the {} ...".format(volume))
        with open(os.path.join(args.input_data, volume),'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                try:
                    record_datum = json.loads(line)
                except JSONDecodeError as e:
                    continue
                if 'log_name' in record_datum and record_datum['log_name'] in {'ClientPolicyUpdate', 'DNSQuery'}:
                    continue
                if 'event_type' not in record_datum:
                    pdb.set_trace()
                if record_datum['event_type'] > 37 or record_datum['event_type'] < 1:
                    continue
                envt_num += 1
                if 'user' in record_datum and record_datum['user'] not in principal_name:
                    principal = {'uuid':record_datum['user'], 'name': record_datum['user']}
                    print(json.dumps(principal), file = principal_file)
                    principal_name.add(record_datum['user'])
                subject, object, object2, event = mo.parse_event(record_datum, args.format, None)
                if subject:
                    if subject.id not in node_dict:
                        node_dict[subject.id] = subject
                        mo.add_subject(subject)
                        uuid_nid_mapping[subject.id] = nodes_num
                        subject.id = nodes_num
                        nodes_num += 1
                        print(subject.dumps(), file = node_file)
                    else:
                        if subject.cmdLine != node_dict[subject.id].cmdLine:
                            update_evnt = {'type': 'UPDATE', 'nid': uuid_nid_mapping[subject.id], 'value': {'cmdl':subject.cmdLine}}
                            print(json.dumps(update_evnt), file = edge_file)
                if object:
                    if event.type == 'chmod':
                        if object.get_name() in file_uuid_mapping:
                            object.id = file_uuid_mapping[object.get_name()]
                            event.dest = file_uuid_mapping[object.get_name()]
                        else:
                            object.id = str(hash(object.get_name()))
                            event.dest = object.id

                    if object.id not in node_dict:
                        node_dict[object.id] = object
                        mo.add_object(object)
                        file_uuid_mapping[object.get_name()] = object.id
                        uuid_nid_mapping[object.id] = nodes_num
                        object.id = nodes_num
                        nodes_num += 1
                        print(object.dumps(), file = node_file)
                    else:
                        pass
                if object2:
                    if object2.id not in node_dict:
                        node_dict[object2.id] = object2
                        mo.add_object(object2)
                        file_uuid_mapping[object2.get_name()] = object2.id
                        uuid_nid_mapping[object2.id] = nodes_num
                        object2.id = nodes_num
                        nodes_num += 1
                        print(object2.dumps(), file = node_file)
                    else:
                        pass
                if event:
                    event.src = uuid_nid_mapping.get(event.src, None)
                    event.dest = uuid_nid_mapping.get(event.dest, None)
                    event.dest2 = uuid_nid_mapping.get(event.dest2, None)
                    event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                    if event_str != last_event_str and (event.src!=None):
                        last_event_str = event_str
                        edge_num += 1
                        print(event.dumps(), file = edge_file)

    node_file.close()
    edge_file.close()
    principal_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {}".format(nodes_num))
    print("#Edges: {:,}".format(edge_num))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--format", type=str)

    args = parser.parse_args()

    start_experiment(args)