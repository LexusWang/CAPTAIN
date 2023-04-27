import json
import os
import argparse
import time
from utils.utils import *
from model.morse import Morse
import time
import pdb

def start_experiment(args):
    begin_time = time.time()
    mo = Morse()

    node_file = open(os.path.join(args.output_data, 'nodes.json'), 'w')
    edge_file = open(os.path.join(args.output_data, 'edges.json'), 'w')
    principal_file = open(os.path.join(args.output_data, 'principals.json'), 'w')

    uuid_nid_mapping = {}

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
                    print("Morse has loaded {} lines.".format(loaded_line))
                record_datum = json.loads(line)
                if 'event_type' not in record_datum:
                    continue
                if record_datum['event_type'] > 37 or record_datum['event_type'] < 1:
                    continue
                envt_num += 1
                subject, object, object2, event = mo.parse_event(record_datum, args.format, args.cdm_version)
                if subject:
                    mo.add_subject(subject)
                    uuid_nid_mapping[subject.id] = nodes_num
                    subject.id = nodes_num
                    nodes_num += 1
                    print(subject.dumps(), file = node_file)
                if object != None:
                    mo.add_object(object)
                    uuid_nid_mapping[object.id] = nodes_num
                    object.id = nodes_num
                    nodes_num += 1
                    print(object.dumps(), file = node_file)
                if object2 != None:
                    mo.add_object(object2)
                    uuid_nid_mapping[object2.id] = nodes_num
                    object2.id = nodes_num
                    nodes_num += 1
                    print(object2.dumps(), file = node_file)
                if event:
                    event.src = uuid_nid_mapping.get(event.src, None)
                    event.dest = uuid_nid_mapping.get(event.dest, None)
                    event.dest2 = uuid_nid_mapping.get(event.dest2, None)
                    event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                    if event_str != last_event_str and event.src:
                        last_event_str = event_str
                        edge_num += 1
                        print(event.dumps(), file = edge_file)
                pdb.set_trace()
                elif record_type == 'Principal':
                    record_datum['euid'] = record_datum['properties']['map']['euid']
                    del record_datum['hostId']
                    del record_datum['properties']
                    print(json.dumps(record_datum), file = principal_file)

    node_file.close()
    edge_file.close()
    principal_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {}".format(envt_num))
    print("#Nodes: {}".format(nodes_num))
    print("#Edges: {}".format(edge_num))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--format", type=str)

    args = parser.parse_args()

    start_experiment(args)