import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
from parse.cdm18.cadets_parser import parse_event_cadets, parse_object_cadets, parse_subject_cadets
from utils.utils import *
from model.morse import Morse

def start_experiment(args):
    begin_time = time.time()

    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    ##### Load File Names #####
    volume_list = [file for file in os.listdir(args.input_data) if file.startswith('.') == False]
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))

    node_buffer = {}
    last_event_str = ''
    node_set = set()

    loaded_line = 0
    envt_num = 0
    edge_num = 0
    node_num = 0

    for volume in volume_list:
        print(f"Loading {volume} ...")
        with open(os.path.join(args.input_data, volume),'r') as fin:
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
                            print(json.dumps(update_evnt), file = output_file)
                    if event:
                        for nid in [event.src, event.dest, event.dest2]:
                            if nid not in node_set:
                                node_set.add(nid)
                                node = node_buffer.get(nid, None)
                                if node:
                                    print(node.dumps(), file = output_file)
                                    node_num += 1
                        if node_buffer.get(event.src, None):
                            event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                            if event_str != last_event_str:
                                last_event_str = event_str
                                print(event.dumps(), file = output_file)
                                edge_num += 1
                elif record_type == 'Subject':
                    subject = parse_subject_cadets(node_buffer, record_datum, args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                elif record_type == 'Principal':
                    record_datum['username'] = record_datum['username']['string']
                    del record_datum['hostId']
                    # del record_datum['properties']
                    print(json.dumps(record_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_cadets(record_datum, record_type)
                    if object:
                        node_buffer[object.id] = object
                # elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
                #     pass
                else:
                    pass

    # node_file.close()
    # edge_file.close()
    # principal_file.close()
    output_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {:,}".format(node_num))
    print("#Edges: {:,}".format(edge_num))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--line_range", nargs=2, type=int)
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)

    args = parser.parse_args()

    start_experiment(args)

