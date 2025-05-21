'''
This script is used to transfer the CADETS data in CDM 20 format 
(used in DARPA Engagement 5) to the standard format.

After the tranlation is finished, the data will be saved in the log.json
file in the output folder.
'''

import json
import os
import argparse
import pdb
import time
import sys
sys.path.extend(['.','..','...'])
from parse.cdm20.cadets_parser import parse_event_cadets, parse_object_cadets, parse_subject_cadets

def start_experiment(args):
    begin_time = time.time()
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    ##### Load File Names #####
    volume_list = []
    for v_index in range(122):
        for sv_index in ['', '.1', '.2']:
            volume_list.append(f"ta1-cadets-1-e5-official-2.bin.{v_index}.json{sv_index}")
    volume_list = volume_list[:-1]

    node_buffer = {}
    last_event_str = ''
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0
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
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Event':
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
                            if event_str != last_event_str and event.src!=None:
                                last_event_str = event_str
                                log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                                print(json.dumps(log_datum), file = output_file)
                                edge_num += 1
                elif record_type == 'Subject':
                    subject = parse_subject_cadets(node_buffer, record_datum, args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                elif record_type == 'Principal':
                    if record_datum['username']:
                        record_datum['username'] = record_datum['username']['string']
                    if record_datum['groupIds']:
                        record_datum['groupIds'] = record_datum['groupIds']['array']
                    # del record_datum['hostId']
                    # del record_datum['properties']
                    log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                    print(json.dumps(log_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_cadets(record_datum, record_type)
                    if object:
                        node_buffer[object.id] = object
                # elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
                #     pass
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
    parser.add_argument("--line_range", nargs=2, type=int)
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)

    args = parser.parse_args()

    start_experiment(args)

