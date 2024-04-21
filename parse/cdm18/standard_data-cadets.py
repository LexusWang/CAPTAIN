import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
from parse.cdm18.cadets_parser import parse_event_cadets, parse_object_cadets, parse_subject_cadets
from utils.utils import *
from model.captain import CAPTAIN

def start_experiment(args):
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    ##### Load File Names #####
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

    ## Mimicry Attack
    ## Mimicry logs
    # volume_list = ['adversarial/artifacts/mimicry_logs.json']
    ## Normal logs
    # file_list = ['ta1-cadets-e3-official-2.json/ta1-cadets-e3-official-2.json']
    # volume_list = []
    # for file in file_list:
    #     volume_list.append(os.path.join(args.input_data, file))
    
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
    # parser.add_argument("--line_range", nargs=2, type=int)
    parser.add_argument("--format", type=str)
    # parser.add_argument("--volume_num", type=int)
    parser.add_argument("--cdm_version", type=int)

    args = parser.parse_args()

    start_experiment(args)
