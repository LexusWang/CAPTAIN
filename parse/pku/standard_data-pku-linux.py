import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
from parse.pku.pku_linux_parser import parse_file_event, parse_process_event, parse_net_event
from utils.utils import *

def start_experiment(args):
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    node_buffer = {}
    last_event_str = ''
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0
    envt_num = 0
    edge_num = 0
    node_num = 0

    begin_time = time.time()

    print(f"Loading {args.input_data} ...")
    with open(args.input_data,'r') as fin:
        for line in fin:
            loaded_line += 1
            if loaded_line % 100000 == 0:
                print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
            record_datum = json.loads(line)
            record_type = record_datum['evt.type']
            if record_type in {"read", "readv", "write", "writev", "fcntl", "rmdir", "rename", "chmod"}:
                subject, object, event = parse_file_event(node_buffer, record_datum)
            elif record_type in {"clone", "pipe", "fork",'execve'}:
                subject, object, event = parse_process_event(node_buffer, record_datum)
            elif record_type in {"sendmsg", "recvmsg", "recvfrom", "send", "sendto"}:
                subject, object, event = parse_net_event(node_buffer, record_datum)
            else:
                pass

            if event:
                log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                print(json.dumps(log_datum), file = output_file)
                edge_num += 1

            if subject and subject.id not in node_set:
                log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                print(json.dumps(log_datum), file = output_file)
                node_set.add(subject.id)
                node_num += 1
            
            if object and object.id not in node_set:
                log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                print(json.dumps(log_datum), file = output_file)
                node_set.add(object.id)
                node_num += 1


            #     envt_num += 1
            #     event, node_updates = parse_event_cadets(node_buffer, record_datum, args.cdm_version)
            #     for key, value in node_updates.items():
            #         if key in node_set:
            #             update_evnt = {'type': 'UPDATE', 'nid': key, 'value': value}
            #             log_datum = {'logType':'EVENT', 'logData': update_evnt}
            #             print(json.dumps(log_datum), file = output_file)
            #     if event:
            #         for nid in [event.src, event.dest, event.dest2]:
            #             if nid not in node_set:
            #                 node_set.add(nid)
            #                 node = node_buffer.get(nid, None)
            #                 if node:
            #                     log_datum = {'logType':'NODE', 'logData': json.loads(node.dumps())}
            #                     print(json.dumps(log_datum), file = output_file)
            #                     node_num += 1
            #         if node_buffer.get(event.src, None):
            #             event_str = '{},{},{}'.format(event.src, event.type, event.dest)
            #             if event_str != last_event_str:
            #                 last_event_str = event_str
            #                 log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
            #                 print(json.dumps(log_datum), file = output_file)
            #                 edge_num += 1
            # elif record_type == 'Subject':
            #     subject = parse_subject_cadets(node_buffer, record_datum, args.cdm_version)
            #     if subject:
            #         node_buffer[subject.id] = subject
            # elif record_type == 'Principal':
            #     record_datum['username'] = record_datum['username']['string']
            #     del record_datum['hostId']
            #     # del record_datum['properties']
            #     log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
            #     print(json.dumps(log_datum), file = output_file)
            # elif record_type.endswith('Object'):
            #     object = parse_object_cadets(record_datum, record_type)
            #     if object:
            #         node_buffer[object.id] = object
            # elif record_type == 'Host':
            #     node_buffer = {}
            #     last_event_str = ''
            #     node_set = set()
            #     log_datum = {'logType':'CTL_EVENT_REBOOT', 'logData': {}}
            #     print(json.dumps(log_datum), file = output_file)
            # # elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
            # #     pass
            # else:
            #     pass

    output_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {:,}".format(node_num))
    print("#Edges: {:,}".format(edge_num))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)

    args = parser.parse_args()

    start_experiment(args)
