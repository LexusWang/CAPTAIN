'''
This script is used to transfer the TRACE data in CDM 20 format 
(used in DARPA Engagement 5) to the standard format.

After the tranlation is finished, the data will be saved in the log.json
file in the output folder.
'''

import json
import os
import argparse
import time
import pdb
import sys
sys.path.extend(['.','..','...'])
from parse.cdm20.trace_parser import parse_subject_trace, parse_object_trace, parse_event_trace
# from trace_parser import parse_subject_trace, parse_object_trace, parse_event_trace
from utils.utils import *

def start_experiment(args):
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    ##### Load File Names #####
    volume_list = []
    for v_index in range(191):
        for sv_index in ['', '.1', '.2']:
            volume_list.append("ta1-trace-2-e5-official-1.bin.{}.json{}".format(v_index, sv_index))
    volume_list = volume_list[:-1]

    last_event_str = ''
    node_buffer = {}
    principals_buffer = {}
    node_set = set()

    ##### Set Up Counters #####
    loaded_line = 0    
    envt_num = 0
    edge_num = 0
    node_num = 0
    
    ##### Object Version Control #####
    object_latest_version = {}

    begin_time = time.time()
    
    decoder = json.JSONDecoder()
    for volume in volume_list[:3]:
        print("Loading {} ...".format(volume))
        with open(os.path.join(args.input_data, volume),'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                record_datum = decoder.decode(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                envt_num += 1
                if record_type == 'Event':
                    envt_num += 1
                    event = parse_event_trace(node_buffer, record_datum, args.cdm_version)
                    if event:
                        if event.type == 'set_uid':
                            event.parameters = int(principals_buffer[event.parameters]['userId'])
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str:
                            last_event_str = event_str
                            edge_num += 1
                            log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                            output_file.write(json.dumps(log_datum)+'\n')
                elif record_type == 'Subject':
                    subject = parse_subject_trace(record_datum, args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                        log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                        output_file.write(json.dumps(log_datum)+'\n')
                        node_num += 1
                elif record_type == 'Principal':
                    record_datum['euid'] = record_datum['properties']['map']['euid']
                    del record_datum['properties']
                    principals_buffer[record_datum['uuid']] = record_datum
                    log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                    output_file.write(json.dumps(log_datum)+'\n')
                elif record_type.endswith('Object'):
                    object = parse_object_trace(record_datum, record_type)
                    if object:
                        node_buffer[object.id] = object
                        log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                        output_file.write(json.dumps(log_datum)+'\n')
                        node_num += 1
                        try:
                            if object.epoch == 0:
                                object_latest_version[object.get_name()] = object.id
                            else:
                                update_evnt = {'type': 'OBJECT_VERSION_UPDATE', 'old': object_latest_version[object.get_name()], 'new': object.id}
                                log_datum = {'logType':'EVENT', 'logData': update_evnt}
                                output_file.write(json.dumps(log_datum)+'\n')
                                object_latest_version[object.get_name()] = object.id
                        except KeyError:
                            pdb.set_trace()
                elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
                    pass
                else:
                    pass

    output_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {:,}".format(node_num))
    print("#Edges: {:,}".format(edge_num))
    
    
def main():
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)
    args = parser.parse_args()

    start_experiment(args)


if __name__ == '__main__':
    # import cProfile
    # cProfile.run("main()")
    main()
