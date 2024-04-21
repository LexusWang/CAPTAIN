import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
from parse.cdm18.theia_parser import parse_subject_theia, parse_object_theia, parse_event_theia
import time
import pdb

def start_experiment(args):
    output_file = open(os.path.join(args.output_data, 'logs.json'), 'w')

    ##### Load File Names #####
    # volume_list = [file for file in os.listdir(args.input_data) if file.startswith('.') == False]
    # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
    volume_list = []
    for volume in range(10):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-1r.json', 'ta1-theia-e3-official-1r.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-1r.json', 'ta1-theia-e3-official-1r.json')+f'.{volume}')
    
    volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-3.json', 'ta1-theia-e3-official-3.json'))
    volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-5m.json', 'ta1-theia-e3-official-5m.json'))

    for volume in range(13):
        if volume == 0:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-6r.json', 'ta1-theia-e3-official-6r.json'))
        else:
            volume_list.append(os.path.join(args.input_data, 'ta1-theia-e3-official-6r.json', 'ta1-theia-e3-official-6r.json')+f'.{volume}')

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
                    event = parse_event_theia(node_buffer, record_datum, args.cdm_version)
                    if event:
                        if event.type == 'set_uid':
                            event.parameters = int(principals_buffer[event.parameters]['userId'])
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str:
                            last_event_str = event_str
                            edge_num += 1
                            log_datum = {'logType':'EVENT', 'logData': json.loads(event.dumps())}
                            print(json.dumps(log_datum), file = output_file)
                elif record_type == 'Subject':
                    subject = parse_subject_theia(record_datum,args.cdm_version)
                    if subject:
                        node_buffer[subject.id] = subject
                        log_datum = {'logType':'NODE', 'logData': json.loads(subject.dumps())}
                        print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                elif record_type == 'Principal':
                    # record_datum['euid'] = record_datum['properties']['map']['euid']
                    del record_datum['hostId']
                    # del record_datum['properties']
                    principals_buffer[record_datum['uuid']] = record_datum
                    log_datum = {'logType':'PRINCIPAL', 'logData': record_datum}
                    print(json.dumps(log_datum), file = output_file)
                elif record_type.endswith('Object'):
                    object = parse_object_theia(record_datum,record_type)
                    if object:
                        node_buffer[object.id] = object
                        log_datum = {'logType':'NODE', 'logData': json.loads(object.dumps())}
                        print(json.dumps(log_datum), file = output_file)
                        node_num += 1
                elif record_type == 'Host':
                    # node_buffer = {}
                    # last_event_str = ''
                    # node_set = set()
                    log_datum = {'logType':'CTL_EVENT_REBOOT', 'logData': {}}
                    print(json.dumps(log_datum), file = output_file)
                # elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency'}:
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
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)
    parser.add_argument("--volume_num", type=int)
    args = parser.parse_args()

    start_experiment(args)

