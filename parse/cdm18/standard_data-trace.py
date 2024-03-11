import json
import os
import argparse
import time
import sys
sys.path.extend(['.','..','...'])
from parse.cdm18.trace_parser import parse_subject_trace, parse_object_trace, parse_event_trace
from model.morse import Morse
import time
import pdb

def start_experiment(args):
    begin_time = time.time()
    mo = Morse(0,0)

    node_file = open(os.path.join(args.output_data, 'nodes.json'), 'w')
    edge_file = open(os.path.join(args.output_data, 'edges.json'), 'w')
    principal_file = open(os.path.join(args.output_data, 'principals.json'), 'w')

    uuid_nid_mapping = {}

    loaded_line = 0
    last_event_str = ''
    volume_list = [file for file in os.listdir(args.input_data) if file.startswith('.') == False]
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))

    
    # # close interval
    # if args.line_range:
    #     l_range = args.line_range[0]
    #     r_range = args.line_range[1]
    # else:
    #     l_range = 0
    #     r_range = 5e7*len(volume_list)

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
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Event':
                    envt_num += 1
                    event = parse_event_trace(mo, record_datum, args.cdm_version)
                    if event:
                        try:
                            event.src = uuid_nid_mapping.get(event.src, None)
                            event.dest = uuid_nid_mapping.get(event.dest, None)
                            event.dest2 = uuid_nid_mapping.get(event.dest2, None)
                            event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                            if event_str != last_event_str:
                                last_event_str = event_str
                                edge_num += 1
                                # print(event.dumps(), file = edge_file)
                        except KeyError:
                            pass
                elif record_type == 'Subject':
                    # subject = mo.parse_subject(record_datum, args.format, args.cdm_version)
                    subject = parse_subject_trace(mo,record_datum,args.cdm_version)
                    if subject:
                        mo.add_subject(subject)
                        uuid_nid_mapping[subject.id] = nodes_num
                        subject.id = nodes_num
                        nodes_num += 1
                        # print(subject.dumps(), file = node_file)
                elif record_type == 'Principal':
                    record_datum['euid'] = record_datum['properties']['map']['euid']
                    del record_datum['hostId']
                    del record_datum['properties']
                    # print(json.dumps(record_datum), file = principal_file)
                    princ_id = record_datum['uuid']
                    del record_datum['uuid']
                    mo.Principals[princ_id] = record_datum
                elif record_type.endswith('Object'):
                    # object = mo.parse_object(record_datum, record_type, args.format, args.cdm_version)
                    object = parse_object_trace(mo,record_datum,record_type)
                    if object:
                        mo.add_object(object)
                        uuid_nid_mapping[object.id] = nodes_num
                        object.id = nodes_num
                        nodes_num += 1
                        # print(object.dumps(), file = node_file)
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

    node_file.close()
    edge_file.close()
    principal_file.close()
    print("Parsing Time: {:.2f}s".format(time.time()-begin_time))
    print("#Events: {:,}".format(envt_num))
    print("#Nodes: {:,}".format(nodes_num))
    print("#Edges: {:,}".format(edge_num))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)

    args = parser.parse_args()

    # if args.line_range:
    #     args.line_range[0] = get_integer(args.line_range[0])
    #     args.line_range[1] = get_integer(args.line_range[1])

    start_experiment(args)

