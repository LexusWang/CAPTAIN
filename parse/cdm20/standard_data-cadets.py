import json
import os
import argparse
import pdb
import time
import sys
sys.path.extend(['.','..','...'])
from parse.cdm20.cadets_parser import parse_event_cadets, parse_object_cadets, parse_subject_cadets
from model.morse import Morse

def start_experiment(args):
    begin_time = time.time()
    mo = Morse(0,0)

    node_file = open(os.path.join(args.output_data, 'nodes.json'), 'w')
    edge_file = open(os.path.join(args.output_data, 'edges.json'), 'w')
    principal_file = open(os.path.join(args.output_data, 'principals.json'), 'w')

    uuid_nid_mapping = {}
    node_id = 0

    loaded_line = 0
    last_event_str = ''
    volume_list = []
    for v_index in range(122):
        for sv_index in ['', '.1', '.2']:
            volume_list.append("ta1-cadets-1-e5-official-2.bin.{}.json{}".format(v_index, sv_index))
    volume_list = volume_list[:-1]
    
    node_set = set()
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
                    event, node_updates = parse_event_cadets(mo, record_datum, args.cdm_version)
                    for key, value in node_updates.items():
                        if key in node_set:
                            update_evnt = {'type': 'UPDATE', 'nid': uuid_nid_mapping[key], 'value': value}
                            print(json.dumps(update_evnt), file = edge_file)
                    if event:
                        for nid in [event.src, event.dest, event.dest2]:
                            if nid not in node_set:
                                node = mo.Nodes.get(nid, None)
                                if node:
                                    node_set.add(nid)
                                    print(node.dumps(), file = node_file)
                                    node_num += 1
                        event.src = uuid_nid_mapping.get(event.src, None)
                        event.dest = uuid_nid_mapping.get(event.dest, None)
                        event.dest2 = uuid_nid_mapping.get(event.dest2, None)
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str and event.src!=None:
                            last_event_str = event_str
                            print(event.dumps(), file = edge_file)
                            edge_num += 1
                elif record_type == 'Subject':
                    subject = parse_subject_cadets(mo, record_datum, args.cdm_version)
                    if subject and subject.id not in uuid_nid_mapping:
                        mo.add_subject(subject)
                        uuid_nid_mapping[subject.id] = node_id
                        subject.id = node_id
                        node_id += 1
                elif record_type == 'Principal':
                    if record_datum['username']:
                        record_datum['username'] = record_datum['username']['string']
                    if record_datum['groupIds']:
                        record_datum['groupIds'] = record_datum['groupIds']['array']
                    del record_datum['properties']
                    princ_id = record_datum['uuid']
                    if princ_id not in mo.Principals:
                        print(json.dumps(record_datum), file = principal_file)
                        mo.Principals[princ_id] = record_datum
                elif record_type.endswith('Object'):
                    object = parse_object_cadets(mo, record_datum, record_type)
                    if object and object.id not in uuid_nid_mapping:
                        mo.add_object(object)
                        uuid_nid_mapping[object.id] = node_id
                        object.id = node_id
                        node_id += 1
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

