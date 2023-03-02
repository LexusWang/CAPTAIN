import json
import os
import argparse
import time
from utils.utils import *
from model.morse import Morse
from policy.initTags import match_path, match_network_addr
import time
from model.morse import Morse

def start_experiment(args):
    begin_time = time.time()
    mo = Morse()

    node_file = open(os.path.join(args.output_data, 'nodes.json'), 'w')
    edge_file = open(os.path.join(args.output_data, 'edges.json'), 'w')
    principal_file = open(os.path.join(args.output_data, 'principals.json'), 'w')
    # record_file = open(os.path.join(args.output_data, 'records.json'), 'w')

    # network_nodes = {}
    # srcsink_nodes = {}

    uuid_nid_mapping = {}
    nodes_num = 0

    loaded_line = 0
    last_event_str = ''
    volume_list = os.listdir(args.input_data)
    # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[1])+0.1*int(x.split('.')[3]))
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
    
    # close interval
    if args.line_range:
        l_range = args.line_range[0]
        r_range = args.line_range[1]
    else:
        l_range = 0
        r_range = 5000000*len(volume_list)
    
    for volume in volume_list:
        print("Loading the {} ...".format(volume))
        with open(os.path.join(args.input_data, volume),'r') as fin:
            for line in fin:
                if loaded_line > r_range:
                    break
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("Morse has loaded {} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Event':
                    if loaded_line < l_range:
                        continue
                    event = mo.parse_event(record_datum, args.format, args.cdm_version)
                    if event:
                        try:
                            event.src = uuid_nid_mapping.get(event.src, None)
                            event.dest = uuid_nid_mapping.get(event.dest, None)
                            event.dest2 = uuid_nid_mapping.get(event.dest2, None)
                            event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                            if event_str != last_event_str and event.src:
                                last_event_str = event_str
                                print(event.dumps(), file = edge_file)
                        except KeyError:
                            pass
                elif record_type == 'Subject':
                    subject = mo.parse_subject(record_datum, args.format, args.cdm_version)
                    if subject != None:
                        mo.add_subject(subject)

                        # is_new = True
                        uuid_nid_mapping[subject.id] = nodes_num
                        subject.id = nodes_num
                        nodes_num += 1

                        # if is_new:
                        print(subject.dumps(), file = node_file)
                elif record_type == 'Principal':
                    if args.format == 'trace':
                        record_datum['euid'] = record_datum['properties']['map']['euid']
                        del record_datum['hostId']
                        del record_datum['properties']
                    elif args.format == 'cadets':
                        record_datum['username'] = record_datum['username']['string']
                        del record_datum['hostId']
                        del record_datum['properties']
                    print(json.dumps(record_datum), file = principal_file)
                    # mo.Principals[record_datum['uuid']] = record_datum
                elif record_type.endswith('Object'):
                    object = mo.parse_object(record_datum, record_type, args.format, args.cdm_version)
                    if object != None:
                        mo.add_object(object)

                        # is_new = True

                        # if object.type == 'NetFlowObject':
                        #     network_feature = '{}:{}'.format(object.IP, object.port)
                        #     if network_feature not in network_nodes:
                        #         network_nodes[network_feature] = nodes_num
                        #         uuid_nid_mapping[object.id] = nodes_num
                        #         object.id = nodes_num
                        #         nodes_num += 1
                        #     else:
                        #         uuid_nid_mapping[object.id] = network_nodes[network_feature]
                        #         object.id = network_nodes[network_feature]
                        #         is_new = False
                        # elif object.type == 'SrcSinkObject':
                        #     if object.name not in srcsink_nodes:
                        #         srcsink_nodes[object.name] = nodes_num
                        #         uuid_nid_mapping[object.id] = nodes_num
                        #         object.id = nodes_num
                        #         nodes_num += 1
                        #     else:
                        #         uuid_nid_mapping[object.id] = srcsink_nodes[object.name]
                        #         object.id = srcsink_nodes[object.name]
                        #         is_new = False
                        # else:
                        #     uuid_nid_mapping[object.id] = nodes_num
                        #     object.id = nodes_num
                        #     nodes_num += 1
                        # if is_new:
                        
                        uuid_nid_mapping[object.id] = nodes_num
                        object.id = nodes_num
                        nodes_num += 1
                        print(object.dumps(), file = node_file)
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
    print(time.time()-begin_time)

    return None

def get_integer(string):
    if string.endswith('K'):
        return int(string[:-1])*1000
    elif string.endswith('M'):
        return int(string[:-1])*1000000
    else:
        return int(string)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Data Standardize")
    parser.add_argument("--input_data", type=str)
    parser.add_argument("--output_data", type=str)
    parser.add_argument("--line_range", nargs=2, type=str)
    parser.add_argument("--format", type=str)
    parser.add_argument("--cdm_version", type=int)

    args = parser.parse_args()

    args.line_range[0] = get_integer(args.line_range[0])
    args.line_range[1] = get_integer(args.line_range[1])

    start_experiment(args)

