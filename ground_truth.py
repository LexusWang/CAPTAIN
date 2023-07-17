import os
import argparse
import json
from datetime import datetime
from utils.utils import *
from model.morse import Morse
import pandas as pd
from model.morse import Morse
from graph.Event import Event
from utils.graph_detection import add_nodes_to_graph
import pdb

def start_experiment(args):
    mo = Morse()

    nodes = pd.read_json(os.path.join(args.test_data, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
    mo.Principals = pd.read_json(os.path.join(args.test_data, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')

    loaded_line = 0
    edge_file = os.path.join(args.test_data, 'edges.json')

    # close interval
    if args.time_range:
        detection_start_time = args.time_range[0]
        detection_end_time = args.time_range[1]
    else:
        detection_start_time = 0
        detection_end_time = 1e21

    with open(edge_file, 'r') as fin:
        for line in fin:
            loaded_line += 1
            edge_datum = json.loads(line)
            if loaded_line == 1:
                if "time" in edge_datum:
                    print(int(edge_datum["time"]))
                else:
                    loaded_line = 0
                # print("Morse has loaded {} edges.".format(loaded_line))
            if edge_datum['type'] == 'UPDATE':
                updated_value = edge_datum['value']
                try:
                    if 'exec' in updated_value:
                        mo.Nodes[edge_datum['nid']].processName = updated_value['exec']
                    elif 'name' in updated_value:
                        mo.Nodes[edge_datum['nid']].name = updated_value['name']
                        mo.Nodes[edge_datum['nid']].path = updated_value['name']
                    elif 'cmdl' in updated_value:
                        mo.Nodes[edge_datum['nid']].cmdLine = updated_value['cmdl']
                except KeyError:
                    pass
            else:
                event = Event(None, None)
                event.loads(line)

                if event.time < detection_start_time:
                    continue
                elif event.time > detection_end_time:
                    break

                if event.src not in mo.Nodes:
                    assert nodes[event.src]['type'] == 'SUBJECT_PROCESS'
                    add_nodes_to_graph(mo, event.src, nodes[event.src])

                if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest, nodes[event.dest])

                if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

                # if mo.Nodes[event.src].pid == 66539:
                #     print(event.dumps())
                #     print(mo.Nodes[event.src].dumps())
                #     print(mo.Nodes[event.dest].dumps())

                # if '/root/fish.sh' in mo.Nodes[event.dest].get_name():
                #     print(event.dumps())
                #     print(mo.Nodes[event.src].dumps())
                #     print(mo.Nodes[event.dest].dumps())

                # if event.type == 'write':
                #     # if mo.Nodes[event.src] == 'chown root /root/discovery.sh':
                #     # pdb.set_trace()
                #     # if mo.Nodes[event.src].cmdLine and "wget http://192.168.1.31:8089/FileUpLoad/Files/pub.sh" in mo.Nodes[event.src].cmdLine:
                #     if '192.168.1.119' in mo.Nodes[event.dest].get_name():
                #         print(event.id)
                #         # print(event.dumps())
                #         # print(mo.Nodes[event.src].dumps())
                #         # print(mo.Nodes[event.dest].dumps())
                #         # pdb.set_trace()
            if "time" in edge_datum.keys():
                finish_time = int(edge_datum["time"])
    print(finish_time)            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--test_data", nargs='?', type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)