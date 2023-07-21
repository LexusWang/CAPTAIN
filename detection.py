import logging
import os
import argparse
import json
import time
from datetime import datetime
from utils.utils import *
from utils.eventClassifier import eventClassifier
from model.morse import Morse
import time
import pandas as pd
from model.morse import Morse
from graph.Event import Event
from utils.graph_detection import add_nodes_to_graph
from pathlib import Path
import pdb

def start_experiment(args):
    begin_time = time.time()
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)

    mo = Morse()
    mo.tuneNetworkTags = False
    mo.tuneFileTags = False

    print("Begin preparing testing...")
    logging.basicConfig(level=logging.INFO,
                        filename='debug.log',
                        filemode='w+',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    experiment.save_hyperparameters()
    ec = eventClassifier(args.ground_truth_file)
        
    mo.node_inital_tags = {}
    Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

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
            if loaded_line % 100000 == 0:
                print("Morse has loaded {} edges.".format(loaded_line))
            edge_datum = json.loads(line)
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

                gt = ec.classify(event.id)
                diagnosis = mo.add_event(event, gt)
                experiment.update_metrics(diagnosis, gt)
                # if gt == 'MkFileExecutable' and diagnosis == None:
                #     print(event.id)
                #     pdb.set_trace()
                    
    # print(mo.secret_src)
    # print(mo.secret_dest)
    # print(mo.secret_dest2)
    mo.alarm_file.close()
    experiment.print_metrics()
    experiment.save_metrics()
    # ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    # ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

    print("Detecting Time: {:.2f}s".format(time.time()-begin_time))
    print("Metrics saved in {}".format(experiment.get_experiment_output_path()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--test_data", nargs='?', type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)
    parser.add_argument("--mode", type=str, default='test')

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)

