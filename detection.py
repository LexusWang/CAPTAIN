import logging
import os
import argparse
import json
import time
import pickle
import pandas as pd

import psutil
import csv
process = psutil.Process(os.getpid())
perf_file = open('system_usage.csv', 'a', newline='')
writer = csv.writer(perf_file)
writer.writerow(['Time', 'CPU Usage (%)', 'Memory Usage (MB)'])

from pympler import asizeof

from datetime import datetime
from utils.utils import *
from utils.eventClassifier import eventClassifier
from model.morse import Morse
from graph.Event import Event
from utils.graph_detection import add_nodes_to_graph
from pathlib import Path
from collections import Counter
import pdb

def start_experiment(args):
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)

    mo = Morse(att = args.att, decay = args.decay)
    mo.mode = 'eval'
    # mo.tuneNetworkTags = False
    # mo.tuneFileTags = False

    print("Begin preparing testing...")
    logging.basicConfig(level=logging.INFO,
                        filename='debug.log',
                        filemode='w+',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    experiment.save_hyperparameters()
    ec = eventClassifier(args.ground_truth_file)
        
    if args.param_path:
        with open(os.path.join(args.param_path, 'train', 'params/lambda-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.lambda_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/tau-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.tau_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/alpha-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.alpha_dict = pickle.load(fin)

    # close interval
    if args.time_range:
        detection_start_time = args.time_range[0]
        detection_end_time = args.time_range[1]
    else:
        detection_start_time = 0
        detection_end_time = 1e21

    # mo.node_inital_tags = {}
    Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

    nodes = pd.read_json(os.path.join(args.data_path, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
    mo.Principals = pd.read_json(os.path.join(args.data_path, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')

    loaded_line = 0
    edge_file = os.path.join(args.data_path, 'edges.json')

    false_alarms = []
    with open(edge_file, 'r') as fin:
        for line in fin:
            if loaded_line == 1:
                begin_time = time.time()
            event = Event(None, None)
            event.loads(line)
            # edge_datum = json.loads(line)
            if event.type == 'UPDATE':
                try:
                    if 'exec' in event.value:
                        mo.Nodes[event.nid].processName = event.value['exec']
                    elif 'name' in event.value:
                        mo.Nodes[event.nid].name = event.value['name']
                        mo.Nodes[event.nid].path = event.value['name']
                    elif 'cmdl' in event.value:
                        mo.Nodes[event.nid].cmdLine = event.value['cmdl']
                except KeyError:
                    pass
            else:
                if loaded_line > 0 and loaded_line % 100000 == 0:
                    print("CAPTAIN has detected {:,} edges.".format(loaded_line))
                    # current_time = time.strftime('%Y-%m-%d %H:%M:%S')
                    # cpu_usage = process.cpu_percent(interval=1)
                    # memory_usage = process.memory_info().rss / (1024 * 1024)  # 转换为MB
                    # writer.writerow([current_time, cpu_usage, memory_usage])
                    # print(f"{current_time}, CPU: {cpu_usage}%, Memory: {memory_usage}MB")
                # event = Event(None, None)
                # event.loads(line)

                if event.time < detection_start_time:
                    continue
                elif event.time > detection_end_time:
                    break

                loaded_line += 1

                if event.src not in mo.Nodes:
                    # assert nodes[event.src]['type'] == 'SUBJECT_PROCESS'
                    add_nodes_to_graph(mo, event.src, nodes[event.src])

                if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest, nodes[event.dest])

                if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

                gt = ec.classify(event.id)
                diagnosis = mo.add_event(event, gt)
                experiment.update_metrics(diagnosis, gt)
                if gt == None and diagnosis != None:
                    false_alarms.append(diagnosis)
    
    experiment.detection_time = time.time()-begin_time
    print('The detection time is :{:.2f} s'.format(experiment.detection_time))
    print('The event throughput is :{:.2f} s'.format(loaded_line/experiment.detection_time))

    print("{} Mb".format(asizeof.asizeof(mo)/(1024*1024)))
    print("# of nodes: {}".format(len(mo.Nodes)))
                    
    mo.alarm_file.close()
    experiment.alarm_dis = Counter(false_alarms)
    experiment.print_metrics()
    experiment.save_metrics()
    ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))
    print("Metrics saved in {}".format(experiment.get_experiment_output_path()))

    perf_file.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--att", type=float, default=0.2)
    parser.add_argument("--decay", type=float, default=0)
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--data_path", nargs='?', type=str)
    parser.add_argument("--param_type", type=str)
    parser.add_argument("--model_index", type=int)
    parser.add_argument("--data_tag", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--param_path", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)
    parser.add_argument("--mode", type=str, default='test')

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)

