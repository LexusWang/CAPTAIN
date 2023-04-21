import json
import torch
import logging
from datetime import datetime
import pdb
import os
import argparse
import time
from utils.utils import *
from collections import Counter
from utils.eventClassifier import eventClassifier
from model.morse import Morse

from feature.NetFlowObjFeatures import get_network_feature_vector
import tqdm
import time
import pandas as pd
from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
from utils.graph_detection import add_nodes_to_graph
from utils.graphLoader import read_events_from_files
import numpy as np
from pathlib import Path
import pickle

def prt_network_tag_prob(file_path, network_nid_index, array):
    with open(file_path, 'w') as outputfile:
        print("NetworkFeature\titag-0\titag-1", file = outputfile)
        for item in network_nid_index.keys():
            i = network_nid_index[item]
            print("{}\t{}\t{}".format(item, array[i][0], array[i][1]), file = outputfile)
    


def get_network_tags(node_features_dict, node_id, initializer, device):
    features = torch.tensor(np.array(node_features_dict[node_id]['features'], dtype=np.int16)).unsqueeze(dim=0).to(device)
    return initializer.initialize(features).squeeze()

def get_file_tags(node_features_dict, node_id, initializer, device):
    orig_feature = node_features_dict[node_id]['features']
    input_feature = np.zeros(10002,dtype=np.int16)
    input_feature[orig_feature[0]] = 1
    input_feature[10000] = orig_feature[1]
    input_feature[10001] = orig_feature[2]
    # features = list(np.zeros(10002,dtype=np.int16))
    # for index in orig_feature[0]:
    #     features[index] = 1
    # features[10000] = orig_feature[1]
    # features[10001] = orig_feature[2]
    features = torch.tensor(input_feature).unsqueeze(dim=0).to(device)
    return initializer.initialize(features).squeeze()

def start_experiment(args):
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)
    mode = args.mode
    mo = Morse()

    # ============= Tag Initializer =============== #
    node_inits = {}

    if (mode == "train"):
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        epochs = args.epoch

        # load the checkpoint if it is given
        if args.checkpoint:
            checkpoint_epoch_path = args.checkpoint
            node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)

        # ================= Load all nodes & edges to memory ==================== #
        pre_loaded_path = experiment.get_pre_load_morse(args.data_tag)

        if pre_loaded_path.endswith('.pkl'):
            with open(pre_loaded_path, 'rb') as f:
                events, nodes, princicals = pickle.load(f)
        else:
            events = read_events_from_files(os.path.join(args.train_data, 'edges.json'), args.time_range)
            nodes = pd.read_json(os.path.join(args.train_data, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
            princicals = pd.read_json(os.path.join(args.train_data, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, nodes, princicals], f)

        mo.Principals = princicals
        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))
            # total_loss = 0.0
            Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
            mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'a')
            mo.reset_morse()

            # ============== Initialization ================== #
            model_tags = {}
            node_inital_tags = {}
            mo.reset_tags()

            # ============= Dectection =================== #
            node_gradients = []
            for event in tqdm.tqdm(events):
                if event.type == 'UPDATE':
                    try:
                        if 'exec' in event.value:
                            mo.Nodes[event.nid].processName = event.value['exec']
                        elif 'name' in event.value:
                            mo.Nodes[event.nid].name = event.value['name']
                            mo.Nodes[event.nid].path = event.value['name']
                    except KeyError:
                        pass
                    continue
                if event.src not in mo.Nodes:
                    add_nodes_to_graph(mo, event.src, nodes[event.src])

                if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest, nodes[event.dest])

                if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

                # gt = ec.classify(event.id)
                diagnosis, s_labels, o_labels = mo.add_event_generate_loss(event, None)
                experiment.update_metrics(diagnosis, None)

                if diagnosis == None:
                    continue

                if s_labels:
                    node_gradients.extend(s_labels)

                if o_labels:
                    node_gradients.extend(o_labels)
            
            mo.alarm_file.close()
            experiment.print_metrics()
            experiment.save_metrics()
            experiment.reset_metrics()
            # ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'r'))
            # ec.summary(os.path.join(experiment.metric_path, "ec_summary.txt"))
            # ec.reset()
            
            node_labels = {}
            for item in node_gradients:
                if item[0] not in node_labels:
                    node_labels[item[0]] = []
                node_labels[item[0]].append(item[1])
                # if item[0][1] == 'i':
                #     if item[0][0] not in node_labels:
                #         node_labels[item[0][0]] = []
                #     node_labels[item[0][0]].append(item[1])

            wlz_dict = {}
            for node, value in node_labels.items():
                if mo.Nodes[node[0]].get_name() not in wlz_dict:
                    wlz_dict[mo.Nodes[node[0]].get_name()] = []
                wlz_dict[mo.Nodes[node[0]].get_name()].extend(value)

            for key, item in wlz_dict.items():
                if len(item) > 10 and sum(item)/len(item) > 0.9:
                    mo.white_name_set.add(key)
            
            print(mo.white_name_set)
            pdb.set_trace()

        return None

    elif (mode == "test"):
        begin_time = time.time()
        experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)
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

        # ================= Load all nodes & edges to memory ==================== #
        pre_loaded_path = experiment.get_pre_load_morse(args.data_tag)

        if pre_loaded_path.endswith('.pkl'):
            with open(pre_loaded_path, 'rb') as f:
                events, nodes, princicals = pickle.load(f)
        else:
            events = read_events_from_files(os.path.join(args.train_data, 'edges.json'), args.time_range)
            nodes = pd.read_json(os.path.join(args.train_data, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
            princicals = pd.read_json(os.path.join(args.train_data, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, nodes, princicals], f)

        mo.Principals = princicals
        # mo.white_name_set = {'128.55.12.56', '128.55.12.10', '193.40.5.73', '127.0.0.1', '207.25.80.123', '207.46.73.59', '128.55.12.118', '128.55.12.166', '212.60.66.243', '207.46.73.60', '128.55.12.55', '216.87.162.115', '194.90.181.242', '128.55.12.167', '128.55.12.110', '212.190.125.38', '/home/user/.bash_history', '83.150.97.73', '66.252.21.131', '162.99.3.50', '69.20.49.234', '128.55.12.67'}
        mo.white_name_set = {'128.55.12.122', '128.55.12.73', '10.0.4.1', '128.55.12.10', '8.15.32.34', '64.4.125.136', '208.17.90.10', '208.75.170.1', '0.0.0.0', '66.252.21.131', '67.28.122.168'}

        for event in tqdm.tqdm(events):
            if event.type == 'UPDATE':
                try:
                    if 'exec' in event.value:
                        mo.Nodes[event.nid].processName = event.value['exec']
                    elif 'name' in event.value:
                        mo.Nodes[event.nid].name = event.value['name']
                        mo.Nodes[event.nid].path = event.value['name']
                except KeyError:
                    pass
                continue
                
            if event.src not in mo.Nodes:
                add_nodes_to_graph(mo, event.src, nodes[event.src])

            if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                add_nodes_to_graph(mo, event.dest, nodes[event.dest])

            if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

            gt = ec.classify(event.id)
            diagnois = mo.add_event(event, gt)
            experiment.update_metrics(diagnois, gt)
            if gt != None and diagnois == None:
                print(event.id)
                        
        mo.alarm_file.close()
        experiment.print_metrics()
        experiment.save_metrics()
        ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
        ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

        print("Detecting Time: {:.2f}s".format(time.time()-begin_time))
        print("Metrics saved in {}".format(experiment.get_experiment_output_path()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--train_data", type=str)
    parser.add_argument("--test_data", type=str)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--mode", type=str)
    parser.add_argument("--data_tag", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)

