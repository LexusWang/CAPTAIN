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
from policy.propTags import dump_event_feature

import tqdm
import time
import pandas as pd
from model.morse import Morse
from utils.graph_detection import add_nodes_to_graph
from utils.graphLoader import read_events_from_files
import numpy as np
from pathlib import Path
import pickle

def start_experiment(args):
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)
    mo = Morse()
    # ============= Tag Initializer =============== #
    node_inits = {}

    if args.mode == "train":
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
                events, nodes, principals = pickle.load(f)
        else:
            events = read_events_from_files(os.path.join(args.data_path, 'edges.json'), args.time_range)
            nodes = pd.read_json(os.path.join(args.data_path, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
            principals = pd.read_json(os.path.join(args.data_path, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, nodes, principals], f)

        lambda_tuning_step = {}
        alpha_tuning_step = {}
        tau_tuning_step = {}
        
        mo.Principals = principals
        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))
            Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
            mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'a')
            mo.reset_morse()
            mo.reset_tags()

            # ============= Dectection =================== #
            node_gradients = []
            propagation_chains = []
            fp_counter = {}
            for event in tqdm.tqdm(events):
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
                    continue
                if event.src not in mo.Nodes:
                    add_nodes_to_graph(mo, event.src, nodes[event.src])

                if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest, nodes[event.dest])

                if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

                diagnosis, tag_indices, s_labels, o_labels, pc = mo.add_event_generate_loss(event, None)
                experiment.update_metrics(diagnosis, None)

                if diagnosis == None:
                    continue

                if s_labels:
                    node_gradients.extend(s_labels)

                if o_labels:
                    node_gradients.extend(o_labels)

                propagation_chains.extend(pc)

                src = mo.Nodes.get(event.src, None)
                dest = mo.Nodes.get(event.dest, None)
                dest2 = mo.Nodes.get(event.dest2, None)
                
                if src:
                    event_key = str(dump_event_feature(event, src, dest, dest2))
                    if event_key not in fp_counter.keys():
                        fp_counter[event_key] = [0, 0, 0, 0, 0, 0, 0, 0]
                    for i in tag_indices:
                        fp_counter[event_key][i] += 1
            
            mo.alarm_file.close()
            experiment.print_metrics()
            experiment.save_metrics()

            # Tune Lambda
            pc_event_counter = Counter()
            for item in propagation_chains:
                pc_event_counter.update(item)
            threshold = 0.5
            filtered_pc_event_counter = {key: value for key, value in sorted(pc_event_counter.items(), key = lambda x:x[1], reverse = True)[:int(threshold * len(pc_event_counter))]}
            
            for key, value in filtered_pc_event_counter.items():
                if key in mo.lambda_dict:
                    mo.lambda_dict[key] = mo.lambda_dict[key] + lambda_tuning_step[key]
                    lambda_tuning_step[key] = 0.5 * lambda_tuning_step[key]
                else:
                    mo.lambda_dict[key] = 0.5
                    lambda_tuning_step[key] = 0.25
            
            for key, value in mo.lambda_dict.items():
                if key not in filtered_pc_event_counter:
                    mo.lambda_dict[key] = mo.lambda_dict[key] - lambda_tuning_step[key]
                    lambda_tuning_step[key] = 0.5 * lambda_tuning_step[key]

            # Tune Alpha
            benign_nid_labels = {}
            public_nid_labels = {}
            for item in node_gradients:
                if item[0][1] == 'i':
                    if item[0] not in benign_nid_labels:
                        benign_nid_labels[item[0]] = []
                    benign_nid_labels[item[0]].append(item[1])
                elif item[0][1] == 'c':
                    if item[0] not in public_nid_labels:
                        public_nid_labels[item[0]] = []
                    public_nid_labels[item[0]].append(item[1])
                
            benign_node_dict = {}
            for node, value in benign_nid_labels.items():
                if mo.Nodes[node[0]].get_name() not in benign_node_dict:
                    benign_node_dict[mo.Nodes[node[0]].get_name()] = []
                benign_node_dict[mo.Nodes[node[0]].get_name()].extend(value)

            public_node_dict = {}
            for node, value in public_nid_labels.items():
                if mo.Nodes[node[0]].get_name() not in public_node_dict:
                    public_node_dict[mo.Nodes[node[0]].get_name()] = []
                public_node_dict[mo.Nodes[node[0]].get_name()].extend(value)

            # for key, item in benign_node_dict.items():
            #     if len(item) > 10 and sum(item)/len(item) > 0.9:
            #         mo.white_name_set.add(key)

            for key, item in benign_node_dict.items():
                if len(item) > 10 and sum(item)/len(item) > 0.9:
                    if key not in mo.alpha_dict:
                        mo.alpha_dict[key] = 0.5
                        alpha_tuning_step[key] = 0.25
                    else:
                        mo.alpha_dict[key] = mo.alpha_dict[key] + alpha_tuning_step[key]
                        alpha_tuning_step[key] = 0.5 * alpha_tuning_step[key]

            for key in mo.alpha_dict.keys():
                if key not in benign_node_dict:
                    mo.alpha_dict[key] = mo.alpha_dict[key] - alpha_tuning_step[key]
                    alpha_tuning_step[key] = 0.5 * alpha_tuning_step[key]

            # Tune tau
            # Sort the event_key by the number of alarms it triggered and keep the top 50%
            sorted_items = sorted(fp_counter.items(), key=lambda x: sum(x[1]), reverse=True)
            half_length = len(sorted_items) // 2
            selected_items = sorted_items[:half_length]
            selected_dict = dict(selected_items)

            for event_key in tau_tuning_step.keys():
                if event_key not in selected_dict.keys():
                    for i, v in enumerate(tau_tuning_step[event_key]):
                        mo.tau_dict[event_key][i] += tau_tuning_step[event_key][i]
                        tau_tuning_step[event_key][i] *= 0.5

            for event_key in selected_dict.keys():
                for i, v in enumerate(selected_dict[event_key]):
                    if v > 10:
                        if event_key not in mo.tau_dict.keys():
                            mo.tau_dict[event_key] = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
                            tau_tuning_step[event_key] = [0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25]
                        mo.tau_dict[event_key][i] -= tau_tuning_step[event_key][i]
                        tau_tuning_step[event_key][i] *= 0.5

            experiment.reset_metrics()
        
        Path(os.path.join(experiment.get_experiment_output_path(), 'params')).mkdir(parents=True, exist_ok=True)
        with open(os.path.join(experiment.get_experiment_output_path(), 'params/lambda.pickle'), 'wb') as fout:
            pickle.dump(mo.lambda_dict, fout)
        with open(os.path.join(experiment.get_experiment_output_path(), 'params/tau.pickle'), 'wb') as fout:
            pickle.dump(mo.tau_dict, fout)
        with open(os.path.join(experiment.get_experiment_output_path(), 'params/alpha.pickle'), 'wb') as fout:
            pickle.dump(mo.alpha_dict, fout)

    elif args.mode == "test":
        begin_time = time.time()
        # experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)
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
            events = read_events_from_files(os.path.join(args.data_path, 'edges.json'), args.time_range)
            nodes = pd.read_json(os.path.join(args.data_path, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
            princicals = pd.read_json(os.path.join(args.data_path, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, nodes, princicals], f)

        mo.Principals = princicals

        with open(os.path.join(args.param_path, 'train', 'params/lambda.pickle'), 'rb') as fin:
            mo.lambda_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/tau.pickle'), 'rb') as fin:
            mo.tau_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/alpha.pickle'), 'rb') as fin:
            mo.alpha_dict = pickle.load(fin)

        false_alarms = []
        for event in tqdm.tqdm(events):
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
                continue
                
            if event.src not in mo.Nodes:
                add_nodes_to_graph(mo, event.src, nodes[event.src])

            if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                add_nodes_to_graph(mo, event.dest, nodes[event.dest])

            if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

            gt = ec.classify(event.id)
            diagnosis = mo.add_event(event, gt)
            experiment.update_metrics(diagnosis, gt)
            # if gt != None and diagnosis == None:
            #     print(event.id)
            if gt == None and diagnosis != None:
                false_alarms.append(diagnosis)
                        
        mo.alarm_file.close()
        experiment.print_metrics()
        experiment.save_metrics()
        ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
        ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

        print(Counter(false_alarms))

        print("Detecting Time: {:.2f}s".format(time.time()-begin_time))
        print("Metrics saved in {}".format(experiment.get_experiment_output_path()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--data_path", type=str)
    parser.add_argument("--epoch", default=10, type=int)
    parser.add_argument("--mode", type=str)
    parser.add_argument("--data_tag", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--param_path", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)
