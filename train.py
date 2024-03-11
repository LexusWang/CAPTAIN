import torch
import logging
from datetime import datetime
import pdb
import os
import argparse
import numpy as np
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
from pathlib import Path
import pickle

# ================= Load all nodes & edges to memory ==================== #
def load_graph(data_path, time_range, pre_loaded_path):
    if pre_loaded_path.endswith('.pkl'):
        with open(pre_loaded_path, 'rb') as f:
            events, nodes, principals = pickle.load(f)
    else:
        events = read_events_from_files(os.path.join(data_path, 'edges.json'), time_range)
        nodes = pd.read_json(os.path.join(data_path, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
        principals = pd.read_json(os.path.join(data_path, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')
        # cache the loaded morse and events for next run
        with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
            pickle.dump([events, nodes, principals], f)
    return events, nodes, principals

def start_experiment(args):
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)
    experiment.save_hyperparameters()
    mo = Morse(att = args.att, decay = args.decay)
    # ============= Tag Initializer =============== #
    node_inits = {}

    if args.mode == "train":
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        epochs = args.epoch
        Path(os.path.join(experiment.get_experiment_output_path(), 'params')).mkdir(parents=True, exist_ok=True)

        # load the checkpoint if it is given
        if args.checkpoint:
            checkpoint_epoch_path = args.checkpoint
            node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)

        events, nodes, principals = load_graph(args.data_path, args.time_range, experiment.get_pre_load_morse(args.data_tag))

        mo.Principals = principals
        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))
            Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
            mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'a')
            mo.reset_morse()
            # mo.reset_tags()
            total_loss = 0

            # ============= Dectection =================== #
            node_gradients = []
            edge_gradients = []
            propagation_chains = []
            fp_counter = {}
            begin_time = time.time()
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

                diagnosis, tag_indices, s_labels, o_labels, pc, lambda_grad, thr_grad, loss = mo.add_event_generate_loss(event, None)
                experiment.update_metrics(diagnosis, None)

                if diagnosis == None:
                    continue

                total_loss += loss

                if s_labels:
                    node_gradients.extend(s_labels)

                if o_labels:
                    node_gradients.extend(o_labels)

                edge_gradients.extend(lambda_grad)

                for key, value in thr_grad.items():
                    if key not in fp_counter:
                        fp_counter[key] = [0, 0, 0, 0, 0, 0, 0, 0]
                    for i, grad in enumerate(value):
                        if grad:
                            fp_counter[key][i] += grad

            print('The detection loss is :{:.2f}'.format(total_loss))
            experiment.save_to_metrics_file('The detection loss is :{:.2f}'.format(total_loss))

            # # calculate lengths of grad dict
            # grad_dict_lens = {}
            # for key, item in mo.Nodes.items():
            #     grad_dict_lens[key] = item.grad_dict_lens()
            # Path(os.path.join(experiment.get_experiment_output_path(), 'overhead')).mkdir(parents=True, exist_ok=True)
            # with open(os.path.join(experiment.get_experiment_output_path(), 'overhead/grad-dict-len-{}.txt'.format(epoch)),'wb') as fout:
            #     pickle.dump(grad_dict_lens, fout)
            
            mo.alarm_file.close()
            experiment.print_metrics()
            experiment.save_metrics()

            if 'g' in args.param_type:
                # Tune G
                if len(edge_gradients) > 0:
                    seo_lambda_gradients = {}
                    for item in edge_gradients:
                        if item[0] not in seo_lambda_gradients:
                            seo_lambda_gradients[item[0]] = 0
                        seo_lambda_gradients[item[0]] += item[1]
                    for key, value in seo_lambda_gradients.items():
                        if key not in mo.lambda_dict:
                            mo.lambda_dict[key] = 0
                        # mo.lambda_dict[key] = mo.lambda_dict[key] - args.lr * value/experiment.fp
                        mo.lambda_dict[key] = mo.lambda_dict[key] - args.lr*value
                        # mo.lambda_dict[key] = mo.lambda_dict[key] - 1e-6 * value
                        mo.lambda_dict[key] = np.clip(mo.lambda_dict[key], 0.0, 1.0)
                    
                    for key in list(mo.lambda_dict.keys()):
                        mo.lambda_dict[key] = mo.lambda_dict[key] - args.lr * args.gamma * mo.lambda_dict[key]
                        # mo.lambda_dict[key] = mo.lambda_dict[key] - 1e-6 * args.gamma * mo.lambda_dict[key]
                        total_loss += args.gamma * mo.lambda_dict[key] * mo.lambda_dict[key]
                        mo.lambda_dict[key] = np.clip(mo.lambda_dict[key], 0.0, 1.0)
                        if mo.lambda_dict[key] <= 1e-6:
                            del mo.lambda_dict[key]

            if 'a' in args.param_type:
                # Tune A
                intg_nid_labels = {}
                conf_nid_labels = {}
                for item in node_gradients:
                    if item[0][1] == 'i':
                        if item[0] not in intg_nid_labels:
                            intg_nid_labels[item[0]] = []
                        intg_nid_labels[item[0]].append(item[1])
                    elif item[0][1] == 'c':
                        if item[0] not in conf_nid_labels:
                            conf_nid_labels[item[0]] = []
                        conf_nid_labels[item[0]].append(item[1])
                    
                node_iTagGradients_dict = {}
                for node, value in intg_nid_labels.items():
                    node_name = mo.Nodes[node[0]].get_name()
                    node_type = mo.Nodes[node[0]].type
                    if (node_type, node_name) not in node_iTagGradients_dict:
                        node_iTagGradients_dict[(node_type, node_name)] = []
                    node_iTagGradients_dict[(node_type, node_name)].extend(value)

                # node_cTagGradients_dict = {}
                # for node, value in conf_nid_labels.items():
                #     node_name = mo.Nodes[node[0]].get_name()
                #     node_type = mo.Nodes[node[0]].type
                #     if (node_type, node_name) not in node_cTagGradients_dict:
                #         node_cTagGradients_dict[(node_type, node_name)] = []
                #     node_cTagGradients_dict[(node_type, node_name)].extend(value)

                for key in node_iTagGradients_dict.keys():
                    node_iTagGradients_dict[key] = sum(node_iTagGradients_dict[key])

                # for key in node_cTagGradients_dict.keys():
                #     node_cTagGradients_dict[key] = sum(node_cTagGradients_dict[key])

                for key, item in node_iTagGradients_dict.items():
                    if key not in mo.alpha_dict:
                        mo.alpha_dict[key] = mo.get_default_a(key[0], key[1])[0]
                    # mo.alpha_dict[key] = mo.alpha_dict[key] - args.lr *item/experiment.fp
                    mo.alpha_dict[key] -= args.lr*item
                    mo.alpha_dict[key] = np.clip(mo.alpha_dict[key], 0.0, 1.0)

                for key in list(mo.alpha_dict.keys()):
                    default_a0 = mo.get_default_a(key[0], key[1])[0]
                    mo.alpha_dict[key] -= args.lr * args.alpha * (mo.alpha_dict[key] - default_a0)
                    mo.alpha_dict[key] = np.clip(mo.alpha_dict[key], 0.0, 1.0)
                    total_loss += args.alpha * (mo.alpha_dict[key] - default_a0) * (mo.alpha_dict[key] - default_a0)
                    if np.absolute(mo.alpha_dict[key] - default_a0) <= 1e-6:
                        del mo.alpha_dict[key]

                # print("mo.alpha_dict[('NetFlowObject', '207.46.73.59')]:{}".format(mo.alpha_dict.get(('NetFlowObject', '207.46.73.59'),0)))

            if 't' in args.param_type:
                # Tune T
                for key in fp_counter.keys():
                    if key not in mo.tau_dict.keys():
                        mo.tau_dict[key] = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
                    for i, value in enumerate(fp_counter[key]):
                        # mo.tau_dict[key][i] -= args.lr * value/experiment.fp
                        mo.tau_dict[key][i] -= args.lr*value
                        mo.tau_dict[key][i] = max(0, mo.tau_dict[key][i])

                for key in list(mo.tau_dict.keys()):
                    for i in range(len(mo.tau_dict[key])):
                        mo.tau_dict[key][i] = min((mo.tau_dict[key][i] + args.lr * args.tau * (0.5-mo.tau_dict[key][i])), 0.5)
                    total_loss += args.tau * np.linalg.norm(np.array(mo.tau_dict[key]) - 0.5)
                    if np.all(np.isclose(mo.tau_dict[key], 0.5)):
                        del mo.tau_dict[key]

            print('The total loss is :{:.2f}'.format(total_loss))
            print('The training time for this epoch is :{:.2f} s'.format(time.time()-begin_time))
            experiment.save_to_metrics_file('The total loss is :{:.2f}'.format(total_loss))
            experiment.save_to_metrics_file('The training time for this epoch is :{:.2f} s'.format(time.time()-begin_time))
            experiment.reset_metrics()
        
            with open(os.path.join(experiment.get_experiment_output_path(), 'params/lambda-e{}.pickle'.format(epoch)), 'wb') as fout:
                pickle.dump(mo.lambda_dict, fout)
            with open(os.path.join(experiment.get_experiment_output_path(), 'params/tau-e{}.pickle'.format(epoch)), 'wb') as fout:
                pickle.dump(mo.tau_dict, fout)
            with open(os.path.join(experiment.get_experiment_output_path(), 'params/alpha-e{}.pickle'.format(epoch)), 'wb') as fout:
                pickle.dump(mo.alpha_dict, fout)

    elif args.mode == "test":
        print("Begin preparing testing...")
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        ec = eventClassifier(args.ground_truth_file)
            
        Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
        mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

        if args.param_path:
            with open(os.path.join(args.param_path, 'train', 'params/lambda-e{}.pickle'.format(args.model_index)), 'rb') as fin:
                mo.lambda_dict = pickle.load(fin)
            with open(os.path.join(args.param_path, 'train', 'params/tau-e{}.pickle'.format(args.model_index)), 'rb') as fin:
                mo.tau_dict = pickle.load(fin)
            with open(os.path.join(args.param_path, 'train', 'params/alpha-e{}.pickle'.format(args.model_index)), 'rb') as fin:
                mo.alpha_dict = pickle.load(fin)

        # ================= Load all nodes & edges to memory ==================== #
        events, nodes, principals = load_graph(args.data_path, args.time_range, experiment.get_pre_load_morse(args.data_tag))
        mo.Principals = principals

        false_alarms = []
        begin_time = time.time()
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
            # if gt:
            #     pdb.set_trace()
            diagnosis = mo.add_event(event, gt)
            experiment.update_metrics(diagnosis, gt)
            if gt == None and diagnosis != None:
                false_alarms.append(diagnosis)
                
        # # calculate lengths of grad dict
        # reduced_node_num = 0
        # for key, item in mo.Nodes.items():
        #     if mo.Nodes[key].tags()[2] < 0.5:
        #         reduced_node_num += 1
        # print('The reduced graph has {} nodes!'.format(reduced_node_num))
        # experiment.save_to_metrics_file('The reduced graph has {} nodes!'.format(reduced_node_num))

        mo.alarm_file.close()
        experiment.alarm_dis = Counter(false_alarms)
        experiment.detection_time = time.time()-begin_time
        experiment.print_metrics()
        experiment.save_metrics()
        ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
        ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))
        print("Metrics saved in {}".format(experiment.get_experiment_output_path()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--att", type=float)
    parser.add_argument("--decay", type=float)
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--data_path", type=str)
    parser.add_argument("--epoch", default=10, type=int)
    parser.add_argument("--mode", type=str)
    parser.add_argument("--param_type", type=str)
    parser.add_argument("--model_index", type=int)
    parser.add_argument("--data_tag", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--param_path", type=str)
    parser.add_argument("--lr", type=float, default=1)
    parser.add_argument("--alpha", type=float, default=0)
    parser.add_argument("--gamma", type=float, default=0)
    parser.add_argument("--tau", type=float, default=0)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)
