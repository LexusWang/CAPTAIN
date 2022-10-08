import json
import torch
import logging
import random
import math
import psutil
import os
import gc
import argparse
import time
from utils.utils import *
from collections import Counter
from utils.eventClassifier import eventClassifier
from model.morse import Morse
from collections import defaultdict

from numpy import gradient, record
from parse.eventParsing import parse_event
from parse.nodeParsing import parse_subject, parse_object
from parse.lttng.recordParsing import read_lttng_record
from policy.initTags import match_path, match_network_addr
import sys
import tqdm
import time
import pandas as pd
from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
from parse.eventType import lttng_events, cdm_events, standard_events
from parse.eventType import UNUSED_SET
from utils.graphLoader import read_graph_from_files
import numpy as np
from pathlib import Path
import pickle

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

def start_experiment(config):
    args = config
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args['experiment_prefix'])

    # if torch.cuda.is_available():
    #     device = torch.device("cuda:0")
    device = torch.device("cpu")
    mode = args['mode']
    no_hidden_layers = args['no_hidden_layers']

    # mo = Morse()

    # ============= Tag Initializer =============== #
    node_inits = {}
    node_inits['NetFlowObject'] = NetFlowObj_Initializer(2, no_hidden_layers).to(device)
    # node_inits['FileObject'] = FileObj_Initializer(10000, 2,no_hidden_layers).to(device)
    # node_inits['SrcSinkObject'] = Initializer(111,2,no_hidden_layers).to(device)
    # node_inits['UnnamedPipeObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['MemoryObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['PacketSocketObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['RegistryKeyObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['Subject'] = Initializer(107, 20, 2, no_hidden_layers).to(device)

    if (mode == "train"):
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        learning_rate = args['learning_rate']
        epochs = args['epoch']

        # load the checkpoint if it is given
        if args['from_checkpoint'] is not None:
            checkpoint_epoch_path = args['from_checkpoint']
            node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)

        # ============= Groud Truth & Optimizers ====================#
        optimizers = {}
        for key in node_inits.keys():
            optimizers[key] = torch.optim.AdamW(node_inits[key].parameters(), lr=learning_rate)
        experiment.save_hyperparameters()

        # ================= Load all nodes & edges to memory ==================== #
        pre_loaded_path = experiment.get_pre_load_morse(args['data_tag'])

        if pre_loaded_path.endswith('.pkl'):
            with open(pre_loaded_path, 'rb') as f:
                events, mo = pickle.load(f)
        else:
            events, mo = read_graph_from_files(args['train_data'], args['line_range'])
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, mo], f)


        model_nids = {}
        model_features = {}
        for node_type in ['NetFlowObject']:
            network_nid_feature = pd.read_csv(os.path.join(args['feature_path'], 'feature_vectors', '{}.csv'.format(node_type)), index_col='Unnamed: 0').to_dict(orient='index')
            with open(os.path.join(args['feature_path'], 'feature_vectors', '{}.json'.format(node_type)),'r') as fin:
                node_features = json.load(fin)
            target_features = pd.DataFrame.from_dict(node_features,orient='index')
            network_feature_index = {}
            for item in target_features.index.tolist():
                index = len(network_feature_index)
                network_feature_index[item] = index
            feature_array = target_features['features'].values.tolist()
            model_features[node_type] = torch.tensor(np.array(feature_array, dtype=np.int16)).to(device)
            
        # for node_type in ['FileObject']:
        #     with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
        #         node_features = json.load(fin)
        #     if len(node_features) > 0:
        #         target_features = pd.DataFrame.from_dict(node_features,orient='index')
        #         model_nids[node_type] = target_features.index.tolist()
        #         ori_feature_array = target_features['features'].values.tolist()
        #         oh_index = [item[0] for item in ori_feature_array]
        #         feature_array = []
        #         for i, item in enumerate(ori_feature_array):
        #             input_feature = np.zeros(10002,dtype=np.int16)
        #             input_feature[oh_index[i]] = 1
        #             input_feature[10000] = item[1]
        #             input_feature[10001] = item[2]
        #             feature_array.append(list(input_feature))
        #     else:
        #         model_nids[node_type] = []
        #         feature_array = []
        #     model_features[node_type] = torch.tensor(feature_array, dtype=torch.int16).to(device)
        
        ec = eventClassifier(args['ground_truth_file'])
        ic_index = {'i':0,'c':1}

        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))

            srcsink_counter = Counter([])

            total_loss = 0.0
            Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
            mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'a')
            mo.reset_morse()

            # ============== Initialization ================== #
            model_tags = {}
            node_inital_tags = {}

            for node_type in ['NetFlowObject']:
                model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
                for nid in network_nid_feature.keys():
                    index = network_feature_index[network_nid_feature[nid]['feature']]
                    node_inital_tags[nid] = model_tags[node_type][index,:]
            mo.node_inital_tags = node_inital_tags
            mo.reset_tags()

            # ============= Dectection =================== #
            node_gradients = {}
            for event_info in tqdm.tqdm(events):
                event_id = event_info[0]
                event = event_info[1]
                gt = ec.classify(event_id)
                diagnosis, s_loss, o_loss, s_tags, o_tags, s_morse_grads, o_morse_grads, s_init_id, o_init_id = mo.add_event_generate_loss(event, gt)
                experiment.update_metrics(diagnosis, gt)

                # if gt == None:
                #     if len(nodes_need_updated) == 0:
                #         continue
                #     if random.randint(0,99) != 37:
                #         continue

                if diagnosis == None:
                    continue

                nodes_need_updated = {}
                if s_loss:
                    total_loss += s_loss.item()
                    s_loss.to(device)
                    s_loss.backward()
                    if s_tags.grad != None:
                        for i, node_info in enumerate(s_init_id):
                            if node_info:
                                if s_tags.grad[i] != 0.0:
                                    node_id = node_info[0]
                                    iorc = node_info[1]
                                    debug_node = mo.Nodes.get(node_id, None)
                                    if debug_node.type == 'SrcSinkObject':
                                        pid = int(debug_node.name.split('_')[-1])
                                        srcsink_counter.update([mo.Nodes[mo.processes[pid]['node']].processName,])
                                        # print(mo.Nodes[mo.processes[pid]['node']].processName)
                                    if node_id not in nodes_need_updated:
                                        nodes_need_updated[node_id] = torch.zeros(2).to(device)
                                    nodes_need_updated[node_id][ic_index[iorc]] += s_tags.grad[i]*s_morse_grads[i]*1

                if o_loss:
                    total_loss += o_loss.item()
                    o_loss.to(device)
                    o_loss.backward()
                    if o_tags.grad != None:
                        for i, node_info in enumerate(o_init_id):
                            if node_info:
                                if o_tags.grad[i] != 0.0:
                                    node_id = node_info[0]
                                    iorc = node_info[1]
                                    debug_node = mo.Nodes.get(node_id, None)
                                    if debug_node.type == 'SrcSinkObject':
                                        pid = int(debug_node.name.split('_')[-1])
                                        srcsink_counter.update([mo.Nodes[mo.processes[pid]['node']].processName,])
                                        # print(mo.Nodes[mo.processes[pid]['node']].processName)
                                    if node_id not in nodes_need_updated:
                                        nodes_need_updated[node_id] = torch.zeros(2).to(device)
                                    nodes_need_updated[node_id][ic_index[iorc]] += o_tags.grad[i]*o_morse_grads[i]*1

                    
                for nid in nodes_need_updated.keys():
                    if nid not in node_gradients:
                        node_gradients[nid] = []
                    node_gradients[nid].append(nodes_need_updated[nid].unsqueeze(0))
                    
            
            for nid in list(node_gradients.keys()):
                node_gradients[nid] = torch.sum(torch.cat(node_gradients[nid],0), dim=0)

            target_tags = {'NetFlowObject': torch.tensor([0.0, 1.0]),
                        'FileObject': torch.tensor([1.0, 1.0]),
                        'SrcSinkObject': torch.tensor([0.0, 1.0])}

            total_unseen_loss = 0.0
            
            for node_type in ['NetFlowObject']:
                gradients = [torch.zeros(2).unsqueeze(0) for i in range(len(network_feature_index))]
                # need_update_index = []
                for nid in network_nid_feature.keys():
                    if nid in node_gradients:
                        i = network_feature_index[network_nid_feature[nid]['feature']]
                        itag, ctag = model_tags[node_type][i].tolist()
                        i_grad, c_grad = node_gradients[nid].tolist()
                        if (itag < 0.8 and i_grad < 0) or (itag > 0.2 and i_grad > 0) or (ctag < 0.8 and c_grad < 0) or (ctag > 0.2 and c_grad > 0):
                            gradients[i] += node_gradients[nid].unsqueeze(0)
                    # else:
                    #     if random.randint(0,999) == 37:
                    #         predicted_tags = model_tags[node_type][i].clone().detach().requires_grad_(True)
                    #         # predicted_tags = torch.tensor(model_tags[node_type][i], requires_grad=True)
                    #         loss = torch.mean(torch.square(predicted_tags - target_tags[node_type]))
                    #         total_unseen_loss += loss.item()
                    #         loss.backward()
                    #         gradients.append(predicted_tags.grad.unsqueeze(0))
                    #         need_update_index.append(i)
                    #         a = predicted_tags.grad.unsqueeze(0)
                    #         b = torch.zeros(2).unsqueeze(0)
                    #     # gradients.append(torch.zeros(2).unsqueeze(0))
                if len(gradients) > 0:
                    # need_update_index = []
                    non_zero_gradients = []
                    for i, item in enumerate(gradients):
                        if item.tolist()[0][0] != 0.0 or item.tolist()[0][1] != 0.0:
                            non_zero_gradients.append(item)
                        else:
                            predicted_tags = model_tags[node_type][i].clone().detach().requires_grad_(True)
                            # loss = loss_func(predicted_tags.unsqueeze(dim=0), torch.tensor([1]))
                            loss = torch.mean(torch.square(predicted_tags - target_tags[node_type]))
                            loss.backward()
                            non_zero_gradients.append(predicted_tags.grad.unsqueeze(0))
                    gradients = torch.cat(non_zero_gradients, 0).to(device)
                    optimizers[node_type].zero_grad()
                    model_tags[node_type].backward(gradient=gradients, retain_graph=True)
                    optimizers[node_type].step()

            print(srcsink_counter)
            print('total loss is {}'.format(total_loss))
            print('total unseen loss is {}'.format(total_unseen_loss))
            mo.alarm_file.close()
            experiment.print_metrics()
            experiment.save_metrics()
            experiment.reset_metrics()
            fAnalyze = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'r')
            ec.analyzeFile(fAnalyze)
            ec.summary(os.path.join(experiment.metric_path, "ec_summary.txt"))
            ec.reset()

            # save checkpoint
            experiment.save_checkpoint(node_inits, epoch)

        experiment.save_model(node_inits)
        # final_metrics = experiment.get_f1_score()
        # experiment.save_metrics()

        return None

    elif (mode == "test"):
        print("Begin preparing testing...")
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()
        
        # load pytorch model
        checkpoint_epoch_path = args['from_checkpoint']
        node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)
        for init in node_inits.keys():
            node_inits[init].to(device)

        print("Begin loading nodes...")
        # model_nids = {}
        # model_features = {}
            
        # print(sys.getsizeof(node_features) / 1024 / 1024, 'MB')
        # print(u'Memory:%.4f GB' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 / 1024))

        ec = eventClassifier(args['ground_truth_file'])
        ic_index = {'i':0,'c':1}

        print('testing mode')
        # ============== Initialization ================== #
        model_tags = {}
        node_inital_tags = {}

        node_type = 'NetFlowObject'
        with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
            node_features = json.load(fin)
        for node_id in tqdm.tqdm(node_features.keys()):
            node_inital_tags[node_id] = get_network_tags(node_features, node_id, node_inits[node_type], device).tolist()

        # node_type = 'FileObject'
        # with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
        #     node_features = json.load(fin)
        # for node_id in tqdm.tqdm(node_features.keys()):
        #     node_inital_tags[node_id] = get_file_tags(node_features, node_id, node_inits[node_type], device).tolist()

        print('Initialization finished!')
        
        mo.node_inital_tags = node_inital_tags
        # mo.reset_tags()

        Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
        mo.alarm_file = open(
            os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

        # # ================= Load all nodes & edges to memory ==================== #
        # pre_loaded_path = experiment.get_pre_load_morse(args['data_tag'])

        volume_list = os.listdir(args['test_data'])
        volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[1])+0.1*int(x.split('.')[3]))
        # close interval
        if args["line_range"]:
            l_range = args["line_range"][0]
            r_range = args["line_range"][1]
        else:
            l_range = 0
            r_range = 5000000*len(volume_list)

        events = []
        loaded_line = 0
        last_event_str = ''
        for volume in volume_list:
            print("Loading the {} ...".format(volume))
            with open(os.path.join(args['test_data'], volume),'r') as fin:
                for line in fin:
                    if loaded_line > r_range:
                        break
                    loaded_line += 1
                    if loaded_line % 100000 == 0:
                        print("Morse has loaded {} lines.".format(loaded_line))
                    record_datum = json.loads(line)['datum']
                    record_type = list(record_datum.keys())
                    assert len(record_type)==1
                    record_datum = record_datum[record_type[0]]
                    record_type = record_type[0].split('.')[-1]
                    if record_type == 'Event':
                        if loaded_line < l_range:
                            continue
                        if cdm_events[record_datum['type']] not in UNUSED_SET:
                            event = parse_event(record_datum)
                            event_str = '{},{},{}'.format(event['src'], event['type'], event['dest'])
                            if event_str != last_event_str:
                                last_event_str = event_str
                                event_id = record_datum['uuid']
                                gt = ec.classify(event_id)
                                diagnosis, s_loss, o_loss, s_tags, o_tags, s_morse_grads, o_morse_grads, s_init_id, o_init_id = mo.add_event_generate_loss(event, gt)
                                experiment.update_metrics(diagnosis, gt)
                    elif record_type == 'Subject':
                        subject = parse_subject(record_datum)
                        if subject != None:
                            mo.add_subject(subject)
                    elif record_type == 'Principal':
                        mo.Principals[record_datum['uuid']] = record_datum
                    elif record_type.endswith('Object'):
                        object = parse_object(record_datum, record_type)
                        if object != None:
                            if object.type == 'FileObject':
                                tag = list(match_path(object.path))
                                mo.node_inital_tags[object.id] = tag
                            mo.add_object(object)
                            mo.set_object_tags(object.id)
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

        
        experiment.print_metrics()
        experiment.save_metrics()
        experiment.reset_metrics()
        
        ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
        ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))
        ec.reset()

        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", default='./results/T32', type=str)
    parser.add_argument("--ground_truth_file", default='./groundTruthT32.txt', type=str)
    parser.add_argument("--train_data", nargs='?', default="../Data/E32-trace", type=str)
    parser.add_argument("--test_data", nargs='?', default="../Data/E32-trace", type=str)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--learning_rate", nargs='?', default=2.0, type=float)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)
    parser.add_argument("--lr_imb", default=2.0, type=float)
    parser.add_argument("--data_tag", default="t32-train", type=str)
    parser.add_argument("--experiment_prefix", default="Train_by_benign", type=str)
    parser.add_argument("--no_hidden_layers", default=1, type=int)
    parser.add_argument("--from_checkpoint", type=str)
    parser.add_argument("--line_range", nargs = 2, type=int, default=[0,10000000])

    args = parser.parse_args()

    config = {
        "learning_rate": args.learning_rate,
        "epoch": args.epoch,
        "lr_imb": args.lr_imb,
        "train_data": args.train_data,
        "test_data": args.test_data,
        "mode": args.mode,
        "device": args.device,
        "ground_truth_file": args.ground_truth_file,
        "feature_path": args.feature_path,
        "data_tag": args.data_tag,
        "no_hidden_layers": args.no_hidden_layers,
        "experiment_prefix": args.experiment_prefix,
        "trained_model_timestamp": args.trained_model_timestamp,
        "from_checkpoint": args.from_checkpoint,
        "line_range": args.line_range
    }

    start_experiment(config)

