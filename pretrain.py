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
from model.loss import get_loss
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
import numpy as np
from pathlib import Path
import pickle

def get_network_tags(node_features_dict, node_id, initializer, device):
    features = torch.tensor(node_features_dict[node_id]['features'], dtype=torch.int16).unsqueeze(dim=0).to(device)
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
    features = torch.tensor(input_feature, dtype=torch.int16).unsqueeze(dim=0).to(device)
    return initializer.initialize(features).squeeze()

def get_network_label(node_features_dict, node_id, initializer, device):
    label = torch.tensor(match_network_addr(node_features_dict[node_id]['remoteAddress']), dtype=torch.float)
    return label

def get_file_label(node_features_dict, node_id, initializer, device):
    label = torch.tensor(match_path(node_features_dict[node_id]['path']), dtype=torch.float)
    return label

def stratify_sampling(node_labels, sampling_num):
    pass

def start_experiment(config):
    args = config
    experiment = Experiment(str(int(time.time())), args, args['experiment_prefix'])

    # if torch.cuda.is_available():
    #     device = torch.device("cuda:0")
    device = torch.device("cpu")
    mode = args['mode']
    no_hidden_layers = args['no_hidden_layers']

    mo = Morse(device = device)

    # ============= Tag Initializer =============== #
    node_inits = {}
    node_inits['NetFlowObject'] = NetFlowObj_Initializer(2, no_hidden_layers).to(device)
    node_inits['FileObject'] = FileObj_Initializer(10000, 2,no_hidden_layers).to(device)
    # node_inits['SrcSinkObject'] = Initializer(111,2,no_hidden_layers).to(device)
    # node_inits['UnnamedPipeObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['MemoryObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['PacketSocketObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['RegistryKeyObject'] = Initializer(1,2,no_hidden_layers)

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

        node_labels = {}
        # label generating
        node_type = 'NetFlowObject'
        node_labels[node_type] = {}
        with open(os.path.join(args['raw_feature_path'],'{}.json'.format(node_type)),'r') as fin:
            node_features = json.load(fin)
        for node_id in tqdm.tqdm(node_features.keys()):
            node_labels[node_type][node_id] = get_network_label(node_features, node_id, node_inits[node_type], device)

        node_type = 'FileObject'
        node_labels[node_type] = {}
        with open(os.path.join(args['raw_feature_path'],'{}.json'.format(node_type)),'r') as fin:
            node_features = json.load(fin)
        for node_id in tqdm.tqdm(node_features.keys()):
            node_labels[node_type][node_id] = get_file_label(node_features, node_id, node_inits[node_type], device)
        
        model_nids = {}
        model_features = {}
        for node_type in ['NetFlowObject']:
            with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
                node_features = json.load(fin)
            if len(node_features) > 0:
                target_features = pd.DataFrame.from_dict(node_features,orient='index')
                model_nids[node_type] = target_features.index.tolist()
                feature_array = target_features['features'].values.tolist()
            else:
                model_nids[node_type] = []
                feature_array = []
            model_features[node_type] = torch.tensor(feature_array, dtype=torch.int16).to(device)

        for node_type in ['FileObject']:
            with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
                node_features = json.load(fin)
            if len(node_features) > 0:
                target_features = pd.DataFrame.from_dict(node_features,orient='index')
                model_nids[node_type] = target_features.index.tolist()
                ori_feature_array = target_features['features'].values.tolist()
                oh_index = [item[0] for item in ori_feature_array]
                feature_array = []
                for i, item in enumerate(ori_feature_array):
                    input_feature = np.zeros(10002,dtype=np.int16)
                    input_feature[oh_index[i]] = 1
                    input_feature[10000] = item[1]
                    input_feature[10001] = item[2]
                    feature_array.append(list(input_feature))
            else:
                model_nids[node_type] = []
                feature_array = []
            model_features[node_type] = torch.tensor(feature_array, dtype=torch.int16).to(device)

        loss_f = torch.nn.MSELoss()

        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))
            total_loss = 0.0
            loss= 0.0
            for batch in range(3):
                # ============== Initialization ================== #
                model_tags = {}
                node_inital_tags = {}
                for node_type in ['NetFlowObject','FileObject']:
                    total_loss += loss
                    loss= 0.0
                    model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
                    for i, node_id in tqdm.tqdm(enumerate(model_nids[node_type])):
                        if node_type == 'NetFlowObject':
                            if node_labels[node_type][node_id] == [0,1]:
                                if random.randint(0,99) != 37:
                                    continue
                            else:
                                if random.randint(0,4) != 2:
                                    continue
                        elif node_type == 'FileObject':
                            if node_labels[node_type][node_id] == [1,1]:
                                if random.randint(0,99) != 37:
                                    continue
                            else:
                                if random.randint(0,4) != 2:
                                    continue
                        node_inital_tags[node_id] = model_tags[node_type][i,:]
                        loss += loss_f(model_tags[node_type][i,:], node_labels[node_type][node_id])

                    optimizers[node_type].zero_grad()
                    loss.backward()
                    optimizers[node_type].step()

            print('total loss is {}'.format(total_loss))

            # save checkpoint
            experiment.save_checkpoint(node_inits, epoch)

        experiment.save_model(node_inits)

        return None

    elif (mode == "test"):
        print("Begin preparing testing...")
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()
        ec = eventClassifier(args['ground_truth_file'])
       
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


        # for node_type in ['SrcSinkObject']:
        #     with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
        #         node_features = json.load(fin)
        #     if len(node_features) > 0:
        #         target_features = pd.DataFrame.from_dict(node_features,orient='index')
        #         model_nids[node_type] = target_features.index.tolist()
        #     else:
        #         model_nids[node_type] = [] 

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
            node_inital_tags[node_id] = get_network_tags(node_features, node_id, node_inits[node_type], device)

        node_type = 'FileObject'
        with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
            node_features = json.load(fin)
        for node_id in tqdm.tqdm(node_features.keys()):
            node_inital_tags[node_id] = get_file_tags(node_features, node_id, node_inits[node_type], device)

        # for node_type in ['NetFlowObject','FileObject']:
        #     model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
        #     for i, node_id in enumerate(model_nids[node_type]):
        #         node_inital_tags[node_id] = model_tags[node_type][i,:]

        # del model_tags
        # del node_inits
        # gc.collect()

        print('Initialization finished!')
        
        mo.node_inital_tags = node_inital_tags
        # mo.reset_tags()

        Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
        mo.alarm_file = open(
            os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

        # # ================= Load all nodes & edges to memory ==================== #
        # pre_loaded_path = experiment.get_pre_load_morse(args['data_tag'])

        events = []
        loaded_line = 0
        for i in range(args['volume_num']):
            print("Loading the no.{} volume...".format(i))
            with open(args['test_data']+'.'+str(i),'r') as fin:
                for line in fin:
                    loaded_line += 1
                    if loaded_line % 100000 == 0:
                        print("Morse has loaded {} lines.".format(loaded_line))
                    record_datum = json.loads(line)['datum']
                    record_type = list(record_datum.keys())
                    assert len(record_type)==1
                    record_datum = record_datum[record_type[0]]
                    record_type = record_type[0].split('.')[-1]
                    if record_type == 'Event':
                        event = parse_event(record_datum)
                        if cdm_events[event['type']] not in UNUSED_SET:
                            event_id = record_datum['uuid']
                            gt = ec.classify(event_id)
                            diagnois, s_loss, o_loss, s_tags, o_tags, s_morse_grads, o_morse_grads, s_init_id, o_init_id = mo.add_event_generate_loss(event, gt)
                            experiment.update_metrics(diagnois, gt)
                    elif record_type == 'Subject':
                        subject = parse_subject(record_datum)
                        if subject != None:
                            mo.add_subject(subject)
                    elif record_type == 'Principal':
                        mo.Principals[record_datum['uuid']] = record_datum
                    elif record_type.endswith('Object'):
                        object = parse_object(record_datum, record_type)
                        if object != None:
                            mo.add_object(object)
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

        ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

        experiment.print_metrics()
        experiment.save_metrics()
        experiment.reset_metrics()
        ec.reset()

        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", default='/home/weijian/weijian/projects/ATPG/results/features/feature_vectors', type=str)
    parser.add_argument("--raw_feature_path", default='/home/weijian/weijian/projects/ATPG/results/features', type=str)
    parser.add_argument("--ground_truth_file", default='/home/weijian/weijian/projects/ATPG/groundTruth32.txt', type=str)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--learning_rate", nargs='?', default=2.0, type=float)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)
    parser.add_argument("--lr_imb", default=2.0, type=float)
    parser.add_argument("--experiment_prefix", default="Pretrain", type=str)
    parser.add_argument("--no_hidden_layers", default=1, type=int)
    parser.add_argument("--from_checkpoint", type=str)
    parser.add_argument("--batch_size", type=int, default=100000000)

    args = parser.parse_args()

    config = {
        "learning_rate": args.learning_rate,
        "epoch": args.epoch,
        "lr_imb": args.lr_imb,
        "mode": args.mode,
        "device": args.device,
        "ground_truth_file": args.ground_truth_file,
        "feature_path": args.feature_path,
        "raw_feature_path": args.raw_feature_path,
        "no_hidden_layers": args.no_hidden_layers,
        "experiment_prefix": args.experiment_prefix,
        "trained_model_timestamp": args.trained_model_timestamp,
        "from_checkpoint": args.from_checkpoint,
        "batch_size": args.batch_size
    }

    start_experiment(config)

