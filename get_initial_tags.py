import json
import torch
import logging
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
# from policy.initTagsAT import get_object_feature, get_subject_feature
import sys
import tqdm
import time
import pandas as pd
from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
import numpy as np
from pathlib import Path
import pickle


def start_experiment(config):
    args = config
    experiment = None
    experiment = Experiment(args['trained_model_timestamp'], args, args['experiment_prefix'])
    no_hidden_layers = args['no_hidden_layers']

    if torch.cuda.is_available():
        device = torch.device("cuda:0")
    else:
        device = torch.device("cpu")

    # ============= Tag Initializer =============== #
    node_inits = {}
    # node_inits['Subject'] = Initializer(150,5,no_hidden_layers)
    # node_inits['NetFlowObject'] = Initializer(1,2)
    node_inits['NetFlowObject'] = NetFlowObj_Initializer(2, no_hidden_layers)
    node_inits['SrcSinkObject'] = Initializer(111,2,no_hidden_layers)
    node_inits['FileObject'] = FileObj_Initializer(2,no_hidden_layers)
    node_inits['UnnamedPipeObject'] = Initializer(1,2,no_hidden_layers)
    node_inits['MemoryObject'] = Initializer(1,2,no_hidden_layers)
    node_inits['PacketSocketObject'] = Initializer(1,2,no_hidden_layers)
    node_inits['RegistryKeyObject'] = Initializer(1,2,no_hidden_layers)
    experiment.load_model(node_inits)

    model_nids = {}
    model_tags = {}
    model_features = {}
    for node_type in ['NetFlowObject','SrcSinkObject','UnnamedPipeObject','MemoryObject']:
        with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
            node_features = json.load(fin)
        if len(node_features) > 0:
            target_features = pd.DataFrame.from_dict(node_features,orient='index')
            model_nids[node_type] = target_features.index.tolist()
            feature_array = target_features['features'].values.tolist()
        else:
            model_nids[node_type] = []
            feature_array = []
        model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64).to(device)
        model_tags[node_type] = node_inits[node_type].forward(model_features[node_type]).squeeze()
        
        with open(os.path.join('./results/features','{}.json'.format(node_type)),'r') as fin:
            node_info = json.load(fin)
        tags = model_tags[node_type].tolist()
        for i, index in enumerate(target_features.index):
            node_info[index]['itags'] = tags[i][0]
            node_info[index]['ctags'] = tags[i][1]
        with open(os.path.join('./results/tags','{}.json'.format(node_type)),'w') as fout:
            json.dump(node_info,fout)

        
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
                feature_array.append(np.zeros(2002))
                feature_array[-1][oh_index[i]] = 1
                feature_array[-1][2000] = item[1]
                feature_array[-1][2001] = item[2]
        else:
            model_nids[node_type] = []
            feature_array = []
        model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64).to(device)
        model_tags[node_type] = node_inits[node_type].forward(model_features[node_type]).squeeze()

        with open(os.path.join('./results/features','{}.json'.format(node_type)),'r') as fin:
            node_info = json.load(fin)
        tags = model_tags[node_type].tolist()
        for i, index in enumerate(target_features.index):
            node_info[index]['itags'] = tags[i][0]
            node_info[index]['ctags'] = tags[i][1]
        with open(os.path.join('./results/tags','{}.json'.format(node_type)),'w') as fout:
            json.dump(node_info,fout)

    return None



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", default='./results/features/feature_vectors', type=str)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    # parser.add_argument("--train_data", nargs='?', default="/root/Downloads/ta1-trace-e3-official-1.json", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default='1640732454', type=str)
    parser.add_argument("--data_tag", default="traindata1", type=str)
    parser.add_argument("--experiment_prefix", default="groupF", type=str)
    parser.add_argument("--no_hidden_layers", default=3, type=int)

    args = parser.parse_args()

    config = {
        # "learning_rate": args.learning_rate,
        # "train_data": args.train_data,
        "mode": args.mode,
        "device": args.device,
        "feature_path": args.feature_path,
        "data_tag": args.data_tag,
        "experiment_prefix": args.experiment_prefix,
        "trained_model_timestamp": args.trained_model_timestamp,
        "no_hidden_layers": args.no_hidden_layers
    }

    start_experiment(config)

