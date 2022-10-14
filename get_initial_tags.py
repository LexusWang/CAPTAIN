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


def get_initial_tags(config):
    args = config
    experiment = None
    if args['mode'] == "train":
        experiment = Experiment(str(int(time.time())), args, args['experiment_prefix'])
    else:
        experiment = Experiment(args['trained_model_timestamp'], args, args['experiment_prefix'])
    device = torch.device("cpu")
    no_hidden_layers = args['no_hidden_layers']

    # ============= Tag Initializer =============== #
    node_inits = {}
    node_inits['NetFlowObject'] = NetFlowObj_Initializer(2, no_hidden_layers).to(device)
    # node_inits['SrcSinkObject'] = Initializer(111,2,no_hidden_layers).to(device)
    node_inits['FileObject'] = FileObj_Initializer(10000, 2,no_hidden_layers).to(device)
    # node_inits['UnnamedPipeObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['MemoryObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['PacketSocketObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['RegistryKeyObject'] = Initializer(1,2,no_hidden_layers)

    # load the checkpoint if it is given
    if args['from_checkpoint'] is not None:
        checkpoint_epoch_path = args['from_checkpoint']
        node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)

    # ============== Initialization ================== #    
    node_inital_tags = []
    node_type = 'NetFlowObject'
    with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
        node_features = json.load(fin)
    for node_id in tqdm.tqdm(node_features.keys()):
        node_inital_tags.append({'id':node_id, 'tags':get_network_tags(node_features, node_id, node_inits[node_type], device).tolist()})
        # node_inital_tags[node_id] = get_network_tags(node_features, node_id, node_inits[node_type], device)
    
    df = pd.DataFrame().from_records(node_inital_tags)
    df['itag'] = df['tags'].apply(lambda x:x[0])
    df['ctag'] = df['tags'].apply(lambda x:x[1])
    df = df.drop(columns = ['tags'])
    df.to_json(os.path.join('./results/tags','{}.json'.format(node_type)),orient='records',lines=True)

    node_inital_tags = []
    node_type = 'FileObject'
    with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
        node_features = json.load(fin)
    for node_id in tqdm.tqdm(node_features.keys()):
        node_inital_tags.append({'id':node_id, 'tags':get_file_tags(node_features, node_id, node_inits[node_type], device).tolist()})
        # node_inital_tags[node_id] = get_file_tags(node_features, node_id, node_inits[node_type], device)

    # for node_type in ['NetFlowObject','SrcSinkObject','FileObject','UnnamedPipeObject','MemoryObject']:
    #     node_inital_tags = []
    #     model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
    #     for i, node_id in enumerate(model_nids[node_type]):
    #         node_inital_tags.append({'id':node_id, 'tags':model_tags[node_type][i,:].tolist()})

    df = pd.DataFrame().from_records(node_inital_tags)
    df['itag'] = df['tags'].apply(lambda x:x[0])
    df['ctag'] = df['tags'].apply(lambda x:x[1])
    df = df.drop(columns = ['tags'])
    df.to_json(os.path.join('./results/tags','{}.json'.format(node_type)),orient='records',lines=True)

    return None



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", default='/home/weijian/weijian/projects/ATPG/results/testing/features/feature_vectors', type=str)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--from_checkpoint", nargs="?", default='/home/weijian/weijian/projects/ATPG/experiments/DefaultSetting1650990071/train/checkpoints/epoch-20', type=str)
    parser.add_argument("--data_tag", default="traindata1", type=str)
    parser.add_argument("--experiment_prefix", default="Testing", type=str)
    parser.add_argument("--no_hidden_layers", default=1, type=int)

    args = parser.parse_args()

    config = {
        # "learning_rate": args.learning_rate,
        # "train_data": args.train_data,
        "mode": args.mode,
        "device": args.device,
        "feature_path": args.feature_path,
        "data_tag": args.data_tag,
        "experiment_prefix": args.experiment_prefix,
        "from_checkpoint": args.from_checkpoint,
        "no_hidden_layers": args.no_hidden_layers
    }

    get_initial_tags(config)

