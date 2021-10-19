<<<<<<< HEAD
import os
import fire
import json
# from globals import GlobalVariable as gv
import torch
import logging
import argparse
# from new_train import train_model
import time
# from predict import predict_entry
# from utils.utils import save_hyperparameters
# from utils.utils import save_evaluation_results
=======
import torch
import logging
import argparse
import time
>>>>>>> 00e1a838b6e506346a3cf9da90e2ebdb373d7ca8
from utils.utils import *
from model.loss import get_loss
from utils.eventClassifier import eventClassifier
from model.morse import Morse
from collections import defaultdict

from numpy import record
from parse.eventParsing import parse_event
from parse.nodeParsing import parse_subject, parse_object
from parse.lttng.recordParsing import read_lttng_record
from policy.initTagsAT import get_object_feature, get_subject_feature
import sys
import tqdm
import time
import pandas as pd
import numpy as np
# from datetime import *
from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer

def start_experiment(config="config.json"):
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--batch_size", nargs='?', default=5, type=int)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--learning_rate", nargs='?', default=0.001, type=float)
    parser.add_argument("--feature_dimension", nargs='?', default=12, type=int)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--train_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--test_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--validation_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)


    args = parser.parse_args()
    if args.mode == "train":
        experiment = Experiment(str(int(time.time())), args)
    else:
        experiment = Experiment(args.trained_model_timestamp, args)

    learning_rate = args.learning_rate
    batch_size = args.batch_size
    sequence_size = args.sequence_length
    feature_size = args.feature_dimension
    if torch.cuda.is_available():
        device = torch.device("cuda:0")
    train_data = args.train_data
    test_data = args.test_data
    validation_data = args.validation_data
    model_save_path = args.model_save_path
    epoch = args.epoch
    mode = args.mode

    if (mode == "train"):
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()

        ec = eventClassifier('groundTruth.txt')

        for epoch in range(epoch):
            # pytorch model training code goes here
            # ...
            null = 0
            mo = Morse()
            
            # ============= Tag Initializer =============== #
            node_inits = {}
            node_inits['Subject'] = Initializer(1,5)
            node_inits['NetFlowObject'] = Initializer(1,2)
            node_inits['SrcSinkObject'] = Initializer(111,2)
            node_inits['FileObject'] = FileObj_Initializer(2)
            node_inits['UnnamedPipeObject'] = Initializer(1,2)
            node_inits['MemoryObject'] = Initializer(1,2)
            node_inits['PacketSocketObject'] = Initializer(1,2)
            node_inits['RegistryKeyObject'] = Initializer(1,2)
            mo.subj_init = node_inits['Subject']
            mo.obj_inits = node_inits

            node_inital_tags = {}
            initialized_line = 0
            node_num = 0

            with open('results/features/features.json','r') as fin:
                node_features = json.load(fin)
            df = pd.DataFrame.from_dict(node_features,orient='index')

            for node_type in ['NetFlowObject','SrcSinkObject','FileObject','UnnamedPipeObject','MemoryObject','PacketSocketObject','RegistryKeyObject']:
                target_features = df[df['type']==node_type]
                feature_array = target_features['features'].values.tolist()
                feature_array = torch.tensor(feature_array, dtype=torch.int64)
                tags = node_inits[node_type].initialize(feature_array).squeeze()
                for i, node_id in enumerate(target_features.index.tolist()):
                    node_inital_tags[node_id] = tags[i,:]

            node_type = 'Subject'
            target_features = df[df['type']==node_type]
            feature_array = [[0] for i in range(len(target_features))]
            feature_array = torch.tensor(feature_array, dtype=torch.int64)
            tags = node_inits[node_type].initialize(feature_array).squeeze()
            for i, node_id in enumerate(target_features.index.tolist()):
                node_inital_tags[node_id] = tags[i,:]

            mo.node_inital_tags = node_inital_tags


            # morse applied here on all events with initial tags from NN
<<<<<<< HEAD

            file = '/Users/lexus/Documents/research/APT/Data/E3/ta1-trace-e3-official-1.json/ta1-trace-e3-official-1.json'
            parsed_line = 0
            for i in range(7):
                with open(file+'.'+str(i),'r') as fin:
                    # for line in tqdm.tqdm(fin):
                    for line in fin:
                        parsed_line += 1
                        if parsed_line % 100000 == 0:
                            print("Morse has parsed {} lines.".format(parsed_line))
                        record_datum = eval(line)['datum']
                        record_type = list(record_datum.keys())
                        assert len(record_type)==1
                        record_datum = record_datum[record_type[0]]
                        record_type = record_type[0].split('.')[-1]
                        if record_type == 'Event':
                            event = parse_event(record_datum)
                            diagnois = mo.add_event(event)
                            gt = ec.classify(event['id'])
                            s = torch.tensor(mo.Nodes[event['src']].tags())
                            o = torch.tensor(mo.Nodes[event['dest']].tags())
                            if diagnois is None:
                                # check if it's fn
                                if gt is not None:
                                    s_loss, o_loss = get_loss(event['type'], s, o, gt, 'false_negative')
                            else:
                                # check if it's fp
                                if gt is None:
                                    s_loss, o_loss = get_loss(event['type'], s, o, diagnois, 'false_positive')
                            s_loss.backward()
                            o_loss.backward()
                        elif record_type == 'Subject':
                            subject_node, subject = parse_subject(record_datum)
                            mo.add_subject(subject_node, subject)
                        elif record_type == 'Principal':
                            mo.Principals[record_datum['uuid']] = record_datum
                        elif record_type.endswith('Object'):
                            object_node, object = parse_object(record_datum, record_type)
                            mo.add_object(object_node, object)
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

=======
            morse = Morse()
            loss_for_nodes = defaultdict([0])
            dataloader = None
            for event in dataloader:
                diagnois = morse.add_event(event)
                gt = ec.classify(event['id'])
                s = torch.tensor(morse.Nodes[event['src']].tags())
                o = torch.tensor(morse.Nodes[event['dest']].tags())
                if diagnois is None:
                    # check if it's fn
                    if gt is not None:
                        s_loss, o_loss = get_loss(event['type'], s, o, gt, 'false_negative')
                        loss_for_nodes[event['src']].append(s_loss)
                        loss_for_nodes[event['dest']].append(o_loss)
                else:
                    # check if it's fp
                    if gt is None:
                        s_loss, o_loss = get_loss(event['type'], s, o, diagnois, 'false_positive')
                        loss_for_nodes[event['src']].append(s_loss)
                        loss_for_nodes[event['dest']].append(o_loss)
>>>>>>> 00e1a838b6e506346a3cf9da90e2ebdb373d7ca8

        trained_model = None
        pred_result = None
        experiment.save_model(trained_model)

    elif (mode == "test"):

        # load pytorch model
        model = experiment.load_model()
        experiment.save_hyperparameters()

        # pytorch model testing code goes here
        # ...
        pred_result = None




        # precision, recall, accuracy, f1 = experiment.evaluate_classification(pred_result)
        # save_evaluation_results(precision, recall, accuracy, f1)


if __name__ == '__main__':
    start_experiment()