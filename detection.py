import os
from datetime import *
import json
# import torch
# import logging
import argparse
import time
from utils.utils import *
from model.loss import get_loss
from utils.eventClassifier import eventClassifier
from model.morse import Morse
# from collections import defaultdict

# from numpy import gradient, record
from parse.eventParsing import parse_event
from parse.nodeParsing import parse_subject, parse_object
from parse.lttng.recordParsing import read_lttng_record
from policy.initTags import initSubjectTags, initObjectTags
# import sys
import tqdm
import time
# import pandas as pd
from model.morse import Morse
# from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
import numpy as np
from pathlib import Path
import pickle


def start_detection(config):
    args = config
    experiment = None
    experiment = Experiment(str(int(time.time())), args, args['experiment_prefix'])

    # learning_rate = args['learning_rate']
    # if torch.cuda.is_available():
    #     device = torch.device("cuda:0")
    # epochs = args['epoch']
    # mode = args['mode']

    mo = Morse()

    # # ============= Tag Initializer =============== #
    # node_inits = {}
    # node_inits['Subject'] = Initializer(150,5)
    # # node_inits['NetFlowObject'] = Initializer(1,2)
    # node_inits['NetFlowObject'] = NetFlowObj_Initializer(2)
    # node_inits['SrcSinkObject'] = Initializer(111,2)
    # node_inits['FileObject'] = FileObj_Initializer(2)
    # node_inits['UnnamedPipeObject'] = Initializer(1,2)
    # node_inits['MemoryObject'] = Initializer(1,2)
    # node_inits['PacketSocketObject'] = Initializer(1,2)
    # node_inits['RegistryKeyObject'] = Initializer(1,2)
    # mo.subj_init = node_inits['Subject']
    # mo.obj_inits = node_inits

    # # ============= Groud Truth & Optimizers ====================#
    # optimizers = {}
    # for key in node_inits.keys():
    #     optimizers[key] = torch.optim.RMSprop(node_inits[key].parameters(), lr=learning_rate)

    # if (mode == "train"):
    #     logging.basicConfig(level=logging.INFO,
    #                         filename='debug.log',
    #                         filemode='w+',
    #                         format='%(asctime)s %(levelname)s:%(message)s',
    #                         datefmt='%m/%d/%Y %I:%M:%S %p')
    #     experiment.save_hyperparameters()

    # ================= Load all nodes & edges to memory ==================== #
    pre_loaded_path = experiment.get_pre_load_morse(args['data_tag'])

    if pre_loaded_path.endswith('.pkl'):
        with open(pre_loaded_path, 'rb') as f:
            events, mo = pickle.load(f)
    else:
        events = []
        loaded_line = 0
        for i in range(1):
            with open(args['detection_data']+'.'+str(i),'r') as fin:
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
                        events.append((record_datum['uuid'],event))
                    elif record_type == 'Subject':
                        subject_node, subject = parse_subject(record_datum)
                        initSubjectTags(subject)
                        mo.add_subject(subject)
                    elif record_type == 'Principal':
                        mo.Principals[record_datum['uuid']] = record_datum
                    elif record_type.endswith('Object'):
                        object_node, object = parse_object(record_datum, record_type)
                        initObjectTags(object)
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
        # cache the loaded morse and events for next run
        with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
            pickle.dump([events, mo], f)


    # model_nids = {}
    # model_features = {}
    # for node_type in ['NetFlowObject','SrcSinkObject','FileObject','UnnamedPipeObject','MemoryObject','PacketSocketObject','RegistryKeyObject','Subject']:
    #     with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
    #         node_features = json.load(fin)
    #     if len(node_features) > 0:
    #         target_features = pd.DataFrame.from_dict(node_features,orient='index')
    #         model_nids[node_type] = target_features.index.tolist()
    #         feature_array = target_features['features'].values.tolist()
    #     else:
    #         model_nids[node_type] = []
    #         feature_array = []
    #     model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64)

    ec = eventClassifier(args['ground_truth_file'])

    # ============== Initialization ================== #
    # model_tags = {}
    # node_inital_tags = {}

    # for node_type in ['NetFlowObject','SrcSinkObject','FileObject','UnnamedPipeObject','MemoryObject','PacketSocketObject','RegistryKeyObject','Subject']:
    #     model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
    #     for i, node_id in enumerate(model_nids[node_type]):
    #         node_inital_tags[node_id] = model_tags[node_type][i,:]
    
    # mo.node_inital_tags = node_inital_tags
    # mo.reset_tags()
    mo.reset_alarms()

    # ============= Dectection =================== #
    # node_gradients = {}
    mo.alarm_file = os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms.txt')
    Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    for event_info in tqdm.tqdm(events):
        event_id = event_info[0]
        event = event_info[1]
        diagnois = mo.add_event(event)
        gt = ec.classify(event_id)
        # s = torch.tensor(mo.Nodes[event['src']].tags(),requires_grad=True)
        # o = torch.tensor(mo.Nodes[event['dest']].tags(),requires_grad=True)
        # is_fp = False

        experiment.update_metrics(diagnois, gt)
        # if diagnois is None:
        #     # check if it's fn
        #     if gt is not None:
        #         s_loss, o_loss = get_loss(event['type'], s, o, gt, 'false_negative')
        # else:
        #     # check if it's fp
        #     if gt is None:
        #         s_loss, o_loss = get_loss(event['type'], s, o, diagnois, 'false_positive')
        #         is_fp = True

    experiment.save_metrics()

    return None


def parse_logs(file):
    null = 0
    mo = Morse()
    data_line = 0
    last_time = 0
    for i in range(7):
        with open(file+'.'+str(i),'r') as fin:
            # for line in tqdm.tqdm(fin):
            for line in fin:
                data_line += 1
                if data_line % 100000 == 0:
                    print("Morse has parsed {} lines.".format(data_line))

                record_datum = eval(line)['datum']
                record_type = list(record_datum.keys())
                assert len(record_type)==1
                record_datum = record_datum[record_type[0]]
                record_type = record_type[0].split('.')[-1]
                if record_type == 'Event':
                    # if record_datum['timestampNanos'] < last_time:
                    #     a = 0
                    # else:
                    #     last_time = record_datum['timestampNanos']
                    event = parse_event(record_datum)
                    mo.add_event(event)
                elif record_type == 'Subject':
                    subject_node, subject = parse_subject(record_datum)
                    mo.add_subject(subject)
                elif record_type == 'TimeMarker':
                    b = 0
                elif record_type == 'StartMarker':
                    b = 0
                elif record_type == 'UnitDependency':
                    b = 0
                elif record_type == 'Host':
                    b = 0
                elif record_type == 'Principal':
                    mo.Principals[record_datum['uuid']] = record_datum
                elif record_type.endswith('Object'):
                    object_node, object = parse_object(record_datum, record_type)
                    mo.add_object(object)
                else:
                    pass



def parse_lttng_logs(file):
    null = 0
    mo = Morse(format='lttng')
    log_types = set()
    event_types = set()
    with open(file,'r') as fin:
        for line in tqdm.tqdm(fin):
            if line[:4] == "data":
                record = read_lttng_record(fin)
            if record.type == 1:
                #edge data
                event = parse_event(record,format='lttng')
                event_types.add(event['type'])
                mo.add_event(event)
            elif record.type == -1:
                #node data
                if record.subtype == 5:
                    # process node
                    if len(record.params)>0:
                        subject_node, subject = parse_subject(record, format='lttng')
                        # print(subject.cmdLine)
                        mo.add_subject(subject)
                elif 0 < record.subtype < 5:
                    # non-common file node
                    object_node, object = parse_object(record, record.subtype, format='lttng')
                    mo.add_object(object)
                elif record.subtype == -1:
                    # common file node
                    object_node, object = parse_object(record, 0, format='lttng')
                    mo.add_object(object)
            else:
                pass

    return log_types


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run MORSE")
    parser.add_argument("--mode", nargs="?", default="detection", type=str)
    # parser.add_argument("--feature_path", default='/home/weijian/weijian/projects/ATPG/results/features/feature_vectors', type=str)
    parser.add_argument("--ground_truth_file", default='/home/weijian/weijian/projects/ATPG/groundTruth.txt', type=str)
    parser.add_argument("--detection_data", nargs='?', default="/root/Downloads/ta1-trace-e3-official-1.json", type=str)
    parser.add_argument("--data_tag", default="E32-morse", type=str)
    parser.add_argument("--experiment_prefix", default="Original", type=str)

    args = parser.parse_args()

    config = {
        "mode": args.mode,
        "detection_data": args.detection_data,
        "ground_truth_file": args.ground_truth_file,
        # "feature_path": args.feature_path,
        "data_tag": args.data_tag,
        "experiment_prefix": args.experiment_prefix
    }

    start_detection(config)
    
    
