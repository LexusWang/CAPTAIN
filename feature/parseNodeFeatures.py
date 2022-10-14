import json
import sys
import logging
import random
import math
import pdb
import os
import gc
import argparse
import time

sys.path.extend(['.', '..', '...'])
# from utils.utils import *
# from model.loss import get_loss
# from utils.eventClassifier import eventClassifier
from collections import defaultdict
from graph.Subject import Subject

from numpy import gradient, record
from policy.initTags import match_path, match_network_addr
import sys
import tqdm
import time
import pandas as pd
from model.morse import Morse
import numpy as np
from pathlib import Path
import pickle

def start_experiment(config):
    begin_time = time.time()
    args = config
    # experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args['experiment_prefix'])

    mo = Morse()

    print("Begin preparing testing...")
    logging.basicConfig(level=logging.INFO,
                        filename='debug.log',
                        filemode='w+',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    # experiment.save_hyperparameters()
    # ec = eventClassifier(args['ground_truth_file'])
        
    mo.node_inital_tags = {}
    # Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    # mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

    # close interval
    if args["line_range"]:
        l_range = args["line_range"][0]
        r_range = args["line_range"][1]
    else:
        l_range = 0
        r_range = 5000000*args['volume_num']

    data_path = args['test_data']
    loaded_line = 0
    last_event_str = ''
    volume_list = os.listdir(data_path)
    # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[1])+0.1*int(x.split('.')[3]))
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
    for volume_name in volume_list:
        print("Loading the {} ...".format(volume_name))
        with open(os.path.join(data_path, volume_name), 'r') as fin:
            for line in fin:
                if loaded_line > r_range:
                    break
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("Morse has loaded {} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())
                record_datum = record_datum[record_type[0]]
                record_type = record_type[0].split('.')[-1]
                if record_type == 'Event':
                    if loaded_line < l_range:
                        continue
                    event = mo.parse_event(record_datum, format='trace', cdm_version = 18)
                elif record_type == 'Subject':
                    subject = mo.parse_subject(record_datum, format='trace', cdm_version = 18)
                    if subject != None:
                        mo.add_subject(subject)
                elif record_type == 'Principal':
                    mo.Principals[record_datum['uuid']] = record_datum
                elif record_type.endswith('Object'):
                    object = mo.parse_object(record_datum, record_type, format='trace', cdm_version = 18)
                    if object != None:
                        mo.add_object(object)
                        # mo.set_object_tags(object.id)
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

    network_feature = open(os.path.join(args['feature_path'], 'NetFlowObject.csv'), 'w')
    file_feature = open(os.path.join(args['feature_path'], 'FileObject.csv'), 'w')
    process_feature = open(os.path.join(args['feature_path'], 'Subject.csv'), 'w')
    src_sink_feature = open(os.path.join(args['feature_path'], 'SrcSinkObject.csv'), 'w')
    print("Key\tProcessName", file = process_feature)
    print("Key\tIP\tPort", file=network_feature)
    print("Key\tPath", file=file_feature)
    print("Key\tSrcSinkName", file=src_sink_feature)

    for key, value in mo.Nodes.items():
        if isinstance(value, Subject):
            print("{}\t{}".format(key, value.processName), file = process_feature)
        else:
            if value.type == 'NetFlowObject':
                print("{}\t{}\t{}".format(key, value.IP, value.port), file=network_feature)
            elif value.type == 'FileObject':
                print("{}\t{}".format(key, value.path), file=file_feature)
            elif value.type == 'SrcSinkObject':
                print("{}\t{}".format(key, value.name), file=src_sink_feature)
    network_feature.close()
    file_feature.close()
    process_feature.close()
    src_sink_feature.close()
    # mo.alarm_file.close()
    # experiment.print_metrics()
    # experiment.save_metrics()
    # ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    # ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

    print(time.time()-begin_time)

    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--test_data", nargs='?', default="/Users/lexus/Documents/research/APT/Data/E32-trace", type=str)
    parser.add_argument("--feature_path", default="/Users/lexus/Documents/research/APT/ATPG/results/T32", type=str)
    parser.add_argument("--line_range", nargs=2, type=int, default=[0,500000000000])

    args = parser.parse_args()

    config = {
        "test_data": args.test_data,
        "feature_path": args.feature_path,
        # "mode": 'test',
        "line_range": args.line_range
    }

    start_experiment(config)

