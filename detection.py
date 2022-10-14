import json
import torch
import logging
import random
import math
import pdb
import os
import gc
import argparse
import time
from utils.utils import *
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
from parse.eventType import lttng_events, cdm_events, standard_events
from parse.eventType import UNUSED_SET
import numpy as np
from pathlib import Path
import pickle

def start_experiment(config):
    begin_time = time.time()
    args = config
    format = 'cadets'
    cdm_version = 18
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args['experiment_prefix'])

    mo = Morse()

    print("Begin preparing testing...")
    logging.basicConfig(level=logging.INFO,
                        filename='debug.log',
                        filemode='w+',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    experiment.save_hyperparameters()
    ec = eventClassifier(args['ground_truth_file'])
        
    mo.node_inital_tags = {}
    Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

    # close interval
    if args["line_range"]:
        l_range = args["line_range"][0]
        r_range = args["line_range"][1]
    else:
        l_range = 0
        r_range = 5000000*args['volume_num']

    loaded_line = 0
    last_event_str = ''
    volume_list = os.listdir(args['test_data'])
    # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[1])+0.1*int(x.split('.')[3]))
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
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
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Event':
                    if loaded_line < l_range:
                        continue
                    event = mo.parse_event(record_datum, format, cdm_version)
                    if event:
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str:
                            last_event_str = event_str
                            gt = ec.classify(event.id)
                            # if event.id in {'9082692A-9506-5FFC-8FE2-5900CC9F70BA', '318602CB-9945-5D02-953F-A97A52F6C15B'}:
                            #     pdb.set_trace()
                            diagnois = mo.add_event(event, gt)
                            # diagnois, s_loss, o_loss, s_tags, o_tags, s_morse_grads, o_morse_grads, s_init_id, o_init_id = mo.add_event_generate_loss(event, gt)
                            experiment.update_metrics(diagnois, gt)
                            if gt != None and diagnois == None:
                                print(event.id)
                elif record_type == 'Subject':
                    subject = mo.parse_subject(record_datum, format, cdm_version)
                    if subject != None:
                        mo.add_subject(subject)
                elif record_type == 'Principal':
                    mo.Principals[record_datum['uuid']] = record_datum
                elif record_type.endswith('Object'):
                    object = mo.parse_object(record_datum, record_type, format, cdm_version)
                    if object != None:
                        if object.type == 'FileObject':
                            tag = list(match_path(object.path))
                            mo.node_inital_tags[object.id] = tag
                        elif object.type == 'NetFlowObject':
                            tag = list(match_network_addr(object.IP, object.port))
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

    mo.alarm_file.close()
    experiment.print_metrics()
    experiment.save_metrics()
    ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

    print(time.time()-begin_time)

    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--test_data", nargs='?', type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--line_range", nargs=2, type=int)

    args = parser.parse_args()

    config = {
        "test_data": args.test_data,
        "ground_truth_file": args.ground_truth_file,
        "experiment_prefix": args.experiment_prefix,
        "mode": 'test',
        "line_range": args.line_range
    }

    start_experiment(config)

