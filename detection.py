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
# from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
from parse.eventType import lttng_events, cdm_events, standard_events
from parse.eventType import UNUSED_SET
import numpy as np
from pathlib import Path
import pickle

def start_experiment(config):
    args = config
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
    for i in range(args['volume_num']):
        print("Loading the no.{} volume...".format(i))
        with open(args['test_data']+'.'+str(i),'r') as fin:
            for line in fin:
                if loaded_line > r_range:
                    break
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("Morse has loaded {} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                # assert len(record_type)==1
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == 'Event':
                    if loaded_line < l_range:
                        continue
                    if cdm_events[record_datum['type']] not in UNUSED_SET:
                        event = parse_event(record_datum)
                        event_str = '{},{},{}'.format(event['src'], event['type'], event['dest'])
                        if event_str != last_event_str:
                            # if event['src'] == '4F7334B2-4889-B654-9AC8-84794886D7B6' or event['dest'] == '4F7334B2-4889-B654-9AC8-84794886D7B6':
                            #     a = 0
                            last_event_str = event_str
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

    ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))

    experiment.print_metrics()
    experiment.save_metrics()
    experiment.reset_metrics()
    ec.reset()

    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--ground_truth_file", default='/home/weijian/weijian/projects/ATPG/groundTruth32.txt', type=str)
    parser.add_argument("--test_data", nargs='?', default="/home/weijian/weijian/projects/E32-trace/ta1-trace-e3-official-1.json", type=str)
    parser.add_argument("--volume_num", nargs='?', default=7, type=int)
    parser.add_argument("--experiment_prefix", default="Manual-T32", type=str)
    parser.add_argument("--mode", nargs="?", default="test", type=str)
    parser.add_argument("--line_range", nargs=2, type=int, default=[10000000,35000000])

    args = parser.parse_args()

    config = {
        "volume_num": args.volume_num,
        "test_data": args.test_data,
        "ground_truth_file": args.ground_truth_file,
        "experiment_prefix": args.experiment_prefix,
        "mode": args.mode,
        "line_range": args.line_range
    }

    start_experiment(config)

