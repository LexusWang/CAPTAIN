from numpy import record
from parse.eventParsing import parse_event
from parse.nodeParsing import parse_subject, parse_object
from parse.lttng.recordParsing import read_lttng_record
from policy.initTagsAT import get_object_feature, get_subject_feature
import re
import sys
import os
import tqdm
import json
import time
import pandas as pd
import numpy as np
import torch
# from datetime import *

import torch
import time
from utils.utils import *
from model.loss import get_loss
from utils.eventClassifier import eventClassifier
from model.morse import Morse
from collections import defaultdict

from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer

def get_node_features(file):
    null = 0
    node_features = {}

    initialized_line = 0
    node_num = 0
    for i in range(7):
        with open(file+'.'+str(i),'r') as fin:
            for line in fin:
                initialized_line += 1
                if initialized_line % 100000 == 0:
                    print("Morse has initialized {} lines, {} nodes.".format(initialized_line, node_num))
                record_datum = eval(line)['datum']
                record_type = list(record_datum.keys())
                assert len(record_type)==1
                record_datum = record_datum[record_type[0]]
                record_type = record_type[0].split('.')[-1]
                if record_type == 'Subject':
                    node_num += 1
                    subject_node, subject = parse_subject(record_datum)
                    node_features[subject_node['uuid']] = {}
                    node_features[subject_node['uuid']]['features'] = get_subject_feature(subject)
                    node_features[subject_node['uuid']]['type'] = 'Subject'
                elif record_type.endswith('Object'):
                    node_num += 1
                    object_node, object = parse_object(record_datum, record_type)
                    node_features[object_node['uuid']] = {}
                    node_features[object_node['uuid']]['features'] = get_object_feature(object)
                    node_features[object_node['uuid']]['type'] = record_type
    df = pd.DataFrame.from_dict(node_features,orient='index')
    # print(df)
    df.to_json('results/features/features.json', orient='index')

def parse_logs(file):
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

    # ============= Dectection =================== #
    ec = eventClassifier('groundTruth.txt')
    if ec.classify('123'):
        print("correctly classified")
    else:
        print("error")
    
    a = node_inits['FileObject'].parameters()
    optimizers = {}
    for key in node_inits.keys():
        optimizers[key] = torch.optim.RMSprop(node_inits[key].parameters(), lr=0.001)

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
                    gt = ec.classify(record_datum['uuid'])
                    s = torch.tensor(mo.Nodes[event['src']].tags(),requires_grad=True)
                    o = torch.tensor(mo.Nodes[event['dest']].tags(),requires_grad=True)
                    needs_to_update = False
                    if diagnois is None:
                        # check if it's fn
                        if gt is not None:
                            s_loss, o_loss = get_loss(event['type'], s, o, gt, 'false_negative')
                            needs_to_update = True
                    else:
                        # check if it's fp
                        if gt is None:
                            s_loss, o_loss = get_loss(event['type'], s, o, diagnois, 'false_positive')
                            needs_to_update = True
                    
                    if needs_to_update:
                        s_loss.backward()
                        o_loss.backward()

                        for key in optimizers.keys():
                            optimizers[key].zero_grad()

                        s_init_id = mo.Nodes[event['src']].getInitID()
                        s_morse_grads = mo.Nodes[event['src']].get_grad()
                        o_init_id = mo.Nodes[event['dest']].getInitID()
                        o_morse_grads = mo.Nodes[event['dest']].get_grad()
                        nodes_need_updated = {}
                        if s.grad != None:
                            for i, node_id in enumerate(s_init_id):
                                if node_id not in nodes_need_updated:
                                    nodes_need_updated[node_id] = torch.zeros(5)
                                nodes_need_updated[node_id][i] += s.grad[i]*s_morse_grads[i]

                        if o.grad != None:
                            for i, node_id in enumerate(o_init_id):
                                if node_id not in nodes_need_updated:
                                    nodes_need_updated[node_id] = torch.zeros(5)
                                nodes_need_updated[node_id][i] += o.grad[i]*o_morse_grads[i]

                        for nid in nodes_need_updated.keys():
                            if node_inital_tags[nid].shape[0] == 2:
                                node_inital_tags[nid].backward(gradient=nodes_need_updated[nid][-2:])
                            else:
                                node_inital_tags[nid].backward(gradient=nodes_need_updated[nid])

                        for key in optimizers.keys():
                            optimizers[key].step()

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
                        mo.add_subject(subject_node, subject)
                elif 0 < record.subtype < 5:
                    # non-common file node
                    object_node, object = parse_object(record, record.subtype, format='lttng')
                    mo.add_object(object_node, object)
                elif record.subtype == -1:
                    # common file node
                    object_node, object = parse_object(record, 0, format='lttng')
                    mo.add_object(object_node, object)
            else:
                pass

    return log_types


if __name__ == '__main__':
    file = '/Users/lexus/Documents/research/APT/Data/E3/ta1-trace-e3-official-1.json/ta1-trace-e3-official-1.json'
    # get_node_features(file)
    parse_logs(file)
    # file = '/Users/lexus/Documents/research/APT/Data/lttng/reverseshell_debug.out'
    # parse_lttng_logs(file)
