import json
import torch
import logging
import math
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
from parse.eventType import lttng_events, cdm_events, standard_events
from parse.eventType import UNUSED_SET
import numpy as np
from pathlib import Path
import pickle


def start_experiment(config):
    args = config
    experiment = None
    if args['mode'] == "train":
        experiment = Experiment(str(int(time.time())), args, args['experiment_prefix'])
    else:
        experiment = Experiment(args['trained_model_timestamp'], args, args['experiment_prefix'])

    learning_rate = args['learning_rate']
    if torch.cuda.is_available():
        device = torch.device("cuda:0")
    epochs = args['epoch']
    mode = args['mode']
    no_hidden_layers = args['no_hidden_layers']

    mo = Morse()

    # ============= Tag Initializer =============== #
    node_inits = {}
    node_inits['NetFlowObject'] = NetFlowObj_Initializer(2, no_hidden_layers)
    node_inits['SrcSinkObject'] = Initializer(111,2,no_hidden_layers)
    node_inits['FileObject'] = FileObj_Initializer(20000, 2,no_hidden_layers)
    node_inits['UnnamedPipeObject'] = Initializer(1,2,no_hidden_layers)
    node_inits['MemoryObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['PacketSocketObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['RegistryKeyObject'] = Initializer(1,2,no_hidden_layers)

    # load the checkpoint if it is given
    if args['from_checkpoint'] is not None:
        checkpoint_epoch_path = args['from_checkpoint']
        node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)

    # mo.subj_init = node_inits['Subject']
    # mo.obj_inits = node_inits

    # ============= Groud Truth & Optimizers ====================#
    optimizers = {}
    for key in node_inits.keys():
        optimizers[key] = torch.optim.AdamW(node_inits[key].parameters(), lr=learning_rate)

    if (mode == "train"):

        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()

        # ================= Load all nodes & edges to memory ==================== #
        pre_loaded_path = experiment.get_pre_load_morse(args['data_tag'])

        if pre_loaded_path.endswith('.pkl'):
            with open(pre_loaded_path, 'rb') as f:
                events, mo = pickle.load(f)
        else:
            events = []
            loaded_line = 0
            for i in range(args['volume_num']):
                with open(args['train_data']+'.'+str(i),'r') as fin:
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
                                events.append((record_datum['uuid'],event))
                        elif record_type == 'Subject':
                            subject_node, subject = parse_subject(record_datum)
                            if subject != None:
                                mo.add_subject(subject)
                        elif record_type == 'Principal':
                            mo.Principals[record_datum['uuid']] = record_datum
                        elif record_type.endswith('Object'):
                            object_node, object = parse_object(record_datum, record_type)
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
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, mo], f)


        model_nids = {}
        model_features = {}
        for node_type in ['SrcSinkObject','NetFlowObject','UnnamedPipeObject','MemoryObject']:
            with open(os.path.join(args['feature_path'],'{}.json'.format(node_type)),'r') as fin:
                node_features = json.load(fin)
            if len(node_features) > 0:
                target_features = pd.DataFrame.from_dict(node_features,orient='index')
                model_nids[node_type] = target_features.index.tolist()
                feature_array = target_features['features'].values.tolist()
            else:
                model_nids[node_type] = []
                feature_array = []
            model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64)

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
                    input_feature = np.zeros(20002,dtype=np.int64)
                    input_feature[oh_index[i]] = 1
                    input_feature[20000] = item[1]
                    input_feature[20001] = item[2]
                    feature_array.append(list(input_feature))
            else:
                model_nids[node_type] = []
                feature_array = []
            model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64)
        
        ec = eventClassifier(args['ground_truth_file'])
        ic_index = {'i':0,'c':1}

        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))
            Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
            mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'a')
            mo.reset_morse()
            batch_num = math.ceil(len(events)/args['batch_size'])
            pbar = tqdm.tqdm(total=len(events))

            for batch in range(batch_num):
                batch_events = events[batch*args['batch_size']:min(len(events),(batch+1)*args['batch_size'])]
            
                # ============== Initialization ================== #
                model_tags = {}
                node_inital_tags = {}

                for node_type in ['NetFlowObject','SrcSinkObject','FileObject','UnnamedPipeObject','MemoryObject']:
                    model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
                    for i, node_id in enumerate(model_nids[node_type]):
                        node_inital_tags[node_id] = model_tags[node_type][i,:]
                
                mo.node_inital_tags = node_inital_tags
                mo.reset_tags()

                # ============= Dectection =================== #
                node_gradients = {}
                for event_info in batch_events:
                    pbar.update(1)
                    event_id = event_info[0]
                    event = event_info[1]
                    if cdm_events[event['type']] not in UNUSED_SET:
                        gt = ec.classify(event_id)
                        diagnois, s_loss, o_loss, s_tags, o_tags, s_morse_grads, o_morse_grads, s_init_id, o_init_id = mo.add_event_generate_loss(event, gt)
                        # needs_to_update = False
                        # is_fp = False
                        # src = mo.Nodes.get(event['src'], None)
                        # dest = mo.Nodes.get(event['dest'], None)
                        # if src and dest:
                        #     s = torch.tensor(src.tags(),requires_grad=True)
                        #     o = torch.tensor(dest.tags(),requires_grad=True)

                        #     if epoch == epochs - 1:
                        #         experiment.update_metrics(diagnois, gt)
                        #     if diagnois is None:
                        #         # check if it's fn
                        #         if gt is not None:
                        #             s_loss, o_loss = get_loss(event['type'], s, o, gt, 'false_negative')
                        #             # if np.random.randint(0, 100, 1) == 1:
                        #             needs_to_update = True
                        #         else:
                        #             s_loss, o_loss = get_loss(event['type'], s, o, gt, 'true_negative')
                        #             # if np.random.randint(0, 100, 1) == 1:
                        #             if s_loss != 0.0 or o_loss != 0.0:
                        #                 needs_to_update = True
                        #     else:
                        #         ec.tally(event_id)
                        #         # check if it's fp
                        #         if gt is None:
                        #             s_loss, o_loss = get_loss(event['type'], s, o, diagnois, 'false_positive')
                        #             # if np.random.randint(0, 100, 1) == 1:
                        #             needs_to_update = True
                        #             is_fp = True
                        #         else:
                        #             s_loss, o_loss = get_loss(event['type'], s, o, diagnois, 'true_positive')
                        #             needs_to_update = True
                        nodes_need_updated = {}
                        
                        if s_loss:
                            s_loss.backward()
                            if s_tags.grad != None:
                                for i, node_info in enumerate(s_init_id):
                                    if node_info:
                                        node_id = node_info[0]
                                        iorc = node_info[1]
                                        if node_id not in nodes_need_updated:
                                            nodes_need_updated[node_id] = torch.zeros(2)
                                        nodes_need_updated[node_id][ic_index[iorc]] += s_tags.grad[i]*s_morse_grads[i]*1

                        if o_loss:
                            o_loss.backward()
                            if o_tags.grad != None:
                                for i, node_info in enumerate(o_init_id):
                                    if node_info:
                                        node_id = node_info[0]
                                        iorc = node_info[1]
                                        if node_id not in nodes_need_updated:
                                            nodes_need_updated[node_id] = torch.zeros(2)
                                        nodes_need_updated[node_id][ic_index[iorc]] += o_tags.grad[i]*o_morse_grads[i]*1

                        for nid in nodes_need_updated.keys():
                            if nid not in node_gradients:
                                node_gradients[nid] = []
                            node_gradients[nid].append(nodes_need_updated[nid].unsqueeze(0))
                        
                        # if needs_to_update:
                        #     if s_loss != 0.0 or o_loss != 0.0:
                        #         s_loss.backward()
                        #         o_loss.backward()

                        #         if is_fp:
                        #             a = args['lr_imb']
                        #         else:
                        #             a = 1

                        #         s_init_id = mo.Nodes[event['src']].getInitID()
                        #         s_morse_grads = mo.Nodes[event['src']].get_grad()
                        #         o_init_id = mo.Nodes[event['dest']].getInitID()
                        #         o_morse_grads = mo.Nodes[event['dest']].get_grad()
                        #         nodes_need_updated = {}
                        #         if s.grad != None:
                        #             for i, node_id in enumerate(s_init_id):
                        #                 if node_id not in nodes_need_updated:
                        #                     nodes_need_updated[node_id] = torch.zeros(5)
                        #                 nodes_need_updated[node_id][i] += s.grad[i]*s_morse_grads[i]*a

                        #         if o.grad != None:
                        #             for i, node_id in enumerate(o_init_id):
                        #                 if node_id not in nodes_need_updated:
                        #                     nodes_need_updated[node_id] = torch.zeros(5)
                        #                 nodes_need_updated[node_id][i] += o.grad[i]*o_morse_grads[i]*a

                        #         for nid in nodes_need_updated.keys():
                        #             if nid not in node_gradients:
                        #                 node_gradients[nid] = []
                        #             node_gradients[nid].append(nodes_need_updated[nid].unsqueeze(0))

                for nid in list(node_gradients.keys()):
                    node_gradients[nid] = torch.mean(torch.cat(node_gradients[nid],0), dim=0)

                ## output gradient to csv
                df =pd.DataFrame.from_dict(node_gradients, orient='index', columns=['i_gradient','c_gradient'])
                df['i_gradient'] = df['i_gradient'].map(lambda x: x.item())
                df['c_gradient'] = df['c_gradient'].map(lambda x: x.item())
                # df.to_csv('results/gradients.csv',index=True,index_label='Node_id')

                df2 =pd.DataFrame.from_dict(node_inital_tags, orient='index', columns=['i_tag','c_tag'])
                df2['i_tag'] = df2['i_tag'].map(lambda x: x.item())
                df2['c_tag'] = df2['c_tag'].map(lambda x: x.item())
                # df2.to_csv('results/tags.csv',index=True,index_label='Node_id')

                df3 = df.join(df2, how='inner')
                df3.to_csv('results/tags-grad-{}.csv'.format(epoch),index=True,index_label='Node_id')

                a = df3.to_dict(orient='records')
                
                for node_type in ['NetFlowObject','SrcSinkObject','FileObject','UnnamedPipeObject','MemoryObject']:
                    gradients = []
                    need_update_index = []
                    for i, nid in enumerate(model_nids[node_type]):
                        if nid in node_gradients:
                            gradients.append(node_gradients[nid].unsqueeze(0))
                            need_update_index.append(i)
                        # else:
                        #     gradients.append(torch.zeros(2).unsqueeze(0))
                    if len(gradients) > 0:
                        gradients = torch.cat(gradients, 0)
                        optimizers[node_type].zero_grad()
                        model_tags[node_type] = model_tags[node_type][need_update_index]
                        model_tags[node_type].backward(gradient=gradients, retain_graph=True)
                        optimizers[node_type].step()

            ec.summary(os.path.join(experiment.metric_path, "ec_summary.txt"))
            ec.reset()

            # save checkpoint
            experiment.save_checkpoint(node_inits, epoch)

        experiment.save_model(node_inits)
        # final_metrics = experiment.get_f1_score()
        experiment.save_metrics()

        return None

    elif (mode == "test"):

        # load pytorch model
        node_inits = experiment.load_model(node_inits)
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()
        ec = eventClassifier(args['ground_truth_file'])

        # ================= Load all nodes & edges to memory ==================== #
        pre_loaded_path = experiment.get_pre_load_morse(args['data_tag'])

        if pre_loaded_path.endswith('.pkl'):
            with open(pre_loaded_path, 'rb') as f:
                events, mo = pickle.load(f)
        else:
            events = []
            loaded_line = 0
            for i in range(7):
                print(f"loading test data {args['test_data'] + '.' + str(i)}")
                with open(args['test_data'] + '.' + str(i), 'r') as fin:
                    for line in fin:
                        loaded_line += 1
                        if loaded_line % 100000 == 0:
                            print("Morse has loaded {} lines.".format(loaded_line))
                        record_datum = json.loads(line)['datum']
                        record_type = list(record_datum.keys())
                        assert len(record_type) == 1
                        record_datum = record_datum[record_type[0]]
                        record_type = record_type[0].split('.')[-1]
                        if record_type == 'Event':
                            event = parse_event(record_datum)
                            events.append((record_datum['uuid'], event))
                        elif record_type == 'Subject':
                            subject_node, subject = parse_subject(record_datum)
                            if subject != None:
                                mo.add_subject(subject)
                        elif record_type == 'Principal':
                            mo.Principals[record_datum['uuid']] = record_datum
                        elif record_type.endswith('Object'):
                            object_node, object = parse_object(record_datum, record_type)
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
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, mo], f)

        model_nids = {}
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
            model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64)

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
            model_features[node_type] = torch.tensor(feature_array, dtype=torch.int64)

        print('testing mode')
        # ============== Initialization ================== #
        model_tags = {}
        node_inital_tags = {}

        for node_type in ['NetFlowObject', 'SrcSinkObject', 'FileObject', 'UnnamedPipeObject', 'MemoryObject']:
            model_tags[node_type] = node_inits[node_type].forward(model_features[node_type]).squeeze()
            for i, node_id in enumerate(model_nids[node_type]):
                node_inital_tags[node_id] = model_tags[node_type][i, :]

        mo.node_inital_tags = node_inital_tags

        Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
        mo.alarm_file = open(
            os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')
        for event_info in tqdm.tqdm(events):
            event_id = event_info[0]
            event = event_info[1]
            diagnois = mo.add_event(event)
            gt = ec.classify(event_id)
            src = mo.Nodes.get(event['src'], None)
            dest = mo.Nodes.get(event['dest'], None)
            if src and dest:
                experiment.update_metrics(diagnois, gt)

        # pytorch model testing code goes here
        # ...
        ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))
        ec.reset()

        experiment.save_metrics()




        # precision, recall, accuracy, f1 = experiment.evaluate_classification(pred_result)
        # save_evaluation_results(precision, recall, accuracy, f1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", default='/home/weijian/weijian/projects/ATPG/results/features/feature_vectors', type=str)
    parser.add_argument("--ground_truth_file", default='/home/weijian/weijian/projects/ATPG/groundTruth32.txt', type=str)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--learning_rate", nargs='?', default=0.1, type=float)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--train_data", nargs='?', default="/root/Downloads/ta1-trace-e3-official-1.json", type=str)
    parser.add_argument("--volume_num", nargs='?', default=7, type=int)
    parser.add_argument("--test_data", nargs='?', default="/root/Downloads/ta1-trace-e3-official-1.json", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)
    parser.add_argument("--lr_imb", default=2.0, type=float)
    parser.add_argument("--data_tag", default="traindata1", type=str)
    parser.add_argument("--experiment_prefix", default="groupF", type=str)
    parser.add_argument("--no_hidden_layers", default=3, type=int)
    parser.add_argument("--from_checkpoint", type=str)
    parser.add_argument("--batch_size", type=int, default=10000000)

    args = parser.parse_args()

    config = {
        "learning_rate": args.learning_rate,
        "epoch": args.epoch,
        "lr_imb": args.lr_imb,
        "train_data": args.train_data,
        "volume_num": args.volume_num,
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
        "batch_size": args.batch_size
    }

    start_experiment(config)

