import json
import torch
import logging
from datetime import datetime
import math
import os
import argparse
import time
from utils.utils import *
from collections import Counter
from utils.eventClassifier import eventClassifier
from model.morse import Morse

from feature.NetFlowObjFeatures import get_network_feature_vector
import tqdm
import time
import pandas as pd
from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
from utils.graph_detection import add_nodes_to_graph
from utils.graphLoader import read_events_from_files
import numpy as np
from pathlib import Path
import pickle

def prt_network_tag_prob(file_path, network_nid_index, array):
    with open(file_path, 'w') as outputfile:
        print("NetworkFeature\titag-0\titag-1", file = outputfile)
        for item in network_nid_index.keys():
            i = network_nid_index[item]
            print("{}\t{}\t{}".format(item, array[i][0], array[i][1]), file = outputfile)
    


def get_network_tags(node_features_dict, node_id, initializer, device):
    features = torch.tensor(np.array(node_features_dict[node_id]['features'], dtype=np.int16)).unsqueeze(dim=0).to(device)
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
    features = torch.tensor(input_feature).unsqueeze(dim=0).to(device)
    return initializer.initialize(features).squeeze()

def start_experiment(args):
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)

    if torch.cuda.is_available():
        device = torch.device("cuda:0")
    else:
        device = torch.device("cpu")

    mode = args.mode
    no_hidden_layers = args.no_hidden_layers

    mo = Morse()

    # ============= Tag Initializer =============== #
    node_inits = {}
    node_inits['NetFlowObject'] = NetFlowObj_Initializer(2, no_hidden_layers).to(device)
    # node_inits['FileObject'] = FileObj_Initializer(10000, 2,no_hidden_layers).to(device)
    # node_inits['SrcSinkObject'] = Initializer(111,2,no_hidden_layers).to(device)
    # node_inits['UnnamedPipeObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['MemoryObject'] = Initializer(1,2,no_hidden_layers).to(device)
    # node_inits['PacketSocketObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['RegistryKeyObject'] = Initializer(1,2,no_hidden_layers)
    # node_inits['Subject'] = Initializer(150, 20, 2, no_hidden_layers).to(device)

    if (mode == "train"):
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        learning_rate = args.learning_rate
        epochs = args.epoch

        # load the checkpoint if it is given
        if args.checkpoint:
            checkpoint_epoch_path = args.checkpoint
            node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)

        # ================= Load all nodes & edges to memory ==================== #
        pre_loaded_path = experiment.get_pre_load_morse(args.data_tag)

        if pre_loaded_path.endswith('.pkl'):
            with open(pre_loaded_path, 'rb') as f:
                events, nodes, princicals = pickle.load(f)
        else:
            events = read_events_from_files(os.path.join(args.train_data, 'edges.json'), args.time_range)
            nodes = pd.read_json(os.path.join(args.train_data, 'nodes.json'), lines=True).set_index('id').to_dict(orient='index')
            princicals = pd.read_json(os.path.join(args.train_data, 'principals.json'), lines=True).set_index('uuid').to_dict(orient='index')
            # cache the loaded morse and events for next run
            with open(os.path.join(pre_loaded_path, 'morse.pkl'), "wb") as f:
                pickle.dump([events, nodes, princicals], f)

        mo.Principals = princicals

        for epoch in range(epochs):
            print('epoch: {}'.format(epoch))
            # total_loss = 0.0
            Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
            mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'a')
            mo.reset_morse()

            # ============== Initialization ================== #
            model_tags = {}
            node_inital_tags = {}

            # mo.node_inital_tags = node_inital_tags
            # mo.subject_tags = subject_tags
            mo.reset_tags()

            # ============= Dectection =================== #
            node_gradients = []
            for event in tqdm.tqdm(events):
                if event.type == 'UPDATE':
                    try:
                        if 'exec' in event.value:
                            mo.Nodes[event.nid].processName = event.value['exec']
                        elif 'name' in event.value:
                            mo.Nodes[event.nid].name = event.value['name']
                            mo.Nodes[event.nid].path = event.value['name']
                    except KeyError:
                        pass
                    continue
                if event.src not in mo.Nodes:
                    add_nodes_to_graph(mo, event.src, nodes[event.src])

                if isinstance(event.dest, int) and event.dest not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest, nodes[event.dest])

                if isinstance(event.dest2, int) and event.dest2 not in mo.Nodes:
                    add_nodes_to_graph(mo, event.dest2, nodes[event.dest2])

                # gt = ec.classify(event.id)
                diagnosis, s_labels, o_labels = mo.add_event_generate_loss(event, None)
                experiment.update_metrics(diagnosis, None)

                if diagnosis == None:
                    continue

                if s_labels:
                    node_gradients.extend(s_labels)
                    # for item in s_labels:
                    #     if item[0][1] == 'i':
                    #         pdb.set_trace()

                if o_labels:
                    node_gradients.extend(o_labels)
                    # for item in s_labels:
                    #     if item[0][1] == 'i':
                    #         pdb.set_trace()
            
            mo.alarm_file.close()
            experiment.print_metrics()
            experiment.save_metrics()
            experiment.reset_metrics()
            # ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-epoch-{}.txt'.format(epoch)),'r'))
            # ec.summary(os.path.join(experiment.metric_path, "ec_summary.txt"))
            # ec.reset()
            
            node_labels = {}
            for item in node_gradients:
                if item[0][1] == 'i':
                    if item[0][0] not in node_labels:
                        node_labels[item[0][0]] = []
                    node_labels[item[0][0]].append(item[1])

            network_feature_labels = {}
            src_sink_feature_labels = {}

            wlz_list = []
            for nid, value in node_labels.items():
                wlz_list.append(mo.Nodes[nid].get_name())

            print(Counter(wlz_list))

            pdb.set_trace()

        #     target_tags = {'NetFlowObject': torch.tensor([0.0, 1.0]),
        #                 'FileObject': torch.tensor([1.0, 1.0]),
        #                 'SrcSinkObject': torch.tensor([0.0, 1.0])}

        #     total_unseen_loss = 0.0
        #     loss_func = torch.nn.CrossEntropyLoss()

        #     for node_type in ['NetFlowObject']:
        #         labels = []
        #         needs_update = []
        #         if len(network_feature_labels) > 0:
        #             for network_feature in network_feature_index.keys():
        #                 if network_feature in network_feature_labels:
        #                     needs_update.append(i)
        #                     print(network_feature)
        #                     labels.append(round(sum(network_feature_labels[network_feature])/len(network_feature_labels[network_feature])))
        #                 else:
        #                     sample_para = math.ceil(len(network_feature_index)/(len(network_feature_labels)+1))
        #                     if random.randint(0, sample_para) == 1:
        #                         needs_update.append(i)
        #                         labels.append(0)
        #         else:
        #             for network_feature in network_feature_index.keys():
        #                 if random.randint(0, 9) == 1:
        #                     needs_update.append(i)
        #                     labels.append(0)
        #         optimizers[node_type].zero_grad()
        #         net_loss = loss_func(model_tags[node_type][needs_update], torch.tensor(labels))
        #         net_loss.backward()
        #         # model_tags[node_type].backward(gradient=gradients, retain_graph=True)
        #         optimizers[node_type].step()

        #     print(labels)

        #     for node_type in ['Subject']:
        #         labels = []
        #         needs_update = []
        #         for i, pname in enumerate(process_name_index.keys()):
        #             if pname in src_sink_feature_labels:
        #                 needs_update.append(i)
        #                 labels.append(round(sum(src_sink_feature_labels[pname])/len(src_sink_feature_labels[pname])))
        #             else:
        #                 if random.randint(0,9) == 3:
        #                     needs_update.append(i)
        #                     labels.append(0)

        #         optimizers[node_type].zero_grad()
        #         src_sink_loss = loss_func(model_tags[node_type][needs_update], torch.tensor(labels))
        #         src_sink_loss.backward()
        #         # model_tags[node_type].backward(gradient=gradients, retain_graph=True)
        #         optimizers[node_type].step()

        #     # print(labels)

        #     print('network loss is {}'.format(net_loss))
        #     print('total unseen loss is {}'.format(total_unseen_loss))

        #     # save checkpoint
        #     experiment.save_checkpoint(node_inits, epoch)

        # experiment.save_model(node_inits)
        # final_metrics = experiment.get_f1_score()
        # experiment.save_metrics()

        return None

    elif (mode == "test"):
        print("Begin preparing testing...")
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()

        format='cadets'
        cdm_version = 18

        begin_time = time.time()
        mo = Morse()
        # load pytorch model
        checkpoint_epoch_path = args.checkpoint
        node_inits = experiment.load_checkpoint(node_inits, checkpoint_epoch_path)
        for init in node_inits.keys():
            node_inits[init].to(device)

        print("Begin loading nodes...")

        ec = eventClassifier(args.ground_truth_file)

        print('testing mode')
        # ============== Initialization ================== #
        model_nids = {}
        model_features = {}
        for node_type in ['NetFlowObject']:
            network_nid_feature = pd.read_csv(os.path.join(args.feature_path, 'feature_vectors', '{}.csv'.format(node_type)), index_col='Unnamed: 0').to_dict(orient='index')
            with open(os.path.join(args.feature_path, 'feature_vectors', '{}.json'.format(node_type)),'r') as fin:
                node_features = json.load(fin)
            target_features = pd.DataFrame.from_dict(node_features,orient='index')
            network_feature_index = {}
            for item in target_features.index.tolist():
                index = len(network_feature_index)
                network_feature_index[item] = index
            feature_array = target_features['features'].values.tolist()
            model_features[node_type] = torch.tensor(np.array(feature_array, dtype=np.int16)).to(device)

        for node_type in ['Subject']:
            target_features = pd.read_csv(os.path.join(args.feature_path,'{}.csv'.format(node_type)), delimiter='\t', index_col='Key')
            node2processName = target_features.to_dict(orient='index')
            process_name_list = sorted(pd.unique(target_features['ProcessName']).tolist())
            process_name_index = {}
            for i, item in enumerate(process_name_list):
                process_name_index[item] = i
            model_nids[node_type] = target_features.index.tolist()
            feature_array = [[i] for i in range(len(process_name_index))]
            model_features[node_type] = torch.tensor(np.array(feature_array, dtype=np.int16)).to(device)

        model_tags = {}
        node_inital_tags = {}

        for node_type in ['NetFlowObject']:
            model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
            for nid in network_nid_feature.keys():
                index = network_feature_index[network_nid_feature[nid]['feature']]
                if model_tags[node_type][index,:].tolist()[0] > 0.5:
                    node_inital_tags[nid] = [0.0, 1.0]
                else:
                    node_inital_tags[nid] = [1.0, 1.0]

        subject_tags = {}
        for node_type in ['Subject']:
            model_tags[node_type] = node_inits[node_type].initialize(model_features[node_type]).squeeze()
            for pname in process_name_index.keys():
                index = process_name_index[pname]
                if model_tags[node_type][index,:].tolist()[0] > 0.5:
                    subject_tags[pname] = [0.0, 1.0]
                else:
                    subject_tags[pname] = [1.0, 1.0]
                    
        mo.node_inital_tags = node_inital_tags
        mo.subject_tags = subject_tags
        
        print('Initialization finished!')
        
        # mo.node_inital_tags = node_inital_tags
        # mo.reset_tags()

        Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
        mo.alarm_file = open(
            os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

        # # ================= Load all nodes & edges to memory ==================== #
        # pre_loaded_path = experiment.get_pre_load_morse(args.data_tag)

        # close interval
        if args["line_range"]:
            l_range = args["line_range"][0]
            r_range = args["line_range"][1]
        else:
            l_range = 0
            r_range = 5000000*args.volume_num

        loaded_line = 0
        last_event_str = ''
        volume_list = os.listdir(args.test_data)
        # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[1])+0.1*int(x.split('.')[3]))
        volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
        for volume in volume_list:
            print("Loading the {} ...".format(volume))
            with open(os.path.join(args.test_data, volume),'r') as fin:
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
                                diagnois = mo.add_event(event, gt)
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
                            # if object.type == 'FileObject':
                            #     tag = list(match_path(object.path))
                            #     mo.node_inital_tags[object.id] = tag
                            # elif object.type == 'NetFlowObject':
                            #     tag = list(match_network_addr(object.IP, object.port))
                            #     mo.node_inital_tags[object.id] = tag
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", type=str)
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--train_data", type=str)
    parser.add_argument("--test_data", type=str)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--device", nargs='?', default="cpu", type=str)
    parser.add_argument("--learning_rate", nargs='?', default=2.0, type=float)
    parser.add_argument("--mode", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)
    parser.add_argument("--lr_imb", default=2.0, type=float)
    parser.add_argument("--data_tag", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--no_hidden_layers", default=1, type=int)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%d-%H:%M:%S'))-3600)*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%d-%H:%M:%S'))-3600)*1e9

    start_experiment(args)

