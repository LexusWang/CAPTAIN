import logging
import os
import argparse
import json
import time
import pickle
from datetime import datetime
import re

from datetime import datetime
from utils.utils import *
from model.captain import CAPTAIN
from graph.Event import Event
from utils.graph_detection import add_nodes_to_graph
from pathlib import Path
from collections import Counter
## For node features
from graph.Object import Object
from graph.Subject import Subject

def check_node(feature, node_type, gt, time):
    if feature == None:
        return False
    attacks = gt['attacks']
    for attack in attacks:
        if time < attack['start_timestamp'] or time > attack['end_timestamp']:
            continue
        entities = attack['entities']
        if node_type == "process":
            processes = entities['process']
            for p in processes:
                # if feature in p:
                if re.match(p,feature):
                    return True
        elif node_type == "file":
            files = entities['file']
            for f in files:
                if re.match(f,feature):
                    return True
        elif node_type == "ip":
            ips = entities['ip']
            for ip in ips:
                if ip == feature or feature.split(':')[0] == ip:
                    return True
    return False

def start_experiment(args):
    dataset = args.dataset
    # load ground truth
    gt_path = f"data/GT/human_readable_gt/e3_{dataset}_gt.json"
    gt_file = open(gt_path, 'r', encoding='UTF-8')
    gt = json.load(gt_file)
    gt_file.close()
    
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)

    mo = CAPTAIN(att = args.att, decay = args.decay)
    mo.mode = 'eval'

    logging.basicConfig(level=logging.INFO,
                        filename='debug.log',
                        filemode='w+',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    experiment.save_hyperparameters()
        
    if args.param_path:
        with open(os.path.join(args.param_path, 'train', 'params/lambda-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.lambda_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/tau-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.tau_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/alpha-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.alpha_dict = pickle.load(fin)
                
    # close interval
    if args.time_range:
        detection_start_time = args.time_range[0]
        detection_end_time = args.time_range[1]
    else:
        detection_start_time = 0
        detection_end_time = 1e21

    Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

    log_file = os.path.join(args.data_path, 'logs.json')
    node_buffer = {}
    loaded_line = 0

    experiment.alarm_dis = Counter([])

    one_hop_nodes = set()

    experiment.detection_time = 0

    decoder = json.JSONDecoder()
    with open(log_file, 'r') as fin:
        for line in fin:
            detection_delay_marker = time.time()
            loaded_line += 1
            # if loaded_line == 1:
            #     begin_time = time.time()
            if loaded_line > 0 and loaded_line % 100000 == 0:
                print("CAPTAIN has detected {:,} logs.".format(loaded_line))
            log_data = decoder.decode(line)
            if log_data['logType'] == 'EVENT':
                event = Event(None, None)
                event.load_from_dict(log_data['logData'])
                if event.type == 'UPDATE':
                    if 'exec' in event.value:
                        if event.nid in mo.Nodes:
                            mo.Nodes[event.nid].processName = event.value['exec']
                        elif event.nid in node_buffer:
                            node_buffer[event.nid]['processName'] = event.value['exec']
                    elif 'name' in event.value:
                        if event.nid in mo.Nodes:
                            mo.Nodes[event.nid].name = event.value['name']
                            mo.Nodes[event.nid].path = event.value['name']
                        elif event.nid in node_buffer:
                            node_buffer[event.nid]['name'] = event.value['name']
                            node_buffer[event.nid]['path'] = event.value['name']
                    elif 'cmdl' in event.value:
                        if event.nid in mo.Nodes:
                            mo.Nodes[event.nid].cmdLine = event.value['cmdl']
                        elif event.nid in node_buffer:
                            node_buffer[event.nid]['cmdLine'] = event.value['cmdl']
                else:
                    if event.time < detection_start_time:
                        continue
                    elif event.time > detection_end_time:
                        break

                    if event.src not in mo.Nodes and event.src in node_buffer:
                        add_nodes_to_graph(mo, event.src, node_buffer[event.src])
                        del node_buffer[event.src]

                    if isinstance(event.dest, str) and event.dest not in mo.Nodes and event.dest in node_buffer:
                        add_nodes_to_graph(mo, event.dest, node_buffer[event.dest])
                        del node_buffer[event.dest]

                    if isinstance(event.dest2, str) and event.dest2 not in mo.Nodes and event.dest2 in node_buffer:
                        add_nodes_to_graph(mo, event.dest2, node_buffer[event.dest2])
                        del node_buffer[event.dest2]
                    
                    related = False
                    if event.src and event.src in mo.Nodes:
                        if check_node(mo.Nodes[event.src].get_name(), 'process', gt, event.time):
                            related = True
                    if related == False and event.dest and event.dest in mo.Nodes:
                        if isinstance(mo.Nodes[event.dest], Subject):
                            if check_node(mo.Nodes[event.dest].get_name(), 'process', gt, event.time):
                                related = True
                        elif isinstance(mo.Nodes[event.dest], Object):
                            if mo.Nodes[event.dest].isFile():
                                if check_node(mo.Nodes[event.dest].get_name(), 'file', gt, event.time):
                                    related = True
                            elif mo.Nodes[event.dest].isIP():
                                if check_node(mo.Nodes[event.dest].get_name(), 'ip', gt, event.time):
                                    related = True
                    if related == False and event.dest2 and event.dest2 in mo.Nodes:
                        if isinstance(mo.Nodes[event.dest2], Subject):
                            if check_node(mo.Nodes[event.dest2].get_name(), 'process', gt, event.time):
                                related = True
                        elif isinstance(mo.Nodes[event.dest2], Object):
                            if mo.Nodes[event.dest2].isFile():
                                if check_node(mo.Nodes[event.dest2].get_name(), 'file', gt, event.time):
                                    related = True
                            elif mo.Nodes[event.dest2].isIP():
                                if check_node(mo.Nodes[event.dest2].get_name(), 'ip', gt, event.time):
                                    related = True 
                    if related:
                        one_hop_nodes.add(event.src)
                        one_hop_nodes.add(event.dest)
                        one_hop_nodes.add(event.dest2)
                    # # gt = ec.classify(event.id)
                    # diagnosis = mo.add_event(event, None)

            elif log_data['logType'] == 'NODE':
                node_buffer[log_data['logData']['id']] = log_data['logData']
                del node_buffer[log_data['logData']['id']]['id']
                # print(f'Size of node buffer {len(node_buffer)}')
            elif log_data['logType'] == 'PRINCIPAL':
                mo.Principals[log_data['logData']['uuid']] = log_data['logData']
                del mo.Principals[log_data['logData']['uuid']]['uuid']
            elif log_data['logType'] == 'CTL_EVENT_REBOOT':
                # mo.reset()
                # node_buffer = {}
                # pdb.set_trace()
                pass
            
            experiment.detection_time += time.time()-detection_delay_marker
    
    # flash_alarm_nodes_file = 'th3-flash-alarm_nodes.txt' 
    # alarm_nodes = set()
    # with open(flash_alarm_nodes_file, 'r') as file:
    #     for line in file:
    #         print(line)
    #         # pdb.set_trace()
    #         if line.endswith('\n'):
    #             line = line[:-1]
    #         # if line == 'D34B0BDD-3B3C-11E8-B8CE-15D78AC88FB6':
    #         #     pdb.set_trace()
    #         alarm_nodes.add(line)

    ## Alarm Nodes
    # alarm_nodes = alarm_nodes - {None}
    # with open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-nodes.txt'), 'w') as fout:
    #     for nid in alarm_nodes:
    #         print(nid, file=fout)
    node_names = set()
    with open(os.path.join(experiment.get_experiment_output_path(), 'one_hop_gt_node_feature_th3.txt'), 'w') as fout:
        for nid in one_hop_nodes:
            if nid not in mo.Nodes:
                print(nid)
                continue
            if isinstance(mo.Nodes[nid], Subject):
                # nname = f"{mo.Nodes[nid].pid} {mo.Nodes[nid].get_name()} {mo.Nodes[nid].get_cmdln()}"
                nname = "{'process': "+f"'{mo.Nodes[nid].get_name()}'" + "}"
            elif isinstance(mo.Nodes[nid], Object):
                # nname = mo.Nodes[nid].get_name()
                if mo.Nodes[nid].isFile():
                    nname = "{'file': "+f"'{mo.Nodes[nid].get_name()}'" + "}"
                elif mo.Nodes[nid].isIP():
                    nname = "{'ip': "+f"'{mo.Nodes[nid].get_name()}'" + "}"
                else:
                    continue
            else:
                continue
            if nname not in node_names:
                print(nname, file=fout)
                node_names.add(nname)
    
    # experiment.alarm_dis = Counter(false_alarms)
    mo.alarm_file.close()
    experiment.print_metrics()
    experiment.save_metrics()
    # ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    # ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))
    print("Metrics saved in {}".format(experiment.get_experiment_output_path()))
    
    
def main():
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--att", type=float, default=0)
    parser.add_argument("--decay", type=float, default=0)
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--data_path", nargs='?', type=str)
    parser.add_argument("--param_type", type=str)
    parser.add_argument("--dataset", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--param_path", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)
    parser.add_argument("--mode", type=str, default='test')

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9

    start_experiment(args)


if __name__ == '__main__':
    main()