''' detection.py
This script is used to perform detection on a given dataset.
'''

import logging
import os
import argparse
import json
import time
import pickle
import pdb
from pathlib import Path
from collections import Counter
from datetime import datetime
import pytz
from pympler import asizeof

# from utils.utils import *
from utils.utils import Experiment
from utils.time import get_ET_from_nano_ts
from utils.eventClassifier import eventClassifier
from model.captain import CAPTAIN
from graph.Event import Event
from utils.graph_detection import add_nodes_to_graph
from utils.logs import logger

# If we want to perform the evaluation about the overhead
OVERHEAD_EVAL = False
# If the dataset is THEIA
IF_THEIA = False

if OVERHEAD_EVAL:
    import psutil
    import resource
    import csv
    current_process = psutil.Process(os.getpid())
    perf_file = open('system_usage_morse.csv', 'a', newline='')
    writer = csv.writer(perf_file)
    writer.writerow(['Time', 'Memory Usage (MB)'])

def start_experiment(args):
    experiment = Experiment(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), args, args.experiment_prefix)
    mo = CAPTAIN(att = args.att, decay = args.decay)
    mo.mode = 'eval'
    # mo.mode = 'train'

    logger.info("Begin testing...")
    experiment.save_hyperparameters()
    logger.info("The hyperparameters were saved!")
    ec = eventClassifier(args.ground_truth_file)
    
    # Load adaptive parameters
    if args.param_path:
        with open(os.path.join(args.param_path, 'train', 'params/lambda-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.lambda_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/tau-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.tau_dict = pickle.load(fin)
        with open(os.path.join(args.param_path, 'train', 'params/alpha-e{}.pickle'.format(args.model_index)), 'rb') as fin:
            mo.alpha_dict = pickle.load(fin)
                
    # Detection time interval
    # If the user specifies the detection interval, use the arguments
    # If not, use the entire dataset for detection 
    if args.time_range:
        detection_start_time = args.time_range[0]
        detection_end_time = args.time_range[1]
    else:
        detection_start_time = 0
        detection_end_time = 1e21

    ## Create the file used to save the detected alarms
    Path(os.path.join(experiment.get_experiment_output_path(), 'alarms')).mkdir(parents=True, exist_ok=True)
    mo.alarm_file = open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'), 'a')

    log_file = os.path.join(args.data_path, 'logs.json')
    node_buffer = {}
    loaded_line = 0

    # false_alarms = []
    experiment.alarm_dis = Counter([])

    ## Alarm Nodes (Save entity-level detection)
    alarm_nodes = set()

    experiment.detection_time = 0

    decoder = json.JSONDecoder()
    with open(log_file, 'r') as fin:
        for line in fin:
            ## Time marker used to record the detection latency
            ## Uncommen
            detection_delay_marker = time.time()
            
            loaded_line += 1
            if loaded_line == 1:
                begin_time = time.time()
                if OVERHEAD_EVAL:
                    # Calculate CPU Time
                    start_cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
            if loaded_line % 100000 == 0:
                print("CAPTAIN has detected {:,} logs.".format(loaded_line))
                print(f"Time in Log: {get_ET_from_nano_ts(prt_ts).strftime('%Y-%m-%d %H:%M:%S %Z')}")
                
                current_time = time.time()
                print(f"Detection time for {int(100000/1000)}K logs is {current_time - begin_time:.2f} s")
                begin_time = current_time
                
                # Overhead
                if OVERHEAD_EVAL:
                    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
                    cpu_usage = current_process.cpu_percent()
                    memory_usage = current_process.memory_info()
                    writer.writerow([current_time, memory_usage.rss/(1024 * 1024)])
                    print(f"{current_time}, Memory: {memory_usage.rss/(1024 * 1024)}MB")
            
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
                # elif event.type == 'OBJECT_VERSION_UPDATE':
                #     if event.old in mo.Nodes and event.new in node_buffer:
                #         add_nodes_to_graph(mo, event.new, node_buffer[event.new])
                #         del node_buffer[event.new]
                #         mo.Nodes[event.new].setObjTags(mo.Nodes[event.old].tags()[2:])
                #         if mo.mode == 'train':
                #             mo.Nodes[event.new].set_grad(mo.Nodes[event.old].get_grad())
                #             mo.Nodes[event.new].set_lambda_grad(mo.Nodes[event.old].get_lambda_grad())
                #         # del mo.Nodes[event.old]
                else:
                    prt_ts = event.time
                    ## Exclude the events outside the detection interval
                    if event.time < detection_start_time:
                        continue
                    elif event.time > detection_end_time:
                        break
                    
                    # If the nodes are not added in the graph, call add_nodes_to_graph() to add it.
                    if event.src not in mo.Nodes and event.src in node_buffer:
                        add_nodes_to_graph(mo, event.src, node_buffer[event.src])
                        del node_buffer[event.src]

                    if isinstance(event.dest, str) and event.dest not in mo.Nodes and event.dest in node_buffer:
                        add_nodes_to_graph(mo, event.dest, node_buffer[event.dest])
                        del node_buffer[event.dest]

                    if isinstance(event.dest2, str) and event.dest2 not in mo.Nodes and event.dest2 in node_buffer:
                        add_nodes_to_graph(mo, event.dest2, node_buffer[event.dest2])
                        del node_buffer[event.dest2]

                    # Query the ground truth of the current event
                    gt = ec.classify(event.id)
                    # Generate the detection result of current event
                    diagnosis = mo.add_event(event, gt)
                    # diagnosis, tag_indices, s_labels, o_labels, pc, lambda_grad, thr_grad, loss = mo.add_event_generate_loss(event, gt)
                    
                    # Update metrics 
                    experiment.update_metrics(diagnosis, gt)

                    # Record the alarm-related nodes
                    # For FileCorruption and RemoveIndicator, we only record the src nodes (processes) of the event
                    if diagnosis != None:
                        if diagnosis in {'FileCorruption', 'RemoveIndicator'}:
                            alarm_nodes.add(event.src)
                        else:
                            alarm_nodes.add(event.src)
                            alarm_nodes.add(event.dest)
                            alarm_nodes.add(event.dest2)

                    if gt == None and diagnosis != None:
                        # false_alarms.append(diagnosis)
                        experiment.alarm_dis[diagnosis] += 1
                        
            elif log_data['logType'] == 'NODE':
                # If the entry is a node, save it into the node_buffer
                node_buffer[log_data['logData']['id']] = log_data['logData']
                del node_buffer[log_data['logData']['id']]['id']
                
            elif log_data['logType'] == 'PRINCIPAL':
                mo.Principals[log_data['logData']['uuid']] = log_data['logData']
                del mo.Principals[log_data['logData']['uuid']]['uuid']
                
            elif log_data['logType'] == 'CTL_EVENT_REBOOT':
                # mo.reset()
                # node_buffer = {}
                # pdb.set_trace()
                pass
            
            experiment.detection_time += time.time()-detection_delay_marker
            
    # Overhead
    if OVERHEAD_EVAL:
        perf_file.close()
    
        # Calculate CPU Time
        end_cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        logger.info(f"CPU Time used for detection: {end_cpu_time - start_cpu_time} s")
    
        # Calculate Max Memory Usage
        max_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        logger.info(f"Memory usage for detection: {max_rss} KB")
    
    logger.info('The detection time is :{:.2f} s'.format(experiment.detection_time))
    logger.info('The event throughput is :{:.2f} events/s'.format(loaded_line/experiment.detection_time))
    logger.info("{} Mb".format(asizeof.asizeof(mo)/(1024*1024)))
    logger.info("# of nodes: {}".format(len(mo.Nodes)))

    # Alarm Nodes
    alarm_nodes = alarm_nodes - {None}
    with open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-nodes.txt'), 'w') as fout:
        for nid in alarm_nodes:
            print(nid, file=fout)
            
    # For Theia dataset, we save the alarm nodes by their names because there exist many duplications (same nodes with different node ids);
    if IF_THEIA:
        from graph.Object import Object
        from graph.Subject import Subject
        node_names = set()
        with open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-nodes-name.txt'), 'w') as fout:
            for nid in alarm_nodes:
                if isinstance(mo.Nodes[nid], Subject):
                    # nname = f"{mo.Nodes[nid].pid} {mo.Nodes[nid].get_name()} {mo.Nodes[nid].get_cmdln()}"
                    nname = "{'subject': "+f"'{mo.Nodes[nid].get_name()}'" + "}"
                elif isinstance(mo.Nodes[nid], Object):
                    # nname = mo.Nodes[nid].get_name()
                    if mo.Nodes[nid].isFile():
                        nname = "{'file': "+f"'{mo.Nodes[nid].get_name()}'" + "}"
                    elif mo.Nodes[nid].isIP():
                        nname = "{'netflow': "+f"'{mo.Nodes[nid].get_name()}'" + "}"
                    else:
                        continue
                else:
                    continue
                if nname not in node_names:
                    print(nname, file=fout)
                    node_names.add(nname)
    
    mo.alarm_file.close()
    experiment.print_metrics()
    experiment.save_metrics()
    ec.analyzeFile(open(os.path.join(experiment.get_experiment_output_path(), 'alarms/alarms-in-test.txt'),'r'))
    ec.summary(os.path.join(experiment.metric_path, "ec_summary_test.txt"))
    logger.info("Metrics saved in {}".format(experiment.get_experiment_output_path()))
    
    
def main():
    parser = argparse.ArgumentParser(description="This is the detection part of CAPTAIN.")
    parser.add_argument("--att", type=float, default=0.2)
    parser.add_argument("--decay", type=float, default=0)
    parser.add_argument("--ground_truth_file", type=str)
    parser.add_argument("--data_path", nargs='?', type=str)
    parser.add_argument("--param_type", type=str)
    parser.add_argument("--model_index", type=int)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--param_path", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)

    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        
    args.mode = 'test'

    start_experiment(args)


if __name__ == '__main__':
    main()