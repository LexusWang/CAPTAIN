import logging
import os
import argparse
import json
import time
from datetime import datetime
import pytz
from datetime import datetime
from utils.utils import *
from model.captain import CAPTAIN
from graph.Event import Event
from utils.graph_detection import add_nodes_to_graph
import pdb

def generate_graph(nodes, edges):
    feature_nid = {}
    merged_nodes = {}
    
    visable_nodes = {None}
    
    duplicated_edges = set()
    # 生成Graphviz DOT代码
    dot_code = "digraph G {\n"

    # 添加节点到DOT代码
    for node in nodes:
        if node.type == 'SUBJECT_PROCESS':
            dot_code += f'    "{node.id}" [label="{node.processName}:{node.pid}"  shape="box"];\n'
            visable_nodes.add(node.id)
        elif node.type == 'NetFlowObject':
            if node.IP not in feature_nid:
                feature_nid[node.IP] = len(feature_nid)
                dot_code += f'    "{feature_nid[node.IP]}" [label="{node.IP}" shape="diamond"];\n'
                visable_nodes.add(feature_nid[node.IP])
            merged_nodes[node.id] = feature_nid[node.IP]
        elif node.type == 'FileObject':
            # pdb.set_trace()
            if node.path not in feature_nid:
                feature_nid[node.path] = len(feature_nid)
                dot_code += f'    "{feature_nid[node.path]}" [label="{node.path}" shape="ellipse"];\n'
                visable_nodes.add(feature_nid[node.path])
            merged_nodes[node.id] = feature_nid[node.path]
        # dot_code += f'    "{node["id"]}" [label="{node["label"]}"];\n'

    # 添加边到DOT代码
    for edge in edges:
        # pdb.set_trace()
        if edge.src in merged_nodes:
            edge.src = merged_nodes[edge.src]
        if edge.dest in merged_nodes:
            edge.dest = merged_nodes[edge.dest]
        if edge.dest2 in merged_nodes:
            edge.dest2 = merged_nodes[edge.dest2]
        if (edge.src, edge.dest, edge.type) not in duplicated_edges:
            duplicated_edges.add((edge.src, edge.dest, edge.type))
            if edge.src in visable_nodes and edge.dest in visable_nodes and edge.dest2 in visable_nodes:
                if edge.dest is not None:
                    if edge.type == 'read':
                        dot_code += f'    "{edge.dest}" -> "{edge.src}" [label="{edge.type}"];\n'
                    elif edge.type == 'write':
                        dot_code += f'    "{edge.src}" -> "{edge.dest}" [label="{edge.type}"];\n'
                    else:
                        dot_code += f'    "{edge.src}" -> "{edge.dest}" [label="{edge.type}"];\n'

    dot_code += "}"

    # 输出DOT代码
    # print(dot_code)

    # 将DOT代码写入文件
    with open("graph.dot", "w") as file:
        file.write(dot_code)

## C3
# mal_nodes = {"81.49.200.166","78.205.235.65","200.36.109.214","139.123.0.113","61.167.39.128","25.159.96.207","76.56.184.25","155.162.39.48","25.159.96.207","76.56.184.25","155.162.39.48","53.158.101.118","192.113.144.28","25.159.96.207","78.205.235.65","155.162.39.48","53.158.101.118","198.115.236.119","62.83.155.175","62.83.155.175","62.83.155.175"}
## T3
# mal_nodes = {"145.199.103.57","61.130.69.232","2.233.33.52","180.156.107.146","145.199.103.57","61.130.69.232","2.233.33.52","180.156.107.146","5.214.163.155","45.26.25.240","161.116.88.72","146.153.68.151","104.228.117.212","141.43.176.203","149.52.198.23","162.66.239.75","17.146.0.252","162.66.239.75","103.12.253.24","207.103.191.4"}
mal_nodes = {"128.55.12.73", "208.75.117.3", "208.75.117.2", "62.83.155.175"}
# mal_nodes = {}

mal_graph = set()
graph_nodes = []
graph_edges = []

def start_experiment(args):
    mo = CAPTAIN(att = args.att, decay = args.decay)
    mo.mode = 'eval'

    print("Begin preparing testing...")
    logging.basicConfig(level=logging.INFO,
                        filename='debug.log',
                        filemode='w+',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
                
    # close interval
    if args.time_range:
        detection_start_time = args.time_range[0]
        detection_end_time = args.time_range[1]
    else:
        detection_start_time = 0
        detection_end_time = 1e21

    log_file = os.path.join(args.data_path, 'logs.json')
    node_buffer = {}
    loaded_line = 0

    # false_alarms = []
    # experiment.alarm_dis = Counter([])

    ## alarm node evaluation
    alarm_nodes = set()

    # experiment.detection_time = 0
    
    node_file = open('node.txt', 'w')
    edge_file = open('edge.txt', 'w')

    decoder = json.JSONDecoder()
    with open(log_file, 'r') as fin:
        for line in fin:
            event_in_graph = False
            loaded_line += 1
            if loaded_line == 1:
                begin_time = time.time()
                ## Calculate CPU Time
                # start_cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
            if loaded_line > 0 and loaded_line % 100000 == 0:
                print("CAPTAIN has detected {:,} logs.".format(loaded_line))
                
                dt = datetime.fromtimestamp(prt_ts / 1e9)
                ny_tz = pytz.timezone('America/New_York')
                ny_dt = dt.astimezone(ny_tz)
                ny_dt_str = ny_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
                print(f"Log Time: {ny_dt_str}")
                
                delta_time = time.time() - begin_time
                begin_time = time.time()
                print(f"Detection time for 100K logs is {delta_time:.2f} s")
                ## Overhead
                # current_time = time.strftime('%Y-%m-%d %H:%M:%S')
                # cpu_usage = current_process.cpu_percent()
                # memory_usage = current_process.memory_info()
                # writer.writerow([current_time, memory_usage.rss/(1024 * 1024)])
                # print(f"{current_time}, Memory: {memory_usage.rss/(1024 * 1024)}MB")
            
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
                    if event.time < detection_start_time:
                        continue
                    elif event.time > detection_end_time:
                        break

                    if event.src not in mo.Nodes and event.src in node_buffer:
                        add_nodes_to_graph(mo, event.src, node_buffer[event.src])
                        if mo.Nodes[event.src].type == 'NetFlowObject':
                            # pdb.set_trace()
                            if mo.Nodes[event.src].IP in mal_nodes:
                                event_in_graph = True
                        # elif mo.Nodes[event.src].type == 'FileObject':
                        #     if 'tcexec' in mo.Nodes[event.src].path:
                        #         event_in_graph = True
                        del node_buffer[event.src]

                    if isinstance(event.dest, str) and event.dest not in mo.Nodes and event.dest in node_buffer:
                        add_nodes_to_graph(mo, event.dest, node_buffer[event.dest])
                        if mo.Nodes[event.dest].type == 'NetFlowObject':
                            # pdb.set_trace()
                            if mo.Nodes[event.dest].IP in mal_nodes:
                                event_in_graph = True
                        # elif mo.Nodes[event.dest].type == 'FileObject':
                        #     if 'tcexec' in mo.Nodes[event.dest].path:
                        #         event_in_graph = True
                        del node_buffer[event.dest]

                    if isinstance(event.dest2, str) and event.dest2 not in mo.Nodes and event.dest2 in node_buffer:
                        add_nodes_to_graph(mo, event.dest2, node_buffer[event.dest2])
                        if mo.Nodes[event.dest2].type == 'NetFlowObject':
                            # pdb.set_trace()
                            if mo.Nodes[event.dest2].IP in mal_nodes:
                                event_in_graph = True
                        # elif mo.Nodes[event.dest2].type == 'FileObject':
                        #     if 'tcexec' in mo.Nodes[event.dest2].path:
                        #         event_in_graph = True
                        del node_buffer[event.dest2]
                        
                    if mo.Nodes.get(event.src, None) and mo.Nodes.get(event.src, None).id in mal_graph:
                        event_in_graph = True
                    if mo.Nodes.get(event.dest, None) and mo.Nodes.get(event.dest, None).id in mal_graph:
                        event_in_graph = True
                    if mo.Nodes.get(event.dest2, None) and mo.Nodes.get(event.dest, None).id in mal_graph:
                        event_in_graph = True
                        
                    if event_in_graph:
                        # pdb.set_trace()
                        if mo.Nodes.get(event.src, None) and mo.Nodes.get(event.src, None).id not in mal_graph:
                            print(mo.Nodes.get(event.src, None), file = node_file)
                            mal_graph.add(mo.Nodes.get(event.src, None).id)
                            graph_nodes.append(mo.Nodes.get(event.src, None))
                        if mo.Nodes.get(event.dest, None) and mo.Nodes.get(event.dest, None).id not in mal_graph:
                            print(mo.Nodes.get(event.dest, None), file = node_file)
                            mal_graph.add(mo.Nodes.get(event.dest, None).id)
                            graph_nodes.append(mo.Nodes.get(event.dest, None))
                        if mo.Nodes.get(event.dest2, None) and mo.Nodes.get(event.dest2, None).id not in mal_graph:
                            print(mo.Nodes.get(event.dest2, None), file = node_file)
                            mal_graph.add(mo.Nodes.get(event.dest2, None).id)
                            graph_nodes.append(mo.Nodes.get(event.dest2, None))
                        print(event, file = edge_file)
                        graph_edges.append(event)
                        # pdb.set_trace()

                    # gt = ec.classify(event.id)
                    # diagnosis = mo.add_event(event, gt)
                    # diagnosis, tag_indices, s_labels, o_labels, pc, lambda_grad, thr_grad, loss = mo.add_event_generate_loss(event, gt)
                    # experiment.update_metrics(diagnosis, gt)
                    # if gt and diagnosis == None:
                    #     pdb.set_trace()

                    ## Mimicry Attack Experiments
                    ## Print the tags of Node 84D440C2-4E50-4A5C-904E-C4772C4ACD5A (FileObject: /tmp/test)
                    # if '84D440C2-4E50-4A5C-904E-C4772C4ACD5A' in {event.dest, event.dest}:
                    #     print(mo.Nodes['84D440C2-4E50-4A5C-904E-C4772C4ACD5A'].tags())

                    # if diagnosis != None:
                    #     if diagnosis == 'FileCorruption':
                    #         alarm_nodes.add(event.src)
                    #     else:
                    #         alarm_nodes.add(event.src)
                    #         alarm_nodes.add(event.dest)
                    #         alarm_nodes.add(event.dest2)

                    # if gt == None and diagnosis != None:
                    #     # false_alarms.append(diagnosis)
                    #     experiment.alarm_dis[diagnosis] += 1
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
            
            # experiment.detection_time += time.time()-detection_delay_marker
            
    node_file.close()
    edge_file.close()
    
    generate_graph(graph_nodes, graph_edges)
    
    
def main():
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--att", type=float, default=0)
    parser.add_argument("--decay", type=float, default=0)
    parser.add_argument("--data_path", nargs='?', type=str)
    parser.add_argument("--param_type", type=str)
    parser.add_argument("--model_index", type=int)
    # parser.add_argument("--experiment_prefix", type=str)
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