import json
import os
import argparse
import time
import pickle
import random
import sys
sys.path.extend(['.','..','...'])
from parse.cdm18.cadets_parser import parse_event_cadets, parse_object_cadets, parse_subject_cadets
from utils.utils import *
from tqdm import tqdm
import networkx as nx

def build_benign_graph(args):
    G = nx.Graph()
    node_dict = {}

    ##### Load File Names #####
    volume_list = ["../data/raw/ta1-cadets-e3-official.json/ta1-cadets-e3-official.json.1"]

    ##### Set Up Counters #####
    loaded_line = 0

    for volume in volume_list:
        print(f"Loading {volume} ...")
        with open(volume,'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == "Event":
                    ##### Get Related Nodes #####
                    src = None
                    dest = None
                    dest2 = None

                    if isinstance(record_datum['subject'], dict):
                        src = record_datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(args.cdm_version)]
                    
                    if isinstance(record_datum['predicateObject'], dict):
                        dest = record_datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(args.cdm_version)]

                    if isinstance(record_datum['predicateObject2'], dict):
                        dest2 = record_datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(args.cdm_version)]

                    if src and src in node_dict:
                        node_dict[src].append(record_datum['uuid'])
                    if dest and dest in node_dict:
                        node_dict[dest].append(record_datum['uuid'])
                    if dest2 and dest2 in node_dict:
                        node_dict[dest2].append(record_datum['uuid'])
                elif record_type == 'Subject':
                    # if record_datum['type'] == 'SUBJECT_PROCESS':
                    #     G.add_node(record_datum['uuid'])
                    pass
                elif record_type == 'Principal':
                    pass
                elif record_type.endswith('Object'):
                    object = parse_object_cadets(record_datum, record_type)
                    if object:
                        if object.type == 'FileObject':
                            node_dict[object.id] = []
                elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
                    pass
                else:
                    pass

    popular_file_nodes = sorted(node_dict.keys(), key= lambda x:len(node_dict[x]), reverse = True)
    pdb.set_trace()
    return node_dict


def extract_benign_graph(k_hop_subgraphs_nodes, volume_list):
    output_file = open(os.path.join('adversarial', 'artifacts', 'mimicry_subgraph.json'), 'w')

    ##### Set Up Counters #####
    loaded_line = 0
    for volume in volume_list:
        print(f"Loading {volume} ...")
        with open(volume,'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has parsed {:,} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())[0]
                record_datum = record_datum[record_type]
                record_type = record_type.split('.')[-1]
                if record_type == "Event":
                    ##### Get Related Nodes #####
                    src = None
                    dest = None
                    dest2 = None

                    if isinstance(record_datum['subject'], dict):
                        src = record_datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(args.cdm_version)]
                    
                    if isinstance(record_datum['predicateObject'], dict):
                        dest = record_datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(args.cdm_version)]

                    if isinstance(record_datum['predicateObject2'], dict):
                        dest2 = record_datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(args.cdm_version)]

                    if src and src in k_hop_subgraphs_nodes and dest and dest in k_hop_subgraphs_nodes:
                        print(line, file = output_file, end='')
                        continue
                    elif src and src in k_hop_subgraphs_nodes and dest2 and dest2 in k_hop_subgraphs_nodes:
                        print(line, file = output_file, end='')
                        continue

                elif record_type == 'Subject':
                    if record_datum['uuid'] in k_hop_subgraphs_nodes:
                        print(line, file=output_file, end='')
                elif record_type == 'Principal':
                    pass
                elif record_type.endswith('Object'):
                    if record_datum['uuid'] in k_hop_subgraphs_nodes:
                        print(line, file=output_file, end='')
                elif record_type in {'TimeMarker', 'StartMarker', 'UnitDependency', 'Host'}:
                    pass
                else:
                    pass

    output_file.close()


def extract_benign_substructure(G, K = 3):
    k_hop_subgraphs = {}
    k_hop_subgraphs_nodes = set()

    for node in tqdm(random.sample(list(G.nodes()), 5)):
        # 使用ego_graph获取以node为中心的K-hop子图
        subgraph = nx.ego_graph(G, node, radius=K)
        # 将子图添加到字典中
        k_hop_subgraphs[node] = set(subgraph.nodes())
        k_hop_subgraphs_nodes = k_hop_subgraphs_nodes | k_hop_subgraphs[node]

    return k_hop_subgraphs, k_hop_subgraphs_nodes

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", type=str, default='cadets')
    parser.add_argument("--cdm_version", type=int, default=18)
    args = parser.parse_args()

    node_dict = build_benign_graph(args)
    # with open('./adversarial/artifacts/benign_graph_c3.pickle', 'wb') as fout:
    #     pickle.dump(G, fout)

    # with open('./adversarial/artifacts/benign_graph_c3.pickle', 'rb') as fin:
    #     G = pickle.load(fin)
    # k_hop_subgraphs, k_hop_subgraphs_nodes = extract_benign_substructure(G, K = 3)
    # with open('./adversarial/artifacts/benign_graph_nodes_c3.pickle', 'wb') as fout:
    #     pickle.dump(k_hop_subgraphs_nodes, fout)

    # with open('./adversarial/artifacts/benign_graph_nodes_c3.pickle', 'rb') as fin:
    #     k_hop_subgraphs_nodes = pickle.load(fin)
    # extract_benign_graph(k_hop_subgraphs_nodes, ['../data/raw/ta1-cadets-e3-official.json/ta1-cadets-e3-official.json'])
