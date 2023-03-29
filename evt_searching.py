import os
import json
import pandas as pd

def evt_searching(nodes_file, edge_file, user_file, start_ts, end_ts, condition):
    nodes = pd.read_json(nodes_file, lines=True).set_index('id').to_dict(orient='index')
    princicals = pd.read_json(user_file, lines=True).set_index('uuid').to_dict(orient='index')

    with open(edge_file, 'r') as fin:
        for line in fin:
            edge_datum = json.loads(line)
            if edge_datum['type'] == 'UPDATE':
                updated_value = edge_datum['value']
                if 'exec' in updated_value:
                    nodes[eval(line)['nid']]['processName'] = updated_value['exec']
                elif 'name' in updated_value:
                    nodes[eval(line)['nid']]['name'] = updated_value['name']
                    nodes[eval(line)['nid']]['path'] = updated_value['name']
                continue
            if edge_datum['time'] < start_ts or edge_datum['time'] > end_ts:
                continue
            src_node = nodes[edge_datum['s']]
            if edge_datum['d']:
                dest_node = nodes[edge_datum['d']]
            else:
                dest_node = None
            if edge_datum['d2']:
                dest2_node = nodes[edge_datum['d2']]
            else:
                dest2_node = None
            if condition(src_node, dest_node, dest2_node, edge_datum):
                print(line)

def match_pname(src_node, dest_node, dest2_node, event):
    if src_node['processName'] == 'vUgefal':
        return True
    else:
        return False

evt_searching('../Data/C31/nodes.json', '../Data/C31/edges.json', '../Data/C31/principals.json', 1523028000e9, 1523038060e9, match_pname)