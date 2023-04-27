import os
import json
import pandas as pd
from datetime import datetime
import argparse

kc_event_set = {'BFFC6EE2-B252-0DC8-217C-5FE2B0C7F578': 1, '34957F55-EC71-438A-27D5-53F8643797E2': 1, '009D87CF-7112-8CD6-7DF6-5535B2D0B662': 1, '6C0B025F-A089-99B0-FF13-9D06973F80EE': 1, '480AE3A5-53D3-BA96-72E2-7B56ABE1B230': 1, '5B429C45-ECF2-104D-B015-C7A60E50AF7C': 1, '99276D99-CECC-AE13-EA02-890B0A8543E8': 1, '665A524C-CF0C-C4B4-18AE-F1D3BE7FCA65': 1, '627DFFE5-B213-165B-ACAA-3BC503AEC397': 1, 'BCCBFCAF-E152-0509-7A39-DE49FA1BE788': 1, 'CC63B2E0-821D-F4E1-6459-7CCA51D92B80': 1, '4007BC39-E4CF-D7F8-255B-DB1CAFC847B4': 1, '9361CB90-D941-BD5C-9FF3-1A9484ACA8DD': 1, '84315E44-FE42-A91C-CA4D-7518E2DBF8E3': 1, '3846F0AD-8A7F-7B73-789D-CE541182B2E8': 1, 'F1A9D3E9-926A-8DF6-25FF-26C8CA5A87E1': 1, '9509CDB3-8990-1FAD-BCF6-2E4EF48B639F': 1, '5C2E71B3-A402-38C2-0F6F-04BFA8EB82A9': 1, 'D1882C2B-61EC-755D-817B-DC2E7A1FCB1B': 1}
def evt_searching(nodes_file, edge_file, user_file, start_ts, end_ts):
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
            # if condition(src_node, dest_node, dest2_node, edge_datum):
            #     print(line)
            if edge_datum['id'] in kc_event_set:
                print(edge_datum)
                print(src_node)
                print(dest_node)
                print(kc_event_set[edge_datum['id']])

def match_pname(src_node, dest_node, dest2_node, event):
    if src_node['processName'] == 'vUgefal':
        return True
    else:
        return False
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--data", type=str)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)
    args = parser.parse_args()
    if args.time_range:
        args.time_range[0] = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
        args.time_range[1] = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9


evt_searching('../data/T31/nodes.json', '../data/T31/edges.json', '../data/T31/principals.json', args.time_range[0], args.time_range[1])