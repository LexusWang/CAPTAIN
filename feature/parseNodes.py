import tqdm
import os
import pandas as pd

null = None

nodes_file = '/home/weijian/weijian/projects/E5data/reduced_json/vertex.json'

network_obj_file = open('/home/weijian/weijian/projects/ATPG/results/features/E51-trace/NetFlowObject.json','a')

file_obj_file = open('/home/weijian/weijian/projects/ATPG/results/features/E51-trace/NetFlowObject.json','a')

with open(nodes_file,'r') as fin:
    for line in tqdm.tqdm(fin):
        record = eval(line[:-1])['datum']
        if list(record.keys())[0].endswith('NetFlowObject'):
            value = list(record.values())[0]
            # print('{{"{}":{{"type":"NetFlowObject","remoteAddress":"{}","remotePort":{},"ipProtocol":{}}}}}\n'.format(value['uuid'], value['remoteAddress']['string'], value['remotePort']['int'],  value['ipProtocol']['int']), file=network_obj_file)
            network_obj_file.write('{{"{}":{{"type":"NetFlowObject","remoteAddress":"{}","remotePort":{},"ipProtocol":{}}}}}\n'.format(value['uuid'], value['remoteAddress']['string'], value['remotePort']['int'],  value['ipProtocol']['int']))
       
