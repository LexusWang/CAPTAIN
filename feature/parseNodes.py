import tqdm
import os

null = None

nodes_file = '/home/weijian/weijian/projects/E31data_updated/vertex.json'

with open(nodes_file,'r') as fin:
    for line in fin:
        a = line[:-1]
        c = eval(a)
        b = 0
