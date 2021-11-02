ExtensionNameType = [
    'pdf',
    'doc',
    'docx',
    'xml',
    'xlsx',
    'cpp'
]

extentsion_name_type = {}
for i, item in enumerate(ExtensionNameType):
    extentsion_name_type[item] = i+1

DirNameType = set([
    'usr','sys','run','sbin','etc',
    'var','home','maildrop','stat',
    'active','incoming','tmp','media',
    'root','data','dev','proc','lib64','lib','bin'
])

dir_name_type = {}

for i, item in enumerate(list(DirNameType)):
    dir_name_type[item] = i+1


from collections import Counter
import json
import pandas as pd
import torch

feature_path = 'results/features/demo/FileObject.json'

with open(feature_path,'r') as fin:
    node_features = json.load(fin)

df = pd.DataFrame.from_dict(node_features,orient='index')

node_type = 'FileObject'
path_list = df['path'].to_list()
path_list = list(set(path_list))

path_feature_map = {}
for path in path_list:
    r_dir = ''
    ext = ''
    if path.startswith('/'):
        path_tree = path[1:].split('/')
    else:
        path_tree = path[1:].split('/')
    r_dir = path_tree[0]
    f_name = path_tree[-1].split('.')
    if len(f_name) >= 2:
        ext = f_name[-1]
    
    path_feature_map[path] = [dir_name_type.get(r_dir,0),extentsion_name_type.get(ext,0)]

df['features'] = df['path'].map(path_feature_map)
old_features = df['features'].to_list()
subtypes = df['FileObjectType'].to_list()
new_features = []
for i in range(len(old_features)):
    new_features.append([old_features[i][0],old_features[i][1],subtypes[i]])

df['features'] = new_features
feature_df = df.drop(columns=['path', 'FileObjectType'])
feature_df.to_json('results/features/demo/features/{}.json'.format(node_type), orient='index')
