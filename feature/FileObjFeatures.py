import tqdm

def get_path_vocb(path_set):
    path_vocb = []
    for path in tqdm.tqdm(path_set):
        if path.startswith('/'):
            path_tree = path[1:].split('/')
        else:
            path_tree = path.split('/')
        path_vocb.extend(path_tree)

    path_vocb = dict(Counter(path_vocb))
    path_vocb = sorted(path_vocb.items(),key=lambda x:x[1],reverse=True)
    with open('results/path_vocabulary.csv','w') as fout:
        for item in path_vocb:
            fout.write('{},{}\n'.format(item[0],item[1]))

    return path_vocb[:10000]


def get_one_hot_encoding(path_tree, path_vocb):
    oh_vector = []
    for dir in path_tree:
        if dir in path_vocb:
            oh_vector.append(path_vocb[dir])
    
    return oh_vector


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

feature_path = 'results/features/FileObject.json'

with open(feature_path,'r') as fin:
    node_features = json.load(fin)

df = pd.DataFrame.from_dict(node_features,orient='index')

node_type = 'FileObject'
path_list = df['path'].to_list()
path_list = list(set(path_list))

path_vocb_freq = get_path_vocb(path_list)
# with open('results/features/path_vocb.csv','w')as fout:
#     fout.write("sub_path,frequency\n")
#     for item in path_vocb_freq:
#         fout.write("{},{}\n".format(item[0],item[1]))
path_vocb = {}
for i, item in enumerate(path_vocb_freq):
    path_vocb[item[0]] = i+1

path_feature_map = {}
for path in path_list:
    r_dir = ''
    ext = ''
    if path.startswith('/'):
        path_tree = path[1:].split('/')
    else:
        path_tree = path.split('/')
    r_dir = path_tree[0]
    f_name = path_tree[-1].split('.')
    if len(f_name) >= 2:
        ext = f_name[-1]
    
    # path_feature_map[path] = [dir_name_type.get(r_dir,0),extentsion_name_type.get(ext,0)]
    path_feature_map[path] = [get_one_hot_encoding(path_tree, path_vocb),extentsion_name_type.get(ext,0)]

df['features'] = df['path'].map(path_feature_map)
old_features = df['features'].to_list()
subtypes = df['FileObjectType'].to_list()
new_features = []
for i in range(len(old_features)):
    new_features.append([old_features[i][0],old_features[i][1],subtypes[i]])

df['features'] = new_features
feature_df = df.drop(columns=['path', 'FileObjectType'])
feature_df.to_json('results/features/feature_vectors/{}.json'.format(node_type), orient='index')
