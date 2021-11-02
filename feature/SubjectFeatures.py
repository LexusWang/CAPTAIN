from collections import Counter
import json
import pandas as pd
import torch

feature_path = 'results/features/demo/Subject.json'

with open(feature_path,'r') as fin:
    node_features = json.load(fin)

df = pd.DataFrame.from_dict(node_features,orient='index')

model_nids = {}
model_features = {}
node_type = 'Subject'
pname_list = df['pname'].to_list()
print(len(set(pname_list)))
pname_result = Counter(pname_list)
# print(pname_result)
pname_index = {}
for i, pname in enumerate(pname_result):
    pname_index[pname] = i

df['features'] = df['pname'].map(pname_index)
feature_df = df.drop(columns=['pname', 'cmdl'])
feature_df.to_json('results/features/demo/features/{}.json'.format(node_type), orient='index')
