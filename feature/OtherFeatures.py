from collections import Counter
import json
import pandas as pd
import torch


for node_type in ['SrcSinkObject','UnnamedPipeObject','MemoryObject']:
    feature_path = 'results/testing/features/{}.json'.format(node_type)
    with open(feature_path,'r') as fin:
        node_features = json.load(fin)

    df = pd.DataFrame.from_dict(node_features,orient='index')
    if len(node_features) > 0:
        df['features'] = df['subtype'].map(lambda x: [x])
        feature_df = df.drop(columns=['subtype'])
        feature_df.to_json('results/testing/features/feature_vectors/{}.json'.format(node_type), orient='index')
    else:
        df.to_json('results/testing/features/feature_vectors/{}.json'.format(node_type), orient='index')
