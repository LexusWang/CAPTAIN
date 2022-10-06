import pandas as pd

df = pd.read_csv("/Users/lexus/Documents/research/APT/ATPG/results/C31/FileObject.csv", delimiter='\t')
df = df[df['Path'] != 'Null']
df1 = df[df['Path'] != '<unknown>']
a = pd.unique(df['Path'])
a = 0

# df = pd.read_csv("/Users/lexus/Documents/research/APT/ATPG/results/C31/NetFlowObject.csv", delimiter='\t')
# df = df[df['Path'] != 'Null']
# df1 = df[df['Path'] != '<unknown>']

# df = pd.read_csv("/Users/lexus/Documents/research/APT/ATPG/results/C31/Subject.csv", delimiter='\t')
# df = df[df['ProcessName'] != 'Null']
# a = pd.unique(df['ProcessName'])
# a = 0
# df1 = df.groupby('ProcessName')

# print(df1.head)