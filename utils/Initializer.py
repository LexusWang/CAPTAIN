import torch
import torch.nn as nn
from torch.nn import Linear

class Initializer(nn.Module):

    def __init__(self, input_dim, output_dim) -> None:
        super().__init__()
        self.dtype = torch.float64
        self.embedding = nn.Embedding(input_dim, output_dim, dtype=self.dtype)

    def initialize(self, features):
        features = torch.tensor(features,dtype=self.dtype)
        tags = torch.sigmoid(self.Embedding(features))
        return tags


class FileObj_Initializer(nn.Module):
    '''
    features = [object_name, object_type]
    '''
    def __init__(self, output_dim):
        super().__init__()
        self.dtype = torch.float64
        self.name_embedding = nn.Embedding(10, 5, dtype=self.dtype)
        self.type_embedding = nn.Embedding(8, 5, dtype=self.dtype)
        self.fc = Linear(10, output_dim,dtype=self.dtype)

    def initialize(self, features):
        name_emb = self.name_embedding(features[0])
        type_emb = self.type_embedding(features[1])
        features = torch.tensor([name_emb,type_emb],dtype=self.dtype)
        tags = torch.sigmoid(self.fc(features))
        return tags

class NetFlowObj_Initializer(nn.Module):
    '''
    features = [localAddress,localPort,remoteAddress,remotePort,ipProtocol]
    '''
    def __init__(self, output_dim):
        self.embedding = nn.Embedding(10, output_dim, dtype=self.dtype)
        super().__init__()
        self.dtype = torch.float64

    def initialize(self, features):
        features = torch.tensor(features,dtype=self.dtype)
        tags = torch.sigmoid(self.fc(features))
        return tags