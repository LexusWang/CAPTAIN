import torch
import torch.nn as nn
from torch.nn import Linear

class Initializer(nn.Module):

    def __init__(self, input_dim, output_dim) -> None:
        super().__init__()
        self.dtype = torch.float64
        self.embedding = nn.Embedding(input_dim, output_dim, dtype=self.dtype)

    def initialize(self, features):
        tags = torch.sigmoid(self.embedding(features))
        return tags


class FileObj_Initializer(nn.Module):
    '''
    features = [dir_name, extension_name, object_type]
    '''
    def __init__(self, output_dim):
        super().__init__()
        self.dtype = torch.float64
        self.dir_name_embedding = nn.Embedding(21, 5, dtype=self.dtype)
        self.extension_name_embedding = nn.Embedding(7, 5, dtype=self.dtype)
        self.type_embedding = nn.Embedding(8, 5, dtype=self.dtype)
        self.fc = Linear(15, output_dim,dtype=self.dtype)

    def initialize(self, features):
        dir_emb = self.dir_name_embedding(features[:,0])
        extname_emb = self.extension_name_embedding(features[:,1])
        type_emb = self.type_embedding(features[:,2])
        features = torch.cat((dir_emb, extname_emb, type_emb),dim=1)
        tags = torch.sigmoid(self.fc(features))
        return tags

class NetFlowObj_Initializer(nn.Module):
    '''
    features = [ipProtocol, remoteAddress, remotePort]
    '''
    def __init__(self, output_dim):
        super().__init__()
        self.dtype = torch.float64
        self.ip_layer = nn.Linear(160, 6, dtype=self.dtype)
        self.port_embedding = nn.Embedding(11, 6, dtype=self.dtype)
        self.protocol_embedding = nn.Embedding(2, 2, dtype=self.dtype)
        self.fc = Linear(14, output_dim,dtype=self.dtype)

    def initialize(self, features):
        proto_vec = self.protocol_embedding(features[:,0])
        ip_vec = self.ip_layer(features[:,1:161])
        port_vec = self.port_embedding(features[:,161:])
        features = torch.cat((proto_vec, ip_vec, port_vec),dim=1)
        tags = torch.sigmoid(self.fc(features))
        return tags