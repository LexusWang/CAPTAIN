import torch
import torch.nn as nn
from torch.nn import Linear, ReLU

class Initializer(nn.Module):

    def __init__(self, input_dim, output_dim, no_hidden_layer=3) -> None:
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
    def __init__(self, output_dim, no_hidden_layer=3):
        super().__init__()
        self.dtype = torch.float64
        # self.dir_name_embedding = nn.Embedding(21, 5, dtype=self.dtype)
        self.dir_name_embedding = nn.Linear(2000, 5, dtype=self.dtype)
        self.extension_name_embedding = nn.Embedding(7, 5, dtype=self.dtype)
        self.type_embedding = nn.Embedding(8, 5, dtype=self.dtype)
        self.fc = Linear(15, 512, dtype=self.dtype)
        self.relu = ReLU()
        self.hidden_layers = []
        for i in range(no_hidden_layer):
            self.hidden_layers.append(Linear(512, 512, dtype=self.dtype))
        self.output_layers = Linear(512, output_dim, dtype=self.dtype)

    def initialize(self, features):
        dir_emb = self.dir_name_embedding(features[:,:2000])
        extname_emb = self.extension_name_embedding(features[:,2000])
        type_emb = self.type_embedding(features[:,2001])
        features = torch.cat((dir_emb, extname_emb, type_emb),dim=1)
        hidden_result = None
        for i, hl in enumerate(self.hidden_layers):
            if i == 0:
                hidden_result = self.relu(hl((self.fc(features))))
            else:
                hidden_result = self.relu(hl(hidden_result))
        hidden_result = self.output_layers(hidden_result)
        tags = torch.sigmoid(hidden_result)
        return tags

class NetFlowObj_Initializer(nn.Module):
    '''
    features = [ipProtocol, remoteAddress, remotePort]
    '''
    def __init__(self, output_dim, no_hidden_layer=3):
        super().__init__()
        self.dtype = torch.float64
        self.ip_layer = nn.Linear(32, 6, dtype=self.dtype)
        self.port_embedding = nn.Embedding(11, 6, dtype=self.dtype)
        self.protocol_embedding = nn.Embedding(2, 2, dtype=self.dtype)
        self.fc = Linear(14, 512,dtype=self.dtype)
        self.relu = ReLU()
        self.hidden_layers = []
        for i in range(no_hidden_layer):
            self.hidden_layers.append(Linear(512, 512, dtype=self.dtype))
        self.output_layers = Linear(512, output_dim, dtype=self.dtype)

    def initialize(self, features):
        proto_vec = self.protocol_embedding(features[:,0])
        ip_vec = torch.sigmoid(self.ip_layer(features[:,1:33].double()))
        port_vec = self.port_embedding(features[:,33:]).squeeze()
        features = torch.cat((proto_vec, ip_vec, port_vec),dim=1)
        hidden_result = None
        for i, hl in enumerate(self.hidden_layers):
            if i == 0:
                hidden_result = self.relu(hl((self.fc(features))))
            else:
                hidden_result = self.relu(hl(hidden_result))
        hidden_result = self.output_layers(hidden_result)
        tags = torch.sigmoid(hidden_result)
        return tags