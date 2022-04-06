import torch
import torch.nn as nn
from torch.nn import Linear, ReLU

class Initializer(nn.Module):

    def __init__(self, input_dim, output_dim, no_hidden_layer=3) -> None:
        super().__init__()
        self.dtype = torch.float32
        self.embedding = nn.Embedding(input_dim, output_dim, dtype=self.dtype)

    def initialize(self, features):
        # features.to(self.device)
        tags = torch.sigmoid(self.embedding(features.to(torch.int32)))
        return tags


class FileObj_Initializer(nn.Module):
    '''
    features = [dir_name, extension_name, object_type]
    '''
    def __init__(self, input_dim, output_dim, no_hidden_layer=3):
        super().__init__()
        self.input_dim = input_dim
        self.dtype = torch.float32
        # self.dir_name_embedding = nn.Embedding(21, 5, dtype=self.dtype)
        self.dir_name_embedding = nn.Linear(input_dim, 500, dtype=self.dtype)
        self.extension_name_embedding = nn.Embedding(7, 5, dtype=self.dtype)
        self.type_embedding = nn.Embedding(8, 5, dtype=self.dtype)
        self.fc = Linear(510, 200, dtype=self.dtype)
        self.relu = ReLU()
        self.hidden_layers = []
        for i in range(no_hidden_layer):
            self.hidden_layers.append(Linear(200, 200, dtype=self.dtype))
        self.output_layers = Linear(200, output_dim, dtype=self.dtype)

    def initialize(self, features):
        dir_emb = self.dir_name_embedding(features[:,:self.input_dim].to(torch.float32))
        extname_emb = self.extension_name_embedding(features[:,self.input_dim].to(torch.int32))
        type_emb = self.type_embedding(features[:,self.input_dim+1].to(torch.int32))
        features = torch.cat((dir_emb, extname_emb, type_emb),dim=1)
        hidden_result = None
        for i, hl in enumerate(self.hidden_layers):
            hl.to(features.device)
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
        self.dtype = torch.float32
        self.ip_layer = nn.Linear(32, 24, dtype=self.dtype)
        self.port_embedding = nn.Embedding(11, 6, dtype=self.dtype)
        self.protocol_embedding = nn.Embedding(2, 2, dtype=self.dtype)
        self.fc = Linear(32, 512,dtype=self.dtype)
        self.relu = ReLU()
        self.hidden_layers = []
        for i in range(no_hidden_layer):
            self.hidden_layers.append(Linear(512, 512, dtype=self.dtype))
        self.output_layers = Linear(512, output_dim, dtype=self.dtype)

    def initialize(self, features):
        proto_vec = self.protocol_embedding(features[:,0].to(torch.int32))
        ip_vec = torch.sigmoid(self.ip_layer(features[:,1:33].to(torch.float32)))
        port_vec = self.port_embedding(features[:,33:].to(torch.int32)).squeeze()
        features = torch.cat((proto_vec, ip_vec, port_vec),dim=1)
        hidden_result = None
        for i, hl in enumerate(self.hidden_layers):
            hl.to(features.device)
            if i == 0:
                hidden_result = self.relu(hl((self.fc(features))))
            else:
                hidden_result = self.relu(hl(hidden_result))
        hidden_result = self.output_layers(hidden_result)
        tags = torch.sigmoid(hidden_result)
        return tags