import torch
import torch.nn as nn
from torch.nn import Linear

class Initializer(nn.Module):

    def __init__(self, input_dim, output_dim) -> None:
        super().__init__()
        self.fc = Linear(input_dim, output_dim)

    def initialze(self, features):
        tags = torch.sigmoid(self.fc(features))
        return tags