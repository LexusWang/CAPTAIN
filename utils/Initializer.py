import torch
from torch.nn import Linear

class Initializer():

    def __init__(self, input_dim, output_dim) -> None:
        self.nn = Linear(input_dim, output_dim)

    def initialze(self, features):
        tags = self.nn(features)
        return tags