import json
import torch
import logging
import argparse
import time
from utils.utils import *
from model.loss import get_loss
from utils.eventClassifier import eventClassifier
from model.morse import Morse
from collections import defaultdict

from numpy import gradient, record
from parse.eventParsing import parse_event
from parse.nodeParsing import parse_subject, parse_object
from parse.lttng.recordParsing import read_lttng_record
from policy.initTagsAT import get_object_feature, get_subject_feature
import sys
import tqdm
import time
import pandas as pd
from model.morse import Morse
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer
import numpy as np
from pathlib import Path
import pickle
import ray
from ray import tune
from start_experiment import start_experiment

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--feature_path", default='/home/weijian/weijian/projects/ATPG/results/features/feature_vectors', type=str)
    parser.add_argument("--ground_truth_file", default='/home/weijian/weijian/projects/ATPG/groundTruth.txt', type=str)
    parser.add_argument("--epoch", default=100, type=int)
    parser.add_argument("--learning_rate", nargs='?', default=0.001, type=float)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--train_data", nargs='?', default="/root/Downloads/ta1-trace-e3-official-1.json", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)
    parser.add_argument("--lr_imb", type=int)

    args = parser.parse_args()

    config = {
        "learning_rate": args.learning_rate,
        "epoch": args.epoch,
        "lr_imb": args.lr_imb,
        "train_data": args.train_data,
        "mode": args.mode,
        "device": args.device,
        "ground_truth_file": args.ground_truth_file,
        "feature_path": args.feature_path,
        "data_tag": "traindata1",
        "experiment_prefix": "groupA"
    }

    start_experiment(config)

