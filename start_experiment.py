import os
import fire
import json
from globals import GlobalVariable as gv
import torch
import logging
import argparse
from new_train import train_model
import time
from predict import predict_entry
from utils import save_hyperparameters
from utils import save_evaluation_results
from utils import *

def start_experiment(config="config.json"):
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--batch_size", nargs='?', default=5, type=int)
    parser.add_argument("--learning_rate", nargs='?', default=0.001, type=float)
    parser.add_argument("--feature_dimension", nargs='?', default=12, type=int)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--train_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--test_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--validation_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--trained_model_timestamp", nargs="?", default=None, type=str)


    args = parser.parse_args()
    if args.mode == "train":
        experiment = Experiment(str(int(time.time())), args)
    else:
        experiment = Experiment(args.trained_model_timestamp, args)

    learning_rate = args.learning_rate
    batch_size = args.batch_size
    sequence_size = args.sequence_length
    feature_size = args.feature_dimension
    if torch.cuda.is_available():
        gv.device = torch.device("cuda:0")
    train_data = args.train_data
    test_data = args.test_data
    validation_data = args.validation_data
    model_save_path = args.model_save_path
    mode = args.mode

    if (mode == "train"):
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        experiment.save_hyperparameters()

        # pytorch model training code goes here
        # ...



        trained_model = None
        pred_result = None
        experiment.save_model(trained_model)

    elif (mode == "test"):

        # load pytorch model
        model = experiment.load_model()
        experiment.save_hyperparameters()

        # pytorch model testing code goes here
        # ...
        pred_result = None




        precision, recall, accuracy, f1 = experiment.evaluate_classification(pred_result)
        save_evaluation_results(precision, recall, accuracy, f1)


if __name__ == '__main__':
    start_experiment()