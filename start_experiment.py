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
    parser.add_argument("--sequence_length", nargs='?', default=5, type=int)
    parser.add_argument("--feature_dimension", nargs='?', default=12, type=int)
    parser.add_argument("--device", nargs='?', default="cuda", type=str)
    parser.add_argument("--train_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--test_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--validation_data", nargs='?', default="EventData/north_korea_apt_attack_data_debug.out", type=str)
    parser.add_argument("--model_save_path", nargs='?', default="trainedModels", type=str)
    parser.add_argument("--mode", nargs="?", default="train", type=str)
    parser.add_argument("--load_model_from", nargs="?", default=None, type=str)
    gv.project_path = os.getcwd()

    args = parser.parse_args()
    experiment = Experiment(str(int(time.time())), args)

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

        paths_setting(str(int(time.time())))
        logging.basicConfig(level=logging.INFO,
                            filename='debug.log',
                            filemode='w+',
                            format='%(asctime)s %(levelname)s:%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        save_hyperparameters(args, "train")
        train_model()
    elif (mode == "test"):
        if args.load_model_from is None:
            raise ValueError("A path must be given to load the trained model from")
        gv.load_model_from = args.load_model_from
        paths_setting(args.load_model_from)
        save_hyperparameters(args, "test")
        out_batches = predict_entry()
        losses = []
        for out_batch in out_batches:
            out_copy = torch.clone(out_batch)  ## m by n by j, where m = # of batches, n = # of sequences in each batch, and j = output_dim
            batch_avg = torch.mean(out_copy, 1, True)  ## m by 1 by j
            # print(batch_avg.is_cuda)
            # print(torch.tensor([out.shape[1]]).is_cuda)
            tmp = torch.tensor([out_batch.shape[1]])
            # print(tmp.is_cuda)
            batch_avg = batch_avg.to(gv.device)
            tmp = tmp.to(gv.device)
            target = torch.repeat_interleave(batch_avg, tmp, dim=1)  ## m by n by j
            loss = (out_batch - target) ** 2
            losses += torch.mean(loss, dim=1)

        # calculate the final accuracy of classification using labels from test data
        pred_labels = []
        for loss in losses:
            if loss <= args.classify_boundary_threshold:
                pred_labels.append("benign")
            else:
                pred_labels.append("malicious")
        print(pred_labels)
        from utils import evaluate_classification
        from prepare_gold_labels import prepare_gold_labels
        gold_labels = prepare_gold_labels()
        precision, recall, accuracy, f1 = evaluate_classification(pred_labels, gold_labels)
        save_evaluation_results(precision, recall, accuracy, f1)

def paths_setting(save_models_dirname):
    gv.save_models_dirname = save_models_dirname
    if not os.path.exists(os.path.join(gv.model_save_path, gv.save_models_dirname)):
        os.makedirs(os.path.join(gv.model_save_path, gv.save_models_dirname))
    gv.morse_model_path = os.path.join(gv.model_save_path, gv.save_models_dirname, gv.morse_model_filename)
    gv.benign_thresh_model_path = os.path.join(gv.model_save_path, gv.save_models_dirname,
                                               gv.benign_thresh_model_filename)
    gv.suspect_env_model_path = os.path.join(gv.model_save_path, gv.save_models_dirname, gv.suspect_env_model_filename)
    gv.rnn_model_path = os.path.join(gv.model_save_path, gv.save_models_dirname, gv.rnn_model_filename)



if __name__ == '__main__':
    start_experiment()