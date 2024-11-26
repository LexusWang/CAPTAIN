from datetime import datetime
import argparse
# from utils.utils import *
from train_by_benign import start_experiment

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="train or test the model")
    parser.add_argument("--att", type=float)
    parser.add_argument("--decay", type=float)
    parser.add_argument("--data_path", type=str)
    parser.add_argument("--epoch", default=10, type=int)
    parser.add_argument("--mode", type=str, default="train")
    parser.add_argument("--param_type", type=str)
    # parser.add_argument("--model_index", type=int)
    parser.add_argument("--data_tag", type=str)
    parser.add_argument("--experiment_prefix", type=str)
    parser.add_argument("--checkpoint", type=str)
    parser.add_argument("--param_path", type=str)
    parser.add_argument("--lr", type=float, default=1)
    parser.add_argument("--alpha", type=float, default=0)
    parser.add_argument("--gamma", type=float, default=0)
    parser.add_argument("--tau", type=float, default=0)
    parser.add_argument("--cv_k", type=int, default = 3)
    parser.add_argument("--time_range", nargs=2, type=str, default = None)
    parser.add_argument("--time_window", type=float)

    args = parser.parse_args()
    
    # This is the time range of the training set.
    train_start_time = (datetime.timestamp(datetime.strptime(args.time_range[0], '%Y-%m-%dT%H:%M:%S%z')))*1e9
    train_end_time = (datetime.timestamp(datetime.strptime(args.time_range[1], '%Y-%m-%dT%H:%M:%S%z')))*1e9
    # This is the moving time window used to seperate different training subsets for cross validation (in the unit of days)
    time_window = args.time_window*24*3600*1e9
    # We will have cv_k subsets
    stride = int((train_end_time - train_start_time - time_window)/args.cv_k)
    # The splitted datasets should share the same prefix
    data_tag_prefix = args.data_tag
    experiment_prefix = args.experiment_prefix
    
    # Perform training on those cv_k subsets respectively
    for k in range(args.cv_k):
        train_start_time += stride
        args.time_range[0] = train_start_time
        args.time_range[1] = min(train_end_time, train_start_time+time_window)
        
        args.data_tag = f'{data_tag_prefix}_cv_{args.cv_k}_{k}'
        args.experiment_prefix = f'{experiment_prefix}-{args.cv_k}-{k}'
    
        start_experiment(args)
