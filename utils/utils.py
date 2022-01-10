import os
import torch
from pathlib import Path
from utils.Initializer import Initializer, FileObj_Initializer, NetFlowObj_Initializer



class Experiment:

    def __init__(self, timestamp: str, args, train_name=""):
        self.timestamp = timestamp
        self.args = args
        self.project_path = os.path.abspath(__file__)
        self.project_path = os.path.dirname(os.path.dirname(self.project_path))
        self.experiment_path = os.path.join(self.project_path, "experiments", train_name+timestamp)
        Path(self.experiment_path).mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.experiment_path):
            os.mkdir(self.experiment_path)
        if torch.cuda.is_available():
            self.device = torch.device("cuda:0")
        else:
            self.device = torch.device("cpu")
        self.device = torch.device("cpu")
        self.results_path = os.path.join(self.experiment_path, self.args['mode'])
        self.checkpoint_path = os.path.join(self.results_path, 'checkpoints')
        Path(self.checkpoint_path).mkdir(parents=True, exist_ok=True)
        if self.args['mode'] == 'test':
            self.train_results_path = os.path.join(self.experiment_path, 'train')
        Path(self.results_path).mkdir(parents=True, exist_ok=True)
        self.metric_path = os.path.join(self.results_path, "metric")
        Path(self.metric_path).mkdir(parents=True, exist_ok=True)
        self.pre_load_morses_repo = os.path.join(self.project_path, "pre_load_morses")
        Path(self.pre_load_morses_repo).mkdir(parents=True, exist_ok=True)

        # final metrics
        self.tp = 0
        self.fp = 0
        self.fn = 0

    def get_experiment_output_path(self):
        return self.results_path

    def get_pre_load_morse(self, data_name):
        pre_load_morse_dir = os.path.join(self.pre_load_morses_repo, data_name)
        pre_load_morse_path = os.path.join(pre_load_morse_dir, 'morse.pkl')
        if Path(pre_load_morse_path).is_file():
            return pre_load_morse_path
        else:
            Path(pre_load_morse_dir).mkdir(parents=True, exist_ok=True)
            return pre_load_morse_dir

    def update_metrics(self, pred, gt):
        if pred is None:
            self.fn += 1
        else:
            if pred == gt:
                self.tp += 1
            else:
                self.fp += 1

    def get_precision(self):
        return self.tp / (self.tp + self.fp)

    def get_recall(self):
        return self.tp / (self.tp + self.fn)

    def get_f1_score(self):
        p = self.get_precision()
        r = self.get_recall()
        return 2 * (p * r / (p + r))

    def save_metrics(self):
        filename = os.path.join(self.results_path, "metrics.txt")
        print(f"final metrics: tp: {self.tp}, fp: {self.fp}, fn: {self.fn}")
        with open(filename, 'w') as f:
            f.write(f"tp: {self.tp}")
            f.write(f"fp: {self.fp}")
            f.write(f"fn: {self.fn}")
            # f.write(f"precision: {self.get_precision()}")
            # f.write(f"recall: {self.get_recall()}")
            # f.write(f"f1: {self.get_f1_score()}")

    def save_hyperparameters(self):
        filename = os.path.join(self.results_path, "_hyperparameters.txt")
        with open(filename, 'w+') as f:
            for arg_item in self.args.items():
                f.write(f"{arg_item[0]}: {arg_item[1]}\n")

    def save_model(self, model_dict):
        Path(os.path.join(self.results_path, "train_models")).mkdir(parents=True, exist_ok=True)
        for key in model_dict.keys():
            torch.save(model_dict[key].state_dict(), os.path.join(self.results_path, "train_models", f"trained_model_{key}.pth"))

    def save_checkpoint(self, model_dict, epoch):
        for key in model_dict.keys():
            torch.save(model_dict[key].state_dict(), os.path.join(self.checkpoint_path, f"epoch-{epoch}", f"{key}.pth"))

    def load_checkpoint(self, node_inits, epoch_path):
        key_list = list(node_inits.keys())
        for key in key_list:
            node_inits[key].load_state_dict(torch.load(os.path.join(epoch_path, f"{key}.pth")))
            node_inits[key].to(self.device)
        return node_inits

    def load_model(self, node_inits):
        key_list = list(node_inits.keys())
        for key in key_list:
            node_inits[key].load_state_dict(torch.load(os.path.join(self.train_results_path, "train_models", f"trained_model_{key}.pth")))
            node_inits[key].to(self.device)
        return node_inits

    def save_pred_labels(pred_labels, file_path):
        '''
        save the prediction results of the test mode to a file
        '''
        with open(file_path, 'w') as f:
            for line in pred_labels:
                f.write(line+"\n")

    def evaluate_classification(pred_labels):
        gold_labels = None
        total = len(pred_labels)
        # positive: benign
        tp = 0
        tn = 0
        fp = 0
        fn = 0
        for i in range(len(gold_labels)):
            if (gold_labels[i] == pred_labels[i]):
                if (pred_labels[i] == 'benign'):
                    tp += 1
                elif (pred_labels[i] == 'malicious'):
                    tn += 1
            else:
                if (pred_labels[i] == 'benign'):
                    fp += 1
                elif (pred_labels[i] == 'malicious'):
                    fn += 1
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        accuracy = (tp + tn) / (tp + tn + fp +fn)
        f1 = 2 * precision * recall / (precision + recall)

        print("======= evaluation results =======")
        print("precision: ", precision)
        print("recall: ", recall)
        print("accuracy: ", accuracy)
        print("f1: ", f1)
        print(f"tp: {tp}")
        print(f"fp: {fp}")
        print(f"tn: {tn}")
        print(f"fn: {fn}")

        return precision, recall, accuracy, f1

    # def save_evaluation_results(precision, recall, accuracy, f1):
    #     filename = "evaluation_results.txt"
    #     p = os.path.join(gv.project_path, gv.model_save_path, gv.save_models_dirname, filename)
    #     with open(p, 'w+') as f:
    #         f.write("======= evaluation results =======\n")
    #         f.write(f"precision: {precision}\n")
    #         f.write(f"recall: {recall}\n")
    #         f.write(f"accuracy: {accuracy}\n")
    #         f.write(f"f1: {f1}\n")