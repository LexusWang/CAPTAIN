# !/bin/bash
## Data Preparation
## TRACE
python standard_data-trace.py --input_data ../data/raw/E3-trace-1 --output_data ../data/T31 --format trace --cdm_version 18
python standard_data-trace.py --input_data ../data/raw/E3-trace-2 --output_data ../data/T32 --format trace --cdm_version 18

# TRACE
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --train_data ../data/T31 --mode train --data_tag t31-train --experiment_prefix TrainT31 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00

python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --train_data ../data/T31 --mode test --data_tag t31-test --experiment_prefix TestT31 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT32.txt --train_data ../data/T32 --mode test --data_tag t32-test --experiment_prefix TestT32

# CADETS
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --train_data ../data/C31 --mode train --data_tag c31-train --experiment_prefix TrainC31 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00

python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --train_data ../data/C31 --mode test --data_tag c31-test --experiment_prefix TestC31 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC32.txt --train_data ../data/C32 --mode test --data_tag c32-test --experiment_prefix TestC32
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC33.txt --train_data ../data/C33 --mode test --data_tag c33-test --experiment_prefix TestC33


python detection.py --ground_truth_file ../data/GT/groundTruthC31.txt --train_data ../data/C31 --data_tag c31-test --experiment_prefix TestC31 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
python detection.py --ground_truth_file ../data/GT/groundTruthC32.txt --train_data ../data/C32 --data_tag c32-test --experiment_prefix ManualC32
python detection.py --ground_truth_file ../data/GT/groundTruthC33.txt --train_data ../data/C33 --data_tag c33-test --experiment_prefix TestC33