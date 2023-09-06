# !/bin/bash
# ## Data Preparation
# ## TRACE
# python standard_data-trace.py --input_data ../data/raw/E3-trace-1 --output_data ../data/T31 --format trace --cdm_version 18
# python standard_data-trace.py --input_data ../data/raw/E3-trace-2 --output_data ../data/T32 --format trace --cdm_version 18

# TRACE Train
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --train_data ../data/T31 --mode train --data_tag t31-train --experiment_prefix TrainT31 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
# TRACE Test
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --train_data ../data/T31 --mode test --data_tag t31-test --experiment_prefix TestT31 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT32.txt --train_data ../data/T32 --mode test --data_tag t32-test --experiment_prefix TestT32

python detection.py --ground_truth_file ../data/GT/groundTruthT31.txt --test_data ../data/T31 --experiment_prefix ManualT31 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
python detection.py --ground_truth_file ../data/GT/groundTruthT32.txt --test_data ../data/T32 --experiment_prefix ManualT32

# # CADETS
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --train_data ../data/C31 --mode train --data_tag c31-train --experiment_prefix TrainC31 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00

# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --train_data ../data/C31 --mode test --data_tag c31-test --experiment_prefix TestC31 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC32.txt --train_data ../data/C32 --mode test --data_tag c32-test --experiment_prefix TestC32
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC33.txt --train_data ../data/C33 --mode test --data_tag c33-test --experiment_prefix TestC33

# python detection.py --ground_truth_file ../data/GT/groundTruthC31.txt --train_data ../data/C31 --data_tag c31-test --experiment_prefix TestC31 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
# python detection.py --ground_truth_file ../data/GT/groundTruthC32.txt --train_data ../data/C32 --data_tag c32-test --experiment_prefix ManualC32
# python detection.py --ground_truth_file ../data/GT/groundTruthC33.txt --train_data ../data/C33 --data_tag c33-test --experiment_prefix TestC33

# LINUX
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --train_data ../data/L11 --mode train --data_tag l11-train --experiment_prefix TrainL11 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --train_data ../data/L11 --mode test --data_tag l11-test --experiment_prefix TestL11 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --train_data ../data/L12 --mode train --data_tag l12-train --experiment_prefix TrainL12 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --train_data ../data/L12 --mode test --data_tag l12-test --experiment_prefix TestL12 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --train_data ../data/L13 --mode train --data_tag l13-train --experiment_prefix TrainL13 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --train_data ../data/L13 --mode test --data_tag l13-test --experiment_prefix TestL13 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

python detection.py --ground_truth_file ../data/GT/groundTruthL11.txt --test_data ../data/L11 --experiment_prefix ManualL11
python detection.py --ground_truth_file ../data/GT/groundTruthL12.txt --test_data ../data/L12 --experiment_prefix ManualL12
python detection.py --ground_truth_file ../data/GT/groundTruthL13.txt --test_data ../data/L13 --experiment_prefix ManualL13

python train_by_benign.py --ground_truth_file /home/shared/linux_data/GT/groundTruthL11.txt --train_data /home/shared/linux_data/L11 --mode train --data_tag l11-train --experiment_prefix TrainL11 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00