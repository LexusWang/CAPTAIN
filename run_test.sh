# !/bin/bash
# ## Data Preparation
# ## TRACE
# python standard_data-trace.py --input_data ../data/raw/E3-trace-1 --output_data ../data/T31 --format trace --cdm_version 18
# python standard_data-trace.py --input_data ../data/raw/E3-trace-2 --output_data ../data/T32 --format trace --cdm_version 18

# # TRACE Train
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode train --data_tag t31-train --experiment_prefix TrainT31 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
# # TRACE Test
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode test --data_tag t31-test --experiment_prefix TestT31 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT32.txt --data_path ../data/T32 --mode test --data_tag t32-test --experiment_prefix TestT32

# python detection.py --ground_truth_file ../data/GT/groundTruthT31.txt --test_data ../data/T31 --experiment_prefix ManualT31 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
# python detection.py --ground_truth_file ../data/GT/groundTruthT32.txt --test_data ../data/T32 --experiment_prefix ManualT32

# # CADETS
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode train --data_tag c31-train --experiment_prefix TrainC31 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00

# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode test --data_tag c31-test --experiment_prefix TestC31 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC32.txt --data_path ../data/C32 --mode test --data_tag c32-test --experiment_prefix TestC32
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ../data/C33 --mode test --data_tag c33-test --experiment_prefix TestC33

# python detection.py --ground_truth_file ../data/GT/groundTruthC31.txt --test_data ../data/C31 --experiment_prefix ManualC31 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
# python detection.py --ground_truth_file ../data/GT/groundTruthC32.txt --test_data ../data/C32 --experiment_prefix ManualC32
# python detection.py --ground_truth_file ../data/GT/groundTruthC33.txt --test_data ../data/C33 --experiment_prefix ManualC33

# # LINUX
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode train --data_tag l11-train --experiment_prefix TrainL11 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode test --data_tag l11-test --experiment_prefix TestL11 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode train --data_tag l12-train --experiment_prefix TrainL12 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode test --data_tag l12-test --experiment_prefix TestL12 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode train --data_tag l13-train --experiment_prefix TrainL13 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode test --data_tag l13-test --experiment_prefix TestL13 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

# python detection.py --ground_truth_file ../data/GT/groundTruthL11.txt --test_data ../data/L11 --experiment_prefix ManualL11 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
# python detection.py --ground_truth_file ../data/GT/groundTruthL12.txt --test_data ../data/L12 --experiment_prefix ManualL12 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
# python detection.py --ground_truth_file ../data/GT/groundTruthL13.txt --test_data ../data/L13 --experiment_prefix ManualL13 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00


# Ablation Test
# Alpha + Lambda
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode train --data_tag t31-train --experiment_prefix ALTrainT31 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode train --data_tag c31-train --experiment_prefix ALTrainC31 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode train --data_tag l11-train --experiment_prefix ALTrainL11 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode train --data_tag l12-train --experiment_prefix ALTrainL12 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode train --data_tag l13-train --experiment_prefix ALTrainL13 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00

# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode test --data_tag t31-test --experiment_prefix ALTestT31 --param_path experiments/ALTrainT312023-09-13-03-08-28 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT32.txt --data_path ../data/T32 --mode test --data_tag t32-test --experiment_prefix ALTestT32 --param_path experiments/ALTrainT312023-09-13-03-08-28
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode test --data_tag c31-test --experiment_prefix ALTestC31 --param_path experiments/ALTrainC312023-09-13-03-59-23 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC32.txt --data_path ../data/C32 --mode test --data_tag c32-test --experiment_prefix ALTestC32 --param_path experiments/ALTrainC312023-09-13-03-59-23
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ../data/C33 --mode test --data_tag c33-test --experiment_prefix ALTestC33 --param_path experiments/ALTrainC312023-09-13-03-59-23
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode test --data_tag l11-test --experiment_prefix ALTestL11 --param_path experiments/ALTrainL112023-09-13-04-03-34 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode test --data_tag l12-test --experiment_prefix ALTestL12 --param_path experiments/ALTrainL122023-09-12-22-28-05 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode test --data_tag l13-test --experiment_prefix ALTestL13 --param_path experiments/ALTrainL132023-09-12-22-25-30 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00

# Alpha + Tau
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode train --data_tag t31-train --experiment_prefix ATTrainT31 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode train --data_tag c31-train --experiment_prefix ATTrainC31 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode train --data_tag l11-train --experiment_prefix ATTrainL11 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode train --data_tag l12-train --experiment_prefix ATTrainL12 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode train --data_tag l13-train --experiment_prefix ATTrainL13 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00

# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode test --data_tag t31-test --experiment_prefix ATTestT31 --param_path experiments/ATTrainT312023-09-14-16-57-32 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT32.txt --data_path ../data/T32 --mode test --data_tag t32-test --experiment_prefix ATTestT32 --param_path experiments/ATTrainT312023-09-14-16-57-32
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode test --data_tag c31-test --experiment_prefix ATTestC31 --param_path experiments/ATTrainC312023-09-14-17-51-14 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC32.txt --data_path ../data/C32 --mode test --data_tag c32-test --experiment_prefix ATTestC32 --param_path experiments/ATTrainC312023-09-14-17-51-14
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ../data/C33 --mode test --data_tag c33-test --experiment_prefix ATTestC33 --param_path experiments/ATTrainC312023-09-14-17-51-14
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode test --data_tag l11-test --experiment_prefix ATTestL11 --param_path experiments/ATTrainL112023-09-14-17-55-21 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode test --data_tag l12-test --experiment_prefix ATTestL12 --param_path experiments/ATTrainL122023-09-14-18-15-00 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode test --data_tag l13-test --experiment_prefix ATTestL13 --param_path experiments/ATTrainL132023-09-14-18-18-39 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00


# Lambda + Tau
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode train --data_tag c31-train --experiment_prefix LTTrainC31 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode train --data_tag l11-train --experiment_prefix LTTrainL11 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode train --data_tag l12-train --experiment_prefix LTTrainL12 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode train --data_tag l13-train --experiment_prefix LTTrainL13 --time_range 2023-4-18T02:00:00+00:00 2023-4-18T08:00:00+00:00
# python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode train --data_tag t31-train --experiment_prefix LTTrainT31 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00

python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT31.txt --data_path ../data/T31 --mode test --data_tag t31-test --experiment_prefix LTTestT31 --param_path experiments/LTTrainT312023-09-15-02-26-09 --time_range 2018-4-10T00:00:00-04:00 2018-4-13T14:00:00-04:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthT32.txt --data_path ../data/T32 --mode test --data_tag t32-test --experiment_prefix LTTestT32 --param_path experiments/LTTrainT312023-09-15-02-26-09
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode test --data_tag c31-test --experiment_prefix LTTestC31 --param_path experiments/LTTrainC312023-09-14-21-45-20 --time_range 2018-4-6T00:00:00-04:00 2018-4-6T13:00:00-04:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC32.txt --data_path ../data/C32 --mode test --data_tag c32-test --experiment_prefix LTTestC32 --param_path experiments/LTTrainC312023-09-14-21-45-20
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ../data/C33 --mode test --data_tag c33-test --experiment_prefix LTTestC33 --param_path experiments/LTTrainC312023-09-14-21-45-20
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL11.txt --data_path ../data/L11 --mode test --data_tag l11-test --experiment_prefix LTTestL11 --param_path experiments/LTTrainL112023-09-14-21-49-29 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL12.txt --data_path ../data/L12 --mode test --data_tag l12-test --experiment_prefix LTTestL12 --param_path experiments/LTTrainL122023-09-14-22-09-28 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00
python train_by_benign.py --ground_truth_file ../data/GT/groundTruthL13.txt --data_path ../data/L13 --mode test --data_tag l13-test --experiment_prefix LTTestL13 --param_path experiments/LTTrainL132023-09-14-22-13-02 --time_range 2023-4-18T08:00:00+00:00 2023-4-18T20:00:00+00:00