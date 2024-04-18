# CAPTAIN
This is the code repository of CAPTAIN

## Enviroment Setup

## Pipeline

### Data Preprocessing

```
mkdir data/C3
python parse/cdm18/standard_data-cadets.py --input_data ../data/raw --output_data data/C3 --format cadets --cdm_version 18
```

### Training
```
python train_by_benign_debug.py --att 0 --decay 0 --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C31 --mode train --data_tag c31-train --param_type agt --experiment_prefix AGT-Train-C31 --lr 1e-3 --alpha 1e-1 --gamma 1e-1 --tau 1e-1 --epoch 100 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00
```

### Detection (Testing)
```
python detection.py --att 0.2 --decay 2 --ground_truth_file ../data/GT/groundTruthC31.txt --data_path ../data/C3 --mode test --data_tag c31-test --experiment_prefix AGT-Test-C3 --param_path experiments/AGT-Train-C312023-11-30-04-16-08 --model_index 99 --time_range 2018-4-6T00:00:00-04:00 2018-4-15T00:00:00-04:00
```


