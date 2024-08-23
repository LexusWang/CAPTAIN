# CAPTAIN
This is the code repository of CAPTAIN.

The code is tested on the Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64) server.

## Contents
[Enviroment Setup](#enviroment-setup)

[Engagement 3 CADETS Pipeline](#engagement-3-cadets-pipeline)

[Engagement 3 TRACE Pipeline](#engagement-3-trace-pipeline)

[Engagement 3 THEIA Pipeline](#engagement-3-theia-pipeline)

[Engagement 5 CADETS Pipeline](#engagement-5-cadets-pipeline)

[Engagement 5 TRACE Pipeline](#engagement-5-trace-pipeline)

[Operationally Transparent Cyber (OpTC) Data](#optc-data-pipeline)

## Enviroment Setup
```
conda install --file requirements.txt
```

## Engagement 3 CADETS Pipeline

### Data Preprocessing

```
mkdir data/C3
python parse/cdm18/standard_data-cadets.py --input_data #CADETS_FILE_PATH --output_data data/C3 --format cadets --cdm_version 18
```

### Training
```
python train_by_benign.py --att 0.2 --decay 2 --data_path data/C3 --data_tag c3-train --param_type agt --experiment_prefix Train-C3 --lr 1e-3 --alpha 1e-1 --gamma 1e-1 --tau 1e-1 --epoch 100 --time_range 2018-4-2T00:00:00-04:00 2018-4-6T00:00:00-04:00
```

### Detection (Testing)
```
## You can use the parameters trained in last step, or use the pre-trained parameters from experiments/Train-C3
python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthC3.txt --data_path data/C3 --experiment_prefix Test-C3 --param_path experiments/Train-C3 --model_index 99 --time_range 2018-4-6T00:00:00-04:00 2018-4-15T00:00:00-04:00

## The default parameters (without any training) can serve as the baseline
python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthC3.txt --data_path data/C3 --experiment_prefix Test-C3 --time_range 2018-4-6T00:00:00-04:00 2018-4-15T00:00:00-04:00
```

## Engagement 3 TRACE Pipeline

### Data Preprocessing

```
mkdir data/T3
python parse/cdm18/standard_data-trace.py --input_data #TRACE_FILE_PATH --output_data data/T3 --format trace --cdm_version 18
```

### Training
```
python train_by_benign.py --att 0 --decay 0 --data_path data/T3 --data_tag t31-train --param_type agt --experiment_prefix Train-T3 --lr 1e-3 --alpha 1e-1 --gamma 1e-1 --tau 1e-1 --epoch 100 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00

python train_by_benign.py --att 0 --decay 0 --data_path data/T3 --data_tag t31-train --param_type agt --experiment_prefix Train-T3 --lr 1e-3 --alpha 1e1 --gamma 1e1 --tau 1e1 --epoch 100 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
```

```
## You can use the parameters trained in last step, or use the pre-trained parameters from experiments/Train-T3
python detection.py --att 0 --decay 0 --ground_truth_file data/GT/groundTruthT3.txt --data_path data/T3 --experiment_prefix Test-T3 --param_path experiments/Train-T3 --model_index 99 --time_range 2018-4-10T00:00:00-04:00 2018-4-15T00:00:00-04:00

## The default parameters (without any training) can serve as the baseline
python detection.py --att 0 --decay 0 --ground_truth_file data/GT/groundTruthT3.txt --data_path data/T3 --experiment_prefix Test-T3 --time_range 2018-4-10T00:00:00-04:00 2018-4-15T00:00:00-04:00
```

## Engagement 3 THEIA Pipeline

### Data Preprocessing

```
mkdir data/TH3
python parse/cdm18/standard_data-theia.py --input_data #THEIA_FILE_PATH --output_data data/TH3 --format theia --cdm_version 18
```

### Training
```
python train_by_benign.py --att 0 --decay 0 --data_path data/TH3 --data_tag th3-train --param_type agt --experiment_prefix Train-TH3 --lr 1e-3 --alpha 1e-1 --gamma 1e-1 --tau 1e-1 --epoch 100 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
```

```
python train_by_benign.py --att 0.2 --decay 2 --data_path data/TH3 --data_tag th3-train --param_type agt --experiment_prefix Train-TH3 --lr 1e-2 --alpha 1e1 --gamma 1e1 --tau 1e1 --epoch 100 --time_range 2018-4-2T00:00:00-04:00 2018-4-10T00:00:00-04:00
```

### Detection (Testing)
```
## You can use the parameters trained in last step, or use the pre-trained parameters from experiments/Train-C3
python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthTH3.txt --data_path data/TH3 --experiment_prefix Test-TH3 --param_path experiments/Train-TH3 --model_index 99 --time_range 2018-4-10T00:00:00-04:00 2018-4-15T00:00:00-04:00

## The default parameters (without any training) can serve as the baseline
python detection.py --att 0 --decay 0 --ground_truth_file data/GT/groundTruthTH3.txt --data_path data/TH3 --experiment_prefix Test-TH3 --time_range 2018-4-10T00:00:00-04:00 2018-4-15T00:00:00-04:00
```


## Engagement 5 CADETS Pipeline

### Data Preprocessing

```
mkdir data/C5
python parse/cdm20/standard_data-cadets.py --input_data #CADETS_FILE_PATH --output_data data/C5 --format cadets --cdm_version 20
```

### Training
```
python train_by_benign.py --att 0.2 --decay 2 --data_path data/C5 --data_tag c5-train --param_type agt --experiment_prefix Train-C5 --lr 1e-3 --alpha 1e-1 --gamma 1e-1 --tau 1e-1 --epoch 100 --time_range 2019-5-7T08:00:00-04:00 2019-5-10T08:00:00-04:00
```

### Detection (Testing)
```
## You can use the parameters trained in last step, or use the pre-trained parameters from experiments/Train-C5
python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthC5.txt --data_path data/C5 --experiment_prefix Test-C5 --param_path experiments/Train-C5 --model_index 99 --time_range 2019-5-10T08:00:00-04:00 2019-5-17T18:00:00-04:00

## The default parameters (without any training) can serve as the baseline
python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthC5.txt --data_path data/C5 --experiment_prefix Test-C5 --time_range 2019-5-10T08:00:00-04:00 2019-5-17T18:00:00-04:00
```

## Engagement 5 TRACE Pipeline

### Data Preprocessing

```
mkdir data/T5
python parse/cdm20/standard_data-trace.py --input_data #TRACE_FILE_PATH --output_data data/T5 --format trace --cdm_version 20
```

### Training
```

python train_by_benign.py --att 0.2 --decay 2 --data_path data/T5 --data_tag t5-train --param_type agt --experiment_prefix Train-T5 --lr 1e-3 --alpha 1e1 --gamma 1e1 --tau 1e1 --epoch 100 --time_range 2019-5-7T08:00:00-04:00 2019-5-10T08:00:00-04:00

python train_by_benign.py --att 0.2 --decay 2 --data_path data/T5 --data_tag t5-train --param_type agt --experiment_prefix Train-T5 --lr 1e-2 --alpha 5 --gamma 5 --tau 5 --epoch 100 --time_range 2019-5-7T08:00:00-04:00 2019-5-10T08:00:00-04:00
```

### Detection (Testing)
```
python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthT5.txt --data_path data/T5 --experiment_prefix Test-T5 --param_path experiments/Train-T5 --model_index 99 --time_range 2019-5-10T08:00:00-04:00 2019-5-17T18:00:00-04:00

python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthT5.txt --data_path data/T5 --experiment_prefix Test-T5 --param_path experiments/Train-T5-2024-04-30-02-09-48 --model_index 99 --time_range 2019-5-10T08:00:00-04:00 2019-5-17T18:00:00-04:00

python detection.py --att 0.2 --decay 2 --ground_truth_file data/GT/groundTruthT5.txt --data_path data/T5 --experiment_prefix Test-T5 --time_range 2019-5-10T08:00:00-04:00 2019-5-17T18:00:00-04:00
```

## OpTC Data Pipeline

### Data Preprocessing

```
mkdir data/optc
python parse/cdm20/standard_data-optc.py --input_data #OPTC_FILE_PATH --output_data data/optc
```

### Training
```

python train_by_benign.py --att 0 --decay 0 --data_path data/optc --data_tag optc-train --param_type agt --experiment_prefix Train-OPTC --lr 1e-3 --alpha 1e1 --gamma 1e1 --tau 1e1 --epoch 100
```

### Detection (Testing)
```
python detection.py --att 0 --decay 0 --ground_truth_file data/GT/groundTruthT5.txt --data_path data/optc --experiment_prefix Test-OPTC
```
