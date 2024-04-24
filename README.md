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

## Enviroment Setup

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

## Engagement 3 THEIA Pipeline

### Data Preprocessing

```
mkdir data/TH3
python parse/cdm18/standard_data-theia.py --input_data #THEIA_FILE_PATH --output_data data/TH3 --format theia --cdm_version 18
```


## Engagement 5 CADETS Pipeline

### Data Preprocessing

```
mkdir data/C5
python parse/cdm20/standard_data-cadets.py --input_data #CADETS_FILE_PATH --output_data data/C5 --format cadets --cdm_version 20
```

## Engagement 5 TRACE Pipeline

### Data Preprocessing

```
mkdir data/T5
python parse/cdm20/standard_data-trace.py --input_data #TRACE_FILE_PATH --output_data data/T5 --format trace --cdm_version 20
```


