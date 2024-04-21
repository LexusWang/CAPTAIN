```
python adversarial/extract_benign_structrue.py --input_data ../data/raw/ta1-cadets-e3-official.json/ta1-cadets-e3-official.json --volume_num 1 --output_data ../data/C31 --format cadets --cdm_version 18
```

```
python adversarial/insert_events.py
```

```
cd ..
```

```
python parse/cdm18/standard_data-cadets.py --input_data adversarial/artifacts/mimicry_logs.json --output_data adversarial/artifacts/mimicry --format cadets --cdm_version 18
```

```
python parse/cdm18/standard_data-cadets.py --input_data ../data/raw --output_data adversarial/artifacts/normal --format cadets --cdm_version 18
```

```
python detection.py --att 0.2 --decay 2 --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ./adversarial/artifacts/mimicry --mode test --data_tag c33-test --experiment_prefix Mimicry-Test-C33 --param_path experiments/AGT-Train-C312023-11-30-04-16-08 --model_index 99 --time_range 2018-4-11T16:30:00-04:00 2018-4-12T22:00:00-04:00
```

```
python detection.py --att 0.2 --decay 2 --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ./adversarial/artifacts/normal --mode test --data_tag c33-test --experiment_prefix Mimicry-Test-Normal --param_path experiments/AGT-Train-C312023-11-30-04-16-08 --model_index 99 --time_range 2018-4-11T16:30:00-04:00 2018-4-12T22:00:00-04:00
```

```
python detection.py --att 0.2 --decay 2 --ground_truth_file ../data/GT/groundTruthC33.txt --data_path ../data/C3 --mode test --data_tag c33-test --experiment_prefix AGT-Test-C33 --param_path experiments/AGT-Train-C312023-11-30-04-16-08 --model_index 99 --time_range 2018-4-11T16:30:00-04:00 2018-4-12T22:00:00-04:00
```