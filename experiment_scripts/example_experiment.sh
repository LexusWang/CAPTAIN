# train
time python start_experiment.py \
      --batch_size 5 \
      --early_stopping_patience 30 \
      --early_stopping_threshold 5 \
      --mode train \
      --train_data "EventData/training_data.out"

# test
time python start_experiment.py \
      --batch_size 5 \
      --early_stopping_patience 30 \
      --early_stopping_threshold 5 \
      --mode test \
      --test_data "EventData/north_korea_apt_attack_data_debug.out"
