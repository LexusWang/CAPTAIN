for LR in 0.1 0.01 0.001 0.0001
do
  for EPOCH in 5 10 20
  do
    for LR_IMB in 1 2 4 8 16
    do
        python start_single_experiments.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB} &
        sleep 1s
    done
  done
done