for LR in 0.0001 0.01 0.001
do
  for EPOCH in 4
  do
    for LR_IMB in 0.5 1 2 4 
    do
        python start_experiment.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB} &
        echo "running python start_experiments.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB}"
        sleep 2s
    done
  done
done

#for LR in 0.1 0.0001
#do
#  for EPOCH in 10
#  do
#    for LR_IMB in 2 4 16
#    do
#        python start_experiments.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB} &
#        echo "running python start_experiments.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB}"
#        sleep 1s
#    done
#  done
#done
#
#for LR in 0.01 0.001
#do
#  for EPOCH in 10
#  do
#    for LR_IMB in 2 4 16
#    do
#        python start_experiments.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB} &
#        echo "running python start_experiments.py --learning_rate ${LR} --epoch ${EPOCH} --lr_imb ${LR_IMB}"
#        sleep 1s
#    done
#  done
#done