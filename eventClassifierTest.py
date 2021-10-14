from utils.eventClassifier import eventClassifier

ec = eventClassifier('groundTruth.txt')
if ec.classify('123'):
    print("correctly classified")
else:
    print("error")
