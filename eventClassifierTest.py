from utils.eventClassifier import eventClassifier

ec = eventClassifier('groundTruth.txt')
if ec.classify('0F8CF745-900F-206D-F134-28686757C4D5') == "DataLeak":
    print("correctly classified DataLeak Alarm")
else:
    print("error")

if ec.classify('DEE900D6-80D1-662E-402E-1137BDF25420') == "FileExec":
    print("correctly classified FileExec Alarm")
else:
    print("error")

if ec.classify('A5DA3328-1DB8-EDDD-4637-60CCE0FEFE3E') == "ChPerm":
    print("correctly classified ChPerm Alarm")
else:
    print("error")