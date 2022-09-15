from utils.eventClassifier import eventClassifier

ec = eventClassifier('groundTruthC31.txt')
# if ec.classify('0F8CF745-900F-206D-F134-28686757C4D5') == "DataLeak":
#     print("correctly classified DataLeak Alarm")
# else:
#     print("error")

# if ec.classify('DEE900D6-80D1-662E-402E-1137BDF25420') == "FileExec":
#     print("correctly classified FileExec Alarm")
# else:
#     print("error")

# if ec.classify('A5DA3328-1DB8-EDDD-4637-60CCE0FEFE3E') == "MkFileExecutable":
#     print("correctly classified MkFileExecutable Alarm")
# else:
#     print("error")

# if ec.classify('60C3AC79-466B-5C25-B2AF-AEC19A5CFC77') == "MkMemExecutable":
#     print("correctly classified MkMemExecutable Alarm")
# else:
#     print("error")

ec.analyzeFile(open('/Users/lexus/Documents/research/APT/ATPG/experiments/Manual-C312022-09-14-12-17-55/test/alarms/alarms-in-test.txt','r'))

ec.summary("../missingTP.txt")