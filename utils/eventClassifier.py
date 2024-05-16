from datetime import datetime
import re
import pdb
import sys
sys.path.extend(['.','..','...'])
from policy.alarms import alarm_types

class eventClassifier:
    def __init__(self, filePath):
        self.reportedProcessUUID = {}
        self.reportedProcessName = {}
        self.dataLeakUUID = {}
        self.mkFileExecutableUUID = {}
        self.mkMemExecutableUUID = {}
        self.fileExecUUID = {}
        self.fileCorruptionUUID = {}
        self.privilegeEscalationUUID = {}
        self.injectionUUID = {}
        self.AlarmType = {}
        with open(filePath, 'r') as f:
            curr_alarm = None
            curr_list = []
            for line in f:
                clean_line = line.strip()
                if clean_line in alarm_types:
                    if curr_alarm:
                        self.__addAlarmUUID(curr_alarm, curr_list)
                    curr_list = []
                    curr_alarm = clean_line
                elif clean_line == "0":
                    self.__addAlarmUUID(curr_alarm, curr_list)
                    curr_list = []
                else:
                    curr_list.append(clean_line)
            # print(self.dataLeakUUID)
            # print(self.mkFileExecutableUUID)
            # print(self.mkMemExecutableUUID)
            # print(self.fileExecUUID)
            # print(self.fileCorruptionUUID)
    
    def reset(self):
        for sublst in self.dataLeakUUID.keys():
            self.dataLeakUUID[sublst] = False
        for sublst in self.mkFileExecutableUUID.keys():
            self.mkFileExecutableUUID[sublst] = False
        for sublst in self.fileExecUUID.keys():
            self.fileExecUUID[sublst] = False
        for sublst in self.mkMemExecutableUUID.keys():
            self.mkMemExecutableUUID[sublst] = False
        for sublst in self.fileCorruptionUUID.keys():
            self.fileCorruptionUUID[sublst] = False
        for sublst in self.privilegeEscalationUUID.keys():
            self.privilegeEscalationUUID[sublst] = False
        for sublst in self.injectionUUID.keys():
            self.injectionUUID[sublst] = False
        self.reportedProcessUUID = {}
        self.reportedProcessName = {}

    # def classify(self, UUID):
    #     for sublst in self.dataLeakUUID.keys():
    #         if UUID in sublst:
    #             return "DataLeak"
    #     for sublst in self.mkFileExecutableUUID.keys():
    #         if UUID in sublst:
    #             return "MkFileExecutable"
    #     for sublst in self.fileExecUUID.keys():
    #         if UUID in sublst:
    #             return "FileExec"
    #     for sublst in self.mkMemExecutableUUID.keys():
    #         if UUID in sublst:
    #             return "MkMemExecutable"
    #     for sublst in self.fileCorruptionUUID.keys():
    #         if UUID in sublst:
    #             return "FileCorruption"
    #     for sublst in self.privilegeEscalationUUID.keys():
    #         if UUID in sublst:
    #             return "PrivilegeEscalation"
    #     for sublst in self.injectionUUID.keys():
    #         if UUID in sublst:
    #             return "Injection"
    #     return None

    def classify(self, UUID):
        return self.AlarmType.get(UUID, None)

    def tally(self, UUID):
        for sublst in self.dataLeakUUID.keys():
            if UUID in sublst:
                self.dataLeakUUID[sublst] = True
        for sublst in self.mkFileExecutableUUID.keys():
            if UUID in sublst:
                self.mkFileExecutableUUID[sublst] = True
        for sublst in self.fileExecUUID.keys():
            if UUID in sublst:
                self.fileExecUUID[sublst] = True
        for sublst in self.mkMemExecutableUUID.keys():
            if UUID in sublst:
                self.mkMemExecutableUUID[sublst] = True
        for sublst in self.fileCorruptionUUID.keys():
            if UUID in sublst:
                self.fileCorruptionUUID[sublst] = True
        for sublst in self.privilegeEscalationUUID.keys():
            if UUID in sublst:
                self.privilegeEscalationUUID[sublst] = True
        for sublst in self.injectionUUID.keys():
            if UUID in sublst:
                self.injectionUUID[sublst] = True

    def analyzeFile(self, f):
        for line in f:
            l = line.strip().split(',')
            self.tally(l[0])
            if(self.classify(l[0])):
                print(self.classify(l[0]), "alarm detected")

            subject_info = re.search(r'Subject:(.*) \(pid:([0-9]*?) pname:(.*) cmdl:(.*)\)', line)
            suuid = subject_info.group(1)
            spid = subject_info.group(2)
            spname = subject_info.group(3)
            scmdl = subject_info.group(4)

            if suuid not in self.reportedProcessUUID.keys():
                # self.reportedProcessUUID[suuid] = ' '.join([l[6]]+l[13:-1])
                self.reportedProcessUUID[suuid] = ' '.join(spname+scmdl)
                # if len(l[14:-1]) > 5:
                #     p_name = ' '.join(l[14:19])
                # else:
                #     p_name = ' '.join(l[14:-1])
                if spname in self.reportedProcessName.keys():
                    self.reportedProcessName[spname] += 1
                else:
                    self.reportedProcessName[spname] = 1

    def summary(self, outFile=None):
        if outFile:
            with open(outFile, 'a') as fout:
                now = datetime.now()
                current_time = now.strftime("%H:%M:%S")
                print("---------------------------------------------------------------", file = fout)
                print("Current Time =", current_time, file = fout)
                print("---------------------------------------------------------------", file = fout)
                for sublst in self.dataLeakUUID.keys():
                    if not self.dataLeakUUID[sublst]:
                        print("missing DataLeak TP from at least one of the following eventids:", file = fout)
                        print(sublst, file = fout)
                for sublst in self.mkFileExecutableUUID.keys():
                    if not self.mkFileExecutableUUID[sublst]:
                        print("missing MkFileExecutable TP from following eventids:", file = fout)
                        print(sublst, file = fout)
                for sublst in self.fileExecUUID.keys():
                    if not self.fileExecUUID[sublst]:
                        print("missing FileExec TP from following eventids:", file = fout)
                        print(sublst, file = fout)
                for sublst in self.mkMemExecutableUUID.keys():
                    if not self.mkMemExecutableUUID[sublst]:
                        print("missing MkMemExecutable TP from following eventids:", file = fout)
                        print(sublst, file = fout)
                for sublst in self.fileCorruptionUUID.keys():
                    if not self.fileCorruptionUUID[sublst]:
                        print("missing FileCorruption TP from following eventids:", file = fout)
                        print(sublst, file = fout)
                for sublst in self.privilegeEscalationUUID.keys():
                    if not self.privilegeEscalationUUID[sublst]:
                        print("missing PrivilegeEscalation TP from following eventids:", file = fout)
                        print(sublst, file = fout)
                for sublst in self.injectionUUID.keys():
                    if not self.injectionUUID[sublst]:
                        print("missing Injection TP from following eventids:", file = fout)
                        print(sublst, file = fout)
                # print("---------------------------------------------------------------", file = fout)
                # print("Reported alarms on the following ", len(self.reportedProcessUUID), " processes with distinguishing UUIDs:", file = fout)
                # for x in self.reportedProcessUUID.keys():
                #     print(x, " ", self.reportedProcessUUID[x], file = fout)
                print("---------------------------------------------------------------", file = fout)
                print("Reported alarms on the following ", len(self.reportedProcessName), " processes with distinguishing UUIDs and process names:", file = fout)
                for y in self.reportedProcessName.keys():
                    print(y, " ", self.reportedProcessName[y], file = fout)
    
    def __addAlarmUUID(self, alarm, lst):
        assert alarm != None
        if alarm == "DataLeak":
            self.dataLeakUUID[tuple(lst)] = False
        elif alarm == "MkFileExecutable":
            self.mkFileExecutableUUID[tuple(lst)] = False
        elif alarm == "FileExec":
            self.fileExecUUID[tuple(lst)] = False
        elif alarm == "MkMemExecutable":
            self.mkMemExecutableUUID[tuple(lst)] = False
        elif alarm == "FileCorruption":
            self.fileCorruptionUUID[tuple(lst)] = False
        elif alarm == "PrivilegeEscalation":
            self.privilegeEscalationUUID[tuple(lst)] = False
        elif alarm == "Injection":
            self.injectionUUID[tuple(lst)] = False

        for item in lst:
            self.AlarmType[item] = alarm