class eventClassifier:
    def __init__(self, filePath):
        self.dataLeakUUID = []
        self.mkFileExecutableUUID = []
        self.mkMemExecutableUUID = []
        self.fileExecUUID = []
        with open(filePath) as f:
            curr_alarm = None
            for line in f:
                clean_line = line.strip()
                if clean_line == "DataLeak" or clean_line == "MkFileExecutable" or clean_line == "FileExec" or clean_line == "MkMemExecutable":
                    curr_alarm = clean_line
                else:
                    self.addAlarmUUID(curr_alarm, clean_line)
            # print(len(self.dataLeakUUID))
            # print(self.fileExecUUID)
            # print(self.chPermUUID)
    
    def classify(self, UUID):
        if UUID in self.dataLeakUUID:
            return "DataLeak"
        elif UUID in self.mkFileExecutableUUID:
            return "MkFileExecutable"
        elif UUID in self.fileExecUUID:
            return "FileExec"
        elif UUID in self.mkMemExecutableUUID:
            return "MkMemExecutable"
        return None
    
    def addAlarmUUID(self, alarm, UUID):
        assert alarm != None
        if alarm == "DataLeak":
            self.dataLeakUUID.append(UUID)
        elif alarm == "MkFileExecutable":
            self.mkFileExecutableUUID.append(UUID)
        elif alarm == "FileExec":
            self.fileExecUUID.append(UUID)
        elif alarm == "MkMemExecutable":
            self.mkMemExecutableUUID.append(UUID)