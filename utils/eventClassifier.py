class eventClassifier:
    def __init__(self, filePath):
        self.dataLeakUUID = []
        self.chPermUUID = []
        self.fileExecUUID = []
        with open(filePath) as f:
            curr_alarm = None
            for line in f:
                clean_line = line.strip()
                if clean_line == "DataLeak" or clean_line == "ChPerm" or clean_line == "FileExec":
                    curr_alarm = clean_line
                else:
                    self.addAlarmUUID(curr_alarm, clean_line)
    
    def classify(self, UUID):
        if UUID in self.dataLeakUUID:
            return "DataLeak"
        elif UUID in self.chPermUUID:
            return "ChPerm"
        elif UUID in self.fileExecUUID:
            return "FileExec"
        return None
    
    def addAlarmUUID(self, alarm, UUID):
        assert alarm != None
        if alarm == "DataLeak":
            self.dataLeakUUID.append(UUID)
        elif alarm == "ChPerm":
            self.chPermUUID.append(UUID)
        elif alarm == "FileExec":
            self.fileExecUUID.append(UUID)