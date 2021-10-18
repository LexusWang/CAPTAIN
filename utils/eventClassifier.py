class eventClassifier:
    def __init__(self, filePath):
        self.maliciousUUID = []
        with open(filePath) as f:
            for line in f:
                self.maliciousUUID.append(line.strip())
    
    def classify(self, UUID):
        if UUID in self.maliciousUUID:
            return "DataLeak"
        return None