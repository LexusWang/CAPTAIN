# ATPG
This is the code repository of our project Auto Tuning Parameter Graph

### Utils

#### eventClassifier class
1. eventClassifier(filePath): constructor of eventClassifier. The filePath should be the path to the ground truth file.
2. eventClassifier.classify(UUID): return alarm type if the event correponding to the UUID should trigger an alarm according to the ground truth. Otherwise, return None.

#### datProcessor class
1. dataProcessor(configFile): constructor of dataProcessor. The configFile should be the path to the .ini file.
2. dataProcessor.separate(): read from and write to files specified in config, as well as applying filtering conditions in the config file if applicable. 