import json
import configparser
import os
import glob

class dataProcessor:
    def __init__(self, configFile):
        self.config = configparser.ConfigParser()
        self.config.read(configFile)
        self.dpConfig = self.config['DataProcessor']
        self.fromFormat = self.dpConfig['FromFileFormat']
        self.toDir = self.dpConfig['ToDir']
        self.vertexDataFileName = self.dpConfig['VertexDataFileName']
        self.edgeDataFileName = self.dpConfig['EdgeDataFileName']
        self.segSize = int(self.dpConfig['SegmentSize'])
        self.startTimestamp = int(self.dpConfig['StartTimestamp'])
        self.endTimestamp = int(self.dpConfig['EndTimestamp'])

    def separate(self):
        if not os.path.exists(self.toDir):
            os.makedirs(self.toDir)
        vertexPath = os.path.join(self.toDir, self.vertexDataFileName)
        counter = 0
        edgeIndex = 0
        edgePath = os.path.join(self.toDir, self.edgeDataFileName + '.' + str(edgeIndex))
        files = glob.glob(self.fromFormat)
        e = open(edgePath, 'w+')
        with open(vertexPath, 'w+') as v:
            for file in sorted(files):
                with open(file, 'r') as f:
                    for line in f:
                        tmp = json.loads(line.strip())
                        if 'com.bbn.tc.schema.avro.cdm18.Subject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.SrcSinkObject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.NetFlowObject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.FileObject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject' in tmp['datum']:
                            v.write(line)
                        elif 'com.bbn.tc.schema.avro.cdm18.Event' in tmp['datum']:
                            timestamp = tmp['datum']['com.bbn.tc.schema.avro.cdm18.Event']['timestampNanos']
                            if timestamp < self.startTimestamp or timestamp > self.endTimestamp:
                                continue
                            e.write(line)
                            counter += 1
                            if counter == self.segSize:
                                e.close()
                                edgeIndex += 1
                                counter = 0
                                edgePath = os.path.join(self.toDir, self.edgeDataFileName + '.' + str(edgeIndex))
                                e = open(edgePath, 'w+')