import json
import configparser
import os

class dataProcessor:
    def __init__(self, configFile):
        self.config = configparser.ConfigParser()
        self.config.read(configFile)
        self.dpConfig = self.config['DataProcessor']
        self.fromPath = self.dpConfig['FromPath']
        self.toDir = self.dpConfig['ToDir']
        self.vertexDataFileName = self.dpConfig['vertexDataFileName']
        self.edgeDataFileName = self.dpConfig['edgeDataFileName']

    def separate(self):
        if not os.path.exists(self.toDir):
            os.makedirs(self.toDir)
        vertexPath = os.path.join(self.toDir, self.vertexDataFileName)
        edgePath = os.path.join(self.toDir, self.edgeDataFileName)
        with open(self.fromPath, 'r') as f:
            with open(vertexPath, 'w+') as v:
                with open(edgePath, 'w+') as e:
                    for line in f:
                        tmp = json.loads(line.strip())
                        if 'com.bbn.tc.schema.avro.cdm18.Subject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.SrcSinkObject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.NetFlowObject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.FileObject' in tmp['datum'] or \
                        'com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject' in tmp['datum']:
                            v.write(line)
                        elif 'com.bbn.tc.schema.avro.cdm18.Event' in tmp['datum']:
                            e.write(line)