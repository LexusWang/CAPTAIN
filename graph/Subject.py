# from morse import Morse
import numpy as np
import re

class Subject:
    def __init__(self, id = -1, time: float = -1.0, type: int = -1, subtype: int = -1, pid: int = -1, ppid: int = -1, cmdLine: str = None,
                 processName: str = None):
        self.id = id
        self.time = time
        self.type = type
        self.subtype = subtype
        self.pid = pid
        self.ppid = ppid
        self.cmdLine = cmdLine
        self.processName = processName
        
        self.updateTime = 0
        self.owner = None

        # init tags
        self.eTag: float = 0.0
        # init tags
        self.ciTag: float = 0.0
        # init tags
        self.invTag: float = 0.0
        # benign
        self.iTag: float = 0.0
        #
        self.cTag: float = 0.0

        self.ciTag_grad: float = 1.0
        self.eTag_grad: float = 1.0
        self.invTag_grad: float = 1.0
        self.iTag_grad: float = 1.0
        self.cTag_grad: float = 1.0

        self.ciTag_initID = id
        self.eTag_initID = id
        self.invTag_initID = id
        self.iTag_initID = id
        self.cTag_initID = id

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['time'] = self.time
        json_dict['type'] = self.type
        json_dict['subtype'] = self.subtype
        json_dict['pid'] = self.pid
        json_dict['ppid'] = self.ppid
        json_dict['cmdLine'] = self.cmdLine
        json_dict['processName'] = self.processName
        return str(json_dict)

    def get_id(self):
        return self.id
    
    def get_pid(self):
        return self.pid

    def get_name(self):
        return self.processName

    def get_cmdln(self):
        return self.cmdLine

    def tags(self):
        return [float(self.ciTag), float(self.eTag), float(self.invTag), float(self.iTag), float(self.cTag)]

    def setSubjTags(self,tags):
        self.ciTag = tags[0]
        self.eTag = tags[1]
        self.invTag = tags[2]
        self.iTag = tags[3]
        self.cTag = tags[4]

    def get_grad(self):
        return [self.ciTag_grad, self.eTag_grad, self.invTag_grad, self.iTag_grad, self.cTag_grad]

    def get_citag_grad(self):
        return self.ciTag_grad

    def get_etag_grad(self):
        return self.eTag_grad

    def get_invtag_grad(self):
        return self.invTag_grad

    def get_itag_grad(self):
        return self.iTag_grad

    def get_ctag_grad(self):
        return self.cTag_grad

    def set_grad(self, grads):
        self.ciTag_grad = grads[0]
        self.eTag_grad = grads[1]
        self.invTag_grad = grads[2]
        self.iTag_grad = grads[3]
        self.cTag_grad = grads[4]

    def update_grad(self, grads):
        self.ciTag_grad *= grads[0]
        self.eTag_grad *= grads[1]
        self.invTag_grad *= grads[2]
        self.iTag_grad *= grads[3]
        self.cTag_grad *= grads[4]
    
    def setInitID(self, InitID):
        self.ciTag_initID = InitID[0]
        self.eTag_initID = InitID[1]
        self.invTag_initID = InitID[2]
        self.iTag_initID = InitID[3]
        self.cTag_initID = InitID[4]

    def setciTagInitID(self, id):
        self.ciTag_initID = id

    def seteTagInitID(self, id):
        self.eTag_initID = id

    def setinvTagInitID(self, id):
        self.invTag_initID = id

    def setiTagInitID(self, id):
        self.iTag_initID = id

    def setcTagInitID(self, id):
        self.cTag_initID = id

    def getInitID(self):
        return [self.ciTag_initID, self.eTag_initID, self.invTag_initID, self.iTag_initID, self.cTag_initID]

    def getciTagInitID(self):
        return self.ciTag_initID

    def geteTagInitID(self):
        return self.eTag_initID

    def getinvTagInitID(self):
        return self.invTag_initID

    def getiTagInitID(self):
        return self.iTag_initID

    def getcTagInitID(self):
        return self.cTag_initID

    def isMatch(self, string):
        if self.processName == None:
            return False
        return isinstance(re.search(string, self.processName), re.Match)

    def get_matrix_array(self, padding: 4):
        if padding < 4:
            return None

        return [self.subtype, self.sTag, self.iTag, self.cTag] + [0] * (padding - 4)
