import json
from policy.floatTags import citag
import numpy as np
import re

class Object:
    def __init__(self, id = None, time: int = None, type: str = None, subtype: str = None, pid: int = None, ppid: int = None,
                 objName: str = None):
        self.id = id
        self.time = time
        self.type = type
        self.subtype = subtype
        self.ppid = ppid
        self.name = objName
        self.path = None

        self.updateTime = 0

        self.iTag: float = 0.0
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
        json_dict['ppid'] = self.ppid
        json_dict['name'] = self.name
        json_dict['path'] = self.path
        return str(json_dict)

    def tags(self):
        if self.iTag > 0.5:
            ciTag = 1.0
        else:
            ciTag = 0.0
        return [ciTag, ciTag, 0.0, float(self.iTag), float(self.cTag)]

    def setObjTags(self, tags):
        self.iTag = tags[0]
        self.cTag = tags[1]

    def isMatch(self, string):
        if self.path == None:
            return False
        return isinstance(re.search(string, self.path), re.Match)

    def isIP(self):
        return self.type in {'NetFlowObject','inet_scoket_file'}

    def set_IP(self, ip, port, protocol):
        assert self.type in {'NetFlowObject','inet_scoket_file'}
        self.IP = ip
        self.port = port
        self.Protocol = protocol

    def get_name(self):
        return self.name

    def get_id(self):
        return self.id

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