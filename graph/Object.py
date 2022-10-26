import json
from policy.floatTags import citag
import numpy as np
import re

class Object:
    def __init__(self, id, type, subtype: str = None, pid: int = None, objName: str = None):
        self.id = id
        self.type = type
        self.subtype = subtype
        self.name = objName
        self.path = None

        self.updateTime = 0

        self.iTag: float = 0.0
        self.cTag: float = 0.0

        self.iTag_grad: float = 1.0
        self.cTag_grad: float = 1.0

        self.iTag_initID = [id,'i']
        self.cTag_initID = [id,'c']

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        # json_dict['time'] = self.time
        json_dict['type'] = self.type
        json_dict['subtype'] = self.subtype
        if self.type == 'NetFlowObject':
            json_dict['ip'] = self.IP
            json_dict['port'] = self.port
        elif self.type == 'FileObject':
            # json_dict['name'] = self.name
            json_dict['path'] = self.path
        else:
            json_dict['name'] = self.name
        return json.dumps(json_dict)

    def load(self, json_dict):
        # json_dict = {}
        # self.id = json_dict['id']
        # json_dict['time'] = self.time
        self.type = json_dict['type']
        self.subtype = json_dict['subtype']
        if self.type == 'NetFlowObject':
            self.IP = json_dict['ip']
            self.port = json_dict['port']
        elif self.type == 'FileObject':
            self.path = json_dict['path']
        else:
            self.name = json_dict['name']

    def tags(self):
        if self.iTag > 0.5:
            ciTag = 1.0
        else:
            ciTag = 0.0
        return [ciTag, ciTag, float(self.iTag), float(self.cTag)]

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

    def isFile(self):
        return self.type in {'FileObject'}

    def get_name(self):
        return self.name

    def get_id(self):
        return self.id

    def get_grad(self):
        return [self.iTag_grad, self.iTag_grad, self.iTag_grad, self.cTag_grad]

    def get_citag_grad(self):
        return self.iTag_grad

    def get_etag_grad(self):
        return self.iTag_grad

    def get_itag_grad(self):
        return self.iTag_grad

    def get_ctag_grad(self):
        return self.cTag_grad

    def set_itag_grad(self, i_grad):
        self.iTag_grad = i_grad

    def set_ctag_grad(self, c_grad):
        self.cTag_grad = c_grad

    def set_grad(self, grads):
        self.iTag_grad = grads[0]
        self.cTag_grad = grads[1]

    def setiTagInitID(self, id):
        self.iTag_initID = id

    def setcTagInitID(self, id):
        self.cTag_initID = id

    def getInitID(self):
        return [self.iTag_initID, self.iTag_initID, self.iTag_initID, self.cTag_initID]

    def getciTagInitID(self):
        return self.iTag_initID

    def geteTagInitID(self):
        return self.iTag_initID

    def getiTagInitID(self):
        return self.iTag_initID

    def getcTagInitID(self):
        return self.cTag_initID