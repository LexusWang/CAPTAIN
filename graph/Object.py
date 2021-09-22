from policy.floatTags import citag
import numpy as np
import re


# from globals import GlobalVariable as gv


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
        self.pipe = []

        self.event_list = []
        self.event_id_list = []
        self.event_type_list = []
        self.state_list = []
        self.morse_grad_list = []
        self.simple_net_grad_list = []
        # grad list stores grad of morse
        self.cur_state = np.zeros([2, 3])
        self.seq_len = 0

        self.iTag: float = 0.0
        self.cTag: float = 0.0

    def tags(self):
        if self.iTag > 0.5:
            ciTag = 1
        else:
            ciTag = 0
        return [ciTag, ciTag, 0, self.iTag, self.cTag]

    def setObjTags(self, tags):
        self.iTag = tags[0]
        self.cTag = tags[1]

    def isMatch(self, string):
        if self.path == None:
            return False
        return isinstance(re.search(string, self.path), re.Match)

    def isIP(self):
        return self.type in {'NetFlowObject','inet_scoket_file'}

    def set_IP(self, ip, port):
        assert self.type in {'NetFlowObject','inet_scoket_file'}
        self.IP = ip
        self.port = port

    def get_name(self):
        return self.name

    def get_id(self):
        return self.id

        
