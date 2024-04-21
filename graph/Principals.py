import numpy as np
import re
import json

class Principal:
    def __init__(self, id, type, pid, ppid: int = None, parentNode: str = None, cmdLine: str = None, processName: str = None):
        self.id = id
        self.type = type
        self.pid = pid
        self.parentNode = parentNode
        self.ppid = ppid
        self.cmdLine = cmdLine
        self.processName = processName
        self.updateTime = 0
        self.owner = None

        # init tags
        self.ciTag: float = 0.0
        self.eTag: float = 0.0
        self.iTag: float = 0.0
        self.cTag: float = 0.0

        self.ciTag_grad: float = 1.0
        self.eTag_grad: float = 1.0
        self.iTag_grad: float = 1.0
        self.cTag_grad: float = 1.0

        self.ciTag_initID = None
        self.eTag_initID = None
        self.iTag_initID = [id,'i']
        self.cTag_initID = [id,'c']

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['type'] = self.type
        json_dict['pid'] = self.pid
        json_dict['ppid'] = self.ppid
        json_dict['cmdLine'] = self.cmdLine
        json_dict['processName'] = self.processName
        return json.dumps(json_dict)
