# from morse import Morse
import math
import re
import json
import pdb

class Subject:
    def __init__(self, id, type, pid: int, ppid: int = None, parentNode: str = None, cmdLine: str = None, processName: str = None):
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

        self.ciTag_gradients = {}
        self.eTag_gradients = {}
        self.iTag_gradients = {(id,'i'): 1.0}
        self.cTag_gradients = {(id,'c'): 1.0}

        self.ci_lambda_gradients = {}
        self.e_lambda_gradients = {}
        self.i_lambda_gradients = {}
        self.c_lambda_gradients = {}

        self.propagation_chain = {'i':[], 'c':[]}

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['type'] = self.type
        json_dict['pid'] = self.pid
        json_dict['ppid'] = self.ppid
        json_dict['cmdLine'] = self.cmdLine
        json_dict['processName'] = self.processName
        json_dict['owner'] = self.owner
        return json.dumps(json_dict)

    def load(self, json_dict):
        # self.id = json_dict['id']
        self.type = json_dict['type']
        self.pid = json_dict['pid']
        if math.isnan(self.pid) == False:
            self.pid = int(self.pid)
        self.ppid = json_dict['ppid']
        if math.isnan(self.ppid) == False:
            self.ppid = int(self.ppid)
        self.cmdLine = json_dict['cmdLine']
        self.processName = json_dict['processName']
        self.owner = json_dict['owner']

    def get_id(self):
        return self.id
    
    def get_pid(self):
        return int(self.pid)

    def get_name(self):
        return self.processName

    def get_cmdln(self):
        return self.cmdLine

    def tags(self):
        return [float(self.ciTag), float(self.eTag), float(self.iTag), float(self.cTag)]

    def setSubjTags(self,tags):
        self.ciTag = tags[0]
        self.eTag = tags[1]
        self.iTag = tags[2]
        self.cTag = tags[3]

    def get_grad(self):
        return [self.ciTag_gradients, self.eTag_gradients, self.iTag_gradients, self.cTag_gradients]

    def set_grad(self, grads):
        self.ciTag_gradients = grads[0]
        self.eTag_gradients = grads[1]
        self.iTag_gradients = grads[2]
        self.cTag_gradients = grads[3]

    def get_lambda_grad(self):
        return [self.ci_lambda_gradients, self.e_lambda_gradients, self.i_lambda_gradients, self.c_lambda_gradients]

    def set_lambda_grad(self, lambda_grads):
        self.ci_lambda_gradients = lambda_grads[0]
        self.e_lambda_gradients = lambda_grads[1]
        self.i_lambda_gradients = lambda_grads[2]
        self.c_lambda_gradients = lambda_grads[3]
    
    def check_gradients(self, threshold = 1e-5):
        for key in list(self.ciTag_gradients.keys()):
            value = self.ciTag_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.ciTag_gradients[key]
        for key in list(self.eTag_gradients.keys()):
            value = self.eTag_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.eTag_gradients[key]
        for key in list(self.iTag_gradients.keys()):
            value = self.iTag_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.iTag_gradients[key]
        for key in list(self.cTag_gradients.keys()):
            value = self.cTag_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.cTag_gradients[key]

        for key in list(self.ci_lambda_gradients.keys()):
            value = self.ci_lambda_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.ci_lambda_gradients[key]
        for key in list(self.e_lambda_gradients.keys()):
            value = self.e_lambda_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.e_lambda_gradients[key]
        for key in list(self.i_lambda_gradients.keys()):
            value = self.i_lambda_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.i_lambda_gradients[key]
        for key in list(self.c_lambda_gradients.keys()):
            value = self.c_lambda_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.c_lambda_gradients[key]


    def isMatch(self, string):
        if self.processName == None:
            return False
        return isinstance(re.search(string, self.processName), re.Match)
    
    def grad_dict_lens(self):
        return (len(self.ciTag_gradients),len(self.eTag_gradients),len(self.iTag_gradients),len(self.cTag_gradients),len(self.ci_lambda_gradients),len(self.e_lambda_gradients),len(self.i_lambda_gradients),len(self.c_lambda_gradients))
