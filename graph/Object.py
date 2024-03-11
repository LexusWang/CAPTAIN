import json
import pdb
import math
import re

class Object:
    def __init__(self, id, type, epoch: int = None, subtype: str = None, objName: str = None, training_mode = True):
        self.id = id
        self.type = type
        self.epoch = epoch
        self.subtype = subtype
        self.name = objName
        self.path = None
        self.updateTime = 0

        self.iTag: float = 0.0
        self.cTag: float = 0.0

        if training_mode:
            self.iTag_gradients = {(id,'i'): 1.0}
            self.cTag_gradients = {(id,'c'): 1.0}
            
            self.i_lambda_gradients = {}
            self.c_lambda_gradients = {}

            self.propagation_chain = {'i':[], 'c':[]}

    def __str__(self):
        return self.dumps()

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['epoch'] = self.epoch
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
        self.type = json_dict['type']
        self.epoch = json_dict['epoch']
        if math.isnan(self.epoch) == False:
            self.epoch = int(self.epoch)
        self.subtype = json_dict['subtype']
        if self.type == 'NetFlowObject':
            self.IP = json_dict['ip']
            self.port = json_dict['port']
            if math.isnan(self.port) == False:
                self.port = int(self.port)
        elif self.type == 'FileObject':
            self.path = json_dict['path']
        else:
            self.name = json_dict['name']

    def tags(self):
        # if self.iTag > 0.5:
        #     ciTag = 1.0
        # else:
        #     ciTag = 0.0
        # return [ciTag, None, float(self.iTag), float(self.cTag)]
        return [float(self.iTag), None, float(self.iTag), float(self.cTag)]

    def setObjTags(self, tags):
        self.iTag = tags[0]
        self.cTag = tags[1]

    def setObjiTag(self, itag):
        self.iTag = itag

    def setObjcTag(self, ctag):
        self.cTag = ctag

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
        if self.isFile():
            return self.path
        elif self.isIP():
            # return "{}:{}".format(self.IP, self.port)
            return "{}".format(self.IP)
        elif self.name.startswith('MEM_'):
            return "MEM_*"
        else:
            return self.name

    def get_id(self):
        return self.id

    def get_grad(self):
        return [self.iTag_gradients, None, self.iTag_gradients, self.cTag_gradients]

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

    def get_lambda_grad(self):
        return [self.i_lambda_gradients, None, self.i_lambda_gradients, self.c_lambda_gradients]

    def check_gradients(self, threshold = 1e-5):
        for key in list(self.iTag_gradients.keys()):
            value = self.iTag_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.iTag_gradients[key]
        for key in list(self.cTag_gradients.keys()):
            value = self.cTag_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.cTag_gradients[key]

        for key in list(self.i_lambda_gradients.keys()):
            value = self.i_lambda_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.i_lambda_gradients[key]
        for key in list(self.c_lambda_gradients.keys()):
            value = self.c_lambda_gradients[key]
            if value > -1.0*threshold and value < 1.0*threshold:
                del self.c_lambda_gradients[key]

    def grad_dict_lens(self):
        return (0, 0,len(self.iTag_gradients),len(self.cTag_gradients),0, 0,len(self.i_lambda_gradients),len(self.c_lambda_gradients))