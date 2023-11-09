import json
from policy.floatTags import citag
import numpy as np
import re

class Event:
    def __init__(self, id, ts):
        self.id = id
        self.time = ts
        self.type = None
        self.parameters = None
        self.src = None
        self.dest = None
        self.dest2 = None
        self.obj_path = None

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['time'] = self.time
        json_dict['type'] = self.type
        json_dict['params'] = self.parameters
        json_dict['s'] = self.src
        json_dict['d'] = self.dest
        json_dict['d2'] = self.dest2
        return json.dumps(json_dict)
    
    def __str__(self):
        return self.dumps()

    def loads(self, data_str):
        json_dict = json.loads(data_str)
        self.type = json_dict['type']
        if self.type == "UPDATE":
            self.value = json_dict['value']
            self.nid = json_dict['nid']
        else:
            self.id = json_dict['id']
            self.time = json_dict['time']
            self.parameters = json_dict['params']
            self.src = json_dict['s']
            self.dest = json_dict['d']
            self.dest2 = json_dict['d2']