import json
from policy.floatTags import citag
import numpy as np
import re

class Event:
    def __init__(self, id, type, ts):
        self.id = id
        self.type = type
        self.time = ts
        self.parameters = None

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['time'] = self.time
        json_dict['type'] = self.type
        json_dict['params'] = self.parameters
        # json_dict['subtype'] = self.subtype
        # json_dict['ppid'] = self.ppid
        # json_dict['name'] = self.name
        # json_dict['path'] = self.path
        return str(json_dict)