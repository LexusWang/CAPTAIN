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
        self.obj_path = None

    def dumps(self) -> str:
        json_dict = {}
        json_dict['id'] = self.id
        json_dict['time'] = self.time
        json_dict['type'] = self.type
        json_dict['params'] = self.parameters
        json_dict['s'] = self.src
        json_dict['d'] = self.dest
        # json_dict['name'] = self.name
        # json_dict['path'] = self.path
        return str(json_dict)