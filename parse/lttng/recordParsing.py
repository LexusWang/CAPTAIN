import numpy as np

class Record:

    def __init__(self):
        self.Id: int = -1
        self.time: int = -1
        self.type: int = -1
        self.subtype: int = -1
        self.size: int = -1
        self.desId: int = -1
        self.srcId: int = -1
        self.params: list = []


def read_lttng_record(f):
    event = Record()
    params = []
    while True:
        line = f.readline()
        # print(line)
        if not line:
            break
        # print(line)
        if line[0] == "}":
            break
        line = pruningStr(line)
        if line == "paras {":
            while True:
                data = f.readline()
                data = pruningStr(data)
                if data == "}":
                    break
                words = data.split(": ")
                # print(words)
                params.append(pruningStr(words[1]))
        else:
            words = line.split(": ")
            # print(words)
            if words[0] == "ID":
                event.Id = int(pruningStr(words[1]))
            elif words[0] == "type":
                event.type = int(pruningStr(words[1]))
            elif words[0] == "time":
                event.time = int(pruningStr(words[1]))
            elif words[0] == "subtype":
                event.subtype = int(words[1])
            elif words[0] == "size":
                event.size = int(words[1])
            elif words[0] == "srcId":
                event.srcId = int(words[1])
            elif words[0] == "desId":
                event.desId = int(words[1])

    if params:
        event.params = params
    return event


def pruningStr(line):
    if not line:
        return line
    start = 0
    while start < len(line):
        if line[start] == ' ' or line[start] == '\t':
            start += 1
        else:
            break
    if line[start] == "\"":
        start += 1
    if line[-1] == "\"":
        line = line[:-1]
    if line[-1] == '\n':
        return line[start:-1]
    return line[start:]