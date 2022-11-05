import json
import os
from utils.utils import *
from model.morse import Morse
from graph.Event import Event

def read_events_from_files(edge_file, line_range):
    # close interval
    if line_range:
        l_range = line_range[0]
        r_range = line_range[1]
    else:
        l_range = 0
        r_range = 1e20

    events = []
    loaded_line = 0
    with open(edge_file, 'r') as fin:
        for line in fin:
            if loaded_line > r_range:
                break
            loaded_line += 1
            if loaded_line % 100000 == 0:
                print("Morse has loaded {} events.".format(loaded_line))
            event = Event(None, None)
            event.loads(line)
            events.append(event)

            if loaded_line < l_range:
                continue

    return events