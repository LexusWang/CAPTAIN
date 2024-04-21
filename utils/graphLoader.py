import json
import pdb
from utils.utils import *
from graph.Event import Event

def read_events_from_files(edge_file, time_range):
    # close interval
    if time_range:
        detection_start_time = time_range[0]
        detection_end_time = time_range[1]
    else:
        detection_start_time = 0
        detection_end_time = 1e21

    events = []
    loaded_line = 0
    with open(edge_file, 'r') as fin:
        for line in fin:
            edge_datum = json.loads(line)
            if edge_datum['type'] != 'UPDATE':
                if edge_datum['time'] < detection_start_time:
                    continue
                if edge_datum['time'] > detection_end_time:
                    break
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("CAPTAIN has loaded {:,} edges.".format(loaded_line))
            event = Event(None, None)
            event.loads(line)
            events.append(event)

    return events