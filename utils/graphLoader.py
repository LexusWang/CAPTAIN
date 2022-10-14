import json
import os
from utils.utils import *
from model.morse import Morse

def read_graph_from_files(data_path, line_range, format = 'cadets', cdm_version = 18):
    # close interval
    if line_range:
        l_range = line_range[0]
        r_range = line_range[1]
    else:
        l_range = 0
        r_range = 5000000*len(volume_list)
    mo = Morse()
    line_range = []
    events = []
    loaded_line = 0
    last_event_str = ''
    volume_list = os.listdir(data_path)
    # volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[1])+0.1*int(x.split('.')[3]))
    volume_list = sorted(volume_list, key=lambda x:int(x.split('.')[2]))
    for volume_name in volume_list:
        print("Loading the {} ...".format(volume_name))
        with open(os.path.join(data_path, volume_name), 'r') as fin:
            for line in fin:
                if loaded_line > r_range:
                    break
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("Morse has loaded {} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())
                record_datum = record_datum[record_type[0]]
                record_type = record_type[0].split('.')[-1]
                if record_type == 'Event':
                    if loaded_line < l_range:
                        continue
                    event = mo.parse_event(record_datum, format, cdm_version)
                    if event:
                        event_str = '{},{},{}'.format(event.src, event.type, event.dest)
                        if event_str != last_event_str:
                            last_event_str = event_str
                            events.append((record_datum['uuid'],event))                        
                elif record_type == 'Subject':
                    subject = mo.parse_subject(record_datum, format, cdm_version)
                    if subject != None:
                        mo.add_subject(subject)
                elif record_type == 'Principal':
                    mo.Principals[record_datum['uuid']] = record_datum
                elif record_type.endswith('Object'):
                    object = mo.parse_object(record_datum, record_type, format, cdm_version)
                    if object != None:
                        mo.add_object(object)
                elif record_type == 'TimeMarker':
                    pass
                elif record_type == 'StartMarker':
                    pass
                elif record_type == 'UnitDependency':
                    pass
                elif record_type == 'Host':
                    pass
                else:
                    pass

    return events, mo