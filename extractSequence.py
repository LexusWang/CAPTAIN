import os
from datetime import *
import json
import argparse
import time
from utils.utils import *
from model.loss import get_loss
from model.morse import Morse
from parse.eventParsing import parse_event
from parse.nodeParsing import parse_subject, parse_object
from parse.lttng.recordParsing import read_lttng_record
from policy.initTags import initSubjectTags, initObjectTags
import tqdm
import time
from model.morse import Morse
import numpy as np
from pathlib import Path
import pickle


def start_detection(config):
    args = config
    target = '40F52486-45FF-19E4-167C-36E2578B23EF'
    fout = open('/Users/lexus/Documents/research/APT/Data/'+target+'.txt','a')
    mo = Morse()
    
    loaded_line = 0
    for i in range(7):
        with open(args['detection_data']+'.'+str(i),'r') as fin:
            for line in fin:
                loaded_line += 1
                if loaded_line % 100000 == 0:
                    print("Morse has loaded {} lines.".format(loaded_line))
                record_datum = json.loads(line)['datum']
                record_type = list(record_datum.keys())
                assert len(record_type)==1
                record_datum = record_datum[record_type[0]]
                record_type = record_type[0].split('.')[-1]
                if record_type == 'Event':
                    event = parse_event(record_datum)
                    if event['src'] == target or event['dest'] == target:
                        print(line[:-1], file = fout)
                elif record_type == 'Subject':
                    if record_datum['type'] in {'SUBJECT_PROCESS'}:
                        subject_node, subject = parse_subject(record_datum)
                        if subject.id == target:
                            print(line[:-1], file = fout)
                elif record_type == 'Principal':
                    pass
                elif record_type.endswith('Object'):
                    object_node, object = parse_object(record_datum, record_type)
                    if object.id == target:
                        print(line[:-1], file = fout)
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


def parse_lttng_logs(file):
    null = 0
    mo = Morse(format='lttng')
    log_types = set()
    event_types = set()
    with open(file,'r') as fin:
        for line in tqdm.tqdm(fin):
            if line[:4] == "data":
                record = read_lttng_record(fin)
            if record.type == 1:
                #edge data
                event = parse_event(record,format='lttng')
                event_types.add(event['type'])
                mo.add_event(event)
            elif record.type == -1:
                #node data
                if record.subtype == 5:
                    # process node
                    if len(record.params)>0:
                        subject_node, subject = parse_subject(record, format='lttng')
                        # print(subject.cmdLine)
                        mo.add_subject(subject)
                elif 0 < record.subtype < 5:
                    # non-common file node
                    object_node, object = parse_object(record, record.subtype, format='lttng')
                    mo.add_object(object)
                elif record.subtype == -1:
                    # common file node
                    object_node, object = parse_object(record, 0, format='lttng')
                    mo.add_object(object)
            else:
                pass

    return log_types


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run MORSE")
    parser.add_argument("--detection_data", nargs='?', default="/Users/lexus/Documents/research/APT/Data/E3/ta1-trace-e3-official-1.json/ta1-trace-e3-official-1.json", type=str)

    args = parser.parse_args()

    config = {
        "detection_data": args.detection_data,
    }

    start_detection(config)
    
    
