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

null = None
false = False
true = True

with open('/Users/lexus/Documents/research/APT/ATPG/E3Analysis-cadets.txt', 'r') as fin:
    for line in fin:
        if line.startswith('{"datum"'):
            record = eval(line)
            print(record["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["uuid"])
    
