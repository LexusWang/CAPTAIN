import os
import torch
import pdb
from pathlib import Path
from policy.initTags import match_path, match_network_addr
from graph.Subject import Subject
from graph.Object import Object

def add_nodes_to_graph(mo, nid, node_data, generate_tags):
    if node_data['type'] == 'SUBJECT_PROCESS':
        subject = Subject(nid, node_data['type'], None)
        subject.load(node_data)
        mo.add_subject(subject)
    else:
        object = Object(nid, node_data['type'])
        object.load(node_data)
        mo.add_object(object)
        mo.set_object_tags(object.id)