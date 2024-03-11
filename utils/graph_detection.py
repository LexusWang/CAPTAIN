from graph.Subject import Subject
from graph.Object import Object

def add_nodes_to_graph(mo, nid, node_data):
    if mo.mode == 'train':
        training_mode = True
    else:
        training_mode = False

    if node_data['type'] == 'SUBJECT_PROCESS':
        subject = Subject(nid, node_data['type'], None, training_mode = training_mode)
        subject.load(node_data)
        mo.add_subject(subject)
    elif node_data['type'] != 'MemoryObject':
    # else:
        object = Object(nid, node_data['type'], training_mode = training_mode)
        object.load(node_data)
        mo.add_object(object)
        mo.set_object_tags(object.id)