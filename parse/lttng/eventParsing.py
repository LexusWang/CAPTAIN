import numpy as np
from graph.Object import Object
from graph.Subject import Subject

def parse_subject_cdm(datum):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = datum['cid']
        pname_ = datum['properties']['map']['name']
        ppid_ = datum['properties']['map']['ppid']
        seen_time_ = float(datum['properties']['map'].get('seen time',0))
        if isinstance(datum['cmdLine'], dict):
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = None
        subject = Subject(id=datum['uuid'], time = seen_time_, type = type_, pid = pid_, ppid=int(ppid_), cmdLine = cmdLine_, processName=pname_)
        subject.owner = datum['localPrincipal']
    elif subject_type == 'SUBJECT_THREAD':
        pass
    elif subject_type == 'SUBJECT_UNIT':
        subject = Subject(id=datum['uuid'])
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        pass
    else:
        # error!
        pass
    
    return subject

def parse_object_cdm(datum, object_type):
    object = Object(type = object_type)
    if object_type == 'FileObject':
        subtype_ = datum['type']
        object.subtype = subtype_
        object.path = datum['baseObject']['properties']['map']['path']
    elif object_type == 'UnnamedPipeObject':
        pass
    elif object_type == 'RegistryKeyObject':
        pass
    elif object_type == 'PacketSocketObject':
        pass
    elif object_type == 'NetFlowObject':
        object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
    elif object_type == 'MemoryObject':
        pass
    elif object_type == 'SrcSinkObject':
        pass
    else:
        # error!
        pass

    return object

def parse_subject(datum):
    subject_node = {}
    subject_node['uuid'] = datum['uuid']
    subject = parse_subject_cdm(datum)
    return subject_node, subject


def parse_object(datum, object_type):
    object_node = {}
    object_node['uuid'] = datum['uuid']
    object = parse_object_cdm(datum, object_type)
    return object_node, object