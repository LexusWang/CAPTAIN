import numpy as np
from graph.Object import Object
from graph.Subject import Subject
from parse.cdm.FileObjectType import file_object_type as cdm_file_object_type
from parse.cdm.SRCSINKType import srcsink_type as cdm_srcsink_type

lttng_object_type = ['common_file', 'share_memory', 'unix_socket_file', 'inet_scoket_file', 'pipe_file']

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
        type_ = datum['type']
        pid_ = datum['cid']
        pname_ = datum['properties']['map']['name']
        ppid_ = datum['properties']['map']['ppid']
        seen_time_ = float(datum['startTimestampNanos'])
        if isinstance(datum['cmdLine'], dict):
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = None
        subject = Subject(id=datum['uuid'], type = type_, pid = pid_, ppid=int(ppid_), cmdLine = cmdLine_, processName=pname_)
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        pass
    else:
        # error!
        pass
    
    return subject

def parse_subject_lttng(datum):
    type_ = 'SUBJECT_PROCESS'
    pid_ = datum.params[0]
    ppid_ = datum.params[1]
    cmdLine_ = datum.params[2]
    pname_ = datum.params[3]
    seen_time_ = float(datum.time)
    subject = Subject(id=datum.Id, time = seen_time_, type = type_, pid = pid_, ppid=int(ppid_), cmdLine = cmdLine_, processName=pname_)
    # subject.owner = datum['localPrincipal']
    
    return subject

def parse_object_cdm(datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if object_type == 'FileObject':
        object.subtype = cdm_file_object_type[datum['type']]
        permission = datum['baseObject']['permission']
        object.name = datum['baseObject']['properties']['map']['path']
        object.path = datum['baseObject']['properties']['map']['path']
    elif object_type == 'UnnamedPipeObject':
        permission = datum['baseObject']['permission']
        object.name = 'UnknownObject'
        object.path = 'UnknownObject'
    elif object_type == 'RegistryKeyObject':
        pass
    elif object_type == 'PacketSocketObject':
        pass
    elif object_type == 'NetFlowObject':
        object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
    elif object_type == 'MemoryObject':
        object.name = 'MemoryObject'
        object.path = 'MemoryObject'
    elif object_type == 'SrcSinkObject':
        object.subtype = cdm_srcsink_type[datum['type']]
        permission = datum['baseObject']['permission']
        object.name = 'UnknownObject'
        object.path = 'UnknownObject'
    else:
        # error!
        pass

    return object

def parse_object_lttng(datum, object_type):
    object = Object(type = lttng_object_type[object_type])
    if object_type == 0:
        object.path = datum.params[0]
    elif object_type == 1:
        pass
    elif object_type == 2:
        object.path = datum.params[0]
    elif object_type == 3:
        object.path = datum.params[0]
        # ip Protocol is set to -1
        object.set_IP(datum.params[1], datum.params[2], -1)
    elif object_type == 4:
        object.pipe = [datum.params[0], datum.params[1]]
    else:
        # error!
        pass

    return object

def parse_subject(datum, format='cdm'):
    subject_node = {}
    if format == 'cdm':
        subject_node['uuid'] = datum['uuid']
        subject = parse_subject_cdm(datum)
    elif format == 'lttng':
        subject_node['uuid'] = datum.Id
        subject = parse_subject_lttng(datum)
    return subject_node, subject


def parse_object(datum, object_type, format='cdm'):
    object_node = {}
    if format == 'cdm':
        object_node['uuid'] = datum['uuid']
        object = parse_object_cdm(datum, object_type)
    elif format == 'lttng':
        object_node['uuid'] = datum.Id
        object = parse_object_lttng(datum, object_type)
    
    return object_node, object