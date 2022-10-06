import numpy as np
from graph.Object import Object
from graph.Subject import Subject
from parse.cdm.FileObjectType import file_object_type as cdm_file_object_type
from parse.cdm.SRCSINKType import srcsink_type as cdm_srcsink_type

lttng_object_type = ['common_file', 'share_memory', 'unix_socket_file', 'inet_scoket_file', 'pipe_file']

def parse_subject_cdm(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = datum['cid']
        pname_ = datum['properties']['map'].get('name', None)

        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            ppid_ = self.Nodes[parent_].pid

        # seen_time_ = float(datum['properties']['map'].get('seen time',0))
        if isinstance(datum['cmdLine'], dict):
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = None
        subject = Subject(id=datum['uuid'], type = type_, pid = pid_, ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        if isinstance(datum['localPrincipal'], dict):
            subject.owner = datum['localPrincipal']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        else:
            subject.owner = datum['localPrincipal']
    elif subject_type == 'SUBJECT_THREAD':
        pass
    elif subject_type == 'SUBJECT_UNIT':
        pass
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        pass
    else:
        # error!
        pass
    
    return subject

def parse_subject_trace(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = datum['cid']
        pname_ = datum['properties']['map'].get('name','Null')
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            a = 0
        else:
            parent_ = datum['parentSubject']
        # ppid_ = datum['properties']['map']['ppid']
        # seen_time_ = float(datum['properties']['map'].get('seen time',0))
        if isinstance(datum['cmdLine'], dict):
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = None
        subject = Subject(id=datum['uuid'], type = type_, pid = pid_, ppid=parent_, cmdLine = cmdLine_, processName=pname_)
        if isinstance(datum['localPrincipal'], dict):
            subject.owner = datum['localPrincipal']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        else:
            subject.owner = datum['localPrincipal']
    elif subject_type == 'SUBJECT_THREAD':
        pass
    elif subject_type == 'SUBJECT_UNIT':
        pass
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        pass
    else:
        # error!
        pass
    
    return subject

def parse_subject_lttng(self, datum):
    type_ = 'SUBJECT_PROCESS'
    pid_ = datum.params[0]
    ppid_ = datum.params[1]
    cmdLine_ = datum.params[2]
    pname_ = datum.params[3]
    seen_time_ = float(datum.time)
    subject = Subject(id=datum.Id, time = seen_time_, type = type_, pid = pid_, ppid=int(ppid_), cmdLine = cmdLine_, processName=pname_)
    # subject.owner = datum['localPrincipal']
    
    return subject

def parse_object_cdm(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if object_type == 'FileObject':
        object.subtype = cdm_file_object_type[datum['type']]
        permission = datum['baseObject']['permission']
        object.name = datum['baseObject']['properties']['map'].get('path','Null')
        object.path = datum['baseObject']['properties']['map'].get('path','Null')
    elif object_type == 'UnnamedPipeObject':
        permission = datum['baseObject']['permission']
        object.name = 'Pipe_{}'.format(object.id)
        # object.name = 'Pipe[{}-{}]'.format(datum['sourceFileDescriptor']['int'], datum['sinkFileDescriptor']['int'])
        object.path = object.name
    elif object_type == 'RegistryKeyObject':
        pass
    elif object_type == 'PacketSocketObject':
        pass
    elif object_type == 'NetFlowObject':
        try:
            object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
        except TypeError:
            object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
        object.path = object.name
    elif object_type == 'SrcSinkObject':
        object.subtype = cdm_srcsink_type[datum['type']]
        permission = datum['baseObject']['permission']
        if object.subtype == cdm_srcsink_type['SRCSINK_UNKNOWN']:
            object.name = 'UnknownObject_{}_{}'.format(datum['fileDescriptor']['int'],datum['baseObject']['properties']['map']['pid'])
            object.path = object.name
    else:
        # error!
        pass

    return object

def parse_object_lttng(self, datum, object_type):
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

def parse_subject(self, datum, format='cdm'):
    # subject_node = {}
    if format == 'cdm':
        # subject_node['uuid'] = datum['uuid']
        subject = parse_subject_cdm(self, datum)
    elif format == 'lttng':
        # subject_node['uuid'] = datum.Id
        subject = parse_subject_lttng(self, datum)
    return subject


def parse_object(self, datum, object_type, format='cdm'):
    if format == 'cdm':
        object = parse_object_cdm(self, datum, object_type)
    elif format == 'lttng':
        object = parse_object_lttng(self, datum, object_type)
    
    return object