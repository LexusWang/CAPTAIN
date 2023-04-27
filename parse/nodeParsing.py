import numpy as np
from graph.Object import Object
from graph.Subject import Subject
from parse.cdm.FileObjectType import file_object_type as cdm_file_object_type
from parse.cdm.SRCSINKType import srcsink_type as cdm_srcsink_type
import pdb

lttng_object_type = ['common_file', 'share_memory', 'unix_socket_file', 'inet_scoket_file', 'pipe_file']

def parse_subject_cadets(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        pname_ = datum['properties'].get('name', None)
        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            ppid_ = self.Nodes[parent_].pid

        if isinstance(datum['cmdLine'], dict):
            cmdLine_ = datum['cmdLine']
        else:
            cmdLine_ = None
        subject = Subject(id=datum['uuid'], type = datum['type'], pid = datum['cid'], ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
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
        pass
    
    return subject

def parse_subject_trace(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = datum['cid']
        pname_ = datum['properties']['map'].get('name',None)
        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            # ppid_ = self.Nodes[parent_].pid
        ppid_ = datum['properties']['map']['ppid']
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

def parse_object_cdm(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    # if datum['uuid'] == 'ADA7293B-7DD9-D1A4-CF58-9D9C2F1E96B2':
    #     pdb.set_trace()
    if isinstance(datum['baseObject']['epoch'], dict):
        object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        # object.subtype = cdm_file_object_type[datum['type']]
        object.subtype = datum['type']
        permission = datum['baseObject']['permission']
        # object.name = datum['baseObject']['properties']['map'].get('path',None)
        object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        return None
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'NetFlowObject':
        try:
            object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
        except TypeError:
            object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
        # object.path = object.name
    elif object_type == 'SrcSinkObject':
        object.subtype = datum['type']
        permission = datum['baseObject']['permission']
        if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
            return None
        else:
            print(datum)
    else:
        # error!
        pass

    return object


def parse_object_cadets(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if isinstance(datum['baseObject']['epoch'], dict):
        object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        object.subtype = datum['type']
        permission = datum['baseObject']['permission']
        object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'NetFlowObject':
        try:
            object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
        except TypeError:
            object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        return None
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type == 'SrcSinkObject':
        object.subtype = datum['type']
        if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
            return None
        else:
            print('New SrcSink Object Type!!!')
            print(datum)
    else:
        pass

    return object

def parse_subject(self, datum, format, cdm_version):
    if format in {'cadets'}:
        return parse_subject_cadets(self, datum, cdm_version)
    elif format in {'trace'}:
        return parse_subject_trace(self, datum, cdm_version)

def parse_object(self, datum, object_type, format, cdm_version):
    if format in {'trace'}:
        object = parse_object_cdm(self, datum, object_type)
    elif format in {'cadets'}:
        object = parse_object_cadets(self, datum, object_type)
    return object