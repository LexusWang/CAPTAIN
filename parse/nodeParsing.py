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
        pass
    
    return subject

def parse_subject_trace(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = datum['cid']
        pname_ = datum['properties']['map'].get('name',None)
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

def parse_object_cdm(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if isinstance(datum['baseObject']['epoch'], dict):
        object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        # object.subtype = cdm_file_object_type[datum['type']]
        object.subtype = datum['type']
        permission = datum['baseObject']['permission']
        # object.name = datum['baseObject']['properties']['map'].get('path',None)
        object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'UnnamedPipeObject':
        permission = datum['baseObject']['permission']
        object.name = 'Pipe_{}'.format(object.id)
        # object.name = 'Pipe[{}-{}]'.format(datum['sourceFileDescriptor']['int'], datum['sinkFileDescriptor']['int'])
        # object.path = object.name
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
        # object.path = object.name
    elif object_type == 'SrcSinkObject':
        object.subtype = datum['type']
        # object.subtype = cdm_srcsink_type[datum['type']]
        permission = datum['baseObject']['permission']
        # if object.subtype == cdm_srcsink_type['SRCSINK_UNKNOWN']:
        if object.subtype == 'SRCSINK_UNKNOWN':
            pid_ = int(datum['baseObject']['properties']['map']['pid'])
            try:
                pname_ = self.Nodes[self.processes[pid_]['node']].processName
            except KeyError:
                pname_ = 'unknown'
            object.name = 'UnknownObject_{}_{}_{}'.format(datum['fileDescriptor']['int'], pid_, pname_)
            # object.path = object.name
        elif object.subtype == 'SRCSINK_IPC':
            return None
        else:
            print(datum)
    else:
        # error!
        pass

    return object

def parse_subject(self, datum, format, cdm_version):
    if format in {'trace', 'cadets'}:
        subject = parse_subject_cdm(self, datum, cdm_version)
        return subject


def parse_object(self, datum, object_type, format, cdm_version):
    if format in {'trace', 'cadets'}:
        object = parse_object_cdm(self, datum, object_type)
        return object