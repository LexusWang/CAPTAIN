from aifc import Error
import pdb
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from policy.initTags import match_path, match_network_addr
from parse.cdm18.eventType import EXECVE_SET, SET_UID_SET, lttng_events, cdm_events, standard_events
from parse.cdm18.eventType import READ_SET, WRITE_SET, INJECT_SET, CHMOD_SET, SET_UID_SET, EXECVE_SET, LOAD_SET, CREATE_SET, RENAME_SET, REMOVE_SET, CLONE_SET, MPROTECT_SET, MMAP_SET, UPDATE_SET, EXIT_SET, UNUSED_SET

def memory_protection(permission: int):
    if permission < 0 or permission > 7:
        raise ValueError("Unvalid permission!!!")
    else:
        if permission == 0:
            return ['PROT_NONE']
        elif permission == 1:
            return ['PROT_EXEC']
        elif permission == 2:
            return ['PROT_WRITE']
        elif permission == 3:
            return ['PROT_WRITE', 'PROT_EXEC']
        elif permission == 4:
            return ['PROT_READ']
        elif permission == 5:
            return ['PROT_READ', 'PROT_EXEC']
        elif permission == 6:
            return ['PROT_READ', 'PROT_WRITE']
        elif permission == 7:
            return ['PROT_READ', 'PROT_WRITE', 'PROT_EXEC']

def parse_event_trace(self, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]

    try:
        if datum['type'] in READ_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in WRITE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'write'
        elif datum['type'] in INJECT_SET:
            event.type = 'inject'
        elif datum['type'] in CHMOD_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'chmod'
            event.parameters = int(event.properties['mode'], 8)
        elif datum['type'] in SET_UID_SET:
            assert self.Nodes.get(event.src, None)
            if datum['properties']['map']['operation'] == 'setuid':
                event.type = 'set_uid'
                event.src = event.dest
                event.dest = None
                event.parameters = int(self.Principals[self.Nodes.get(event.src, None).owner]['userId'])
            else:
                return None
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'update_process'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            assert self.Nodes.get(event.src, None)
            if self.Nodes.get(event.dest, None) and self.Nodes[event.dest].isFile():
                event.type = 'load'
            else:
                event.type = 'mmap'
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'create'
        elif datum['type'] in RENAME_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None) and self.Nodes.get(event.dest2, None)
            event.type = 'rename'
        elif datum['type'] in REMOVE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            assert self.Nodes.get(event.src, None)
            event.type = 'mprotect'
            event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in UPDATE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None) and self.Nodes.get(event.dest2, None)
            event.type = 'update'
        elif datum['type'] in EXIT_SET:
            assert self.Nodes.get(event.src, None)
            event.dest = None
            event.type = 'exit'
        else:
            return None
    except AssertionError as ae:
        return None 
    
    return event

def parse_subject_trace(self, datum, cdm_version=18):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = int(datum['cid'])
        pname_ = datum['properties']['map'].get('name',None)
        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            # ppid_ = self.Nodes[parent_].pid
        ppid_ = int(datum['properties']['map']['ppid'])
        if isinstance(datum['cmdLine'],dict):
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = datum['cmdLine']
        subject = Subject(id=datum['uuid'], type = type_, pid = pid_, ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        if isinstance(datum['localPrincipal'],dict):
            subject.owner = datum['localPrincipal']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        else:
            subject.owner = datum['localPrincipal']
        return subject
    elif subject_type == 'SUBJECT_THREAD':
        return None
    elif subject_type == 'SUBJECT_UNIT':
        return None
    elif subject_type == 'SUBJECT_BASIC_BLOCK':
        return None
    else:
        return None

def parse_object_trace(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if isinstance(datum['baseObject']['epoch'], dict):
        object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        # object.subtype = cdm_file_object_type[datum['type']]
        object.subtype = datum['type']
        object.name = datum['baseObject']['properties']['map'].get('path',None)
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
        # object.name = 'MEM_{}'.format(datum['memoryAddress'])
        return None
    elif object_type == 'SrcSinkObject':
        return None
        # object.subtype = datum['type']
        # permission = datum['baseObject']['permission']
        # if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
        #     return None
        # else:
        #     print(datum)
    else:
        return None

    return object
