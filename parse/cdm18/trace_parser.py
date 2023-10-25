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

    if datum['type'] in UNUSED_SET:
        return None
    
    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]


    # try:
    #     if isinstance(datum['predicateObjectPath'], dict):
    #         event.obj_path = datum['predicateObjectPath']['string']
    #         if self.Nodes[event.dest].path == 'Null':
    #             self.Nodes[event.dest].name = event.obj_path
    #             self.Nodes[event.dest].path = event.obj_path
    #             tag = list(match_path(event.obj_path))
    #             self.node_inital_tags[event.dest] = tag
    #             self.Nodes[event.dest].setObjTags(tag)
    # except KeyError:
    #     pass

    # try:
    #     if 'exec' in event.properties:
    #         if self.Nodes[event.src].processName != event.properties['exec']:
    #             self.Nodes[event.src].processName = event.properties['exec']
    # except KeyError:
    #     pass

    if datum['type'] in READ_SET:
        if self.Nodes.get(event.dest, None):
            event.type = 'read'
        else:
            # TO DO: How to deal with unknown object
            return None
    elif datum['type'] in WRITE_SET:
        if self.Nodes.get(event.dest, None):
            event.type = 'write'
        else:
            # TO DO: How to deal with unknown object
            return None
    elif datum['type'] in INJECT_SET:
        event.type = 'inject'
    elif datum['type'] in CHMOD_SET:
        event.type = 'chmod'
        event.parameters = int(event.properties['mode'], 8)
    elif datum['type'] in SET_UID_SET:
        if datum['properties']['map']['operation'] == 'setuid':
            event.type = 'set_uid'
            event.src = event.dest
            event.dest = None
            event.parameters = int(self.Principals[self.Nodes.get(event.src, None).owner]['userId'])
        else:
            return None
    elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
        event.type = 'update_process'
    elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
        event.type = 'execve'
    elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        if self.Nodes.get(event.dest, None):
            if self.Nodes[event.dest].isFile():
                event.type = 'load'
            else:
                event.type = 'mmap'
                event.parameters = memory_protection(eval(event.properties['protection']))
        else:
            return None
    elif datum['type'] in CREATE_SET:
        assert event.src and event.dest
        if self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None):
            event.type = 'create'
        else:
            return None
    elif datum['type'] in RENAME_SET:
        event.type = 'rename'
    elif datum['type'] in REMOVE_SET:
        event.type = 'remove'
    elif datum['type'] in CLONE_SET:
        event.type = 'clone'
    elif datum['type'] in MPROTECT_SET:
        event.type = 'mprotect'
        event.parameters = memory_protection(eval(event.properties['protection']))
    elif datum['type'] in UPDATE_SET:
        event.type = 'update'
    elif datum['type'] in EXIT_SET:
        event.type = 'exit'
    else:
        return None
    
    return event

def parse_subject_trace(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
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

def parse_object_trace(self, datum, object_type):
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
