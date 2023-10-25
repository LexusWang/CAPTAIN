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

def parse_event_cadets(self, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    node_updates = {}

    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    try:
        if isinstance(datum['predicateObjectPath'], dict):
            event.obj_path = datum['predicateObjectPath']['string']
            if self.Nodes[event.dest].path != event.obj_path:
                self.Nodes[event.dest].name = event.obj_path
                self.Nodes[event.dest].path = event.obj_path
                node_updates[event.dest] = {'name':event.obj_path}
    except KeyError:
        pass

    try:
        if isinstance(datum['predicateObject2Path'], dict):
            event.obj2_path = datum['predicateObject2Path']['string']
            if self.Nodes[event.dest2].path != event.obj2_path:
                self.Nodes[event.dest2].name = event.obj2_path
                self.Nodes[event.dest2].path = event.obj2_path
                node_updates[event.dest2] = {'name':event.obj2_path}
    except KeyError:
        pass

    try:
        if 'exec' in event.properties:
            if self.Nodes[event.src].processName != event.properties['exec']:
                self.Nodes[event.src].processName = event.properties['exec']
                node_updates[event.src] = {'exec':event.properties['exec']}
    except KeyError:
        pass

    if datum['type'] in READ_SET:
        if self.Nodes.get(event.dest, None):
            event.type = 'read'
        else:
            # TO DO: How to deal with unknown object
            return None, node_updates
    elif datum['type'] in WRITE_SET:
        if self.Nodes.get(event.dest, None):
            event.type = 'write'
        else:
            return None, node_updates
    elif datum['type'] in INJECT_SET:
        event.type = 'inject'
    elif datum['type'] in CHMOD_SET:
        if datum['name']['string'] == 'aue_chmod':
            event.type = 'chmod'
            event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
            # print('8-based: {}'.format(oct(event.parameters)))
        else:
            return None, node_updates  
    elif datum['type'] in SET_UID_SET:
        if datum['name']['string'] in {'aue_setuid'}:
            event.type = 'set_uid'
            event.parameters = int(datum['properties']['map']['arg_uid'])
            # print('arg_uid: {}'.format(datum['properties']['map']['arg_uid']))
            # print('byte: {}'.format(datum['parameters']['array'][0]['valueBytes']['bytes']))
        else:
            return None, node_updates
    elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
        event.parameters = datum['properties']['map']['cmdLine']
        event.type = 'execve'
    elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
        # pdb.set_trace()
        return None, node_updates
    elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        if self.Nodes[event.dest].isFile():
            event.type = 'load'
        else:
            event.type = 'mmap'
            event.parameters = memory_protection(eval(event.properties['protection']))
    elif datum['type'] in CREATE_SET:
        assert event.src and event.dest
        if datum['name']['string'] not in  {'aue_socketpair', 'aue_mkdirat'}:
            if self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None):
                event.type = 'create'
            else:
                return None, node_updates
        else:
            return None, node_updates
    elif datum['type'] in RENAME_SET:
        a = self.Nodes.get(event.src, None)
        b = self.Nodes.get(event.dest, None)
        c = self.Nodes.get(event.dest2, None)
        event.type = 'rename'
    elif datum['type'] in REMOVE_SET:
        event.type = 'remove'
    elif datum['type'] in CLONE_SET:
        a = self.Nodes[event.src]
        b = self.Nodes[event.dest]
        event.type = 'clone'
    elif datum['type'] in MPROTECT_SET:
        # a = self.Nodes[event.dest]
        assert event.dest == None
        b = self.Nodes[event.src]
        event.type = 'mprotect'
        event.parameters = eval(datum['properties']['map']['arg_mem_flags'])
    elif datum['type'] in UPDATE_SET:
        event.type = 'update'
    elif datum['type'] in EXIT_SET:
        event.type = 'exit'
    else:
        return None, node_updates
    
    return event, node_updates

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