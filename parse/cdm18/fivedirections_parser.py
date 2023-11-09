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

def parse_event_fivedirections(self, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    node_updates = {}

    if isinstance(datum['subject'], dict):
        event.src = list(datum['subject'].values())[0]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = list(datum['predicateObject'].values())[0]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = list(datum['predicateObject2'].values())[0]

    if isinstance(datum['predicateObjectPath'], dict):
        obj_path = datum['predicateObjectPath']['string']
        if event.dest in self.Nodes and self.Nodes[event.dest].path == None and self.Nodes[event.dest].path != obj_path:
            self.Nodes[event.dest].name = obj_path
            self.Nodes[event.dest].path = obj_path
            node_updates[event.dest] = {'name': obj_path}

    if isinstance(datum['predicateObject2Path'], dict):
        obj2_path = datum['predicateObject2Path']['string']
        if event.dest2 in self.Nodes and self.Nodes[event.dest2].path == None and self.Nodes[event.dest2].path != obj2_path:
            self.Nodes[event.dest2].name = obj2_path
            self.Nodes[event.dest2].path = obj2_path
            node_updates[event.dest2] = {'name': obj2_path}

    if datum['type'] in READ_SET:
        if self.Nodes.get(event.dest, None):
            event.type = 'read'
        else:
            # TO DO: How to deal with unknown object
            return None, node_updates
    elif datum['type'] in WRITE_SET:
        object = self.Nodes.get(event.dest, None)
        if object:
            if isinstance(object, Object):
                event.type = 'write'
                if object.isIP():
                    event.parameters = {'size':datum['size']}
            # elif isinstance(object, Subject):
            #     event.type = 'inject'
            else:
                return None, node_updates
        else:
            return None, node_updates
    elif datum['type'] in INJECT_SET:
        event.type = 'inject'
    elif datum['type'] in CHMOD_SET:
        # event.type = 'chmod'
        return None, node_updates
    elif datum['type'] in SET_UID_SET:
        # event.type = 'set_uid'
        return None, node_updates
    elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
        event.parameters = datum['predicateObjectPath']['string']
        event.type = 'execve'
    elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
        event.type = 'load'
    elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        if self.Nodes[event.dest].isFile():
            event.type = 'load'
        else:
            event.type = 'mmap'
            event.parameters = memory_protection(eval(event.properties['protection']))
    elif datum['type'] in CREATE_SET:
        assert event.src and event.dest
        # what is the meaning of the properties
        if self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None):
            event.type = 'create'
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
        event.parameters = datum['properties']['map']
        event.type = 'clone'
    elif datum['type'] in MPROTECT_SET:
        event.type = 'mprotect'
        event.parameters = eval(datum['properties']['map']['arg_mem_flags'])
    elif datum['type'] in UPDATE_SET:
        a = self.Nodes.get(event.src, None)
        b = self.Nodes.get(event.dest, None)
        c = self.Nodes.get(event.dest2, None)
        if b.subtype == 'SRCSINK_DATABASE':
            event.type = 'write'
        elif c:
            event.type = 'update'
        else:
            return None, node_updates
    elif datum['type'] in EXIT_SET:
        event.parameters = datum['properties']['map']
        event.type = 'exit'
    else:
        return None, node_updates
    
    return event, node_updates

def parse_subject_fivedirections(self, datum, cdm_version=18):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        parent_ = None
        ppid_ = None
        cmdLine_ = None
        pname_ = None
        if datum['parentSubject']:
            parent_ = list(datum['parentSubject'].values())[0]
            ppid_ = self.Nodes[parent_].pid
        if datum['cmdLine']:
            cmdLine_ = datum['cmdLine']['string']
            pname_ = datum['cmdLine']['string']
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

def parse_object_fivedirections(self, datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if isinstance(datum['baseObject']['epoch'], dict):
        object.epoch = datum['baseObject']['epoch']['int']
    if object_type == 'FileObject':
        object.subtype = datum['type']
        if datum['baseObject']['properties']:
            object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'NetFlowObject':
        if datum['remoteAddress'] == '' or datum['remotePort'] == '':
            return None
        else:
            object.set_IP(datum['remoteAddress'], datum['remotePort'],datum['ipProtocol']['int'])
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        object.subtype = 'RegistryKeyObject'
        object.name = datum['key']
        object.value = list(datum['value'].values())[0]
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type == 'SrcSinkObject':
        object.subtype = datum['type']
        if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
            return None
        elif object.subtype in {'SRCSINK_DATABASE','SRCSINK_PROCESS_MANAGEMENT'}:
            object.name = object.subtype
        else:
            print('New SrcSink Object Type!!!')
            print(datum)
    else:
        pass

    return object