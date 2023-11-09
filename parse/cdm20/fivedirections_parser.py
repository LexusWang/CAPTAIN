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

    if datum['subject']:
        event.src = datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    
    if datum['predicateObject']:
        event.dest = datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    if datum['predicateObject2']:
        event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    if isinstance(datum['predicateObjectPath'], dict):
        obj_path = datum['predicateObjectPath']['string']
        if self.Nodes.get(event.dest, None):
            if isinstance(self.Nodes[event.dest], Subject):
                if self.Nodes[event.dest].processName == None:
                    self.Nodes[event.dest].processName = obj_path
                    # node_updates[event.dest] = {'name': obj_path}
            elif self.Nodes[event.dest].isFile():
                if self.Nodes[event.dest].path == None:
                    self.Nodes[event.dest].name = obj_path
                    self.Nodes[event.dest].path = obj_path
                    node_updates[event.dest] = {'name': obj_path}

    if isinstance(datum['predicateObject2Path'], dict):
        obj2_path = datum['predicateObject2Path']['string']
        if self.Nodes.get(event.dest2, None):
            if isinstance(self.Nodes[event.dest2], Subject):
                if self.Nodes[event.dest2].processName == None:
                    self.Nodes[event.dest2].processName = obj_path
                    # node_updates[event.dest] = {'name': obj_path}
            elif self.Nodes[event.dest2].isFile():
                if self.Nodes[event.dest2].name == None:
                    self.Nodes[event.dest2].name = obj2_path
                    self.Nodes[event.dest2].path = obj2_path
                    node_updates[event.dest2] = {'name': obj2_path}

    try:
        if datum['type'] in READ_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in WRITE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            object = self.Nodes.get(event.dest, None)
            if isinstance(object, Object):
                event.type = 'write'
                if object.isIP():
                    event.parameters = {'size':datum['size']}
            # elif isinstance(object, Subject):
            #     event.type = 'inject'
        elif datum['type'] in INJECT_SET:
            # pdb.set_trace()
            event.type = 'inject'
        elif datum['type'] in CHMOD_SET:
            # event.type = 'chmod'
            return None, node_updates
        elif datum['type'] in SET_UID_SET:
            # event.type = 'set_uid'
            return None, node_updates
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.parameters = datum['predicateObjectPath']['string']
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'load'
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            if self.Nodes[event.dest].isFile():
                # pdb.set_trace()
                event.type = 'load'
            else:
                # pdb.set_trace()
                event.type = 'mmap'
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            # pdb.set_trace()
            event.type = 'create'
        elif datum['type'] in RENAME_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None) and self.Nodes.get(event.dest2, None)
            event.type = 'rename'
        elif datum['type'] in REMOVE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            event.parameters = datum['properties']['map']
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            # pdb.set_trace()
            event.type = 'mprotect'
            event.parameters = eval(datum['properties']['map']['arg_mem_flags'])
        elif datum['type'] in UPDATE_SET:
            assert self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None)
            # pdb.set_trace()
            if self.Nodes.get(event.dest2, None):
                event.type = 'update'
            else:
                return None, node_updates
        elif datum['type'] in EXIT_SET:
            event.parameters = datum['properties']['map']
            event.type = 'exit'
        else:
            return None, node_updates
    except AssertionError as ae:
        return None, node_updates   
    
    return event, node_updates

def parse_subject_fivedirections(self, datum, cdm_version):
    subject_type = datum['type']
    subject = None
    if subject_type == 'SUBJECT_PROCESS':
        parent_ = None
        ppid_ = None
        cmdLine_ = None
        pname_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            ppid_ = self.Nodes.get(parent_, None)
            if ppid_:
                ppid_ = ppid_.pid
        if datum['cmdLine']:
            cmdLine_ = datum['cmdLine']['string']
            # pname_ = datum['cmdLine']['string']
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
    if object_type == 'FileObject':
        object.subtype = datum['type']
        if datum['baseObject']['properties']:
            pdb.set_trace()
            object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'NetFlowObject':
        if datum['remoteAddress'] == None or datum['remotePort'] == None:
            return None
        else:
            object.set_IP(datum['remoteAddress']['string'], datum['remotePort']['int'],datum['ipProtocol']['int'])
    elif object_type == 'UnnamedPipeObject':
        return None
    elif object_type == 'RegistryKeyObject':
        object.subtype = 'RegistryKeyObject'
        object.name = datum['key']
        # object.value = list(datum['value'].values())[0]
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type == 'SrcSinkObject':
        return None
        # object.subtype = datum['type']
        # if object.subtype in {'SRCSINK_UNKNOWN', 'SRCSINK_IPC'}:
        #     return None
        # elif object.subtype in {'SRCSINK_DATABASE','SRCSINK_PROCESS_MANAGEMENT'}:
        #     object.name = object.subtype
        # else:
        #     print('New SrcSink Object Type!!!')
        #     print(datum)
    else:
        pass

    return object