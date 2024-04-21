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

def parse_event_cadets(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]

    event.properties = datum['properties']['map']

    ##### Get Related Nodes #####
    if isinstance(datum['subject'], dict):
        event.src = datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    ##### Check if the nodes get updated #####
    node_updates = {}
    if datum['predicateObjectPath']:
        event.obj_path = datum['predicateObjectPath']['string']
        if event.dest in node_buffer and node_buffer[event.dest].path == None:
            node_buffer[event.dest].name = event.obj_path
            node_buffer[event.dest].path = event.obj_path
            node_updates[event.dest] = {'name':event.obj_path}

    if datum['predicateObject2Path']:
        event.obj2_path = datum['predicateObject2Path']['string']
        if event.dest2 in node_buffer and node_buffer[event.dest2].path == None:
            node_buffer[event.dest2].name = event.obj2_path
            node_buffer[event.dest2].path = event.obj2_path
            node_updates[event.dest2] = {'name':event.obj2_path}

    if 'exec' in event.properties:
        if event.src in node_buffer and node_buffer[event.src].processName != event.properties['exec']:
            node_buffer[event.src].processName = event.properties['exec']
            node_updates[event.src] = {'exec':event.properties['exec']}
            
    if 'ppid' in event.properties:
        if node_buffer[event.src].ppid == None:
            node_buffer[event.src].ppid = event.properties['ppid']

    ##### Begin Parsing Event Type #####
    try:
        if datum['type'] in READ_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in WRITE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'write'
        elif datum['type'] in INJECT_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'inject'
        elif datum['type'] in CHMOD_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            if 'aue_chmod' in datum['names']['array']:
                event.type = 'chmod'
                event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
                # print('8-based: {}'.format(oct(event.parameters)))
            else:
                return None, node_updates  
        elif datum['type'] in SET_UID_SET:
            assert node_buffer.get(event.src, None)
            if 'aue_setuid' in datum['names']['array']:
                event.type = 'set_uid'
                event.parameters = int(datum['properties']['map']['arg_uid'])
            else:
                return None, node_updates
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.parameters = datum['properties']['map']['cmdLine']
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            pdb.set_trace()
            return None, node_updates
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            if node_buffer.get(event.dest, None) and node_buffer[event.dest].isFile():
                assert node_buffer.get(event.src, None)
                event.type = 'load'
            else:
                pdb.set_trace()
                event.type = 'mmap'
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'create'
        elif datum['type'] in RENAME_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'rename'
            event.parameters = datum['predicateObjectPath']['string']
            # node_updates[event.dest] = {'name':event.parameters}
        elif datum['type'] in REMOVE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            assert node_buffer.get(event.src, None)
            event.dest = None
            event.type = 'mprotect'
            event.parameters = eval(datum['properties']['map']['arg_mem_flags'])
        elif datum['type'] in UPDATE_SET:
            pdb.set_trace()
            event.type = 'update'
        elif datum['type'] in EXIT_SET:
            assert node_buffer.get(event.src, None)
            event.dest = None
            event.type = 'exit'
        else:
            return None, node_updates
    except AssertionError as ae:
        return None, node_updates
    
    return event, node_updates

def parse_subject_cadets(node_buffer, datum, cdm_version):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        pname_ = datum['properties'].get('name', None)
        parent_ = None
        ppid_ = None
        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
            ppid_ = node_buffer[parent_].pid
        cmdLine_ = datum['cmdLine']
        subject = Subject(id=datum['uuid'], type = datum['type'], pid = datum['cid'], ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        if isinstance(datum['localPrincipal'], dict):
            subject.owner = datum['localPrincipal']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    elif subject_type in {'SUBJECT_THREAD', 'SUBJECT_UNIT', 'SUBJECT_BASIC_BLOCK'}:
        return None
    else:
        return None
    
    return subject


def parse_object_cadets(datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if object_type == 'FileObject':
        ## We ignore all other types of file
        if datum['type'] != 'FILE_OBJECT_FILE':
            return None
        object.subtype = datum['type']
        ## Usually it is null
        object.path = datum['baseObject']['properties']['map'].get('path', None)
    elif object_type == 'NetFlowObject':
        object.set_IP(datum['remoteAddress']['string'], datum['remotePort']['int'], None)
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type in {'UnnamedPipeObject', 'RegistryKeyObject', 'PacketSocketObject', 'SrcSinkObject'}:
        return None
    else:
        return None

    return object