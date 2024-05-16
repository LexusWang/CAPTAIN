import pdb
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
# from policy.initTags import match_path, match_network_addr
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

def parse_event_trace(node_buffer, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]
    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = datum['subject']["com.bbn.tc.schema.avro.cdm20.UUID"]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = datum['predicateObject']["com.bbn.tc.schema.avro.cdm20.UUID"]

    if isinstance(datum['predicateObject2'], dict):
        event.dest2 = datum['predicateObject2']["com.bbn.tc.schema.avro.cdm20.UUID"]

    try:
        if datum['type'] in READ_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'read'
        elif datum['type'] in WRITE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'write'
        elif datum['type'] in INJECT_SET:
            event.type = 'inject'
        elif datum['type'] in CHMOD_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'chmod'
            event.parameters = int(event.properties['mode'], 8)
        elif datum['type'] in SET_UID_SET:
            assert node_buffer.get(event.src, None)
            if datum['properties']['map']['operation'] == 'setuid':
                event.type = 'set_uid'
                event.src = event.dest
                event.dest = None
                event.parameters = node_buffer.get(event.src, None).owner
            else:
                return None
        elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'update_process'
        elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'execve'
        elif datum['type'] in {cdm_events['EVENT_MMAP']}:
            assert node_buffer.get(event.src, None)
            if node_buffer.get(event.dest, None) and node_buffer[event.dest].isFile():
                event.type = 'load'
                event.dest2 = None
            else:
                event.type = 'mmap'
                event.dest = None
                event.dest2 = None
                event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in CREATE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'create'
            event.parameters = datum['properties']['map']
        elif datum['type'] in RENAME_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.type = 'rename'
        elif datum['type'] in REMOVE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'remove'
        elif datum['type'] in CLONE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'clone'
        elif datum['type'] in MPROTECT_SET:
            assert node_buffer.get(event.src, None)
            event.type = 'mprotect'
            event.dest = None
            event.dest2 = None
            event.parameters = memory_protection(eval(event.properties['protection']))
        elif datum['type'] in UPDATE_SET:
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            event.type = 'update'
        elif datum['type'] in EXIT_SET:
            assert node_buffer.get(event.src, None)
            event.type = 'exit'
            event.dest = None
        else:
            return None
    except AssertionError as ae:
        return None
    
    return event

def parse_subject_trace(datum, cdm_version):
    subject_type = datum['type']
    if subject_type == 'SUBJECT_PROCESS':
        type_ = datum['type']
        pid_ = int(datum['cid'])
        pname_ = datum['properties']['map'].get('name',None)
        ppid_ = int(datum['properties']['map']['ppid'])

        if datum['parentSubject']:
            parent_ = datum['parentSubject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
        else:
            parent_ = None

        if datum['cmdLine']:
            cmdLine_ = datum['cmdLine'].get('string')
        else:
            cmdLine_ = None
        subject = Subject(id=datum['uuid'], type = type_, pid = pid_, ppid = ppid_, parentNode = parent_, cmdLine = cmdLine_, processName=pname_)
        if datum['localPrincipal']:
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

def parse_object_trace(datum, object_type):
    object = Object(id=datum['uuid'], type = object_type)
    if object_type == 'FileObject':
        if datum['type'] == 'FILE_OBJECT_FILE':
            object.subtype = datum['type']
            object.epoch = datum['baseObject']['epoch']['int']
            # permission = datum['baseObject']['permission']
            object.name = datum['baseObject']['properties']['map'].get('path', None)
            object.path = datum['baseObject']['properties']['map'].get('path', None)
        else:
            return None
    elif object_type == 'IpcObject':
        object.subtype = datum['type']
        if object.subtype == 'IPC_OBJECT_PIPE_UNNAMED':
            object.epoch = datum['baseObject']['epoch']['int']
            try:
                name = "unnamedPipe_{}".format(datum['baseObject']["properties"]["map"]["pid"])
            except:
                name = "unnamedPipe_unknown_pid"
            object.name = name
            object.path = name
        else:
            return None
    elif object_type == 'RegistryKeyObject':
        return None
    elif object_type == 'PacketSocketObject':
        return None
    elif object_type == 'NetFlowObject':
        object.epoch = datum['baseObject']['epoch']['int']
        object.set_IP(datum['remoteAddress']['string'], datum['remotePort']['int'], datum['ipProtocol']['int'])
    elif object_type == 'MemoryObject':
        return None
    elif object_type == 'SrcSinkObject':
        return None
    else:
        return None

    return object
