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

LINUX_READ_SET = set([4, 5, 6, 7, 19, 20])
LINUX_WRITE_SET = set([8, 9, 10, 11, 17, 18])
LINUX_CHMOD_SET = set([25, 26, 14])
LINUX_SET_UID_SET = set([30, 31])
LINUX_LOADLIBRARY_SET = set([35])
LINUX_CREATE_SET = set([27])
LINUX_RENAME_SET = set([22, 23])
LINUX_REMOVE_SET = set([32, 33])
LINUX_CLONE_SET = set([12, 13, 14])
LINUX_EXIT_SET = set([38])

def check_file_path(s):
    n = len(s)
    if n % 2 != 0:
        return s
    
    first_half = s[:n//2]
    second_half = s[n//2:]
    
    if first_half == second_half:
        return first_half
    else:
        return s

def parse_event_linux(self, datum):
    subject = None
    object = None
    object2 = None
    event = Event(datum['id'], datum['timestamp']*1e6)
    event_type_num = datum['event_type']
    args = datum['arguments']

    if 'filepath' in args:
        args['filepath'] = check_file_path(args['filepath'])
    if 'new_filepath' in args:
        args['new_filepath'] = check_file_path(args['new_filepath'])
    
    if event_type_num in LINUX_READ_SET:
        event.type = 'read'
        args = datum['arguments']
        subject = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'])
        if datum['log_category'] == 'Network':
            object = Object(id='{}:{}'.format(args['destination_ip'],args['destination_port']), type='NetFlowObject')
            object.set_IP(args['destination_ip'], args['destination_port'], None)
        elif datum['log_category'] == 'File':
            object = Object(id=args['file_uuid'], type='FileObject', objName=args['filepath'])
            object.path = args['filepath']
        else:
            raise TypeError("Unknown Object Type!!!")
        event.src = subject.id
        event.dest = object.id
    elif event_type_num in LINUX_WRITE_SET:
        event.type = 'write'
        args = datum['arguments']
        subject = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'])
        if datum['log_category'] == 'Network':
            object = Object(id='{}:{}'.format(args['destination_ip'],args['destination_port']), type='NetFlowObject')
            object.set_IP(args['destination_ip'], args['destination_port'], None)
        elif datum['log_category'] == 'File':
            object = Object(id=args['file_uuid'], type='FileObject', objName=args['filepath'])
            object.path = args['filepath']
        else:
            raise TypeError("Unknown Object Type!!!")
        event.src = subject.id
        event.dest = object.id
    elif event_type_num in LINUX_CHMOD_SET:
        if 'chmod' in args['process_commandline']:
            event.type = 'chmod'
            subject = Subject(id=args['parent_process_uuid'], type='SUBJECT_PROCESS',pid=args['parent_process_id'],processName=args['parent_process_name'], cmdLine=args['parent_process_commandline'])
            file_name = args['process_commandline'].split(' ')[-1]
            if file_name.startswith('.'):
                file_name = args['work_directory'] + file_name[1:]
            object = Object(id=None, type='FileObject', objName=file_name)
            object.path = file_name
            if '+' in args['process_commandline'].split(' ')[-2]:
                event.parameters = 0
                if 'x' in args['process_commandline'].split(' ')[-2]:
                    event.parameters += int('0111', 8)
                if 'w' in args['process_commandline'].split(' ')[-2]:
                    event.parameters += int('0222', 8)
                if 'r' in args['process_commandline'].split(' ')[-2]:
                    event.parameters += int('0444', 8)
            else:
                event.parameters = int(args['process_commandline'].split(' ')[-2], 8)
                # print(args['process_commandline'].split(' ')[-2])
                # pdb.set_trace()
            event.src = subject.id
            event.dest = object.id
        elif 'chmod' in args['parent_process_commandline']:
            raise TypeError("Undefined Event Type {}!!!".format(event.type))
        else:
            return subject, object, object2, None
    elif event_type_num in LINUX_SET_UID_SET:
        event.type = 'set_uid'
        raise TypeError("Undefined Event Type {}!!!".format(event.type))
    elif event_type_num in LINUX_LOADLIBRARY_SET:
        event.type = 'execve'
        args = datum['arguments']
        subject = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'])
        object = Object(id=args['file_uuid'], type='FileObject', objName=args['filepath'])
        object.path = args['filepath']
        event.src = subject.id
        event.dest = object.id
    elif event_type_num in LINUX_CREATE_SET:
        # assert event.src and event.dest
        # if self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None):
        event.type = 'create'
        subject = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'])
        object = Object(id=args['file_uuid'], type='FileObject', objName=args['filepath'])
        object.path = args['filepath']
        event.src = subject.id
        event.dest = object.id
    elif event_type_num in LINUX_RENAME_SET:
        event.type = 'rename'
        subject = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'])
        object = Object(id=args['file_uuid'], type='FileObject', objName=args['filepath'])
        object.path = args['filepath']
        object2 = Object(id="{}-new".format(args['file_uuid']), type='FileObject', objName=args['new_filepath'])
        object2.path = args['new_filepath']
        event.src = subject.id
        event.dest = object.id
        event.dest2 = object2.id
    elif event_type_num in LINUX_REMOVE_SET:
        event.type = 'remove'
        args = datum['arguments']
        subject = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'])
        object = Object(id=args['file_uuid'], type='FileObject', objName=args['filepath'])
        object.path = args['filepath']
        event.src = subject.id
        event.dest = object.id
    elif event_type_num in LINUX_CLONE_SET:
        event.type = 'clone'
        args = datum['arguments']
        subject = Subject(id=args['parent_process_uuid'], type='SUBJECT_PROCESS',pid=args['parent_process_id'],processName=args['parent_process_name'], cmdLine=args['parent_process_commandline'])
        object = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'], cmdLine=args['process_commandline'])
        subject.owner = args['parent_process_user']
        object.owner = args['parent_process_user']
        event.src = subject.id
        event.dest = object.id
    elif event_type_num in LINUX_EXIT_SET:
        event.type = 'exit'
        args = datum['arguments']
        # subject = Subject(id=args['parent_process_uuid'], type='SUBJECT_PROCESS',pid=args['parent_process_id'],processName=args['parent_process_name'], cmdLine=args['parent_process_commandline'])
        # object = Subject(id=args['process_uuid'], type='SUBJECT_PROCESS',pid=args['process_id'],processName=args['process_name'], cmdLine=args['process_commandline'])
        # subject.owner = args['parent_process_user']
        # object.owner = args['parent_process_user']
        # event.src = subject.id
        # event.dest = object.id
    else:
        return subject, object, object2, None
    
    return subject, object, object2, event
