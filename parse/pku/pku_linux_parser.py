from aifc import Error
import pdb
from graph.Object import Object
from graph.Event import Event
from graph.Subject import Subject
from policy.initTags import match_path, match_network_addr
from hashlib import md5
import re

import uuid
import hashlib

def hash_to_uuid(input_object):
    input_string = str(input_object)
    # 计算输入字符串的SHA-256哈希值
    hasher = hashlib.sha256()
    hasher.update(input_string.encode('utf-8'))
    hash_bytes = hasher.digest()

    # 将前16个字节的哈希用作UUID的基础
    return str(uuid.UUID(bytes=hash_bytes[:16]))

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

def get_md5(s):
    """
    get md5 hash value of String s
    :param s:
    :return:
    """
    return str(md5(s.encode('utf8')).hexdigest())

def parse_file_event(node_buffer, row):
    s_node = hash_to_uuid(row['proc.cmdline'])
    if s_node not in node_buffer:
        parent_ = hash_to_uuid(row['proc.pcmdline'])
        subject = Subject(id=s_node, type = 'SUBJECT_PROCESS', pid = None, ppid = None, parentNode = parent_, cmdLine = row['proc.cmdline'], processName=row['proc.name'])
    else:
        subject = node_buffer[s_node]
    t_node = hash_to_uuid(row['fd.name'])
    if t_node not in node_buffer:
        object = Object(id=t_node, type = 'FileObject')
        # object.subtype = 'FILE_OBJECT_FILE'
        object.path = row['fd.name']
        # self.nodes[t_node] = {'label': row['fd.name'], 'type': APTLOG_NODE_TYPE.FILE, 'score': 0}
    else:
        object = node_buffer[t_node]


    event = Event(hash_to_uuid(row), row['evt.time'])

    # datum['type'] = cdm_events[datum['type']]
    # event.properties = datum['properties']['map']

    ##### Get Related Nodes #####
    event.src = s_node
    event.dest = t_node

    # if isinstance(datum['predicateObject2'], dict):
    #     event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]

    ##### Begin Parsing Event Type #####
    try:
        if row['evt.type'] in {"read", "readv"}:
            assert subject and object
            event.type = 'read'
        elif row['evt.type'] in {"write", "writev"}:
            assert subject and object
            event.type = 'write'
        elif row['evt.type'] in {"fcntl"}:
            assert subject and object
            event.type = 'fcntl'
        elif row['evt.type'] in {"chmod"}:
            pdb.set_trace()
            assert subject and object
            event.type = 'chmod'
            event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
        elif row['evt.type'] in {"rmdir"}:
            pdb.set_trace()
            assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            event.type = 'remove'
        elif row['evt.type'] in {"rename"}:
            pdb.set_trace()
            # assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None) and node_buffer.get(event.dest2, None)
            # event.parameters = datum['predicateObjectPath']['string']
            event.type = 'rename'
    except AssertionError as ae:
        return None, None, None
    
    return subject, object, event


def parse_process_event(node_buffer, row):
    event = Event(hash_to_uuid(row), row['evt.time'])

    ##### Begin Parsing Event Type #####
    try:
        if row['evt.type'] in {"clone"}:
            match = re.search(r'tid=[0-9]+', row['evt.args'])
            if match:
                oldpath = match.group(1)  # 提取第一个匹配的组（即A的值）
                newpath = match.group(2)  # 提取第二个匹配的组（即B的值）
                print("tid:", newpath)
            else:
                print("No match found")

            match = re.search(r'ptid=(\S+)', row['evt.args'])
            if match:
                oldpath = match.group(1)  # 提取第一个匹配的组（即A的值）
                newpath = match.group(2)  # 提取第二个匹配的组（即B的值）
                print("ptid:", newpath)
            else:
                print("No match found")
            s_node = hash_to_uuid(row['proc.pcmdline'])
            if s_node not in node_buffer:
                pdb.set_trace()
                subject = Subject(id=s_node, type = 'SUBJECT_PROCESS', pid = None, ppid = None, parentNode = None, cmdLine = row['proc.cmdline'], processName=row['proc.name'])
            else:
                subject = node_buffer[s_node]
            t_node = hash_to_uuid(row['proc.cmdline'])
            if t_node not in node_buffer:
                pdb.set_trace()
                object = Subject(id=t_node, type = 'SUBJECT_PROCESS', pid = None, ppid = None, parentNode = s_node, cmdLine = row['proc.cmdline'], processName=row['proc.name'])
            else:
                subject = node_buffer[t_node]

            event.type = 'clone' 
        elif row['evt.type'] in {"pipe"}:
            # assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            # event.type = 'write'
            return None, None, None
        elif row['evt.type'] in {"fork"}:
            # event.type = 'inject'
            return None, None, None
        elif row['evt.type'] in {"execve"}:
            # if datum['name']['string'] == 'aue_chmod':
            #     assert node_buffer.get(event.src, None) and node_buffer.get(event.dest, None)
            #     event.type = 'chmod'
            #     event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
            # else:
            #     return None, node_updates 
            return None, None, None 
    except AssertionError as ae:
        return None, None, None
    
    return subject, object, event

def parse_net_event(node_buffer, row):
    s_node = hash_to_uuid(row['proc.cmdline'])
    if s_node not in node_buffer:
        parent_ = hash_to_uuid(row['proc.pcmdline'])
        if parent_ not in node_buffer:
            pdb.set_trace()
        subject = Subject(id=s_node, type = 'SUBJECT_PROCESS', pid = None, ppid = None, parentNode = parent_, cmdLine = row['proc.cmdline'], processName=row['proc.name'])
    else:
        subject = node_buffer[s_node]
    remote_addr = row['fd.name'].split('->')[1]
    remote_ip = remote_addr.split(':')[0]
    remote_port = remote_addr.split(':')[1]
    t_node = hash_to_uuid(remote_addr)
    if t_node not in node_buffer:
        object = Object(id=t_node, type = 'NetFlowObject')
        object.set_IP(remote_ip, int(remote_port), None)
    else:
        object = node_buffer[t_node]


    event = Event(hash_to_uuid(row), row['evt.time'])

    ##### Get Related Nodes #####
    event.src = s_node
    event.dest = t_node

    ##### Begin Parsing Event Type #####
    try:
        if row['evt.type'] in {"recvmsg", "recvfrom"}:
            assert subject and object
            event.type = 'read'
        elif row['evt.type'] in {"sendmsg", "send", "sendto"}:
            assert subject and object
            event.type = 'write'
    except AssertionError as ae:
        return None, None, None
    
    return subject, object, event

def parse_subject_cadets(node_buffer, datum, cdm_version=18):
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
        subject.owner = datum['localPrincipal']
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
        object.set_IP(datum['remoteAddress'], datum['remotePort'], None)
    elif object_type == 'MemoryObject':
        object.name = 'MEM_{}'.format(datum['memoryAddress'])
    elif object_type in {'UnnamedPipeObject', 'RegistryKeyObject', 'PacketSocketObject', 'SrcSinkObject'}:
        return None
    else:
        return None

    return object