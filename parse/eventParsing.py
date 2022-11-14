from aifc import Error
import pdb
from graph.Event import Event
from policy.initTags import match_path, match_network_addr
from parse.eventType import EXECVE_SET, SET_UID_SET, lttng_events, cdm_events, standard_events
from parse.eventType import READ_SET, WRITE_SET, INJECT_SET, CHMOD_SET, SET_UID_SET, EXECVE_SET, LOAD_SET, CREATE_SET, RENAME_SET, REMOVE_SET, CLONE_SET, MPROTECT_SET, MMAP_SET, UPDATE_SET, EXIT_SET, UNUSED_SET

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

lttng_sys_event = ['sys_open','sys_openat','sys_close','sys_read','sys_readv','sys_pread',
    'sys_preadv','sys_write','sys_writev','sys_pwrite','sys_pwritev','sys_clone','sys_fork',
    'sys_execve','sys_accept','sys_connect','sys_recvfrom','sys_recvmsg','sys_sendto','sys_sendmsg',
    'sys_socket','sys_rename','sys_renameat','sys_dup2','sys_chmod','sys_chown','sys_create','sys_pipe','sys_pipe2','sys_setuid',
    'sys_setgid','sys_unlink','sys_unlinkat','sys_unknow','sys_imageload','ipaddr_info','dns_info']

lttng_sched_event = ['sched_switch','sched_process_fork','sched_process_free','sched_process_exec','sched_wakeup_new']

lttng_lttng_event = ['lttng_statedump_start','lttng_statedump_end','lttng_statedump_process_state','lttng_statedump_file_descriptor']

def parse_event_cadets(self, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]

    if datum['type'] in UNUSED_SET:
        return None
    
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
    except KeyError:
        pass

    try:
        if isinstance(datum['predicateObject2Path'], dict):
            event.obj2_path = datum['predicateObject2Path']['string']
            if self.Nodes[event.dest2].path != event.obj2_path:
                self.Nodes[event.dest2].name = event.obj2_path
                self.Nodes[event.dest2].path = event.obj2_path
    except KeyError:
        pass

    try:
        if 'exec' in event.properties:
            if self.Nodes[event.src].processName != event.properties['exec']:
                self.Nodes[event.src].processName = event.properties['exec']
    except KeyError:
        pass

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
            return None
    elif datum['type'] in INJECT_SET:
        event.type = 'inject'
    elif datum['type'] in CHMOD_SET:
        if datum['name']['string'] == 'aue_chmod':
            event.type = 'chmod'
            event.parameters = int(datum['parameters']['array'][0]['valueBytes']['bytes'], 16)
        else:
            return None   
    elif datum['type'] in SET_UID_SET:
        # TO DO
        # a = self.Nodes.get(event.src, None)
        # b = self.Nodes.get(event.dest, None)
        # c = self.Nodes.get(event.dest2, None)
        event.type = 'set_uid'
    elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
        self.parameters = datum['properties']['map']['cmdLine']
        event.type = 'execve'
    elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
        pdb.set_trace()
    elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        if self.Nodes[event.dest].isFile():
            event.type = 'load'
        else:
            print("MMAP: {}".format(str(datum)))
            event.type = 'mmap'
            event.parameters = memory_protection(eval(event.properties['protection']))
    elif datum['type'] in CREATE_SET:
        assert event.src and event.dest
        if datum['name']['string'] not in  {'aue_socketpair', 'aue_mkdirat'}:
            if self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None):
                event.type = 'create'
            else:
                return None
        else:
            return None
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
        return None
    
    return event

def parse_event_trace(self, datum, cdm_version):
    event = Event(datum['uuid'], datum['timestampNanos'])
    datum['type'] = cdm_events[datum['type']]

    if datum['type'] in UNUSED_SET:
        return None
    
    # event['type'] = datum['type']
    event.properties = datum['properties']['map']

    if isinstance(datum['subject'], dict):
        event.src = datum['subject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    
    if isinstance(datum['predicateObject'], dict):
        event.dest = datum['predicateObject']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]


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
            return None
    elif datum['type'] in INJECT_SET:
        event.type = 'inject'
    elif datum['type'] in CHMOD_SET:
        event.type = 'chmod'
        event.parameters = int(event.properties['mode'], 8)
    elif datum['type'] in SET_UID_SET:
        event.type = 'set_uid'
    elif datum['type'] in {cdm_events['EVENT_EXECUTE']}:
        event.type = 'update_process'
    elif datum['type'] in {cdm_events['EVENT_LOADLIBRARY']}:
        event.type = 'execve'
    elif datum['type'] in {cdm_events['EVENT_MMAP']}:
        if self.Nodes[event.dest].isFile():
            event.type = 'load'
        else:
            # print("MMAP: {}".format(str(datum)))
            event.type = 'mmap'
            event.parameters = memory_protection(eval(event.properties['protection']))
    elif datum['type'] in CREATE_SET:
        assert event.src and event.dest
        if self.Nodes.get(event.src, None) and self.Nodes.get(event.dest, None):
            event.type = 'create'
        else:
            return None
    elif datum['type'] in RENAME_SET:
        event.type = 'rename'
        # New file name
        event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    elif datum['type'] in REMOVE_SET:
        event.type = 'remove'
    elif datum['type'] in CLONE_SET:
        event.type = 'clone'
    elif datum['type'] in MPROTECT_SET:
        # a = self.Nodes[event.dest]
        # assert event.dest == None
        # b = self.Nodes[event.src]
        event.type = 'mprotect'
        event.parameters = memory_protection(eval(event.properties['protection']))
    elif datum['type'] in UPDATE_SET:
        event.type = 'update'
        event.dest2 = datum['predicateObject2']['com.bbn.tc.schema.avro.cdm{}.UUID'.format(cdm_version)]
    elif datum['type'] in EXIT_SET:
        event.type = 'exit'
    else:
        return None
    
    return event

def parse_event(self, datum, format, cdm_version):
    if format == 'trace':
        return parse_event_trace(self, datum, cdm_version)
    elif format == 'cadets':
        return parse_event_cadets(self, datum, cdm_version)