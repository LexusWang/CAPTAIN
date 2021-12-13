import numpy as np

lttng_sys_event = ['sys_open','sys_openat','sys_close','sys_read','sys_readv','sys_pread',
    'sys_preadv','sys_write','sys_writev','sys_pwrite','sys_pwritev','sys_clone','sys_fork',
    'sys_execve','sys_accept','sys_connect','sys_recvfrom','sys_recvmsg','sys_sendto','sys_sendmsg',
    'sys_socket','sys_rename','sys_renameat','sys_dup2','sys_chmod','sys_chown','sys_create','sys_pipe','sys_pipe2','sys_setuid',
    'sys_setgid','sys_unlink','sys_unlinkat','sys_unknow','sys_imageload','ipaddr_info','dns_info']

lttng_sched_event = ['sched_switch','sched_process_fork','sched_process_free','sched_process_exec','sched_wakeup_new']

lttng_lttng_event = ['lttng_statedump_start','lttng_statedump_end','lttng_statedump_process_state','lttng_statedump_file_descriptor']

cdm_events_list = ['EVENT_ACCEPT','EVENT_ADD_OBJECT_ATTRIBUTE','EVENT_BIND','EVENT_BLIND','EVENT_BOOT','EVENT_CHANGE_PRINCIPAL',
            'EVENT_CHECK_FILE_ATTRIBUTES','EVENT_CLONE','EVENT_CLOSE','EVENT_CONNECT','EVENT_CREATE_OBJECT','EVENT_CREATE_THREAD',
            'EVENT_DUP','EVENT_EXECUTE','EVENT_EXIT','EVENT_FLOWS_TO','EVENT_FCNTL','EVENT_FORK','EVENT_LINK','EVENT_LOADLIBRARY',
            'EVENT_LOGCLEAR','EVENT_LOGIN','EVENT_LOGOUT','EVENT_LSEEK','EVENT_MMAP','EVENT_MODIFY_FILE_ATTRIBUTES','EVENT_MODIFY_PROCESS',         
            'EVENT_MOUNT','EVENT_MPROTECT','EVENT_OPEN','EVENT_OTHER','EVENT_READ','EVENT_READ_SOCKET_PARAMS','EVENT_RECVFROM','EVENT_RECVMSG',                
            'EVENT_RENAME','EVENT_SENDTO','EVENT_SENDMSG','EVENT_SERVICEINSTALL','EVENT_SHM','EVENT_SIGNAL','EVENT_STARTSERVICE',           
            'EVENT_TRUNCATE','EVENT_UMOUNT','EVENT_UNIT','EVENT_UNLINK','EVENT_UPDATE','EVENT_WAIT','EVENT_WRITE','EVENT_WRITE_SOCKET_PARAMS']


standard_events = {}
cdm_events = {}

for i, event in enumerate(cdm_events_list):
    standard_events[event] = i
    cdm_events[event] = i

lttng_common_events = {'sys_open':29,'sys_close':8,'sys_read':31,'sys_write': 48,'sys_clone':7,'sys_fork':17,
    'sys_execve':13,'sys_accept':0,'sys_connect':9,'sys_recvfrom':33,'sys_recvmsg':34,'sys_sendto':36,'sys_sendmsg':37,
    'sys_rename':35,'sys_dup2':12,'sys_create':10,'sys_unlink':45, 'sys_setuid':5, 'sys_chmod':25}

lttng_special_events = ['sys_openat', 'sys_readv','sys_pread', 'sys_preadv', 'sys_writev','sys_pwrite','sys_pwritev',
'sys_socket', 'sys_renameat','sys_chown','sys_pipe','sys_pipe2','sys_setgid',
'sys_unlinkat','sys_unknow','sys_imageload','ipaddr_info','dns_info']

lttng_special_events.extend(lttng_sched_event)
lttng_special_events.extend(lttng_lttng_event)

lttng_events = lttng_common_events.copy()
for i, event in enumerate(lttng_special_events):
    lttng_events[event] = 50 + i
    standard_events[event] = 50 + i

READ_SET = {standard_events['EVENT_READ'],standard_events['EVENT_RECVMSG']}
WRITE_SET = {standard_events['EVENT_WRITE'], standard_events['EVENT_SENDMSG']}
INJECT_SET = {}
SET_UID_SET = {standard_events['EVENT_CHANGE_PRINCIPAL']}
EXECVE_SET = {standard_events['EVENT_EXECUTE']}
LOAD_SET = {standard_events['EVENT_LOADLIBRARY']}
CREATE_SET = {}


# for key, value in standard_events.items():
#     print(key+': '+str(value))

# EVENT_ACCEPT: 0
# EVENT_ADD_OBJECT_ATTRIBUTE: 1
# EVENT_BIND: 2
# EVENT_BLIND: 3
# EVENT_BOOT: 4
# EVENT_CHANGE_PRINCIPAL: 5
# EVENT_CHECK_FILE_ATTRIBUTES: 6
# EVENT_CLONE: 7
# EVENT_CLOSE: 8
# EVENT_CONNECT: 9
# EVENT_CREATE_OBJECT: 10
# EVENT_CREATE_THREAD: 11
# EVENT_DUP: 12
# EVENT_EXECUTE: 13
# EVENT_EXIT: 14
# EVENT_FLOWS_TO: 15
# EVENT_FCNTL: 16
# EVENT_FORK: 17
# EVENT_LINK: 18
# EVENT_LOADLIBRARY: 19
# EVENT_LOGCLEAR: 20
# EVENT_LOGIN: 21
# EVENT_LOGOUT: 22
# EVENT_LSEEK: 23
# EVENT_MMAP: 24
# EVENT_MODIFY_FILE_ATTRIBUTES: 25
# EVENT_MODIFY_PROCESS: 26
# EVENT_MOUNT: 27
# EVENT_MPROTECT: 28
# EVENT_OPEN: 29
# EVENT_OTHER: 30
# EVENT_READ: 31
# EVENT_READ_SOCKET_PARAMS: 32
# EVENT_RECVFROM: 33
# EVENT_RECVMSG: 34
# EVENT_RENAME: 35
# EVENT_SENDTO: 36
# EVENT_SENDMSG: 37
# EVENT_SERVICEINSTALL: 38
# EVENT_SHM: 39
# EVENT_SIGNAL: 40
# EVENT_STARTSERVICE: 41
# EVENT_TRUNCATE: 42
# EVENT_UMOUNT: 43
# EVENT_UNIT: 44
# EVENT_UNLINK: 45
# EVENT_UPDATE: 46
# EVENT_WAIT: 47
# EVENT_WRITE: 48
# EVENT_WRITE_SOCKET_PARAMS: 49
# sys_openat: 50
# sys_readv: 51
# sys_pread: 52
# sys_preadv: 53
# sys_writev: 54
# sys_pwrite: 55
# sys_pwritev: 56
# sys_socket: 57
# sys_renameat: 58
# sys_chmod: 59
# sys_chown: 60
# sys_pipe: 61
# sys_pipe2: 62
# sys_setgid: 63
# sys_unlinkat: 64
# sys_unknow: 65
# sys_imageload: 66
# ipaddr_info: 67
# dns_info: 68
# sched_switch: 69
# sched_process_fork: 70
# sched_process_free: 71
# sched_process_exec: 72
# sched_wakeup_new: 73
# lttng_statedump_start: 74
# lttng_statedump_end: 75
# lttng_statedump_process_state: 76
# lttng_statedump_file_descriptor: 77



