import time
import sys
sys.path.extend(['.','..','...'])
# import floatTags
from graph.Subject import Subject
from graph.Object import Object
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag,ctag,itag,etag, isRoot, permbits
from policy.alarms import AlarmArguments, getTime, prtSOAlarm, prtSAlarm, prtSSAlarm

def get_target_pre(event, s, o, gt):
    event_type = event.type
    s_target_ = None
    o_target_ = None

    if event_type in {'remove', 'rename'}:
        if o.isMatch("null") == False:
            if gt == "FileCorruption":
                s_target_ = [None, None, 0, None]
                o_target_ = [None, None, 1, None]
            else:
                s_target_ = [None, None, 1, None]
                o_target_ = [None, None, 0, None]

    if event_type in {'chmod'}:
        prm = event.parameters
        if ((prm & int('0111',8)) != 0):
            if gt == "MkFileExecutable":
                o_target_ = [None, None, 0, None]
            else:
                o_target_ = [None, None, 1, None]

    return s_target_, o_target_


def get_target(event, s, o, gt):
    event_type = event.type
    # alarm_result = None
    s_target_ = None
    o_target_ = None

    if event_type in {'execve'}:
        if gt == "FileExec":
            s_target_ = [0, None, None, None]
        else:
            s_target_ = [1, None, None, None]

    if event_type in {'load'}:
        if o.isFile():
            if gt == "FileExec":
                s_target_ = [0, None, None, None]
            else:
                s_target_ = [1, None, None, None]

    # Not Used
    if event_type in {'inject'}:
        if gt == "Inject":
            o_target_ = [0, None, None, None]
        else:
            o_target_ = [1, None, None, None]
   
    if event_type in {'write'}:
        if o.isIP() == False:
            if gt == "FileCorruption":
                o_target_ = [None, None, 0, None]
            else:
                o_target_ = [None, None, 1, None]
        else:
            # if (itag(s.tags()) < 0.5 and ctag(s.tags()) < 0.5):
            #     if itag(o.tags()) < 0.5:
            #         # if not alarms[(s.get_pid(), o.get_name())]:
            #         alarm_sum[1] = alarm_sum[1] + 1
            #         alarm_result = prtSOAlarm(ts, "DataLeak", s, o, alarms, event.id, alarm_file)
            if gt == "DataLeak":
                s_target_ = [None, None, 0, 0]
                o_target_ = [None, None, 0, None]
            else:
                s_target_ = [None, None, 1, 1]
                o_target_ = [None, None, 1, None]

    if event_type in {'set_uid'}:
        if gt == "PrivilegeEscalation":
            s_target_ = [None, None, 0, None]
        else:
            s_target_ = [None, None, 1, None]
   
    if event_type in {'mmap'}:
        if o.isFile() == False:
            # prm = int(event['properties']['map']['protection'])
            # if ((prm & int('01',8)) == int('01',8)):
            if 'PROT_EXEC' in set(event.parameters):
                if gt == "MkMemExecutable":
                    s_target_ = [None, None, 0, None]
                else:
                    s_target_ = [None, None, 1, None]
    
    if event_type in {'mprotect'}:
        # prm = int(event['properties']['map']['protection'])
        # if ((prm & int('01',8)) == int('01',8)):
        if 'PROT_EXEC' in set(event.parameters):
            if gt == "MkMemExecutable":
                s_target_ = [None, None, 0, None]
            else:
                s_target_ = [None, None, 1, None]

    return s_target_, o_target_