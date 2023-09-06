import sys
sys.path.extend(['.','..','...'])

def get_target(event, s, o, gt):
    event_type = event.type
    s_target_ = None
    o_target_ = None

    if event_type in {'execve', 'load'}:
        if o.isFile():
            if gt == "FileExec":
                o_target_ = [None, None, 0, None]
            else:
                o_target_ = [None, None, 1, None]

    if event_type in {'mmap', 'mprotect'}:
        if o and o.isFile() == False:
            if 'PROT_EXEC' in set(event.parameters):
                if gt == "MkMemExecutable":
                    s_target_ = [None, None, 0, None]
                else:
                    s_target_ = [None, None, 1, None]
        else:
            if 'PROT_EXEC' in set(event.parameters):
                if gt == "MkMemExecutable":
                    s_target_ = [None, None, 0, None]
                else:
                    s_target_ = [None, None, 1, None]
        
    if event_type in {'write', 'remove', 'rename'}:
        if o.isIP() == False:
            if gt == "FileCorruption":
                s_target_ = [None, None, 0, None]
                # o_target_ = [None, None, 1, None]
            else:
                s_target_ = [None, None, 1, None]
                # o_target_ = [None, None, 0, None]
        elif o.isIP() and event_type == 'write':
            if gt == "DataLeak":
                s_target_ = [None, None, 0, 0]
                o_target_ = [None, None, None, 1]
            else:
                s_target_ = [None, None, 1, 1]
                o_target_ = [None, None, None, 0]

    # if event_type in {'inject'}:
    #    if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(o.tags()))):
    #       alarm_result = prtSSAlarm(ts,"Inject", s, o,event.id, alarm_file)

    if event_type in {'set_uid'}:
        if gt == "PrivilegeEscalation":
            s_target_ = [None, None, 0, None]
        else:
            s_target_ = [None, None, 1, None]
    
    if event_type in {'chmod'}:
        prm = event.parameters
        if ((prm & int('0111',8)) != 0):
            if gt == "MkFileExecutable":
                o_target_ = [None, None, 0, None]
            else:
                o_target_ = [None, None, 1, None]
    
    return s_target_, o_target_