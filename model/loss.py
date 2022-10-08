import time
import sys
sys.path.extend(['.','..','...'])
import torch

# import floatTags
from graph.Subject import Subject
from graph.Object import Object
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag,ctag,itag,etag, isRoot, permbits
from policy.alarms import AlarmArguments, printTime, getTime, prtSOAlarm, prtSAlarm, prtSSAlarm
# from parse.eventType import SET_UID_SET, lttng_events, cdm_events, standard_events
# from parse.eventType import READ_SET, LOAD_SET, EXECVE_SET, WRITE_SET, INJECT_SET, CREATE_SET, RENAME_SET, MPROTECT_SET, REMOVE_SET, CHMOD_SET, MMAP_SET

def check_alarm_pre_loss(event, s, o, alarms, created, alarm_sum, gt, format = 'cdm', morse = None, alarm_file = None):
    ts = event.time
    event_type = event.type

    s_loss, o_loss = torch.zeros(4, requires_grad=True), torch.zeros(4, requires_grad=True)
    if s:
        s_tags = torch.tensor(s.tags(),requires_grad=True)
    if o:
        o_tags = torch.tensor(o.tags(),requires_grad=True)
    else:
        o_tags = None
    s_target_ = False
    o_target_ = False

    alarmarg = AlarmArguments()
    alarmarg.origtags = None
    alarmarg.pre_alarm = None
    alarmarg.s_loss = None
    alarmarg.o_loss = None
    alarmarg.s_tags = None
    alarmarg.o_tags = None

    if event_type in {'read', 'load', 'execve', 'inject', 'mprotect'}:
       alarmarg.origtags = s.tags()

    if event_type in {'write'}:
       alarmarg.origtags = o.tags()

    if event_type in {'inject'}:
       alarmarg.origtags = o.tags()

    if event_type in {'set_uid'}:
        if (itag(s.tags()) < 0.5):
            alarmarg.rootprinc = isRoot(morse.Principals[s.owner])

    if event_type in {'remove'}:
        assert isinstance(o,Object) and isinstance(s,Subject)
        if o.isMatch("null") == False:
            if (itag(o.tags()) > 0.5 and itag(s.tags()) < 0.5):
                # if not alarms[(s.get_pid(), o.get_name())]:
                alarm_sum[1] = alarm_sum[1] + 1
                alarmarg.pre_alarm = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, alarm_file)
            if gt == "FileCorruption":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])
  

    if event_type in {'rename'} :
        if o.isMatch("null")==False:
            if itag(o.tags()) > 0.5 and itag(s.tags()) < 0.5:
                # if not alarms[(s.get_pid(), o.get_name())]:
                alarm_sum[1] = alarm_sum[1] + 1
                alarmarg.pre_alarm = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, alarm_file)
            if gt == "FileCorruption":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])


    if event_type in {'chmod'}:
        ositag = itag(o.tags())
        # prm = permbits(event)
        prm = event.parameters
        if ((prm & int('0111',8)) != 0):
            if ositag < 0.5:
                # if (alarms[(s.get_pid(), o.get_name())] == False):
                alarm_sum[1] = alarm_sum[1] + 1
                alarmarg.pre_alarm = prtSOAlarm(ts, "MkFileExecutable", s, o, alarms, event.id, alarm_file)
            if gt == "MkFileExecutable":
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])
            else:
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])

    if isinstance(s_target_, torch.Tensor):
        s_loss = s_tags - s_target_
        alarmarg.s_loss = torch.mean(torch.square(s_loss))
        alarmarg.s_tags = s_tags
    if isinstance(o_target_, torch.Tensor):
        o_loss = o_tags - o_target_
        alarmarg.o_loss = torch.mean(torch.square(o_loss))
        alarmarg.o_tags = o_tags
    
    return alarmarg


def check_alarm_loss(event, s, o, alarms, created, alarm_sum, alarmarg, gt, format = 'cdm', morse = None, alarm_file = None):
    ts = event.time
    event_type = event.type
    alarm_result = None

    s_loss, o_loss = torch.zeros(4, requires_grad=True), torch.zeros(4, requires_grad=True)
    if s:
        s_tags = torch.tensor(s.tags(),requires_grad=True)
    if o:
        o_tags = torch.tensor(o.tags(),requires_grad=True)
    else:
        o_tags = None
    s_target_ = False
    o_target_ = False

    if alarmarg.pre_alarm != None:
        alarm_result = alarmarg.pre_alarm
    
    if event_type in {'create'}:
        created[(s.get_pid(), o.get_name())] = True  

    if event_type in {'execve'}:
        if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(s.tags()))):
            # if not alarms[(s.get_pid(), o.get_name())]:
            alarm_sum[1] = alarm_sum[1] + 1
            alarm_result = prtSOAlarm(ts,"FileExec", s, o, alarms, event.id, alarm_file)
        if gt == "FileExec":
            s_target_ = torch.tensor([0.0, s_tags[1], s_tags[2], s_tags[3]])
        else:
            s_target_ = torch.tensor([1.0, s_tags[1], s_tags[2], s_tags[3]])

    if event_type in {'load'}:
        if o.isFile():
            if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(s.tags()))):
                # if not alarms[(s.get_pid(), o.get_name())]:
                alarm_sum[1] = alarm_sum[1] + 1
                alarm_result = prtSOAlarm(ts,"FileExec", s, o, alarms, event.id, alarm_file)
            if gt == "FileExec":
                s_target_ = torch.tensor([0.0, s_tags[1], s_tags[2], s_tags[3]])
            else:
                s_target_ = torch.tensor([1.0, s_tags[1], s_tags[2], s_tags[3]])

    # Not Used
    if event_type in {'inject'}:
        if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(o.tags()))):
            alarm_result = prtSSAlarm(ts,"Inject", s, o,event.id, alarm_file)
            alarm_sum[1] = alarm_sum[1] + 1
        if gt == "Inject":
            o_target_ = torch.tensor([0.0, o_tags[1], o_tags[2], o_tags[3]])
        else:
            o_target_ = torch.tensor([1.0, o_tags[1], o_tags[2], o_tags[3]])
   
    if event_type in {'write'}:
        if (not o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe\[") and not o.isMatch("pipe") and not o.isMatch("null")):
            if (itag(alarmarg.origtags) > 0.5 and itag(o.tags()) <= 0.5):
                if not created.get((s.get_pid(), o.get_name()), False):
                    # if not alarms[(s.get_pid(), o.get_name())]:
                    alarm_sum[1] = alarm_sum[1] + 1
                    alarm_result = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, alarm_file)
            if gt == "FileCorruption":
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])
            else:
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])
            

        if o.isIP():
            if (itag(s.tags()) < 0.5 and ctag(s.tags()) < 0.5):
                if itag(o.tags()) < 0.5:
                    # if not alarms[(s.get_pid(), o.get_name())]:
                    alarm_sum[1] = alarm_sum[1] + 1
                    alarm_result = prtSOAlarm(ts, "DataLeak", s, o, alarms, event.id, alarm_file)
            if gt == "DataLeak":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, 0.0])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, 1.0])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])

   
   
    #    setuid(s, _, ts) --> {
    #       if (itag(subjTags(s)) < 128 && !rootprinc) {
    #          if (isRoot(sowner(s))) {
    #             prtSAlarm(ts, "PrivilegeEscalation", s)
    #             talarms = talarms + 1
    #    }
    #       }
    #    }
    if event_type in {'set_uid'}:
        # if isRoot(morse.Principals[o.owner]) and alarmarg.rootprinc == False:
        if itag(s.tags()) < 0.5:
            alarm_result = prtSAlarm(ts, "PrivilegeEscalation", s, event.id, alarm_file)
            alarm_sum[1] = alarm_sum[1] + 1
        if gt == "PrivilegeEscalation":
            s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
        else:
            s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
   
    if event_type in {'mmap'}:
        if o.isFile() == False:
            it = itag(s.tags())
            # prm = int(event['properties']['map']['protection'])
            # if ((prm & int('01',8)) == int('01',8)):
            if 'PROT_EXEC' in set(event.parameters):
                if it < 0.5:
                    # if not alarms[(s.get_pid(), o.get_name())]:
                    alarm_sum[1] = alarm_sum[1] + 1
                    alarm_result = prtSOAlarm(ts, "MkMemExecutable", s, o, alarms, event.id, alarm_file)
                if gt == "MkMemExecutable":
                    s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
                else:
                    s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
    
    if event_type in {'mprotect'}:
        it = itag(s.tags())
        # prm = int(event['properties']['map']['protection'])
        # if ((prm & int('01',8)) == int('01',8)):
        if 'PROT_EXEC' in set(event.parameters):
            if it < 0.5:
                # if not alarms[(s.get_pid(), o.get_name())]:
                alarm_sum[1] = alarm_sum[1] + 1
                alarm_result = prtSOAlarm(ts, "MkMemExecutable", s, o, alarms, event.id, alarm_file)
            if gt == "MkMemExecutable":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
   
   

    # open(s, _, _, ts) \/ close(s, _, ts) \/ chown_pre(s, _, _, ts) \/
    #    chmod(s, _, _, ts) \/ mprotect(s, _, _, ts) \/ mmap_pre(s, _, _, ts) \/
    #    remove_pre(s, _, ts) \/ rename_pre(s, _, _, _, ts) \/ clone(s, _, _, ts) \/
    #    read(s, _, _, _, ts) \/ load(s, _, _, _, ts) \/ execve(s, _, _, ts) \/
    #    inject(s, _, _, ts) \/ setuid(s, _, ts) \/ create(s, _, ts) \/ 
    #    write(s, _, _, _, ts)  --> {
    #    if (start_ts == 0) start_ts = ts
    #    else if (ts - start_ts >= 3600000000) {
    #       start_ts = ts
    #       print("Total Alarms: ", talarms)
    #       talarms = 0
    #    }
    
    # if 0 <= event_type < len(standard_events):
    #    if alarm_sum[0] == 0:
    #       alarm_sum[0] = ts
    #    elif ts - alarm_sum[0] >= 3600000000:
    #       alarm_sum[0] = ts
    #       print("Total Alarms: ", alarm_sum[1])
    #       alarm_sum[1] = 0

    alarm_s_loss = alarmarg.s_loss
    alarm_o_loss = alarmarg.o_loss
    if alarm_s_loss or alarm_o_loss:
        grad_before_prop = True
        s_tags = alarmarg.s_tags
        o_tags = alarmarg.o_tags
    else:
        grad_before_prop = False
        
    if isinstance(s_target_, torch.Tensor):
        s_loss = s_tags - s_target_
        alarm_s_loss = torch.mean(torch.square(s_loss))
    if isinstance(o_target_, torch.Tensor):
        o_loss = o_tags - o_target_
        alarm_o_loss = torch.mean(torch.square(o_loss))

    return alarm_result, alarm_s_loss, alarm_o_loss, s_tags, o_tags, grad_before_prop