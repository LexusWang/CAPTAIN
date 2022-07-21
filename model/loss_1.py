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
from parse.eventType import SET_UID_SET, lttng_events, cdm_events, standard_events
from parse.eventType import READ_SET, LOAD_SET, EXECVE_SET, WRITE_SET, INJECT_SET, CREATE_SET, RENAME_SET, MPROTECT_SET, REMOVE_SET, CHMOD_SET

class AlarmArguments():
   
   def __init__(self) -> None:
       self.rootprinc = None

def printTime(ts):
   # Transfer time to ET
   time_local = time.localtime((ts/1000000000) + 3600)
   dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
   print(dt, end='')

def getTime(ts):
   # Transfer time to ET
   time_local = time.localtime((ts/1000000000) + 3600)
   dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
   return dt

def prtSOAlarm(ts, an, s, o, alarms, event_id, alarmfile= None):
    if not alarms[(s.get_pid(), o.get_name())]:
        alarms[(s.get_pid(), o.get_name())] = True
        if alarmfile:
            # with open(alarmfile, 'a') as fout:
            alarm_string = "{} AlarmS {} : Alarm: {} : Object {} ({}) Subject {}  pid={} {}  AlarmE\n".format(event_id, getTime(ts), an, o.get_id(),o.get_name(), s.get_id(), s.get_pid(), s.get_cmdln())
            alarmfile.write(alarm_string)
        return an
   

def prtSSAlarm(ts, an, s, ss, event_id, alarmfile= None):
    # Question
    # print(": Alarm: ", an, ": Subject ", s.get_subjid(), " pid=", s.get_pid(),
    #        " ", s.get_cmdln(), " Subject ", ssubjid(ss), " pid=", ss.get_pid(), " ", ss.get_cmdln(), " AlarmE", "\n")
    if alarmfile:
        # with open(alarmfile, 'a') as fout:
        alarm_string = "{} AlarmS {} : Alarm: {} : Subject {} pid={} {} Subject {} pid={} {} AlarmE\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_cmdln(),ss.get_id(), ss.get_pid(), ss.get_cmdln())
        alarmfile.write(alarm_string)
    return an


def prtSAlarm(ts, an, s, event_id, alarmfile= None):
    if alarmfile:
        # with open(alarmfile, 'a') as fout:
        alarm_string = "{} AlarmS {} : Alarm: {} : Subject {} pid={} {} AlarmE\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_cmdln())
        alarmfile.write(alarm_string)
    return an

def check_alarm_pre(event, s, o, alarms, created, alarm_sum, gt, format = 'cdm', morse = None, alarm_file = None):
    if event['uuid'] == '1FE4A44E-9FAB-3A3F-6DAA-1DD31338C216':
        a = 0
    ts = event['timestamp']
    if format == 'cdm':
       event_type = cdm_events[event['type']]
    elif format == 'lttng':
       event_type = lttng_events[event['type']]

    s_loss, o_loss = torch.zeros(4, requires_grad=True), torch.zeros(4, requires_grad=True)
    s_tags = torch.tensor(s.tags(),requires_grad=True)
    o_tags = torch.tensor(o.tags(),requires_grad=True)
    s_target_ = False
    o_target_ = False

    alarmarg = AlarmArguments()
    alarmarg.origtags = None
    alarmarg.pre_alarm = None
    alarmarg.s_loss = None
    alarmarg.o_loss = None
    alarmarg.s_tags = None
    alarmarg.o_tags = None

    if event_type in READ_SET or event_type in LOAD_SET or event_type in EXECVE_SET or event_type in INJECT_SET or event_type in MPROTECT_SET:
       alarmarg.origtags = s.tags()

    if event_type in WRITE_SET:
       alarmarg.origtags = o.tags()

    if event_type in INJECT_SET:
       alarmarg.origtags = o.tags()

    if event_type in SET_UID_SET:
        if (itag(s.tags()) < 0.5):
            alarmarg.rootprinc = isRoot(morse.Principals[s.owner])

    if event_type in REMOVE_SET:
        assert isinstance(o,Object) and isinstance(s,Subject)
        if o.isMatch("null") == False:
            if (itag(o.tags()) > 0.5 and itag(s.tags()) < 0.5):
                if not alarms[(s.get_pid(), o.get_name())]:
                   alarm_sum[1] = alarm_sum[1] + 1
                alarmarg.pre_alarm = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event['uuid'], alarm_file)
            if gt == "FileCorruption":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])
  

    if event_type in RENAME_SET :
        if o.isMatch("null")==False:
            if itag(o.tags()) > 0.5 and itag(s.tags()) < 0.5:
                if not alarms[(s.get_pid(), o.get_name())]:
                    alarm_sum[1] = alarm_sum[1] + 1
                alarmarg.pre_alarm = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event['uuid'], alarm_file)
            if gt == "FileCorruption":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])


    if event_type in CHMOD_SET:
        ositag = itag(o.tags())
        prm = permbits(event)
        if ((prm & int('0111',8)) != 0):
            if ositag < 0.5:
                if (alarms[(s.get_pid(), o.get_name())] == False):
                    alarm_sum[1] = alarm_sum[1] + 1
                alarmarg.pre_alarm = prtSOAlarm(ts, "MkFileExecutable", s, o, alarms, event['uuid'], alarm_file)
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


def check_alarm(event, s, o, alarms, created, alarm_sum, alarmarg, gt, format = 'cdm', morse = None, alarm_file = None):
    ts = event['timestamp']
    alarm_result = None

    s_loss, o_loss = torch.zeros(5, requires_grad=True), torch.zeros(4, requires_grad=True)
    s_tags = torch.tensor(s.tags(),requires_grad=True)
    o_tags = torch.tensor(o.tags(),requires_grad=True)
    s_target_ = False
    o_target_ = False

    if format == 'cdm':
        event_type = cdm_events[event['type']]
    elif format == 'lttng':
        event_type = lttng_events[event['type']]

    if alarmarg.pre_alarm != None:
        alarm_result = alarmarg.pre_alarm
    
    if event_type in CREATE_SET:
        created[(s.get_pid(), o.get_name())] = True  

    if event_type in EXECVE_SET:
        if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(s.tags()))):
            if not alarms[(s.get_pid(), o.get_name())]:
                alarm_sum[1] = alarm_sum[1] + 1
            alarm_result = prtSOAlarm(ts,"FileExec", s, o, alarms, event['uuid'], alarm_file)
        if gt == "FileExec":
            s_target_ = torch.tensor([0.0, s_tags[1], s_tags[2], s_tags[3]])
        else:
            s_target_ = torch.tensor([1.0, s_tags[1], s_tags[2], s_tags[3]])

    if event_type in LOAD_SET:
        if o.isFile():
            if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(s.tags()))):
                if not alarms[(s.get_pid(), o.get_name())]:
                    alarm_sum[1] = alarm_sum[1] + 1
                alarm_result = prtSOAlarm(ts,"FileExec", s, o, alarms, event['uuid'], alarm_file)
            if gt == "FileExec":
                s_target_ = torch.tensor([0.0, s_tags[1], s_tags[2], s_tags[3]])
            else:
                s_target_ = torch.tensor([1.0, s_tags[1], s_tags[2], s_tags[3]])

    # Not Used
    if event_type in INJECT_SET:
        if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(o.tags()))):
            alarm_result = prtSSAlarm(ts,"Inject", s, o,event['uuid'], alarm_file)
            alarm_sum[1] = alarm_sum[1] + 1
        if gt == "Inject":
            o_target_ = torch.tensor([0.0, o_tags[1], o_tags[2], o_tags[3]])
        else:
            o_target_ = torch.tensor([1.0, o_tags[1], o_tags[2], o_tags[3]])
   
    if event_type in WRITE_SET:
        if (not o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe\[") and not o.isMatch("pipe") and not o.isMatch("null")):
            if (itag(alarmarg.origtags) > 0.5 and itag(o.tags()) <= 0.5):
                if not created.get((s.get_pid(), o.get_name()), False):
                    if not alarms[(s.get_pid(), o.get_name())]:
                        alarm_sum[1] = alarm_sum[1] + 1
                    alarm_result = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event['uuid'], alarm_file)
            if gt == "FileCorruption":
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 0.0, o_tags[3]])
            else:
                o_target_ = torch.tensor([o_tags[0], o_tags[1], 1.0, o_tags[3]])
            

        if o.isIP():
            if (itag(s.tags()) < 0.5 and ctag(s.tags()) < 0.5):
                if itag(o.tags()) < 0.5:
                    if not alarms[(s.get_pid(), o.get_name())]:
                        alarm_sum[1] = alarm_sum[1] + 1
                    alarm_result = prtSOAlarm(ts, "DataLeak", s, o, alarms, event['uuid'], alarm_file)
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
    if event_type in SET_UID_SET:
        if isRoot(morse.Principals[o.owner]) and alarmarg.rootprinc == False:
            if itag(s.tags()) < 0.5:
                alarm_result = prtSAlarm(ts, "PrivilegeEscalation", s, event['uuid'], alarm_file)
                alarm_sum[1] = alarm_sum[1] + 1
            if gt == "PrivilegeEscalation":
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 0.0, s_tags[3]])
            else:
                s_target_ = torch.tensor([s_tags[0], s_tags[1], 1.0, s_tags[3]])
   

    #    mprotect(s, o, p, ts) --> {
    #       unsigned it = itag(subjTags(s))
    #       unsigned prm = permbits(p)
        
    #       if (it < 128 && ((prm & 0100) == 0100)) {
    #    if (!alarms[(pid(s), name(o))]) talarms = talarms + 1
    #          prtSOAlarm(ts, "MkMemExecutable", s, o, alarms)
    #       }
    #    }
   
    if event_type in MPROTECT_SET:
        it = itag(s.tags())
        # prm = permbits(event)
        prm = int(event['properties']['map']['protection'])
        # print(event['properties']['map']['protection'])

        if o.isFile() == False:
            if ((prm & int('01',8)) == int('01',8)):
                if it < 0.5:
                    if not alarms[(s.get_pid(), o.get_name())]:
                        alarm_sum[1] = alarm_sum[1] + 1
                    alarm_result = prtSOAlarm(ts, "MkMemExecutable", s, o, alarms, event['uuid'], alarm_file)
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