import time
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag,ctag,itag,etag, isRoot, permbits
import pdb

class AlarmArguments():
   def __init__(self) -> None:
       self.rootprinc = None

def getTime(ts):
   # Transfer time to ET
   time_local = time.localtime((ts/1e9) - 4*3600)
   dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
   return dt

def prtSOAlarm(ts, an, s, o, alarms, event_id, alarmfile= None):
      if not alarms[(s.get_pid(), o.get_name())]:
         alarms[(s.get_pid(), o.get_name())] = True
      if alarmfile:
         # with open(alarmfile, 'a') as fout:
         alarm_string = "{}, AlarmSO, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{}), Object:{} (name:{})\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln(), o.get_id(),o.get_name())
         alarmfile.write(alarm_string)
      return an
   

def prtSSAlarm(ts, an, s, ss, event_id, alarmfile= None):
    # Question
    # print(": Alarm: ", an, ": Subject ", s.get_subjid(), " pid=", s.get_pid(),
    #        " ", s.get_cmdln(), " Subject ", ssubjid(ss), " pid=", ss.get_pid(), " ", ss.get_cmdln(), " AlarmE", "\n")
    if alarmfile:
        # with open(alarmfile, 'a') as fout:
        alarm_string = "{}, AlarmSS, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{}), Subject:{} (pid:{} pname:{} cmdl:{})\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln(),ss.get_id(), ss.get_pid(), ss.get_name(), ss.get_name())
        alarmfile.write(alarm_string)
    return an


def prtSAlarm(ts, an, s, event_id, alarmfile= None):
    if alarmfile:
        # with open(alarmfile, 'a') as fout:
        alarm_string = "{}, AlarmS, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{})\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln())
        alarmfile.write(alarm_string)
    return an

def check_alarm_pre(event, s, o, alarms, morse = None, alarm_file = None):
   ts = event.time
   event_type = event.type

   alarmarg = AlarmArguments()
   alarmarg.origtags = None
   alarmarg.pre_alarm = None

   if event_type in {'read', 'load', 'execve', 'inject', 'mprotect'}:
      alarmarg.origtags = s.tags()

   if event_type in {'write'}:
      alarmarg.origtags = o.tags()

   if event_type in {'inject'}:
      alarmarg.origtags = o.tags()

   if event_type in {'set_uid'}:
      if (itag(s.tags()) < 0.5):
         alarmarg.rootprinc = isRoot(morse.Principals[s.owner])

   if event_type in {'remove', 'rename'}:
      assert isinstance(o,Object) and isinstance(s,Subject)
      if o.isMatch("null") == False: 
         if (itag(o.tags()) > 0.5 and itag(s.tags()) < 0.5): 
            if not alarms[(s.get_pid(), o.get_name())]: 
               alarmarg.alarm_trigger = [(o.get_name(), 'i', 'more than', 0.5), (s.get_name(), 'i', 'less than', 0.5)]
               alarmarg.pre_alarm = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, alarm_file)

   if event_type in {'chmod'}:
      prm = event.parameters
      if ((prm & int('0111',8)) != 0):
         if itag(o.tags()) < 0.5:
            if not alarms[(s.get_pid(), o.get_name())]:
               alarmarg.alarm_trigger = [(o.get_name(), 'i', 'less than', 0.5)]
               alarmarg.pre_alarm = prtSOAlarm(ts, "MkFileExecutable", s, o, alarms, event.id, alarm_file)
   
   return alarmarg


def check_alarm(event, s, o, alarms, created, alarm_sum, alarmarg, gt, morse = None, alarm_file = None):
   ts = event.time
   event_type = event.type
   alarm_result = None
   alarm_trigger = None

   if alarmarg.pre_alarm != None:
      alarm_result = alarmarg.pre_alarm
      alarm_trigger = alarmarg.alarm_trigger  

   if event_type in {'execve'}:
      if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(s.tags()))):
         if not alarms[(s.get_pid(), o.get_name())]:
            alarm_sum[1] = alarm_sum[1] + 1
            alarm_result = prtSOAlarm(ts, "FileExec", s, o, alarms, event.id, alarm_file)

   if event_type in {'load'}:
      if o.isFile():
         if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(s.tags()))):
            if not alarms[(s.get_pid(), o.get_name())]:
               alarm_sum[1] = alarm_sum[1] + 1
               alarm_result = prtSOAlarm(ts,"FileExec", s, o, alarms, event.id, alarm_file)

   # Not Used
   if event_type in {'inject'}:
      if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(o.tags()))):
         alarm_result = prtSSAlarm(ts,"Inject", s, o,event.id, alarm_file)
         alarm_sum[1] = alarm_sum[1] + 1
   
   if event_type in {'write'}:
      # if (not o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe\[") and not o.isMatch("pipe") and not o.isMatch("null")):
      if o.isIP() == False:
         if (itag(alarmarg.origtags) > 0.5 and itag(o.tags()) <= 0.5):
            if not created.get((s.get_pid(), o.get_name()), False):
               if not alarms[(s.get_pid(), o.get_name())]:
                  alarm_sum[1] = alarm_sum[1] + 1
                  alarm_result = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, alarm_file)
      elif o.isIP():
         if (itag(s.tags()) < 0.5 and ctag(s.tags()) < 0.5):
            if itag(o.tags()) < 0.5:
               if not alarms[(s.get_pid(), o.get_name())]:
                  alarm_sum[1] = alarm_sum[1] + 1
                  alarm_result = prtSOAlarm(ts, "DataLeak", s, o, alarms, event.id, alarm_file)
   
   if event_type in {'set_uid'}:
      # if isRoot(morse.Principals[o.owner]) and alarmarg.rootprinc == False:
      if itag(s.tags()) < 0.5:
         alarm_result = prtSAlarm(ts, "PrivilegeEscalation", s, event.id, alarm_file)
         alarm_sum[1] = alarm_sum[1] + 1

   if event_type in {'mmap'}:
      if o.isFile() == False:
         # prm = int(event['properties']['map']['protection'])
         # if ((prm & int('01',8)) == int('01',8)):
         if 'PROT_EXEC' in set(event.parameters):
            if itag(s.tags()) < 0.5:
               if o:
                  if not alarms[(s.get_pid(), o.get_name())]:
                     alarm_sum[1] = alarm_sum[1] + 1
                     alarm_result = prtSOAlarm(ts, "MkMemExecutable", s, o, alarms, event.id, alarm_file)
               else:
                  alarm_sum[1] = alarm_sum[1] + 1
                  alarm_result = prtSAlarm(ts, "MkMemExecutable", s, event.id, alarm_file)
    
   if event_type in {'mprotect'}:
      # prm = int(event['properties']['map']['protection'])
      # if ((prm & int('01',8)) == int('01',8)):
      if 'PROT_EXEC' in set(event.parameters):
         if itag(s.tags()) < 0.5:
            if o:
               if not alarms[(s.get_pid(), o.get_name())]:
                  alarm_sum[1] = alarm_sum[1] + 1
                  alarm_result = prtSOAlarm(ts, "MkMemExecutable", s, o, alarms, event.id, alarm_file)
            else:
               alarm_sum[1] = alarm_sum[1] + 1
               alarm_result = prtSAlarm(ts, "MkMemExecutable", s, event.id, alarm_file)
   
   
   return alarm_result