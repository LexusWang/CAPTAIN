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
         alarm_string = "{}, AlarmSO, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{}), Object:{} (name:{})\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln(), o.get_id(),o.get_name())
         alarmfile.write(alarm_string)
      return an
   
def prtSSAlarm(ts, an, s, ss, event_id, alarmfile= None):
    # Question
    # print(": Alarm: ", an, ": Subject ", s.get_subjid(), " pid=", s.get_pid(),
    #        " ", s.get_cmdln(), " Subject ", ssubjid(ss), " pid=", ss.get_pid(), " ", ss.get_cmdln(), " AlarmE", "\n")
    if alarmfile:
        alarm_string = "{}, AlarmSS, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{}), Subject:{} (pid:{} pname:{} cmdl:{})\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln(),ss.get_id(), ss.get_pid(), ss.get_name(), ss.get_name())
        alarmfile.write(alarm_string)
    return an

def prtSAlarm(ts, an, s, event_id, alarmfile= None):
    if alarmfile:
        alarm_string = "{}, AlarmS, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{})\n".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln())
        alarmfile.write(alarm_string)
    return an

def check_alarm(event, s, o, alarms, created, alarm_file = None):
   ts = event.time
   event_type = event.type
   alarm_result = None

   if event_type in {'execve', 'load'}:
      if o.isFile():
         if isTRUSTED(citag(s.tags())) and itag(o.tags()) < 0.5:
            if not alarms[(s.get_pid(), o.get_name())]:
               alarm_result = prtSOAlarm(ts, "FileExec", s, o, alarms, event.id, alarm_file)

   if event_type in {'mmap', 'mprotect'}:
      if o and o.isFile() == False:
         if 'PROT_EXEC' in set(event.parameters):
            if itag(s.tags()) < 0.5:
               alarm_result = prtSAlarm(ts, "MkMemExecutable", s, event.id, alarm_file)
      else:
         if 'PROT_EXEC' in set(event.parameters):
            if itag(s.tags()) < 0.5:
               alarm_result = prtSAlarm(ts, "MkMemExecutable", s, event.id, alarm_file)
    
   if event_type in {'write', 'remove', 'rename'}:
      if o.isIP() == False:
         if (itag(o.tags()) >= 0.5 and itag(s.tags()) < 0.5):
            if not created.get((s.get_pid(), o.get_name()), False):
               if not alarms[(s.get_pid(), o.get_name())]:
                  alarm_result = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, alarm_file)
      elif o.isIP() and event_type == 'write':
         if itag(s.tags()) < 0.5:
            if  ctag(s.tags()) < 0.5 and ctag(o.tags()) >= 0.5:
               if not alarms[(s.get_pid(), o.get_name())]:
                  alarm_result = prtSOAlarm(ts, "DataLeak", s, o, alarms, event.id, alarm_file)

   # if event_type in {'inject'}:
   #    if (isTRUSTED(citag(alarmarg.origtags)) and isUNTRUSTED(citag(o.tags()))):
   #       alarm_result = prtSSAlarm(ts,"Inject", s, o,event.id, alarm_file)

   if event_type in {'set_uid'}:
      if itag(s.tags()) < 0.5:
         alarm_result = prtSAlarm(ts, "PrivilegeEscalation", s, event.id, alarm_file)

   if event_type in {'chmod'}:
      prm = event.parameters
      if ((prm & int('0111',8)) != 0):
         if itag(o.tags()) < 0.5:
            if not alarms[(s.get_pid(), o.get_name())]:
               alarm_result = prtSOAlarm(ts, "MkFileExecutable", s, o, alarms, event.id, alarm_file)
   
   return alarm_result