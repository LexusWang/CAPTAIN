import time
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag,ctag,itag,etag, isRoot, permbits
import pdb
from utils.utils import getTime

class AlarmArguments():
   def __init__(self) -> None:
       self.rootprinc = None

def prtSOAlarm(ts, an, s, o, alarms, event_id, event_type, alarmfile= None):
   if not alarms[(s.get_pid(), event_type, o.get_name())]:
      alarms[(s.get_pid(), event_type, o.get_name())] = True
      # alarm_info  = {'eventId': event_id, 'alarmType':'AlarmSO', 'time': getTime(ts), }
      if alarmfile:
         alarm_string = "{}, AlarmSO, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{}), Object:{} (name:{})".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln(), o.get_id(),o.get_name())
         alarm_string = alarm_string.replace('\n',' ')
         alarmfile.write(alarm_string+'\n')
      return an
   
def prtSSAlarm(ts, an, s, ss, event_id, alarmfile= None):
   if alarmfile:
      alarm_string = "{}, AlarmSS, Time:{}, Type:{}, Subject1:{} (pid:{} pname:{} cmdl:{}), Subject2:{} (pid:{} pname:{} cmdl:{})".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln(),ss.get_id(), ss.get_pid(), ss.get_name(), ss.get_cmdln())
      alarm_string = alarm_string.replace('\n',' ')
      alarmfile.write(alarm_string+'\n')
   return an

def prtSAlarm(ts, an, s, event_id, alarmfile= None):
   if alarmfile:
      alarm_string = "{}, AlarmS, Time:{}, Type:{}, Subject:{} (pid:{} pname:{} cmdl:{})".format(event_id, getTime(ts), an, s.get_id(), s.get_pid(), s.get_name(), s.get_cmdln())
      alarm_string = alarm_string.replace('\n',' ')
      alarmfile.write(alarm_string+'\n')
   return an

alarm_types = {"DataLeak", "MkFileExecutable", "FileExec", "MkMemExecutable", "FileCorruption", "PrivilegeEscalation", "Injection", "MaliciousFileCreation"}

def check_alarm(event, s, o, alarms, created, alarm_file = None, tau = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]):
   ts = event.time
   event_type = event.type
   alarm_result = None
   tag_indices = []
   tau_s_ci = tau[0]
   tau_s_e = tau[1]
   tau_s_i = tau[2]
   tau_s_c = tau[3]
   tau_o_ci = tau[4]
   tau_o_e = tau[5]
   tau_o_i = tau[6]
   tau_o_c = tau[7]

   if event_type in {'execve', 'load'}:
      if o.isFile():
         if isTRUSTED(citag(s.tags()), tau_s_ci) and itag(o.tags()) < tau_o_i:
            if not alarms[(s.get_pid(), event.type, o.get_name())]:
               alarm_result = prtSOAlarm(ts, "FileExec", s, o, alarms, event.id, event.type, alarm_file)
               tag_indices.extend([0, 6])

   if event_type in {'mmap', 'mprotect'}:
      if 'PROT_EXEC' in set(event.parameters):
         if itag(s.tags()) < tau_s_i:
            tag_indices.append(2)
            if o:
               alarm_result = prtSOAlarm(ts, "MkMemExecutable", s, o, alarms, event.id, event.type, alarm_file)
            else:
               alarm_result = prtSAlarm(ts, "MkMemExecutable", s, event.id, alarm_file)

   if event_type in {'write', 'remove', 'rename'}:
      if o.isIP() == False:
         if (itag(o.tags()) >= tau_o_i and itag(s.tags()) < tau_s_i):
         # if itag(s.tags()) < tau_s_i:
            if not created.get((s.get_pid(), o.get_name()), False):
               if not alarms[(s.get_pid(), event.type, o.get_name())]:
                  alarm_result = prtSOAlarm(ts, "FileCorruption", s, o, alarms, event.id, event.type, alarm_file)
                  tag_indices.append(2)
      elif o.isIP() and event_type == 'write':
         if itag(s.tags()) < tau_s_i:
            if ctag(s.tags()) < tau_s_c and ctag(o.tags()) >= tau_o_c:
               if not alarms[(s.get_pid(), event.type, o.get_name())]:
                  alarm_result = prtSOAlarm(ts, "DataLeak", s, o, alarms, event.id, event.type, alarm_file)
                  tag_indices.extend([2,3])
   
   if event_type in {'remove'}:  
      if o.isFile():
         if itag(o.tags()) < tau_o_i:
            if not alarms[(s.get_pid(), event.type, o.get_name())]:
               alarm_result = prtSOAlarm(ts, "RemoveIndicator", s, o, alarms, event.id, event.type, alarm_file)
               tag_indices.append(6)

   if event_type in {'create'}:
      if o.isFile():
         if itag(s.tags()) < tau_s_i:
            if not alarms[(s.get_pid(), event.type, o.get_name())]:
               alarm_result = prtSOAlarm(ts, "MaliciousFileCreation", s, o, alarms, event.id, event.type, alarm_file)
               tag_indices.append(2)

   if event_type in {'inject'}:
      if itag(s.tags()) < tau_s_i:
         alarm_result = prtSSAlarm(ts,"Inject", s, o,event.id, alarm_file)
         # Problem

   if event_type in {'set_uid'}:
      if event.parameters == 0:
         if itag(s.tags()) < tau_s_i:
            alarm_result = prtSAlarm(ts, "PrivilegeEscalation", s, event.id, alarm_file)
            tag_indices.append(2)

   if event_type in {'chmod'}:
      if isinstance(event.parameters, int) and ((event.parameters & int('0111',8)) != 0):
         if itag(o.tags()) < tau_o_i:
            if not alarms[(s.get_pid(), event.type, o.get_name())]:
               alarm_result = prtSOAlarm(ts, "MkFileExecutable", s, o, alarms, event.id, event.type, alarm_file)
               tag_indices.append(6)

   return alarm_result, tag_indices