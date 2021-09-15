import time
import sys
sys.path.extend(['.','..','...'])

# import floatTags
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import citag,ctag,invtag,itag,etag,alltags
from parse.eventType import lttng_events, cdm_events, standard_events

def printTime(ts):
   print(ts)

def prtSOAlarm(ts, an, s, o, alarms):
   if not alarms[(s.get_pid(), o.get_name())]:
      print("AlarmS ")
      printTime(ts)
      alarms[(s.get_pid(), o.get_name())] = True
      print(": Alarm: ", an, ": Object ", o.get_id(), " (", o.get_name(), 
             ") Subject ", s.get_id(), " pid=", s.get_pid(), " ", s.get_cmdln(), " AlarmE" ,"\n")
      # setAlarm(s, o, an, ts)
   

def prtSSAlarm(ts, an, s, ss):
   print("AlarmS ")
   printTime(ts)
   # Question
   # print(": Alarm: ", an, ": Subject ", s.get_subjid(), " pid=", s.get_pid(),
   #        " ", s.get_cmdln(), " Subject ", ssubjid(ss), " pid=", ss.get_pid(), " ", ss.get_cmdln(), " AlarmE", "\n")
   print(": Alarm: ", an, ": Subject ", s.get_id(), " pid=", s.get_pid(),
          " ", s.get_cmdln(), " Subject ", ss.get_id(), " pid=", ss.get_pid(), " ", ss.get_cmdln(), " AlarmE", "\n")


def prtSAlarm(ts, an, s):
   print("AlarmS ")
   printTime(ts)
   print(": Alarm: ", an, ": Subject ", s.get_id(), " pid=", s.get_pid()," ", s.get_cmdln(), " AlarmE", "\n")

def check_alarm_pre(event, s, o, alarms, created, alarm_sum, format = 'cdm'):
   ts = event['timestamp']
   if format == 'cdm':
      event_type = cdm_events[event['type']]
   elif format == 'lttng':
      event_type = lttng_events[event['type']]

   origtags = None

   if event_type in {standard_events['EVENT_READ'],standard_events['EVENT_EXECUTE'],standard_events['EVENT_LOADLIBRARY']}:
      origtags = s.tags()

   # write_pre(_, o, useful, _, _)|useful --> origtags = o.tags()
   if event_type == standard_events['EVENT_WRITE']:
      origtags = o.tags()

   # setuid_pre(s, _, ts) --> {
   #    if (itag(subjTags(s)) < 128) {
   #       rootprinc = isRoot(sowner(s));
   #    }
   # }
   if event_type == standard_events['EVENT_WRITE']:
      origtags = o.tags()

   #    remove_pre(s, o, ts) --> {
   #       if (itag(objTags(o)) > 127 && itag(subjTags(s)) < 128 && !isMatch(o, "null")  ) {
   #          if (!alarms[(pid(s), name(o))]) talarms = talarms + 1
   #          prtSOAlarm(ts, "FileCorruption", s, o, alarms)
   #       }
   #    }
   
  
   #    rename_pre(s, o, _, _, ts) --> {
   #       if (itag(objTags(o)) > 127 && itag(subjTags(s)) < 128 && !isMatch(o, "null") ) {
   #          if (!alarms[(pid(s), name(o))]) talarms = talarms + 1
   #          prtSOAlarm(ts, "FileCorruption", s, o, alarms)
   #       }

   #    }

   if event_type == standard_events['EVENT_RENAME']:
      if itag(o.tags()) > 0.5 and itag(s.tags()) < 0.5 and o.isMatch("null")==False:
         if not alarms[(s.get_pid(), o.get_name())]:
            alarm_sum[1] = alarm_sum[1] + 1
         prtSOAlarm(ts, "FileCorruption", s, o, alarms)

   #    chmod_pre(s, o, p, ts) --> {
   #       unsigned ositag = itag(objTags(o))
   #       unsigned prm = permbits(p)
      
   #       if (ositag < 128 && ((prm & 0111) != 0)) {
   #    if (!alarms[(pid(s), name(o))]) talarms = talarms + 1
   #          prtSOAlarm(ts, "MkFileExecutable", s, o, alarms)
   #       }
   #    }
   '''
   if event_type == standard_events['sys_chmod']:
      ositag = itag(objTags(o))
      prm = permbits(p)
      
      if (ositag < 128 && ((prm & 0111) != 0)):
         if (!alarms[(pid(s), name(o))]):
            talarms = talarms + 1
         prtSOAlarm(ts, "MkFileExecutable", s, o, alarms)
   '''

   return origtags


def check_alarm(event, s, o, alarms, created, alarm_sum, origtags, format = 'cdm'):
   ts = event['timestamp']
   if format == 'cdm':
      event_type = cdm_events[event['type']]
   elif format == 'lttng':
      event_type = lttng_events[event['type']]
   # print(s.tags())
   # print(o.tags())
   # print("================")


   if event_type == standard_events['EVENT_CREATE_OBJECT']:
      created[(s.get_pid(), o.get_name())] = True
      

   if event_type == standard_events['EVENT_EXECUTE']:
      # if citag(s.tags()) == UNTRUSTED:
      if (citag(origtags) == TRUSTED and citag(s.tags()) == UNTRUSTED):
         if (alarms[(s.get_pid(), o.get_name())]==False):
            alarm_sum[1] = alarm_sum[1] + 1
         prtSOAlarm(ts,"FileExec", s, o, alarms)
         

   #    load(s, o, useful, _, ts)|useful --> 
   #       if (citag(origtags) == TRUSTED && citag(subjTags(s)) == UNTRUSTED) {
   #    if (!alarms[(pid(s), name(o))]) talarms = talarms + 1
   #          prtSOAlarm(ts,"FileExec", s, o, alarms)
   #       }
   if event_type == standard_events['EVENT_LOADLIBRARY']:
      if (citag(origtags) == TRUSTED and citag(s.tags()) == UNTRUSTED):
         if not alarms[(s.get_pid(), o.get_name())]:
            alarm_sum[1] = alarm_sum[1] + 1
         prtSOAlarm(ts,"FileExec", s, o, alarms)

   #    inject(s, ss, useful, ts)|useful --> 
   #       if (citag(origtags) == TRUSTED && citag(subjTags(ss)) == UNTRUSTED) {
   #          prtSSAlarm(ts,"Inject", s, ss)
   #          talarms = talarms + 1
   #       }
   
   if event_type == standard_events['EVENT_WRITE']:
      if (o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe[") and not o.isMatch("pipe") and not o.isMatch("null") and itag(origtags) > 0.5 and itag(o.tags()) <= 0.5):
         if not created[(s.get_pid(), o.get_name())]:
            if not alarms[(s.get_pid(), o.get_name())]:
               alarm_sum[1] = alarm_sum[1] + 1
               prtSOAlarm(ts, "FileCorruption", s, o, alarms)

         if (itag(s.tags()) < 128 and ctag(s.tags()) < 128):
            if (o.isIP() and itag(o.tags()) < 128):
               if not alarms[(s.get_pid(), o.get_name())]:
                  alarm_sum[1] = alarm_sum[1] + 1
               prtSOAlarm(ts, "DataLeak", s, o, alarms)
   
   
   #    setuid_pre(s, _, ts) --> {
   #       if (itag(subjTags(s)) < 128) {
   #          rootprinc = isRoot(sowner(s))
   #       }
   #    }

   #    setuid(s, _, ts) --> {
   #       if (itag(subjTags(s)) < 128 && !rootprinc) {
   #          if (isRoot(sowner(s))) {
   #             prtSAlarm(ts, "PrivilegeEscalation", s)
   #             talarms = talarms + 1
   #    }
   #       }
   #    }
   

   #    mprotect(s, o, p, ts) --> {
   #       unsigned it = itag(subjTags(s))
   #       unsigned prm = permbits(p)
      
   #       if (it < 128 && ((prm & 0100) == 0100)) {
   #    if (!alarms[(pid(s), name(o))]) talarms = talarms + 1
   #          prtSOAlarm(ts, "MkMemExecutable", s, o, alarms)
   #       }
   #    }
   '''
   if event_type == standard_events['EVENT_MPROTECT']:
      it = itag(s.tags())
      prm = permbits(p)
      
      if (it < 0.5 and ((prm & 0100) == 0100)):
         if not alarms[(pid(s), name(o))]:
            alarm_sum[1] = alarm_sum[1] + 1
         prtSOAlarm(ts, "MkMemExecutable", s, o, alarms)
   '''
   

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
   
   if 0 <= event_type < len(standard_events):
      if alarm_sum[0] == 0:
         alarm_sum[0] = ts
      elif ts - alarm_sum[0] >= 3600000000:
         alarm_sum[0] = ts
         print("Total Alarms: ", alarm_sum[1])
         alarm_sum[1] = 0