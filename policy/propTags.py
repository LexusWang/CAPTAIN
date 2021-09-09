from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import citag, ctag, invtag, itag, etag, alltags, alltags2
from parse.eventType import lttng_events, cdm_events, standard_events

def isRoot(pric_id):
   #TODO
   pass

def propTags(event, s, o, whitelisted = False, att = 0.5, decay = 0.5, format = 'cdm'):
   if format == 'cdm':
      event_type = cdm_events[event['type']]
   elif format == 'lttng':
      event_type = lttng_events[event['type']]
   intags = None
   newtags = None
   whitelisted = False
   # att = 255 * (floatTags.intToFloat(getEnv("TAG_ATT"))/100)
   ab = att
   ae = att - (att/2)
   dpPow = decay
   dpi = 1.0/pow(2, dpPow)
   dpc = 1.0/pow(2, dpPow)

   if event_type in {standard_events['EVENT_LOADLIBRARY'],standard_events['EVENT_EXECUTE'],standard_events['EVENT_READ']}:
      intags = o.tags()
      whitelisted = False


   if event_type == standard_events['EVENT_LOADLIBRARY']:
      if (o.isMatch("/dev/null")==False and o.isMatch("libresolv.so.2")==False):
         stg = s.tags()
         cit = min(citag(stg), citag(intags))
         et = etag(stg)
         if (et > cit):
            et = cit
         inv = invtag(stg)
         if (cit == UNTRUSTED):
            inv = UNTRUSTED
         it = min(itag(stg), itag(intags))
         ct = ctag(stg)

         s.setSubjTags(alltags(cit, et, inv, it, ct))

   elif event_type == standard_events['EVENT_EXECUTE']:
      if (o.isMatch("/bin/bash")):
         whitelisted = True

      if (whitelisted == False):
         stg = s.tags()
         cit = citag(stg)
         et = etag(stg)
         if (citag(intags) == TRUSTED):
            if (cit == TRUSTED and et == TRUSTED):
               it = BENIGN
               ct = PUBLIC
            elif (cit == TRUSTED and et == UNTRUSTED):
               et = TRUSTED
               it = min(itag(stg), itag(intags))
               ct = min(ctag(stg), ctag(intags))
            else:
               cit = TRUSTED
               et = UNTRUSTED
               it = min(itag(stg), itag(intags))
               ct = min(ctag(stg), ctag(intags))
         else:
            cit = UNTRUSTED; et = UNTRUSTED
            it = min(itag(stg), itag(intags))
            ct = min(ctag(stg), ctag(intags))
         inv = UNTRUSTED
         s.setSubjTags(alltags(cit, et, inv, it, ct))

   elif event_type == standard_events['EVENT_WRITE']:
      stg = s.tags()
      otg = o.tags()
      it = itag(stg)
      ct = ctag(stg)

      if (citag(stg) == TRUSTED and etag(stg) == TRUSTED):
         it = it + ab
         ct = ct + ab
         it = min(1, it)
         ct = min(1, ct)
      elif (citag(stg) == TRUSTED and etag(stg) == UNTRUSTED): 
         it = it + ae
         ct = ct + ae
         it = min(1, it)
         ct = min(1, ct)

      it = min(itag(otg), it)
      ct = min(ctag(otg), ct)
      newtags = alltags2(it, ct)

      if (o.isIP() == False and o.isMatch("UnknownObject")== False):
         o.setObjTags(newtags); 

   elif event_type == standard_events['EVENT_READ']:
      if (s.isMatch("sshd")):
         stg = s.tags()
         cit = citag(stg)
         et = etag(stg)
         if (isRoot(s.owner) and cit == TRUSTED and et == TRUSTED ):
            s.setSubjTags(stg)
            whitelisted = True

      if (whitelisted == False and o.isMatch("UnknownObject")):
         stg = s.tags()
         whitelisted = True
         s.setSubjTags(alltags(citag(stg), etag(stg), invtag(stg), 0, ctag(stg)))

      if (whitelisted == False) and (o.isMatch("/.X11-unix/") or o.isMatch("/dev/null") or o.isMatch("/dev/pts")):
         whitelisted = True

      if (whitelisted == False):
         stg = s.tags()
         it = itag(stg)
         oit = itag(intags)
         ct = ctag(stg)
         oct = ctag(intags)
         if (invtag(stg) !=  TRUSTED):
            it = min(it, oit)
            ct = min(ct, oct)
         s.setSubjTags(alltags(citag(stg), etag(stg), invtag(stg), it, ct))
      
   elif event_type == standard_events['EVENT_CREATE_OBJECT']:
      st = s.tags(); 
      sit = itag(st)
      cit = ctag(st)
      if (citag(st) == TRUSTED and etag(st) == TRUSTED):
         o.setObjTags(alltags2(BENIGN, PUBLIC))
      else:
         o.setObjTags(alltags2(sit, cit))
   
   if 0 <= event_type < len(standard_events) and s and o:
      diff = 0
      stg = s.tags()
      fit = itag(stg)
      fct = ctag(stg)
      et = etag(stg)
      inv = invtag(stg)
      ts = event['timestamp']
      if (s.updateTime == 0):
         s.updateTime = ts
      elif (et == TRUSTED and fit < 1):
         diff = ts - s.updateTime / 4000000
         temp = pow(dpi, diff)
         nit = temp * fit + (1 - temp) * 0.75
         temp = pow(dpc, diff)
         nct = temp * fct + (1 - temp) * 0.75
         it = max(it, nit)
         ct = max(ct, nct)
         s.setSubjTags(alltags(citag(stg), et, inv, it, ct))
      
      elif (citag(stg) == TRUSTED and et == UNTRUSTED and fit < 0.5):
         diff = ts - s.updateTime / 4000000
         temp = pow(dpi, diff)
         nit = temp * fit + (1 - temp) * 0.45
         temp = pow(dpc, diff)
         nct = temp * fct + (1 - temp) * 0.45
         if (nit < 0.5):
            it = max(it, nit)
            ct = max(ct, nct)
      
         s.setSubjTags(alltags(citag(stg), et, inv, it, ct))
      
      stg = s.tags()
      if ((itag(stg)> 127 and etag(stg)==UNTRUSTED) or etag(stg)>citag(stg)):
         print("DANGER!!!")



# module propTags() {
#    unsigned intags, newtags;
#    bool whitelisted;
#    double att = 255 * (intToFloat(getEnv("TAG_ATT"))/100);
#    unsigned ab = roundtoInt(att);
#    unsigned ae = roundtoInt(att - (att/2));
#    unsigned dpPow = getEnv("DECAY");
#    double dpi = 1.0/pow(2, dpPow);
#    double dpc = 1.0/pow(2, dpPow);
 
#    dict(Subj, long) updateTab;

#    read_pre(_, o, _, useful, _) \/ 
#       load_pre(_, o, useful, _, _) \/
#       execve_pre(_, o, _, _) -->  {
#       intags = objTags(o);
#       whitelisted = false;
#    }


#    subjread_pre(_, s, useful, _) \/ inject_pre(s, _, useful, _) 
#       --> intags = subjTags(s);


#    read(s, _, _, useful, _) --> {
#       if (isSMatch(s, "sshd")) { 
      #    unsigned stg = subjTags(s);
      #    unsigned cit = citag(stg);
      #    unsigned et = etag(stg);
      #    if (isRoot(sowner(s)) && cit == TRUSTED && et == TRUSTED ) {
      #       setSubjTags(s, stg);
      #       whitelisted = true;
      #    }
      # } 
#    }
   
#    read(s, o, _, useful, _) --> {
#       if (!whitelisted && isMatch(o, "UnknownObject")) {
# 	 unsigned stg = subjTags(s);
# 	 whitelisted = true;
# 	 setSubjTags(s, alltags(citag(stg), etag(stg), invtag(stg), 0, ctag(stg)));
#       }
#    }

#    read(s, o, _, useful, _) --> {
#       if (!whitelisted && isMatch(o, "/.X11-unix/") || isMatch(o, "/dev/null") 
# 		      || isMatch(o, "/dev/pts")) {
#          unsigned stg = subjTags(s);
#          whitelisted = true;
#          setSubjTags(s, stg);
#       }
#    }

#    read(s, o, _, useful, _) --> {
#       if (!whitelisted) {
#          unsigned stg = subjTags(s);
#          unsigned it = itag(stg);
#          unsigned oit = itag(intags);
#          unsigned ct = ctag(stg);
#          unsigned oct = ctag(intags);
#          if (invtag(stg) !=  TRUSTED) {
#             it = min(it, oit);
#             ct = min(ct, oct);
   
#          }

#          setSubjTags(s, alltags(citag(stg), etag(stg), invtag(stg), it, ct));
#       }
#    }

#    subjread(s, ss, _, useful) --> {
#       if (!whitelisted) {
#          unsigned stg = subjTags(s);
#          unsigned it = itag(stg);
#          unsigned ssit = itag(intags);
#          unsigned ct = ctag(stg);
#          unsigned ssct = ctag(intags);
#          if (invtag(stg) !=  TRUSTED) {
#             it = min(it, ssit);
#             ct = min(ct, ssct);
   
#          }

#          setSubjTags(s, alltags(citag(stg), etag(stg), invtag(stg), it, ct));
#       }
#    }


   # load(s, o, useful, _, _) --> {
   #    if (!isMatch(o, "/dev/null") && !isMatch(o, "libresolv.so.2")) {
   #       unsigned stg = subjTags(s);
	#  unsigned cit = min(citag(stg), citag(intags));
	#  unsigned et = etag(stg);
	#  unsigned inv, it, ct;
	#  if (et > cit) et = cit;
	#  inv = invtag(stg);
	#  if (cit == UNTRUSTED) inv = UNTRUSTED;
	#  it = min(itag(stg), itag(intags));
	#  ct = ctag(stg);

	#  setSubjTags(s, alltags(cit, et, inv, it, ct));
   #    }
   # }
  
   
#    execve(s, o, _, _)  --> {
#       if (isMatch(o, "/bin/bash")) {
#          unsigned stg = subjTags(s);
#          whitelisted = true;
# 	 setSubjTags(s, alltags(citag(stg), etag(stg), invtag(stg), itag(stg), 
# 				 itag(stg)));
#       }

#    }

#    execve(s, _, _, _) --> {
#       if (!whitelisted) {
#          unsigned stg = subjTags(s);
#          unsigned cit = citag(stg);
#          unsigned et = etag(stg);
#          unsigned inv, it, ct;
#          if (citag(intags) == TRUSTED) {
#             if (cit == TRUSTED && et == TRUSTED)  {
#                it = BENIGN; ct = PUBLIC;
#             }
#             else if (cit == TRUSTED && et == UNTRUSTED) {
#                et = TRUSTED;
#                it = min(itag(stg), itag(intags));
#                ct = min(ctag(stg), ctag(intags));
#             }
#             else {
#                cit = TRUSTED; et = UNTRUSTED;
#                it = min(itag(stg), itag(intags));
#                ct = min(ctag(stg), ctag(intags));
#             }
#          }
#          else {
#             cit = UNTRUSTED; et = UNTRUSTED;
#             it = min(itag(stg), itag(intags));
#             ct = min(ctag(stg), ctag(intags));
#          }  
#          inv = UNTRUSTED;
#          setSubjTags(s, alltags(cit, et, inv, it, ct));
#       }
#    }

#    inject(_, s, useful, _)|useful --> {
#       unsigned stg = subjTags(s);
#       unsigned cit = min(citag(stg), citag(intags));
#       unsigned et, inv, it, ct;
#       if (cit == TRUSTED && itag(intags) < 128) cit = UNTRUSTED;
#       et = etag(stg);
#       if (et > cit) et = cit;
#       inv = invtag(stg);
#       if (cit == UNTRUSTED) inv = UNTRUSTED;
#       it = min(itag(stg), itag(intags));
#       ct = min(ctag(stg), ctag(intags));
       
#       setSubjTags(s, alltags(cit, et, inv, it, ct));

#    }

#    setuid(s, p, _ts) --> {
#       unsigned st = subjTags(s);
#       if (!isRoot(p) && invtag(st) == TRUSTED)
#          setSubjTags(s, alltags(citag(st), etag(st), 0, itag(st), ctag(st)));
#    }


#    create(sb, o, _) --> {
#       unsigned st = subjTags(sb); 
#       unsigned sit = itag(st);
#       unsigned cit = ctag(st);
#       if (citag(st) == TRUSTED && etag(st) == TRUSTED)
#          setObjTags(o, alltags2(BENIGN, PUBLIC));
#       else
#          setObjTags(o, alltags2(sit, cit));
#    }
  
#    write_pre(s, o, useful, _, _) --> {
#       unsigned stg = subjTags(s);
#       unsigned otg = objTags(o);
#       unsigned it = itag(stg);
#       unsigned ct = ctag(stg);
#       if (citag(stg) == TRUSTED && etag(stg) == TRUSTED) {
#          it = it + ab;
# 	 ct = ct + ab;
# 	 if (it > 255) it = 255;
# 	 if (ct > 255) ct = 255;
#       }
#       else if (citag(stg) == TRUSTED && etag(stg) == UNTRUSTED) {
#          it = it + ae;
# 	 ct = ct + ae;
# 	 if (it > 255) it = 255;
# 	 if (ct > 255) ct = 255;
#       }
#       it = min(itag(otg), it);
#       ct = min(ctag(otg), ct);
      
#       newtags = alltags2(it, ct);
    
#    }


#    write(s, o, useful, _, _) --> 
#       if !isIP(o) && !isMatch(o, "UnknownObject")
#          setObjTags(o, newtags);
  
#    tagCompare(dst, src, type) --> {
#       unsigned rv;
#       if ((itag(dst) < itag(src) && type == 0) ||
#           (ctag(dst) < ctag(src) && type == 1)) rv = 0;
#       if ((itag(dst) == itag(src) && type == 0) ||
#           (ctag(dst) == ctag(src) && type == 1)) rv = 1;
#       else rv = 2;
#       setrv(rv);
#    }

#    open(s, _, _, ts) \/ close(s, _, ts) \/ chown_pre(s, _, _, ts) \/
#       chmod(s, _, _, ts) \/ mprotect(s, _, _, ts) \/ mmap_pre(s, _, _, ts) \/
#       remove_pre(s, _, ts) \/ rename_pre(s, _, _, _, ts) \/ clone(s, _, _, ts) \/
#       read(s, _, _, useful, ts)|useful \/  load(s, _, useful, _, ts)|useful \/ 
#       execve(s, _, _, ts) \/ inject(s, _, useful, ts)|useful \/ setuid(s, _, ts) \/ create(s, _, ts) \/ 
#       write(s, _, useful, _, ts)|useful \/ subjread(s,_, useful, ts)|useful  --> {
#       double diff = 0;
#       unsigned stg = subjTags(s);
#       unsigned it = itag(stg);
#       double fit = intToFloat(it)/255;
#       unsigned ct = ctag(stg);
#       double fct = intToFloat(it)/255;
#       unsigned et = etag(stg);
#       unsigned inv = invtag(stg); 
#       double upd, temp;
#       unsigned nit, nct;
#       if (updateTab[s] == 0) 
#          updateTab[s] = ts;
#       else if (et == TRUSTED && it < 255) {
#          diff = intToFloat(ts - updateTab[s]) / 4000000 ;
#          temp = pow(dpi, diff);
#          upd = temp * fit + (1 - temp) * 0.75;
#          nit = roundtoInt(upd * 255);
#          temp = pow(dpc, diff);
#          upd = temp * fct + (1 - temp) * 0.75;
#          nct = roundtoInt(upd * 255);
#          it = max(it, nit);
#          ct = max(ct, nct);
#          setSubjTags(s, alltags(citag(stg), et, inv, it, ct));
#       }
#       else if (citag(stg) == TRUSTED && et == UNTRUSTED && fit < 0.5) {
#          diff = intToFloat(ts - updateTab[s]) / 4000000;
#          temp = pow(dpi, diff);
#          upd = temp * fit + (1 - temp) * 0.45;
#          nit = roundtoInt(upd * 255);
#          temp = pow(dpc, diff);
#          upd = temp * fct + (1 - temp) * 0.45;
#          nct = roundtoInt(upd * 255);
#          if (nit < 0.5) {
#             it = max(it, nit);
#             ct = max(ct, nct);
#          }
#          setSubjTags(s, alltags(citag(stg), et, inv, it, ct));
#       }
#       stg = subjTags(s);
#       if ((itag(stg)> 127 && etag(stg)==UNTRUSTED) || etag(stg)>citag(stg))
#          print("DANGER!!!");
#    }

#    printTags(newtags, cit) --> {
#       prtTags(newtags, cit);
#    }
# }