from graph.Subject import Subject
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag, ctag, invtag, itag, etag, alltags, alltags2, isRoot
from parse.eventType import EXECVE_SET, SET_UID_SET, lttng_events, cdm_events, standard_events
from parse.eventType import READ_SET, LOAD_SET, EXECVE_SET, WRITE_SET, INJECT_SET, CREATE_SET, CLONE_SET

def propTags_pre():
   pass

def propTags(event, s, o, whitelisted = False, att = 0.25, decay = 0, format = 'cdm', morse = None):
   if format == 'cdm':
      event_type = cdm_events[event['type']]
   elif format == 'lttng':
      event_type = lttng_events[event['type']]

   intags = None
   newtags = None
   whitelisted = False
   # att = 255 * (floatTags.intToFloat(getEnv("TAG_ATT"))/100)
   ab = att
   ae = att/2
   dpPow = decay
   dpi = 1.0/pow(2, dpPow)
   dpc = 1.0/pow(2, dpPow)

   if event_type in LOAD_SET or event_type in EXECVE_SET or event_type in READ_SET:
      intags = o.tags()
      whitelisted = False

   if event_type in READ_SET:
      if (s.isMatch("sshd")):
         stg = s.tags()
         cit = citag(stg)
         et = etag(stg)
         if (isRoot(morse.Principals[s.owner]) and isTRUSTED(cit) and isTRUSTED(et) ):
            s.setSubjTags(stg) # is this doing anything?
            # whitelisted = True

      if (whitelisted == False and o.isMatch("UnknownObject")):
         stg = s.tags()
         whitelisted = True
         s.setSubjTags(alltags(citag(stg), etag(stg), invtag(stg), 0, ctag(stg)))
         s.update_grad([1, 1, 1, 0, 1])

      if whitelisted == False and o.isMatch("/.X11-unix/") or o.isMatch("/dev/null") or o.isMatch("/dev/pts"):
         whitelisted = True

      if (whitelisted == False):
         stg = s.tags()
         it = itag(stg)
         oit = itag(intags)
         ct = ctag(stg)
         oct = ctag(intags)
         citag_grad = s.get_citag_grad()
         etag_grad = s.get_etag_grad()
         invtag_grad = s.get_invtag_grad()
         itag_grad = s.get_itag_grad()
         ctag_grad = s.get_ctag_grad()

         if (isTRUSTED(invtag(stg)) == False):
            if it > oit:
               itag_grad = o.get_itag_grad()
               s.setiTagInitID(o.getiTagInitID())
            it = min(it, oit)

            if ct > oct:
               ctag_grad = o.get_ctag_grad()
               s.setcTagInitID(o.getcTagInitID())
            ct = min(ct, oct)
         s.setSubjTags(alltags(citag(stg), etag(stg), invtag(stg), it, ct))
         s.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])

   elif event_type in LOAD_SET:
      if o.isMatch("/dev/null")==False and o.isMatch("libresolv.so.2")==False:
         # if (o.iTag+o.cTag) != 2:
         #    print(o.path)
         stg = s.tags()
         citag_grad = s.get_citag_grad()
         etag_grad = s.get_etag_grad()
         invtag_grad = s.get_invtag_grad()
         itag_grad = s.get_itag_grad()
         ctag_grad = s.get_ctag_grad()

         if citag(stg) > citag(intags):
            citag_grad = o.get_citag_grad()
            s.setciTagInitID(o.getciTagInitID())
         cit = min(citag(stg), citag(intags))

         et = etag(stg)
         if (et > cit):
            et = cit
            etag_grad = citag_grad
            s.seteTagInitID(s.getciTagInitID())
         inv = invtag(stg)
         if (isUNTRUSTED(cit)):
            inv = UNTRUSTED
            invtag_grad = 0
         if itag(stg) > itag(intags):
            itag_grad = o.get_itag_grad()
            s.setiTagInitID(o.getiTagInitID())
         it = min(itag(stg), itag(intags))
         ct = ctag(stg)

         s.setSubjTags(alltags(cit, et, inv, it, ct))
         s.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])

   elif event_type in INJECT_SET:
      intags = s.tags()
      stg = o.tags()
      citag_grad = s.get_citag_grad()
      etag_grad = o.get_etag_grad()
      invtag_grad = o.get_invtag_grad()
      itag_grad = s.get_itag_grad()
      ctag_grad = s.get_ctag_grad()

      if citag(stg) < citag(intags):
         citag_grad = o.get_citag_grad()
         s.setciTagInitID(o.getciTagInitID())
      cit = min(citag(stg), citag(intags))
      if (isTRUSTED(cit) and itag(intags) < 0.5):
         cit = UNTRUSTED
         citag_grad = 0
      et = etag(stg)
      if (et > cit):
         et = cit
         etag_grad = citag_grad
         s.seteTagInitID(s.getciTagInitID())
      inv = invtag(stg)
      if (isUNTRUSTED(cit)):
         inv = UNTRUSTED
         invtag_grad = 0
      if itag(stg) < itag(intags):
         itag_grad = o.get_itag_grad()
         s.setiTagInitID(o.getiTagInitID())
      it = min(itag(stg), itag(intags))
      if ctag(stg) < ctag(intags):
         ctag_grad = o.get_ctag_grad()
         s.setcTagInitID(o.getcTagInitID())
      ct = min(ctag(stg), ctag(intags))
       
      s.setSubjTags(alltags(cit, et, inv, it, ct))
      s.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])

   elif event_type in EXECVE_SET:
      if (o.isMatch("/bin/bash")):
         whitelisted = True

      if (whitelisted == False):
         stg = s.tags()
         cit = citag(stg)
         et = etag(stg)
         citag_grad = s.get_citag_grad()
         etag_grad = s.get_etag_grad()
         invtag_grad = s.get_invtag_grad()
         itag_grad = s.get_itag_grad()
         ctag_grad = s.get_ctag_grad()

         if isTRUSTED(citag(intags)):
            if (isTRUSTED(cit) and isTRUSTED(et)):
               it = BENIGN
               itag_grad = 0
               ct = PUBLIC
               ctag_grad = 0
            elif (isTRUSTED(cit) and isUNTRUSTED(et)):
               et = TRUSTED
               etag_grad = 0
               if itag(stg) > itag(intags):
                  itag_grad = o.get_itag_grad()
                  s.setiTagInitID(o.getiTagInitID())
               it = min(itag(stg), itag(intags))
               if ctag(stg) > ctag(intags):
                  ctag_grad = o.get_ctag_grad()
                  s.setcTagInitID(o.getcTagInitID())
               ct = min(ctag(stg), ctag(intags))
            else:
               cit = TRUSTED
               citag_grad = 0
               et = UNTRUSTED
               etag_grad = 0
               if itag(stg) > itag(intags):
                  itag_grad = o.get_itag_grad()
                  s.setiTagInitID(o.getiTagInitID())
               it = min(itag(stg), itag(intags))
               if ctag(stg) > ctag(intags):
                  ctag_grad = o.get_ctag_grad()
                  s.setcTagInitID(o.getcTagInitID())
               ct = min(ctag(stg), ctag(intags))
         else:
            cit = UNTRUSTED
            citag_grad = 0
            et = UNTRUSTED
            etag_grad = 0
            if itag(stg) > itag(intags):
                  itag_grad = o.get_itag_grad()
                  s.setiTagInitID(o.getiTagInitID())
            it = min(itag(stg), itag(intags))
            if ctag(stg) > ctag(intags):
                  ctag_grad = o.get_ctag_grad()
                  s.setcTagInitID(o.getcTagInitID())
            ct = min(ctag(stg), ctag(intags))
         inv = UNTRUSTED
         invtag_grad = 0
         s.setSubjTags(alltags(cit, et, inv, it, ct))
         s.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
         o.setSubjTags(alltags(cit, et, inv, it, ct))
         o.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])

   elif event_type in SET_UID_SET :
      st = s.tags()
      new_owner = morse.Principals[o.owner]
      if isRoot(new_owner) == False and isTRUSTED(invtag(st)):
         o.setSubjTags(alltags(citag(st), etag(st), 0, itag(st), ctag(st)))
         o.update_grad([1, 1, 0, 1, 1])
      
   elif event_type in CREATE_SET:
      st = s.tags(); 
      sit = itag(st)
      cit = ctag(st)
      citag_grad = o.get_citag_grad()
      etag_grad = o.get_etag_grad()
      invtag_grad = o.get_invtag_grad()
      itag_grad = s.get_itag_grad()
      ctag_grad = s.get_ctag_grad()
      if (isTRUSTED(citag(st)) and isTRUSTED(etag(st))):
         o.setObjTags(alltags2(BENIGN, PUBLIC))
         itag_grad = 0
         ctag_grad = 0
      else:
         o.setObjTags(alltags2(sit, cit))
         o.setiTagInitID(s.getiTagInitID())
         o.setcTagInitID(s.getcTagInitID())
      o.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])

   elif event_type in WRITE_SET:
      stg = s.tags()
      otg = o.tags()
      it = itag(stg)
      ct = ctag(stg)
      citag_grad = o.get_citag_grad()
      etag_grad = o.get_etag_grad()
      invtag_grad = o.get_invtag_grad()
      itag_grad = o.get_itag_grad()
      ctag_grad = o.get_ctag_grad()
      isiTagChanged = False
      iscTagChanged = False

      if (isTRUSTED(citag(stg)) and isTRUSTED(etag(stg))):
         it = it + ab
         ct = ct + ab
         if it > 1:
            itag_grad = 0
         it = min(1, it)
         if ct > 1:
            ctag_grad = 0
         ct = min(1, ct)
      elif (isTRUSTED(citag(stg)) and isUNTRUSTED(etag(stg))): 
         it = it + ae
         ct = ct + ae
         if it > 1:
            itag_grad = 0
         it = min(1, it)
         if ct > 1:
            ctag_grad = 0
         ct = min(1, ct)

      if itag(otg) > it:
         itag_grad = s.get_itag_grad()
         isiTagChanged = True
      it = min(itag(otg), it)
      if ctag(otg) > ct:
         ctag_grad = s.get_ctag_grad()
         iscTagChanged = True
      ct = min(ctag(otg), ct)
      newtags = alltags2(it, ct)

      if (o.isIP() == False and o.isMatch("UnknownObject")== False):
         o.setObjTags(newtags); 
         o.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
         if isiTagChanged:
            o.setiTagInitID(s.getiTagInitID())
         if iscTagChanged:
            o.setcTagInitID(s.getcTagInitID())
   
   elif event_type in CLONE_SET:
      assert isinstance(o,Subject)
      stg = s.tags()
      citag_grad = s.get_citag_grad()
      etag_grad = s.get_etag_grad()
      invtag_grad = s.get_invtag_grad()
      itag_grad = s.get_itag_grad()
      ctag_grad = s.get_ctag_grad()
      o.setSubjTags(alltags(citag(stg), etag(stg), invtag(stg), itag(stg), ctag(stg)))
      o.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
      o.setInitID(s.getInitID())

   
   if 0 <= event_type < len(standard_events) and s and o:
      diff = 0
      stg = s.tags()
      it = itag(stg)
      ct = ctag(stg)
      et = etag(stg)
      inv = invtag(stg)
      citag_grad = s.get_citag_grad()
      etag_grad = s.get_etag_grad()
      invtag_grad = s.get_invtag_grad()
      itag_grad = s.get_itag_grad()
      ctag_grad = s.get_ctag_grad()
      ts = event['timestamp']
      if (s.updateTime == 0):
         s.updateTime = ts
      elif (et > 0.5 and it < 1):
         diff = (ts - s.updateTime) / 4000000
         temp = pow(dpi, diff)
         nit = temp * it + (1 - temp) * 0.75
         temp = pow(dpc, diff)
         nct = temp * ct + (1 - temp) * 0.75
         if nit > it:
            itag_grad *= temp
         it = max(it, nit)
         if nct > ct:
            ctag_grad *= temp
         ct = max(ct, nct)
         s.setSubjTags(alltags(citag(stg), et, inv, it, ct))
         s.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
      
      elif (citag(stg) > 0.5 and et < 0.5 and it < 0.5):
         diff = (ts - s.updateTime) / 4000000
         temp = pow(dpi, diff)
         nit = temp * it + (1 - temp) * 0.45
         temp = pow(dpc, diff)
         nct = temp * ct + (1 - temp) * 0.45
         if (nit < 0.5):
            if nit > it:
               itag_grad *= temp
            it = max(it, nit)
            if nct > ct:
               ctag_grad *= temp
            ct = max(ct, nct)
      
         s.setSubjTags(alltags(citag(stg), et, inv, it, ct))
         s.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
      
      stg = s.tags()
      # if ((itag(stg)> 0.5 and isUNTRUSTED(etag(stg))) or etag(stg)>citag(stg)):
      #    print("DANGER!!!")

