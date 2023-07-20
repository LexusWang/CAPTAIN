from graph.Subject import Subject
from graph.Object import Object
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag, ctag, itag, etag, isRoot
import pdb

def propTags(event, s, o, o2, att = 0.2, decay = 0):
   event_type = event.type
   intags = None
   newtags = None
   whitelisted = False
   ab = att
   ae = att/2
   dpPow = decay
   dpi = 1.0/pow(2, dpPow)
   dpc = 1.0/pow(2, dpPow)

   if event_type in {'read'}:
      assert isinstance(s,Subject) and isinstance(o,Object)
      stg = s.tags()
      otg = o.tags()
      sit = itag(stg)
      oit = itag(otg)
      sct = ctag(stg)
      oct = ctag(otg)
      
      citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
      ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()

      if sit > oit:
         itag_grad = o.get_itag_grad()
         i_init_id = o.getiTagInitID()
         sit = min(sit, oit)
         s.propagation_chain['i'] = o.propagation_chain['i'][:]
         s.propagation_chain['i'].append(event.id)

      if sct > oct:
         ctag_grad = o.get_ctag_grad()
         c_init_id = o.getcTagInitID()
         sct = min(sct, oct)
         s.propagation_chain['c'] = o.propagation_chain['c'][:]
         s.propagation_chain['c'].append(event.id)

      s.setSubjTags([citag(stg), etag(stg), sit, sct])
      s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
      s.setInitID([ci_init_id, e_init_id, i_init_id, c_init_id])
      s.updateTime = event.time

   elif event_type in {'create'}:
      assert isinstance(s, Subject) and isinstance(o, Object)
      st = s.tags()
      sit = itag(st)
      sct = ctag(st)
      itag_grad = s.get_itag_grad()
      ctag_grad = s.get_ctag_grad()
      ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()
      
      o.setObjTags([sit, sct])
      o.setiTagInitID(i_init_id)
      o.setcTagInitID(c_init_id)
      o.set_grad([itag_grad, ctag_grad])
      o.propagation_chain['i'] = s.propagation_chain['i'][:]
      o.propagation_chain['i'].append(event.id)
      o.propagation_chain['c'] = s.propagation_chain['c'][:]
      o.propagation_chain['c'].append(event.id)
      o.updateTime = event.time

   elif event_type in {'write'}:
      assert isinstance(s,Subject) and isinstance(o,Object)
      if (o.isIP() == False and o.isMatch("UnknownObject")== False):
         stg = s.tags()
         otg = o.tags()
         it = itag(stg)
         ct = ctag(stg)
         citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
         ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()

         if (isTRUSTED(citag(stg)) and isTRUSTED(etag(stg))):
            new_it = min(1, it + ab)
            new_ct = min(1, ct + ab)
         elif (isTRUSTED(citag(stg)) and isUNTRUSTED(etag(stg))): 
            new_it = min(1, it + ae)
            new_ct = min(1, ct + ae)
         else:
            new_it = it
            new_ct = ct

         if itag(otg) > new_it:
            o.set_itag_grad(itag_grad)
            o.setiTagInitID(i_init_id)
            o.setObjiTag(new_it)
            o.propagation_chain['i'] = s.propagation_chain['i'][:]
            o.propagation_chain['i'].append(event.id)

         if ctag(otg) > new_ct:
            o.set_ctag_grad(ctag_grad)
            o.setcTagInitID(c_init_id)
            o.setObjcTag(new_ct)
            o.propagation_chain['c'] = s.propagation_chain['c'][:]
            o.propagation_chain['c'].append(event.id)
         
         o.updateTime = event.time
            

   elif event_type in {'load'}:
      assert isinstance(s, Subject) and isinstance(o, Object) and o.isFile()
      if o.isFile():
         stg = s.tags()
         otag = o.tags()
         citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
         ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()

         if citag(stg) > citag(o.tags()):
            citag_grad = o.get_citag_grad()
            ci_init_id = o.getciTagInitID()
         cit = min(citag(stg), citag(otag))

         if itag(stg) > itag(otag):
            itag_grad = o.get_itag_grad()
            i_init_id = o.getiTagInitID()
            s.propagation_chain['i'] = o.propagation_chain['i'][:]
            s.propagation_chain['i'].append(event.id)
         it = min(itag(stg), itag(otag))

         if ctag(stg) > ctag(otag):
            ctag_grad = o.get_ctag_grad()
            c_init_id = o.getcTagInitID()
            s.propagation_chain['c'] = o.propagation_chain['c'][:]
            s.propagation_chain['c'].append(event.id)
         ct = min(ctag(stg), ctag(otag))

         s.setSubjTags([cit, etag(stg), it, ct])
         s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
         s.setInitID([ci_init_id, e_init_id, i_init_id, c_init_id])
         s.updateTime = event.time

   elif event_type in {'inject'}:
      assert isinstance(o,Subject)
      intags = s.tags()
      stg = o.tags()

      # citag_grad = s.get_citag_grad()
      # etag_grad = o.get_etag_grad()
      # invtag_grad = o.get_invtag_grad()
      # itag_grad = s.get_itag_grad()
      # ctag_grad = s.get_ctag_grad()

      citag_grad, etag_grad, itag_grad, ctag_grad = o.get_grad()
      ci_init_id, e_init_id, i_init_id, c_init_id = o.getInitID()

      if citag(stg) > citag(intags):
         citag_grad = s.get_citag_grad()
         ci_init_id = s.getciTagInitID()
      cit = min(citag(stg), citag(intags))

      if (isTRUSTED(cit) and itag(intags) < 0.5):
         cit = UNTRUSTED
         citag_grad = s.get_itag_grad()
         ci_init_id = s.getiTagInitID()

      et = etag(stg)
      if (et > cit):
         et = cit
         etag_grad = citag_grad
         e_init_id = ci_init_id

      inv = invtag(stg)
      if (isUNTRUSTED(cit)):
         inv = UNTRUSTED
         invtag_grad = citag_grad
         inv_init_id = ci_init_id

      if itag(stg) > itag(intags):
         itag_grad = s.get_itag_grad()
         i_init_id = s.getiTagInitID()
      it = min(itag(stg), itag(intags))
      
      if ctag(stg) > ctag(intags):
         ctag_grad = s.get_ctag_grad()
         c_init_id = s.getcTagInitID()
      ct = min(ctag(stg), ctag(intags))
       
      o.setSubjTags(alltags(cit, et, inv, it, ct))
      o.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
      o.setInitID([ci_init_id, e_init_id, inv_init_id, i_init_id, c_init_id])
      o.updateTime = event.time

   elif event_type in {'execve'}:
      assert isinstance(o,Object) and isinstance(s,Subject)
      otg = o.tags()

      if (o.isMatch("/bin/bash")):
         whitelisted = True

      if (whitelisted == False):
         stg = s.tags()
         cit = citag(stg)
         et = etag(stg)
         citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
         ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()

         if (isTRUSTED(cit) and isTRUSTED(et)):
            s.setSubjTags([citag(otg), et, 1.0, 1.0])
            s.set_grad([o.get_itag_grad(), etag_grad, 1.0, 1.0])
            s.setInitID([o.getiTagInitID(), e_init_id, None, None])
            s.propagation_chain['i'] = []
            s.propagation_chain['c'] = []
         elif (isTRUSTED(cit) and isUNTRUSTED(et)):
            cit = citag(otg)
            citag_grad = o.get_itag_grad()
            ci_init_id = o.getiTagInitID()

            if itag(stg) > itag(otg):
               itag_grad = o.get_itag_grad()
               i_init_id = o.getiTagInitID()
               s.propagation_chain['i'] = o.propagation_chain['i'][:]
               s.propagation_chain['i'].append(event.id)
            it = min(itag(stg), itag(otg))

            if ctag(stg) > ctag(otg):
               ctag_grad = o.get_ctag_grad()
               c_init_id = o.getcTagInitID()
               s.propagation_chain['c'] = o.propagation_chain['c'][:]
               s.propagation_chain['c'].append(event.id)
            ct = min(ctag(stg), ctag(otg))

            s.setSubjTags([cit, et, it, ct])
            s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
            s.setInitID([ci_init_id, etag_grad, i_init_id, c_init_id])
         else:
            cit = citag(otg)
            citag_grad = 1.0 * o.get_itag_grad()
            ci_init_id = o.getiTagInitID()

            et = 1 - citag(otg)
            etag_grad = -1.0 * o.get_itag_grad()
            etag_grad = o.getiTagInitID()

            if itag(stg) > itag(otg):
               itag_grad = o.get_itag_grad()
               i_init_id = o.getiTagInitID()
               s.propagation_chain['i'] = o.propagation_chain['i'][:]
               s.propagation_chain['i'].append(event.id)
            it = min(itag(stg), itag(otg))
            if ctag(stg) > ctag(otg):
               ctag_grad = o.get_ctag_grad()
               c_init_id = o.getcTagInitID()
               s.propagation_chain['c'] = o.propagation_chain['c'][:]
               s.propagation_chain['c'].append(event.id)
            ct = min(ctag(stg), ctag(otg))
            
            s.setSubjTags([cit, et, it, ct])
            s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
            s.setInitID([ci_init_id, etag_grad, i_init_id, c_init_id])
         
         s.updateTime = event.time

   # elif event_type in SET_UID_SET :
   #    assert isinstance(o,Subject)
   #    st = s.tags()
   #    citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
   #    ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()
   #    new_owner = morse.Principals[o.owner]
   #    if isRoot(new_owner) == False:
   #       o.setSubjTags([citag(st), etag(st), itag(st), ctag(st)])
   #       o.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
   #       o.setInitID([ci_init_id, e_init_id, i_init_id, c_init_id])
      
   
   
   elif event_type in {'clone'}:
      assert isinstance(o,Subject) and isinstance(s,Subject)
      o.setSubjTags(s.tags())
      o.set_grad(s.get_grad())
      o.setInitID(s.getInitID())
      o.propagation_chain['i'] = s.propagation_chain['i'][:]
      o.propagation_chain['i'].append(event.id)
      o.propagation_chain['c'] = s.propagation_chain['c'][:]
      o.propagation_chain['c'].append(event.id)
      o.updateTime = event.time

   elif event_type in {'update'}:
      assert isinstance(o,Object) and isinstance(o2,Object)
      initag = o.tags()
      o2.setObjTags([initag[2],initag[3]])
      o2.set_grad([o.get_itag_grad(), o.get_ctag_grad()])
      o2.setiTagInitID(o.getiTagInitID())
      o2.setcTagInitID(o.getcTagInitID())
      o2.propagation_chain['i'] = o.propagation_chain['i'][:]
      o2.propagation_chain['i'].append(event.id)
      o2.propagation_chain['c'] = o.propagation_chain['c'][:]
      o2.propagation_chain['c'].append(event.id)
      o2.updateTime = event.time

   elif event_type in {'set_uid'}:
      assert isinstance(o,Subject) and isinstance(s,Subject)
      o.setSubjTags(s.tags())
      o.set_grad(s.get_grad())
      o.setInitID(s.getInitID())
      o.propagation_chain['i'] = s.propagation_chain['i'][:]
      o.propagation_chain['i'].append(event.id)
      o.propagation_chain['c'] = s.propagation_chain['c'][:]
      o.propagation_chain['c'].append(event.id)
      o.updateTime = event.time

   elif event_type in {'rename'}:
      assert isinstance(o,Object) and isinstance(o2,Object)
      o2.setObjTags(o.tags())
      o2.set_grad(o.get_grad())
      o2.setiTagInitID(o.getiTagInitID())
      o2.setcTagInitID(o.getcTagInitID())
      o2.propagation_chain['i'] = o.propagation_chain['i'][:]
      o2.propagation_chain['i'].append(event.id)
      o2.propagation_chain['c'] = o.propagation_chain['c'][:]
      o2.propagation_chain['c'].append(event.id)
      o2.updateTime = event.time

   
   if event_type in {'chmod', 'set_uid', 'mprotect', 'mmap', 'remove', 'clone', 'read', 'load', 'execve', 'inject', 'create', 'write'} and s and o:
      assert isinstance(s,Subject)
      diff = 0
      stg = s.tags()
      it = itag(stg)
      ct = ctag(stg)
      et = etag(stg)
      citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
      ts = event.time
      if (s.updateTime == 0):
         s.updateTime = ts
      elif (isTRUSTED(citag(stg)) and isTRUSTED(etag(stg))):
         diff = (ts - s.updateTime) / 4e9
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
         s.setSubjTags([citag(stg), et, it, ct])
         s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
         s.updateTime = ts
      
      elif (isTRUSTED(citag(stg)) and isUNTRUSTED(etag(stg))):
         diff = (ts - s.updateTime) / 4e9
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
      
         s.setSubjTags([citag(stg), et, it, ct])
         s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
         s.updateTime = ts
