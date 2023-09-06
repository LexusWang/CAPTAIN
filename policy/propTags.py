from graph.Subject import Subject
from graph.Object import Object
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import isTRUSTED, isUNTRUSTED
from policy.floatTags import citag, ctag, itag, etag, isRoot
import pdb

def dump_event_feature(event, s, o, o2):
   if o2:
      features = (s.get_name(), event.type, o.get_name(), o2.get_name())
   else:
      features = (s.get_name(), event.type, o.get_name())
   return features

def propTags(event, s, o, o2, att = 0.2, decay = 0, prop_lambda = 0, tau = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]):
   event_type = event.type
   intags = None
   newtags = None
   whitelisted = False
   ab = att
   ae = att/2
   dpPow = decay
   dpi = 1.0/pow(2, dpPow)
   dpc = 1.0/pow(2, dpPow)
   tau_s_ci = tau[0]
   tau_s_e = tau[1]
   tau_s_i = tau[2]
   tau_s_c = tau[3]
   tau_o_ci = tau[4]
   tau_o_e = tau[5]
   tau_o_i = tau[6]
   tau_o_c = tau[7]

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
         sit  = (1-prop_lambda) * oit + prop_lambda * sit
         s.propagation_chain['i'] = o.propagation_chain['i'][:]
         s.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))

      if sct > oct:
         ctag_grad = o.get_ctag_grad()
         c_init_id = o.getcTagInitID()
         sct = (1-prop_lambda) * oct + prop_lambda * sct
         s.propagation_chain['c'] = o.propagation_chain['c'][:]
         s.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))

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
      o.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
      o.propagation_chain['c'] = s.propagation_chain['c'][:]
      o.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
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

         if (isTRUSTED(citag(stg), tau_s_ci) and isTRUSTED(etag(stg), tau_s_e)):
            new_it = min(1, it + ab)
            new_ct = min(1, ct + ab)
         elif (isTRUSTED(citag(stg), tau_s_ci) and isUNTRUSTED(etag(stg), tau_s_e)): 
            new_it = min(1, it + ae)
            new_ct = min(1, ct + ae)
         else:
            new_it = it
            new_ct = ct

         if itag(otg) > new_it:
            o.set_itag_grad(itag_grad)
            o.setiTagInitID(i_init_id)
            new_it = (1-prop_lambda) * new_it + prop_lambda * itag(otg)
            o.setObjiTag(new_it)
            o.propagation_chain['i'] = s.propagation_chain['i'][:]
            o.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))

         if ctag(otg) > new_ct:
            o.set_ctag_grad(ctag_grad)
            o.setcTagInitID(c_init_id)
            new_ct = (1-prop_lambda) * new_ct + prop_lambda * ctag(otg)
            o.setObjcTag(new_ct)
            o.propagation_chain['c'] = s.propagation_chain['c'][:]
            o.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
         
         o.updateTime = event.time
            

   elif event_type in {'load'}:
      assert isinstance(s, Subject) and isinstance(o, Object) and o.isFile()
      if o.isFile():
         stg = s.tags()
         otg = o.tags()
         citag_grad, etag_grad, itag_grad, ctag_grad = s.get_grad()
         ci_init_id, e_init_id, i_init_id, c_init_id = s.getInitID()

         if citag(stg) > citag(o.tags()):
            citag_grad = o.get_citag_grad()
            ci_init_id = o.getciTagInitID()
            cit = (1-prop_lambda) * citag(otg) + prop_lambda * citag(stg)
         else:
            cit = citag(stg)

         if itag(stg) > itag(otg):
            itag_grad = o.get_itag_grad()
            i_init_id = o.getiTagInitID()
            s.propagation_chain['i'] = o.propagation_chain['i'][:]
            s.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
            it = (1-prop_lambda) * itag(otg) + prop_lambda * itag(stg)
         else:
            it = itag(stg)

         if ctag(stg) > ctag(otg):
            ctag_grad = o.get_ctag_grad()
            c_init_id = o.getcTagInitID()
            s.propagation_chain['c'] = o.propagation_chain['c'][:]
            s.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
            ct = (1-prop_lambda) * ctag(otg) + prop_lambda * ctag(stg)
         else:
            ct = ctag(stg)

         s.setSubjTags([cit, etag(stg), it, ct])
         s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
         s.setInitID([ci_init_id, e_init_id, i_init_id, c_init_id])
         s.updateTime = event.time

   # elif event_type in {'inject'}:
   #    assert isinstance(o,Subject)
   #    intags = s.tags()
   #    stg = o.tags()

   #    # citag_grad = s.get_citag_grad()
   #    # etag_grad = o.get_etag_grad()
   #    # invtag_grad = o.get_invtag_grad()
   #    # itag_grad = s.get_itag_grad()
   #    # ctag_grad = s.get_ctag_grad()

   #    citag_grad, etag_grad, itag_grad, ctag_grad = o.get_grad()
   #    ci_init_id, e_init_id, i_init_id, c_init_id = o.getInitID()

      # if citag(stg) > citag(intags):
      #    citag_grad = s.get_citag_grad()
      #    ci_init_id = s.getciTagInitID()
      # cit = min(citag(stg), citag(intags))
      # tau_cit = tau_s_ci
      # if cit == citag(intags):
      #    tau_cit = tau_o_ci

      # if (isTRUSTED(cit, tau_cit) and itag(intags) < tau_s_i):
      #    cit = UNTRUSTED
      #    citag_grad = s.get_itag_grad()
      #    ci_init_id = s.getiTagInitID()

   #    et = etag(stg)
   #    if (et > cit):
   #       et = cit
   #       etag_grad = citag_grad
   #       e_init_id = ci_init_id

      # inv = invtag(stg)
      # if (isUNTRUSTED(cit, tau_cit)):
      #    inv = UNTRUSTED
      #    invtag_grad = citag_grad
      #    inv_init_id = ci_init_id

   #    if itag(stg) > itag(intags):
   #       itag_grad = s.get_itag_grad()
   #       i_init_id = s.getiTagInitID()
   #    it = min(itag(stg), itag(intags))
      
   #    if ctag(stg) > ctag(intags):
   #       ctag_grad = s.get_ctag_grad()
   #       c_init_id = s.getcTagInitID()
   #    ct = min(ctag(stg), ctag(intags))
       
   #    o.setSubjTags(alltags(cit, et, inv, it, ct))
   #    o.set_grad([citag_grad, etag_grad, invtag_grad, itag_grad, ctag_grad])
   #    o.setInitID([ci_init_id, e_init_id, inv_init_id, i_init_id, c_init_id])
   #    o.updateTime = event.time

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

         if (isTRUSTED(cit, tau_s_ci) and isTRUSTED(et, tau_s_e)):
            s.setSubjTags([citag(otg), et, 1.0, 1.0])
            s.set_grad([o.get_itag_grad(), etag_grad, 1.0, 1.0])
            s.setInitID([o.getiTagInitID(), e_init_id, None, None])
            s.propagation_chain['i'] = []
            s.propagation_chain['c'] = []
         elif (isTRUSTED(cit, tau_s_ci) and isUNTRUSTED(et, tau_s_e)):
            cit = citag(otg)
            citag_grad = o.get_itag_grad()
            ci_init_id = o.getiTagInitID()

            if itag(stg) > itag(otg):
               itag_grad = o.get_itag_grad()
               i_init_id = o.getiTagInitID()
               s.propagation_chain['i'] = o.propagation_chain['i'][:]
               s.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
               it = (1-prop_lambda) * itag(otg) + prop_lambda * itag(stg)
            else:
               it = itag(stg)

            if ctag(stg) > ctag(otg):
               ctag_grad = o.get_ctag_grad()
               c_init_id = o.getcTagInitID()
               s.propagation_chain['c'] = o.propagation_chain['c'][:]
               s.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
               ct = (1-prop_lambda) * ctag(otg) + prop_lambda * ctag(stg)
            else:
               ct = ctag(stg)

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
               s.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
               it = (1-prop_lambda) * itag(otg) + prop_lambda * itag(stg)
            else:
               it = itag(stg)

            if ctag(stg) > ctag(otg):
               ctag_grad = o.get_ctag_grad()
               c_init_id = o.getcTagInitID()
               s.propagation_chain['c'] = o.propagation_chain['c'][:]
               s.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
               ct = (1-prop_lambda) * ctag(otg) + prop_lambda * ctag(stg)
            else:
               ct = ctag(stg)
            
            s.setSubjTags([cit, et, it, ct])
            s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
            s.setInitID([ci_init_id, etag_grad, i_init_id, c_init_id])
         
         s.updateTime = event.time   
   
   elif event_type in {'clone'}:
      assert isinstance(o,Subject) and isinstance(s,Subject)
      o.setSubjTags(s.tags())
      o.set_grad(s.get_grad())
      o.setInitID(s.getInitID())
      o.propagation_chain['i'] = s.propagation_chain['i'][:]
      o.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
      o.propagation_chain['c'] = s.propagation_chain['c'][:]
      o.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
      o.updateTime = event.time

   elif event_type in {'update'}:
      assert isinstance(o,Object) and isinstance(o2,Object)
      initag = o.tags()
      o2.setObjTags([initag[2],initag[3]])
      o2.set_grad([o.get_itag_grad(), o.get_ctag_grad()])
      o2.setiTagInitID(o.getiTagInitID())
      o2.setcTagInitID(o.getcTagInitID())
      o2.propagation_chain['i'] = o.propagation_chain['i'][:]
      o2.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
      o2.propagation_chain['c'] = o.propagation_chain['c'][:]
      o2.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
      o2.updateTime = event.time

   # elif event_type in {'set_uid'}:
   #    assert isinstance(o,Subject) and isinstance(s,Subject)
   #    o.setSubjTags(s.tags())
   #    o.set_grad(s.get_grad())
   #    o.setInitID(s.getInitID())
   #    o.propagation_chain['i'] = s.propagation_chain['i'][:]
   #    o.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
   #    o.propagation_chain['c'] = s.propagation_chain['c'][:]
   #    o.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
   #    o.updateTime = event.time

   elif event_type in {'rename'}:
      assert isinstance(o,Object) and isinstance(o2,Object)
      o2.setObjTags(o.tags())
      o2.set_grad(o.get_grad())
      o2.setiTagInitID(o.getiTagInitID())
      o2.setcTagInitID(o.getcTagInitID())
      o2.propagation_chain['i'] = o.propagation_chain['i'][:]
      o2.propagation_chain['i'].append(str(dump_event_feature(event, s, o, o2)))
      o2.propagation_chain['c'] = o.propagation_chain['c'][:]
      o2.propagation_chain['c'].append(str(dump_event_feature(event, s, o, o2)))
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
      elif (isTRUSTED(citag(stg), tau_s_ci) and isTRUSTED(etag(stg), tau_s_e)):
         diff = (ts - s.updateTime) / 4e9
         temp = pow(dpi, diff)
         nit = temp * it + (1 - temp) * 0.75
         temp = pow(dpc, diff)
         nct = temp * ct + (1 - temp) * 0.75
         if nit > it:
            itag_grad *= temp
            it = nit
         if nct > ct:
            ctag_grad *= temp
            ct = nct
         s.setSubjTags([citag(stg), et, it, ct])
         s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
         s.updateTime = ts
      
      elif (isTRUSTED(citag(stg), tau_s_ci) and isUNTRUSTED(etag(stg), tau_s_e)):
         diff = (ts - s.updateTime) / 4e9
         temp = pow(dpi, diff)
         nit = temp * it + (1 - temp) * 0.45
         temp = pow(dpc, diff)
         nct = temp * ct + (1 - temp) * 0.45
         if (nit < tau_s_i):
            if nit > it:
               itag_grad *= temp
               it = nit
            if nct > ct:
               ctag_grad *= temp
               ct = nct
      
         s.setSubjTags([citag(stg), et, it, ct])
         s.set_grad([citag_grad, etag_grad, itag_grad, ctag_grad])
         s.updateTime = ts
