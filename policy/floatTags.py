import time

TRUSTED = 1
UNTRUSTED = 0
BENIGN = 1
PUBLIC = 1

def alltags(cit, et, inv, it, ct):
   return [cit, et, inv, it, ct]

def alltags2(it, ct):
   citag = 0
   if (it > 0.5):
      citag = 1
   return alltags(citag, citag, 0, it, ct)

def ctag(allTags):
   return allTags[4]

def itag(allTags):
   return allTags[3]

def invtag(allTags):
   return allTags[2]

def etag(allTags):
   return allTags[1]

def citag(allTags):
   return allTags[0]


def isRoot(principal):
   if principal['userId'] == '0':
      return True
   else:
      return False

def permbits(event):
   permstr = event['properties']['map']['mode']
   perm = int(permstr,8)
   return perm

def isTRUSTED(tag):
   return tag > 0.5

def isUNTRUSTED(tag):
   return tag <= 0.5