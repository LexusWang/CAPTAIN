import time

TRUSTED = 1
UNTRUSTED = 0
BENIGN = 1
PUBLIC = 1

def citag(alltags):
   return alltags[0]

def etag(allTags):
   return allTags[1]

def itag(allTags):
   return allTags[2]

def ctag(allTags):
   return allTags[3]


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