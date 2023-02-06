import re
import pdb

# init_otag("[:any:]*passwd", BENIGN, SECRET)
# init_otag("[:any:]*pwd\.db", BENIGN, SECRET)
# init_otag("[:any:]*auth\.log[:any:]*", BENIGN, SECRET)
# init_otag("[:any:]*shadow", BENIGN, SECRET)
# init_otag("[:any:]*ssh/[:any:]*", BENIGN, SECRET)
# init_otag("/home/[:any:]*(pdf|doc|docx|xml|xlsx|cpp)", BENIGN, SECRET)

# benign_secret_group = [r'.*passwd',r'.*pwd\.db',r'.*auth\.log.*',r'.*shadow',r'.*ssh/.*',r'/home/.*(pdf|doc|docx|xml|xlsx|cpp)']
benign_secret_group = [r'.*passwd',r'.*/var/log/.*',r'.*auth\.log.*',r'.*shadow']

# init_otag("/tmp/\.X11-unix/[:any:]*", BENIGN, PUBLIC)
# init_otag("/tmp/\.ICE-unix/[:any:]*", BENIGN, PUBLIC)
# init_otag("(/lib/|/bin/)[:any:]*", BENIGN, PUBLIC)
# init_otag("/log/[:any:]*", BENIGN, PUBLIC)
# init_otag("(/root/|/data/|/dev/|/proc/)[:any:]*", BENIGN, PUBLIC)
# init_otag("(/usr/|/sys/|/run/|/sbin/|/etc/|/var/|stdin|stderr|/home/|/maildrop|/stat/|/active/|/incoming/)[:any:]*", BENIGN, PUBLIC)

# benign_public_group = [r'/tmp/\.X11-unix/.*',r'/tmp/\.ICE-unix/.*',r'(/lib64/|/lib/|/bin/).*',r'/log/.*',r'(/root/|/data/|/dev/|/proc/).*',r'(/usr/|/sys/|/run/|/sbin/|/etc/|/var/|stdin|stderr|/home/|/maildrop|/stat/|/active/|/incoming/).*']
benign_public_group = []

# init_otag("/tmp[:any:]*", UNTRUSTED, PUBLIC)
# init_otag("/media/[:any:]*", UNTRUSTED, PUBLIC)

# untrusted_public_group = [r'/tmp.*',r'/media/.*']
untrusted_public_group = []

# special_group = [r'/tmp/\.X11-unix/.*',r'/tmp/\.ICE-unix/.*']
special_group = []

def match_path(path):
    itag = 1
    ctag = 1
    for regexp in benign_public_group:
        if re.match(regexp,path):
            itag = 1
            ctag = 1

    for regexp in benign_secret_group:
        if re.match(regexp,path):
            ctag = 0

    for regexp in untrusted_public_group:
        if re.match(regexp,path):
            itag = 0

    for regexp in special_group:
        if re.match(regexp,path):
            itag = 1
            ctag = 1
    
    return itag, ctag


# preExistingObject(o, nm, _) --> initOtag(o, nm, BENIGN, PUBLIC)
# init_otag("IP:[:any:]*", UNTRUSTED, PUBLIC)
# init_otag("LOCAL:[:any:]*", BENIGN, PUBLIC)
# init_otag("IP:7f[:any:]*", BENIGN, PUBLIC)
# init_otag("IP:a000[:any:]*", BENIGN, PUBLIC)
# init_otag("IP:[a-f0-9]+:53[.][0-9]+H", BENIGN, PUBLIC)

# benign_public_ips = [r'128.55.12.10',r'128.55.12.73']
# benign_ports = set([5353, 53])
benign_public_ips = []
benign_ports = set()

def match_network_addr(ip_address, port):
    itag = 0
    ctag = 1

    if int(port) in benign_ports:
        itag = 1
        ctag = 1
        return itag, ctag

    for regexp in benign_public_ips:
        if re.match(regexp,ip_address):
            itag = 1
            ctag = 1

    return itag, ctag


def initSubjectTags(subject):
    citag = 1.0
    eTag = 1.0
    itag = 1.0
    ctag = 1.0
    subject.setSubjTags([citag, eTag, itag, ctag])

def initObjectTags(object, format = 'cdm'):
    itag = 0
    ctag = 0
    if format == 'cdm':
        if object.type in 'NetFlowObject':
            ctag = 1
            itag, ctag = match_network_addr(object.IP, object.port)
        elif object.type == 'SrcSinkObject':
            ctag = 1
            itag = 0
        elif object.type == 'FileObject':
            path = object.path
            itag, ctag = match_path(path)
        elif object.type == 'UnnamedPipeObject':
            ctag = 1
            itag = 0
        elif object.type == 'MemoryObject':
            ctag = 0
            itag = 0

    object.setObjTags([itag, ctag])


#         init_otag("stderr", BENIGN, PUBLIC)
#         init_otag("stdout", UNTRUSTED, SECRET)
#         






