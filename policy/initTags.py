import re

# init_otag("[:any:]*passwd", BENIGN, SECRET)
# init_otag("[:any:]*pwd\.db", BENIGN, SECRET)
# init_otag("[:any:]*auth\.log[:any:]*", BENIGN, SECRET)
# init_otag("[:any:]*shadow", BENIGN, SECRET)
# init_otag("[:any:]*ssh/[:any:]*", BENIGN, SECRET)
# init_otag("/home/[:any:]*(pdf|doc|docx|xml|xlsx|cpp)", BENIGN, SECRET)
benign_secret_group = [r'.*passwd',r'.*pwd\.db',r'.*auth\.log.*',r'.*shadow',r'.*ssh/.*',r'/home/.*(pdf|doc|docx|xml|xlsx|cpp)']

# init_otag("/tmp/\.X11-unix/[:any:]*", BENIGN, PUBLIC)
# init_otag("/tmp/\.ICE-unix/[:any:]*", BENIGN, PUBLIC)
# init_otag("(/lib/|/bin/)[:any:]*", BENIGN, PUBLIC)
# init_otag("/log/[:any:]*", BENIGN, PUBLIC)
# init_otag("(/root/|/data/|/dev/|/proc/)[:any:]*", BENIGN, PUBLIC)
# init_otag("(/usr/|/sys/|/run/|/sbin/|/etc/|/var/|stdin|stderr|/home/|/maildrop|/stat/|/active/|/incoming/)[:any:]*", BENIGN, PUBLIC)
benign_public_group = [r'/tmp/\.X11-unix/.*',r'/tmp/\.ICE-unix/.*',r'(/lib64/|/lib/|/bin/).*',r'/log/.*',r'(/root/|/data/|/dev/|/proc/).*',r'(/usr/|/sys/|/run/|/sbin/|/etc/|/var/|stdin|stderr|/home/|/maildrop|/stat/|/active/|/incoming/).*']

# init_otag("/tmp[:any:]*", UNTRUSTED, PUBLIC)
# init_otag("/media/[:any:]*", UNTRUSTED, PUBLIC)
untrusted_public_group = [r'/tmp.*',r'/media/.*']


def match_path(path):
    itag = 0
    ctag = 1
    for regexp in benign_secret_group:
        if re.match(regexp,path):
            itag = 1
            ctag = 0
            return itag, ctag

    for regexp in untrusted_public_group:
        if re.match(regexp,path):
            itag = 0
            ctag = 1
            return itag, ctag

    for regexp in benign_public_group:
        if re.match(regexp,path):
            itag = 1
            ctag = 1
            return itag, ctag

    return itag, ctag


# preExistingObject(o, nm, _) --> initOtag(o, nm, BENIGN, PUBLIC)
# init_otag("IP:[:any:]*", UNTRUSTED, PUBLIC)
# init_otag("LOCAL:[:any:]*", BENIGN, PUBLIC)
# init_otag("IP:7f[:any:]*", BENIGN, PUBLIC)
# init_otag("IP:a000[:any:]*", BENIGN, PUBLIC)
# init_otag("IP:[a-f0-9]+:53[.][0-9]+H", BENIGN, PUBLIC)
benign_public_ips = []

def match_ip(ip_address):
    itag = 0
    ctag = 1
    for regexp in benign_public_ips:
        if re.match(regexp,ip_address):
            itag = 1
            ctag = 0
            return itag, ctag

    return itag, ctag


def initSubjectTags(subject):
    citag = 1
    eTag = 1
    invTag = 1
    itag = 1
    ctag = 1
    subject.setSubjTags([citag, eTag, invTag, itag, ctag])

def initObjectTags(object, format = 'cdm'):
    itag = 0
    ctag = 0
    if format == 'cdm':
        if object.type in 'NetFlowObject':
            ctag = 1
            itag, ctag = match_ip(object.IP)
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
    elif format == 'lttng':
        if object.type in {'NetFlowObject','inet_scoket_file'}:
            ctag = 0
            print(object.IP)
            itag, ctag = match_ip(object.IP)
        elif object.type == 'common_file':
            path = object.path
            itag, ctag = match_path(path)
        elif object.type == 'unix_socket_file':
            b = 0
        elif object.type in {'UnnamedPipeObject','pipe_file'}:
            b = 0
        elif object.type in {'MemoryObject','share_memory'}:
            b = 0

    object.setObjTags([itag, ctag])
    if itag + ctag != 2:
        a = 0


#         init_otag("stderr", BENIGN, PUBLIC)
#         init_otag("stdout", UNTRUSTED, SECRET)
#         






