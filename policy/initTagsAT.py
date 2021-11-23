import re

def get_subject_feature(subject):
    pname = subject.processName
    pcmd = subject.cmdLine
    feature = [pname,pcmd]
    return feature

def get_object_feature(object):
    feature = []
    if object.type == 'NetFlowObject':
        remoteAddress = object.IP
        remotePort = object.port
        ipProtocol = object.Protocol
        feature = [remoteAddress,remotePort,ipProtocol]
    elif object.type == 'SrcSinkObject':
        SrcSinkType = object.subtype
        feature = [SrcSinkType]
    elif object.type == 'FileObject':
        FileObjectType = object.subtype
        path = object.path
        if path:
            feature = [path, FileObjectType]
        else:
            feature = [None, FileObjectType]
    elif object.type == 'UnnamedPipeObject':
        feature = [0]
    elif object.type == 'MemoryObject':
        feature = [0]
    elif object.type == 'PacketSocketObject':
        feature = [0]
    elif object.type == 'RegistryKeyObject':
        feature = [0]

    return feature


def initSubjectTags(subject,sub_init):
    citag = 1
    eTag = 1
    invTag = 1
    itag = 1
    ctag = 1
    # features = get_subject_feature(subject)
    # [citag, eTag, invTag, itag, ctag] = sub_init.initialize(features)
    subject.setSubjTags([citag, eTag, invTag, itag, ctag])

def initObjectTags(object, obj_inits, format = 'cdm'):
    itag = 0
    ctag = 0
    if format == 'cdm':
        initializer = obj_inits[object.type]
        features = get_object_feature(object)
        tags = initializer.initialize(features).squeeze()
        itag = tags[0].item()
        ctag = tags[1].item()
        # [itag, ctag] = initializer.initialize(features)
        object.setObjTags([itag, ctag])
    # elif format == 'lttng':
    #     if object.type in {'NetFlowObject','inet_scoket_file'}:
    #         ctag = 0
    #         print(object.IP)
    #         itag, ctag = match_ip(object.IP)
    #     elif object.type == 'common_file':
    #         path = object.path
    #         itag, ctag = match_path(path)
    #     elif object.type == 'unix_socket_file':
    #         b = 0
    #     elif object.type in {'UnnamedPipeObject','pipe_file'}:
    #         b = 0
    #     elif object.type in {'MemoryObject','share_memory'}:
    #         b = 0

    object.setObjTags([itag, ctag])
