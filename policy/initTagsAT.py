import re
from utils.Initializer import Initializer

def get_subject_feature(subject):
    feature = []
    return feature

def get_object_feature(object):
    feature = []
    if object.type in 'NetFlowObject':
        localAddress = None
        localPort = None
        remoteAddress = None
        remotePort = None
        ipProtocol = None
    elif object.type == 'SrcSinkObject':
        SrcSinkType = object.subtype
    elif object.type == 'FileObject':
        FileObjectType = object.subtype
        path = object.path
    elif object.type == 'UnnamedPipeObject':
        pass
    elif object.type == 'MemoryObject':
        pass
    elif object.type == 'PacketSocketObject':
        pass
    elif object.type == 'RegistryKeyObject':
        pass

    return feature


def initSubjectTags(subject,sub_init):
    features = get_subject_feature(subject)
    [citag, eTag, invTag, itag, ctag] = sub_init.initialize(features)
    subject.setSubjTags([citag, eTag, invTag, itag, ctag])

def initObjectTags(object, obj_inits, format = 'cdm'):
    if format == 'cdm':
        initializer = obj_inits[object.type]
        features = get_object_feature(object)
        [itag, ctag] = initializer.initialize(features)
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
