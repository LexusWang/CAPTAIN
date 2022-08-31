import time
import sys
import torch

sys.path.extend(['.', '..', '...'])

# import floatTags
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import citag, ctag, itag, etag
from parse.eventType import lttng_events, cdm_events, standard_events
from parse.eventType import READ_SET, LOAD_SET, EXECVE_SET, WRITE_SET, INJECT_SET, CREATE_SET, RENAME_SET, MPROTECT_SET, SET_UID_SET

import numpy as np

# loss function is called only when false positive or false negative appear
def get_loss(event_type: str, s: torch.Tensor, o: torch.Tensor, alarm_name: str, side, format = 'cdm'):
    if format == 'cdm':
      event_type = cdm_events[event_type]
    elif format == 'lttng':
        event_type = lttng_events[event_type]

    s_loss, o_loss = torch.zeros(5, requires_grad=True), torch.zeros(5, requires_grad=True)

    if side == "false_positive":
        if event_type in EXECVE_SET or event_type in LOAD_SET:
            s_loss = s - torch.tensor([TRUSTED, s[1], s[2], s[3], s[4]])

        elif event_type == standard_events['EVENT_MODIFY_PROCESS']:
            o_loss = o - torch.tensor([TRUSTED, o[1], o[2], o[3], o[4]])

        elif event_type in WRITE_SET:
            # to be discussed: which to be chosen to optimized (one is enough, more is also ok)
            o_loss = o - torch.tensor([o[0], o[1], o[2], 1, o[4]])
            if alarm_name == "DataLeak":
                s_loss = s - torch.tensor([s[0], s[1], s[2], 1, 1])

        elif event_type in SET_UID_SET:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 1, s[4]])

        elif event_type == standard_events['EVENT_MODIFY_FILE_ATTRIBUTES']:
            o_loss = o - torch.tensor([o[0], o[1], o[2], 1, o[4]])


        elif event_type in {standard_events['EVENT_MPROTECT'], standard_events['EVENT_MMAP']}:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 1, s[4]])

    elif side == "false_negative":
        if event_type in EXECVE_SET or event_type in LOAD_SET:
            s_loss = s - torch.tensor([UNTRUSTED, s[1], s[2], s[3], s[4]])

        elif event_type == standard_events['EVENT_MODIFY_PROCESS']:
            o_loss = o - torch.tensor([UNTRUSTED, o[1], o[2], o[3], o[4]])

        elif event_type in WRITE_SET:
            o_loss = o - torch.tensor([o[0], o[1], o[2], 0, o[4]])
            if alarm_name == "DataLeak":
                s_loss = s - torch.tensor([s[0], s[1], s[2], 0, 0])

        elif event_type in SET_UID_SET:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 0, s[4]])

        elif event_type == standard_events['EVENT_MODIFY_FILE_ATTRIBUTES']:
            o_loss = o - torch.tensor([o[0], o[1], o[2], 0, o[4]])

        elif event_type in {standard_events['EVENT_MPROTECT'], standard_events['EVENT_MMAP']}:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 0, s[4]])

    if side == "true_positive":
        if event_type in EXECVE_SET or event_type in LOAD_SET:
            s_loss = s - torch.tensor([UNTRUSTED, s[1], s[2], s[3], s[4]])

        elif event_type == standard_events['EVENT_MODIFY_PROCESS']:
            o_loss = o - torch.tensor([UNTRUSTED, o[1], o[2], o[3], o[4]])

        elif event_type in WRITE_SET:
            o_loss = o - torch.tensor([o[0], o[1], o[2], 0, o[4]])
            if alarm_name == "DataLeak":
                s_loss = s - torch.tensor([s[0], s[1], s[2], 0, 0])

        elif event_type in SET_UID_SET:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 0, s[4]])

        elif event_type == standard_events['EVENT_MODIFY_FILE_ATTRIBUTES']:
            o_loss = o - torch.tensor([o[0], o[1], o[2], 0, o[4]])

        elif event_type in {standard_events['EVENT_MPROTECT'], standard_events['EVENT_MMAP']}:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 0, s[4]])

    elif side == "true_negative":
        if event_type in EXECVE_SET or event_type in LOAD_SET:
            s_loss = s - torch.tensor([TRUSTED, s[1], s[2], s[3], s[4]])

        elif event_type == standard_events['EVENT_MODIFY_PROCESS']:
            o_loss = o - torch.tensor([TRUSTED, o[1], o[2], o[3], o[4]])

        elif event_type in WRITE_SET:
            # to be discussed: which to be chosen to optimized (one is enough, more is also ok)
            o_loss = o - torch.tensor([o[0], o[1], o[2], 1, o[4]])
            # if alarm_name == "DataLeak":
            #     s_loss = s - torch.tensor([s[0], s[1], s[2], 1, 1])

        elif event_type in SET_UID_SET:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 1, s[4]])

        elif event_type == standard_events['EVENT_MODIFY_FILE_ATTRIBUTES']:
            o_loss = o - torch.tensor([o[0], o[1], o[2], 1, o[4]])

        elif event_type in {standard_events['EVENT_MPROTECT'], standard_events['EVENT_MMAP']}:
            s_loss = s - torch.tensor([s[0], s[1], s[2], 1, s[4]])

    return torch.mean(torch.square(s_loss)), torch.mean(torch.square(o_loss))