import time
import sys
import torch

sys.path.extend(['.', '..', '...'])

# import floatTags
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import citag, ctag, invtag, itag, etag, alltags
from parse.eventType import lttng_events, cdm_events, standard_events

import numpy as np

# loss function is called only when false positive or false negative appear
def get_loss(event_type: str, s: torch.Tensor, o: torch.Tensor, alarm_name: str, side, format = 'cdm'):
    if format == 'cdm':
      event_type = cdm_events[event_type]
    elif format == 'lttng':
        event_type = lttng_events[event_type]

    s_loss, o_loss = torch.zeros(5, requires_grad=True), torch.zeros(5, requires_grad=True)

    if side == "false_positive":
        if event_type == standard_events['EVENT_EXECUTE'] or event_type == standard_events['EVENT_LOADLIBRARY']:
            s_loss = s - torch.tensor([TRUSTED, 0, 0, 0, 0])

        elif event_type == standard_events['EVENT_MODIFY_PROCESS']:
            o_loss = o - torch.tensor([TRUSTED, 0, 0, 0, 0])

        elif event_type in {standard_events['EVENT_WRITE'],standard_events['EVENT_SENDMSG']}:
            # to be discussed: which to be chosen to optimized (one is enough, more is also ok)
            o_loss = o - torch.tensor([0, 0, 0, np.random.normal(0.75, 1), 0])
            if alarm_name == "DataLeak":
                s_loss = s - torch.tensor([0, 0, 0, np.random.normal(0.75, 1), np.random.normal(0.75, 1)])

        elif event_type == standard_events['EVENT_CHANGE_PRINCIPAL']:
            s_loss = s - torch.tensor([0, 0, 0, np.random.normal(0.75, 1), 0])

    elif side == "false_negative":
        if event_type == standard_events['EVENT_EXECUTE'] or event_type == standard_events['EVENT_LOADLIBRARY']:
            s_loss = s - torch.tensor([UNTRUSTED, 0, 0, 0, 0])

        elif event_type == standard_events['EVENT_MODIFY_PROCESS']:
            o_loss = o - torch.tensor([UNTRUSTED, 0, 0, 0, 0])

        elif event_type in {standard_events['EVENT_WRITE'],standard_events['EVENT_SENDMSG']}:
            o_loss = o - torch.tensor([0, 0, 0, np.random.normal(0.25, 1), 0])
            if alarm_name == "DataLeak":
                s_loss = s - torch.tensor([0, 0, 0, np.random.normal(0.25, 1), np.random.normal(0.25, 1)])

        elif event_type == standard_events['EVENT_CHANGE_PRINCIPAL']:
            s_loss = s - torch.tensor([0, 0, 0, np.random.normal(0.25, 1), 0])

    return torch.mean(s_loss), torch.mean(o_loss)