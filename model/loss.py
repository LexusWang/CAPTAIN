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
def get_loss(event_type: int, s, o, origtags, alarm_name: str, side):
    origtags_loss, s_loss, o_loss = torch.zeros(5), torch.zeros(5), torch.zeros(5)

    if side == "false_positive":
        if event_type == standard_events['EVENT_EXECUTE'] or event_type == standard_events['EVENT_LOADLIBRARY']:
            if citag(origtags) == TRUSTED and citag(s.tags()) == UNTRUSTED:
                s_loss -= torch.tensor([TRUSTED, 0, 0, 0, 0])

        elif event_type == standard_events['EVENT_WRITE']:
            if (o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe[") and not o.isMatch(
                    "pipe") and not o.isMatch("null") and itag(origtags) > 0.5 and itag(o.tags()) <= 0.5):
                # to be discussed: which to be chosen to optimized (one is enough, more is also ok)
                o_loss -= torch.tensor([0, 0, 0, np.random.normal(0.75, 1), 0])
                if alarm_name == "DataLeak":
                    s_loss -= torch.tensor([0, 0, 0, np.random.normal(0.75, 1), np.random.normal(0.75, 1)])

    elif side == "false_negative":
        if event_type == standard_events['EVENT_EXECUTE'] or event_type == standard_events['EVENT_LOADLIBRARY']:
            s_loss = alltags(citag(s.tags()) - UNTRUSTED, 0, 0, 0, 0)
            s_loss -= torch.tensor([UNTRUSTED, 0, 0, 0, 0])
        elif event_type == standard_events['EVENT_WRITE']:
            if (o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe[") and not o.isMatch(
                    "pipe") and not o.isMatch("null")):
                o_loss -= torch.tensor([0, 0, 0, np.random.normal(0.25, 1), 0])
                if alarm_name == "DataLeak":
                    s_loss -= torch.tensor([0, 0, 0, np.random.normal(0.25, 1), np.random.normal(0.25, 1)])

    return torch.mean(s_loss), torch.mean(o_loss)