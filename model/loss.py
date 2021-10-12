import time
import sys

sys.path.extend(['.', '..', '...'])

# import floatTags
from policy.floatTags import TRUSTED, UNTRUSTED, BENIGN, PUBLIC
from policy.floatTags import citag, ctag, invtag, itag, etag, alltags
from parse.eventType import lttng_events, cdm_events, standard_events

import numpy as np

# loss function is called only when false positive or false negative appear
def get_loss(event_type: int, s, o, origtags, alarm_name: str, side):
    origtags_loss, s_loss, o_loss = [0] * 5, [0] * 5, [0] * 5

    if side == "false_positive":
        if event_type == standard_events['EVENT_EXECUTE'] or event_type == standard_events['EVENT_LOADLIBRARY']:
            if citag(origtags) == TRUSTED and citag(s.tags()) == UNTRUSTED:
                origtags_loss = alltags(citag(origtags) - UNTRUSTED, 0, 0, 0, 0)
                s_loss = alltags(citag(s.tags()) - TRUSTED, 0, 0, 0, 0)
            return s_loss, o_loss, origtags_loss

        if event_type == standard_events['EVENT_WRITE']:
            if (o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe[") and not o.isMatch(
                    "pipe") and not o.isMatch("null") and itag(origtags) > 0.5 and itag(o.tags()) <= 0.5):

                # to be discussed: which to be chosen to optimized (one is enough, more is also ok)
                origtags_loss = alltags(0, 0, 0, itag(origtags) - np.random.normal(0.25, 1), 0)
                o_loss = alltags(0, 0, 0, itag(o.tags()) - np.random.normal(0.75, 1), 0)

                if alarm_name == "DataLeak":
                    s_loss = alltags(0, 0, 0, itag(s.tags()) - np.random.normal(0.75, 1), ctag(s.tags()) - np.random.normal(0.75, 1))

            return s_loss, o_loss, origtags_loss

    elif side == "false_negative":
        if event_type == standard_events['EVENT_EXECUTE'] or event_type == standard_events['EVENT_LOADLIBRARY']:
            origtags_loss = alltags(citag(origtags) - TRUSTED, 0, 0, 0, 0)
            s_loss = alltags(citag(s.tags()) - UNTRUSTED, 0, 0, 0, 0)
            return s_loss, o_loss, origtags_loss
        if event_type == standard_events['EVENT_WRITE']:
            if (o.isIP() and not o.isMatch("UnknownObject") and not o.isMatch("Pipe[") and not o.isMatch(
                    "pipe") and not o.isMatch("null")):
                origtags_loss = alltags(0, 0, 0, itag(origtags) - np.random.normal(0.75, 1), 0)
                o_loss = alltags(0, 0, 0, itag(o.tags()) - np.random.normal(0.25, 1), 0)

                if alarm_name == "DataLeak":
                    s_loss = alltags(0, 0, 0, itag(s.tags()) - np.random.normal(0.25, 1),
                                     ctag(s.tags()) - np.random.normal(0.25, 1))
            return s_loss, o_loss, origtags_loss

    return s_loss, o_loss, origtags_loss