from datetime import datetime
import pytz

def get_ET_from_nano_ts(prt_ts):
    dt = datetime.fromtimestamp(prt_ts / 1e9)
    ny_tz = pytz.timezone('America/New_York')
    ny_dt = dt.astimezone(ny_tz)
    
    return ny_dt