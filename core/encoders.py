import base64 as b64
import re
from urllib.parse import quote, unquote


def base64(string):
    if re.match(r'^[A-Za-z0-9+\/=]+$', string) and (len(string) % 4) == 0:
        return b64.b64decode(string.encode('utf-8')).decode('utf-8')
    else:
        return b64.b64encode(string.encode('utf-8')).decode('utf-8')


def urlEncode(string):
    """
    Toggles URL-encoding: decodes if the string looks percent-encoded,
    otherwise encodes it. Mirrors base64()'s "detect direction" behavior
    so it can be used as a drop-in --encode option.
    """
    decoded = unquote(string)
    if decoded != string:
        return decoded
    return quote(string, safe='')


# Registry so callers (e.g. xsstrike.py) can resolve an --encode value
# like "url" or "base64" to the right function without new branching
# inside the existing scan/crawl/fuzz functions.
ENCODERS = {
    'base64': base64,
    'url': urlEncode,
}


def get_encoder(name):
    return ENCODERS.get(name, False)
