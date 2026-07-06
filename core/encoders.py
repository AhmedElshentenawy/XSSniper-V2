import base64 as b64
import binascii
import re
from urllib.parse import quote, unquote

from core.log import setup_logger

logger = setup_logger(__name__)


def base64(string):
    """
    Toggles base64 encoding: decodes if `string` looks like valid base64,
    otherwise encodes it.

    Fallback/retry: a string can pass the "looks like base64" check (right
    alphabet, length a multiple of 4) and still fail to decode into valid
    UTF-8, e.g. because it's really plaintext that happens to only use
    base64-alphabet characters. Rather than let that raise mid-scan, we
    log it at debug level and fall back to encoding the string instead.
    """
    if re.match(r'^[A-Za-z0-9+\/=]+$', string) and (len(string) % 4) == 0:
        try:
            return b64.b64decode(string.encode('utf-8')).decode('utf-8')
        except (UnicodeDecodeError, binascii.Error) as e:
            logger.debug(
                'base64 encoder: "%s" looked like base64 but failed to '
                'decode (%s); falling back to encoding it instead.'
                % (string, e))
    return b64.b64encode(string.encode('utf-8')).decode('utf-8')


def urlEncode(string):
    """
    Toggles URL-encoding: decodes if the string looks percent-encoded,
    otherwise encodes it. Mirrors base64()'s "detect direction" behavior
    so it can be used as a drop-in --encode option.

    Fallback/retry: wraps the decode attempt so any unexpected failure
    while unquoting falls back to encoding instead of propagating and
    aborting the run.
    """
    try:
        decoded = unquote(string)
        if decoded != string:
            return decoded
    except Exception as e:
        logger.debug(
            'url encoder: failed to decode "%s" (%s); falling back to '
            'encoding it instead.' % (string, e))
    return quote(string, safe='')


# Registry so callers (e.g. xssniper.py) can resolve an --encode value
# like "url" or "base64" to the right function without new branching
# inside the existing scan/crawl/fuzz functions.
ENCODERS = {
    'base64': base64,
    'url': urlEncode,
}


def get_encoder(name):
    """
    Resolves an --encode value to its encoder function. Returns False for
    an unrecognized name, matching the historical hardcoded-check
    behavior -- but now logs a warning naming the bad value and the
    supported options instead of silently doing nothing.

    This matters because argparse's `choices` validation is only enforced
    when a flag is actually supplied on the command line. A value that
    arrives via `--config` (through `apply_config_defaults`, which sets
    argparse *defaults*) skips that validation entirely, so a typo'd or
    unsupported encoder name in a config file would otherwise fail silent.
    """
    encoder = ENCODERS.get(name, False)
    if not encoder and name:
        logger.warning(
            'Unrecognized --encode value "%s". Supported options are: %s. '
            'Continuing without payload encoding.'
            % (name, ', '.join(sorted(ENCODERS.keys()))))
    return encoder

