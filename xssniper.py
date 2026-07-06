#!/usr/bin/env python3

from __future__ import print_function

from core.colors import end, red, white, bad, info

# Just a fancy ass banner
print('''%s
\txssniper %sv3.1.5
%s''' % (red, white, end))

try:
    import concurrent.futures
    from urllib.parse import urlparse
    try:
        import fuzzywuzzy
    except ImportError:
        import os
        print ('%s fuzzywuzzy isn\'t installed, installing now.' % info)
        ret_code = os.system('pip3 install fuzzywuzzy')
        if(ret_code != 0):
            print('%s fuzzywuzzy installation failed.' % bad)
            quit()
        print ('%s fuzzywuzzy has been installed, restart xssniper.' % info)
        quit()
except ImportError:  # throws error in python2
    print('%s xssniper isn\'t compatible with python2.\n Use python > 3.4 to run xssniper.' % bad)
    quit()

# Let's import whatever we need from standard lib
import sys
import json
import argparse

# ... and configurations core lib
import core.config
import core.log

# NEW: config-file overlay + encoder registry (see core/configLoader.py, core/encoders.py)
from core.configLoader import load_config, apply_config_defaults
from core.encoders import get_encoder

# Processing command line arguments, where dest var names will be mapped to local vars with the same name
parser = argparse.ArgumentParser(
    description='xssniper (formerly XSStrike) - Advanced XSS Detection Suite')

# NEW: --config, parsed and applied as defaults before the "real" parse below
parser.add_argument('--config', help='path to a YAML or JSON config file whose '
                    'values act as defaults (CLI flags you type still win)',
                    dest='config_path')

target_group = parser.add_argument_group('Target')
target_group.add_argument('-u', '--url', help='url', dest='target')
target_group.add_argument('--data', help='post data', dest='paramData')
target_group.add_argument('--seeds', help='load crawling seeds from a file',
                          dest='args_seeds')

mode_group = parser.add_argument_group('Mode')
mode_group.add_argument('--crawl', help='crawl', dest='recursive', action='store_true')
mode_group.add_argument('--fuzzer', help='fuzzer', dest='fuzz', action='store_true')
mode_group.add_argument('-f', '--file', help='load payloads from a file', dest='args_file')

payload_group = parser.add_argument_group('Payloads & Encoding')
payload_group.add_argument('-e', '--encode', help='encode payloads: base64 or url',
                           dest='encode', choices=['base64', 'url'])
payload_group.add_argument('--json', help='treat post data as json',
                           dest='jsonData', action='store_true')
payload_group.add_argument('--path', help='inject payloads in the path',
                           dest='path', action='store_true')

network_group = parser.add_argument_group('Network')
network_group.add_argument('--timeout', help='timeout', dest='timeout',
                           type=int, default=core.config.timeout)
network_group.add_argument('--proxy', help='use prox(y|ies)', dest='proxy',
                           action='store_true')
network_group.add_argument('-t', '--threads', help='number of threads',
                           dest='threadCount', type=int, default=core.config.threadCount)
network_group.add_argument('-d', '--delay', help='delay between requests',
                           dest='delay', type=int, default=core.config.delay)
network_group.add_argument('--headers', help='add headers', dest='add_headers',
                           nargs='?', const=True)

crawl_group = parser.add_argument_group('Crawling')
crawl_group.add_argument('-l', '--level', help='level of crawling', dest='level',
                         type=int, default=2)
crawl_group.add_argument('--skip-dom', help="don't check for DOM XSS",
                         dest='skipDOM', action='store_true')
crawl_group.add_argument('--blind', help='inject blind XSS payload while crawling',
                         dest='blindXSS', action='store_true')

misc_group = parser.add_argument_group('Misc')
misc_group.add_argument('--update', help='update', dest='update', action='store_true')
misc_group.add_argument('--skip', help="don't ask to continue", dest='skip',
                        action='store_true')
misc_group.add_argument('--console-log-level', help='console logging level',
                        dest='console_log_level', default=core.log.console_log_level,
                        choices=core.log.log_config.keys())
misc_group.add_argument('--file-log-level', help='file logging level',
                        dest='file_log_level', choices=core.log.log_config.keys(),
                        default=None)
misc_group.add_argument('--log-file', help='name of the file to log',
                        dest='log_file', default=core.log.log_file)

# NEW: --config overlay. We peek at just --config first (parse_known_args
# ignores everything else / unrecognized flags), apply its values as new
# argparse defaults, then do the real parse so actual CLI flags still win.
prelim_args, _ = parser.parse_known_args()
if getattr(prelim_args, 'config_path', None):
    overrides = load_config(prelim_args.config_path)
    apply_config_defaults(parser, overrides)

args = parser.parse_args()

# Pull all parameter values of dict from argparse namespace into local variables of name == key
target = args.target
path = args.path
jsonData = args.jsonData
paramData = args.paramData
encode = args.encode
fuzz = args.fuzz
update = args.update
timeout = args.timeout
proxy = args.proxy
recursive = args.recursive
args_file = args.args_file
args_seeds = args.args_seeds
level = args.level
add_headers = args.add_headers
threadCount = args.threadCount
delay = args.delay
skip = args.skip
skipDOM = args.skipDOM
blindXSS = args.blindXSS
core.log.console_log_level = args.console_log_level
core.log.file_log_level = args.file_log_level
core.log.log_file = args.log_file

logger = core.log.setup_logger()

core.config.globalVariables = vars(args)

# Import everything else required from core lib
from core.config import blindPayload
from core.photon import photon
from core.prompt import prompt
from core.updater import updater
from core.utils import extractHeaders, reader, converter

from modes.bruteforcer import bruteforcer
from modes.crawl import crawl
from modes.scan import scan
from modes.singleFuzz import singleFuzz

if type(args.add_headers) == bool:
    headers = extractHeaders(prompt())
elif type(args.add_headers) == str:
    headers = extractHeaders(args.add_headers)
else:
    from core.config import headers

core.config.globalVariables['headers'] = headers
core.config.globalVariables['checkedScripts'] = set()
core.config.globalVariables['checkedForms'] = {}
core.config.globalVariables['definitions'] = json.loads('\n'.join(reader(sys.path[0] + '/db/definitions.json')))

if path:
    paramData = converter(target, target)
elif jsonData:
    headers['Content-type'] = 'application/json'
    paramData = converter(paramData)

if args_file:
    if args_file == 'default':
        payloadList = core.config.payloads
    else:
        payloadList = list(filter(None, reader(args_file)))

seedList = []
if args_seeds:
    seedList = list(filter(None, reader(args_seeds)))

# CHANGED: was `base64 if encode and encode == 'base64' else False`.
# Now resolves through the encoder registry so --encode url also works,
# and adding another encoding later doesn't need another elif here.
encoding = get_encoder(encode) if encode else False

if not proxy:
    core.config.proxies = {}

if update:  # if the user has supplied --update argument
    updater()
    quit()  # quitting because files have been changed

if not target and not args_seeds:  # if the user hasn't supplied a url
    logger.no_format('\n' + parser.format_help().lower())
    quit()

if fuzz:
    singleFuzz(target, paramData, encoding, headers, delay, timeout)
elif not recursive and not args_seeds:
    if args_file:
        bruteforcer(target, paramData, payloadList, encoding, headers, delay, timeout)
    else:
        scan(target, paramData, encoding, headers, delay, timeout, skipDOM, skip)
else:
    if target:
        seedList.append(target)
    for target in seedList:
        logger.run('Crawling the target')
        scheme = urlparse(target).scheme
        logger.debug('Target scheme: {}'.format(scheme))
        host = urlparse(target).netloc
        main_url = scheme + '://' + host
        crawlingResult = photon(target, headers, level,
                                threadCount, delay, timeout, skipDOM)
        forms = crawlingResult[0]
        domURLs = list(crawlingResult[1])
        difference = abs(len(domURLs) - len(forms))
        if len(domURLs) > len(forms):
            for i in range(difference):
                forms.append(0)
        elif len(forms) > len(domURLs):
            for i in range(difference):
                domURLs.append(0)
        threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=threadCount)
        futures = (threadpool.submit(crawl, scheme, host, main_url, form,
                                     blindXSS, blindPayload, headers, delay, timeout, encoding) for form, domURL in zip(forms, domURLs))
        for i, _ in enumerate(concurrent.futures.as_completed(futures)):
            if i + 1 == len(forms) or (i + 1) % threadCount == 0:
                logger.info('Progress: %i/%i\r' % (i + 1, len(forms)))
        logger.no_format('')

