# Patch notes for `xsstrike.py`

None of this touches `modes/scan.py`, `modes/crawl.py`, `modes/singleFuzz.py`,
`modes/bruteforcer.py`, or any of the parser/generator/checker core logic.
It only changes how `xsstrike.py` builds its argparse config before calling
into those unchanged functions.

## 1. Import the new config loader

Add near the other `core.*` imports at the top:

```python
from core.configLoader import load_config, apply_config_defaults
from core.encoders import get_encoder
```

## 2. Add `--config` and group the existing arguments

Replace the flat `parser.add_argument(...)` block with grouped ones for
cleaner `--help` output, and add `--config`. Example (trimmed to show the
pattern -- keep all your existing arguments, just move them into groups):

```python
parser = argparse.ArgumentParser(
    description='XSStrike / xssniper - Advanced XSS Detection Suite')

parser.add_argument('--config', help='path to a YAML or JSON config file '
                    'whose values act as defaults (CLI flags still win)',
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
misc_group.add_argument('--file-log-level', help='name of the file to log',
                        dest='file_log_level', choices=core.log.log_config.keys(),
                        default=None)
misc_group.add_argument('--log-file', help='name of the file to log',
                        dest='log_file', default=core.log.log_file)

# --- config overlay: parse just --config first, apply it as new defaults,
# then do the real parse so real CLI flags still take priority.
prelim_args, _ = parser.parse_known_args()
if getattr(prelim_args, 'config_path', None):
    overrides = load_config(prelim_args.config_path)
    apply_config_defaults(parser, overrides)

args = parser.parse_args()
```

## 3. Resolve the encoder through the registry instead of a hardcoded check

Replace:

```python
encoding = base64 if encode and encode == 'base64' else False
```

with:

```python
encoding = get_encoder(encode) if encode else False
```

(`get_encoder` returns `False` for an unrecognized name, matching the old
fallback behavior, and now also understands `'url'`.)

Everything downstream (`scan()`, `crawl()`, `singleFuzz()`, `bruteforcer()`)
already accepts `encoding` as "a callable or False", so no changes are
needed there.

## 4. requirements.txt

Add `pyyaml` as an optional dependency for YAML configs (JSON configs work
with zero new dependencies):

```
tld
fuzzywuzzy
requests
pyyaml
```

## 5. Running the tests

```
pip install pytest --break-system-packages
pytest tests/
```
