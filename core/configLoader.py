"""
core/configLoader.py

Adds support for external configuration overlays, e.g.:

    python xsstrike.py --config xssniper.yaml
    python xsstrike.py --config xssniper.json

The loaded file's keys are used to override argparse *defaults* before
parsing, so command-line flags the user actually types always win.
Supported keys are any `dest` name used in xsstrike.py's argparse setup
(e.g. "target", "delay", "threadCount", "level", "timeout", "skip", ...).

This module is intentionally standalone: it doesn't change any of the
existing scanning/crawling/fuzzing functions, it only helps populate
the arguments that get passed into them.
"""

import json
import os

from core.log import setup_logger

logger = setup_logger(__name__)

SUPPORTED_EXTENSIONS = ('.yaml', '.yml', '.json')


def _load_yaml(path):
    try:
        import yaml
    except ImportError:
        logger.error(
            'PyYAML is not installed but a .yaml/.yml config was supplied. '
            'Install it with: pip install pyyaml --break-system-packages')
        return {}
    with open(path, 'r') as f:
        data = yaml.safe_load(f)
    return data or {}


def _load_json(path):
    with open(path, 'r') as f:
        data = json.load(f)
    return data or {}


def load_config(path):
    """
    Reads a YAML or JSON config file and returns a dict of overrides.
    Returns an empty dict (and logs an error) on any problem, so a bad
    config file never crashes a scan -- it just falls back to defaults.
    """
    if not path:
        return {}
    if not os.path.isfile(path):
        logger.error('Config file not found: %s' % path)
        return {}

    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in ('.yaml', '.yml'):
            config = _load_yaml(path)
        elif ext == '.json':
            config = _load_json(path)
        else:
            logger.error(
                'Unsupported config extension "%s". Use one of: %s'
                % (ext, ', '.join(SUPPORTED_EXTENSIONS)))
            return {}
    except Exception as e:
        logger.error('Failed to parse config file %s: %s' % (path, e))
        return {}

    if not isinstance(config, dict):
        logger.error('Config file %s must contain a top-level mapping/object.' % path)
        return {}

    logger.debug_json('Loaded config overrides from %s:' % path, config)
    return config


def apply_config_defaults(parser, config):
    """
    Overlays `config` dict values onto an argparse.ArgumentParser's
    defaults, matched by `dest` name. Unknown keys are ignored with a
    warning so typos in a config file don't silently do nothing.

    BUGFIX: argparse only enforces an argument's `choices=` restriction
    when the flag is typed on the command line -- `parser.set_defaults()`
    happily accepts anything, since it bypasses that check entirely. A
    config file setting, e.g., `console_log_level: TRACE` used to sail
    through here and only blow up later as a raw KeyError inside
    core/log.py's setup_logger(), or (for `encode`) silently rely on a
    separate downstream check in get_encoder(). This validates against
    each action's declared `choices` at the same place the value is
    accepted, so the whole class of "config file bypasses choices" bugs
    is closed here instead of needing a bespoke guard at every call site.
    """
    if not config:
        return

    dest_to_action = {action.dest: action for action in parser._actions}
    for key, value in config.items():
        action = dest_to_action.get(key)
        if action is None:
            logger.warning('Ignoring unknown config key: %s' % key)
            continue
        if action.choices is not None and value not in action.choices:
            logger.warning(
                'Ignoring invalid value %r for "%s" in config file. Supported '
                'values are: %s. Falling back to the built-in default.'
                % (value, key, ', '.join(str(c) for c in action.choices)))
            continue
        parser.set_defaults(**{key: value})

