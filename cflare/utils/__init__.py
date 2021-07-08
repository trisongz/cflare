import os
import json

from . import logs
from .logs import get_logger

logger = get_logger()

from .. import cflare_config

if os.path.exists(cflare_config):
    config = json.load(open(cflare_config, 'r'))
    for key, val in config.items():
        os.environ[key] = val

def save_config(config):
    with open(cflare_config, 'w') as f:
        json.dump(config, f)