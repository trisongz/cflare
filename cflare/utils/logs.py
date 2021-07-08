import os
import sys
import logging
import threading
from typing import Optional


try:
    from google.colab import auth
    _colab = True
except ImportError:
    _colab = False

_lock = threading.Lock()
_cflare_handler: Optional[logging.Handler] = None
_notebook = sys.argv[-1].endswith('json')


class LogFormatter(logging.Formatter):
    COLOR_CODES = {
        logging.CRITICAL: "\033[38;5;196m", # bright/bold magenta
        logging.ERROR:    "\033[38;5;9m", # bright/bold red
        logging.WARNING:  "\033[38;5;11m", # bright/bold yellow
        logging.INFO:     "\033[38;5;111m", # white / light gray
        logging.DEBUG:    "\033[1;30m"  # bright/bold black / dark gray
    }

    RESET_CODE = "\033[0m"
    def __init__(self, color, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.color = color

    def format(self, record, *args, **kwargs):
        if (self.color == True and record.levelno in self.COLOR_CODES):
            record.color_on  = self.COLOR_CODES[record.levelno]
            record.color_off = self.RESET_CODE
        else:
            record.color_on  = ""
            record.color_off = ""
        return super(LogFormatter, self).format(record, *args, **kwargs)

class CFlareLogger:
    def __init__(self, config):
        self.config = config
        self.logger = self.setup_logging()
    
    def setup_logging(self):
        logger = logging.getLogger(self.config['name'])
        logger.setLevel(logging.INFO)
        if _notebook or _colab:
            console_log_output = sys.stdout
        else:
            console_log_output = sys.stderr
        
        console_handler = logging.StreamHandler(console_log_output)
        console_handler.setLevel(self.config["console_log_level"].upper())
        console_formatter = LogFormatter(fmt=self.config["log_line_template"], color=self.config["console_log_color"])
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        return logger

    def get_logger(self):
        return self.logger
    
    def debug(self, msg, *args, **kwargs):
        return self.logger.debug(msg, *args, **kwargs)
    
    def info(self, msg, *args, **kwargs):
        return self.logger.info(msg, *args, **kwargs)
    
    def warn(self, msg, *args, **kwargs):
        return self.logger.warn(msg, *args, **kwargs)
    
    def error(self, msg, *args, **kwargs):
        return self.logger.error(msg, *args, **kwargs)
    
    def __call__(self, msg, *args, **kwargs):
        return self.logger.info(msg, *args, **kwargs)
    


def _setup_library_root_logger(name):
    logger_config = {
        'name': name,
        'console_log_output': "stdout", 
        'console_log_level': "info",
        'console_log_color': True,
        'logfile_file': None,
        'logfile_log_level': "debug",
        'logfile_log_color': False,
        'log_line_template': f"%(color_on)s[{name}] %(funcName)-5s%(color_off)s: %(message)s"
    }
    return CFlareLogger(logger_config)


def _configure_library_root_logger(name="CFlare") -> None:
    global _cflare_handler
    with _lock:
        if _cflare_handler:
            return
        _cflare_handler = _setup_library_root_logger(name)
        _cflare_handler.propagate = True


def get_logger(name: Optional[str] = "CFlare") -> logging.Logger:
    if name is None:
        name = "CFlare"
    _configure_library_root_logger(name)
    return _cflare_handler
