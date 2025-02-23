#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Time    : 2024/12/11
@Author  : lexuswang
@File    : logs.py
"""


import sys
from datetime import datetime
from pathlib import Path

from loguru import logger as _logger

PROJECT_ROOT = Path(__file__).parent

_print_level = "INFO"

def define_log_level(print_level="INFO", logfile_level="DEBUG", name: str = None):
    """Adjust the log level to above level"""
    global _print_level
    _print_level = print_level

    current_date = datetime.now()
    formatted_date = current_date.strftime("%Y%m%d")
    log_name = f"{name}_{formatted_date}" if name else formatted_date  # name a log with prefix name

    _logger.remove()
    _logger.add(sys.stderr, level=print_level)
    _logger.add(PROJECT_ROOT / f"logs/{log_name}.txt", level=logfile_level)
    return _logger


logger = define_log_level()