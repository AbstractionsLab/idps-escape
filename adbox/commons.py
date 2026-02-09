"""Common exceptions, classes, and functions for IDPS-ESCAPE."""

import argparse
import logging
import os
import json
import functools

import adbox.settings as settings


verbosity = 0  # global verbosity setting for controlling string formatting
PRINT_VERBOSITY = 0  # minimum verbosity to using `print`
STR_VERBOSITY = 3  # minimum verbosity to use verbose `__str__`
MAX_VERBOSITY = 4  # maximum verbosity level implemented



logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name="idsp-escape-adbox"), filemode='a', format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)
# exception classes ##########################################################



class EscapeError(Exception):
    """Generic idps-escape error."""
    def __init__(self, message:str,log:logging.Logger|None=logger): 
        if log is not None: log.exception(message)
        super().__init__(message)
    
class EscapeWarning(EscapeError, Warning):
    """Generic idps-escape warning."""
    def __init__(self, message:str, log:logging.Logger|None=logger): 
        if log is not None: log.warning(message)
        super().__init__(message)

class EscapeInfo:
    """Generic idps-escape info."""
    def __init__(self, message:str, log:logging.Logger|None=logger): 
        if log is not None: log.info(message)
        print(message)


