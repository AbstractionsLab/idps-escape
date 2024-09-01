"""Common exceptions, classes, and functions for IDPS-ESCAPE."""

import argparse
import logging
import os
import json
import functools

import siem_mtad_gat.settings as escape_settings


verbosity = 0  # global verbosity setting for controlling string formatting
PRINT_VERBOSITY = 0  # minimum verbosity to using `print`
STR_VERBOSITY = 3  # minimum verbosity to use verbose `__str__`
MAX_VERBOSITY = 4  # maximum verbosity level implemented



logger = logging.getLogger
log = logger(__name__)


# exception classes ##########################################################


class EscapeError(Exception):
    """Generic idps-escape error."""

class IdpsEscapeWarning(EscapecError, Warning):
    """Generic idps-escape warning."""

class IdpsEscapeInfo(EscapeWarning, Warning):
    """Generic idps-escape info."""

# Logging classes #################

class WarningFormatter(logging.Formatter):
    """Logging formatter that displays verbose formatting for WARNING+."""

    def __init__(self, default_format, verbose_format, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_format = default_format
        self.verbose_format = verbose_format

    def format(self, record):
        """Python 3 hack to change the formatting style dynamically."""
        if record.levelno > logging.INFO:
            self._style._fmt = self.verbose_format  # pylint: disable=W0212
        else:
            self._style._fmt = self.default_format  # pylint: disable=W0212
        return super().format(record)

### Files management (possibly to be moved)