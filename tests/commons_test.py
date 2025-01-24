import logging
import os
import unittest

from siem_mtad_gat import settings
from siem_mtad_gat.commons import EscapeError, EscapeInfo, EscapeWarning

os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.VERBOSE_LOGGING_LEVEL)



class TestException(unittest.TestCase):  
    def test_error(self):
         with self.assertRaises(Exception):
            raise EscapeError("Test Error",logger)
         
    def test_warning(self):
         with self.assertRaises(Warning):
            raise EscapeWarning("Test Warning",logger)
         
    def test_info(self):
        EscapeInfo("Test Info",logger)    
