"""
This module is used to add the csmlog.
"""

import os
import errno
import logging
from mme.mme.constants import Constants

class MMELogMgr(object):
    """ This class update all MME log"""
    def __init__(self, cls_name):
        self._mme_log = logging.getLogger(cls_name)
        self.mkdir(Constants.MME_DEBUG_LOG_PATH)
        self.mkdir(Constants.MME_ERROR_LOG_PATH)
        self._mme_log.setLevel(logging.DEBUG)
        fileHandler1 = logging.FileHandler(Constants.MME_DEBUG_LOG_PATH)
        fileHandler1.setLevel(logging.DEBUG)
        fileHandler2 = logging.FileHandler(Constants.MME_ERROR_LOG_PATH)
        fileHandler2.setLevel(logging.ERROR)

        formatter = logging.Formatter(Constants.MME_LOG_FORMAT)
        fileHandler2.setFormatter(formatter)
        fileHandler1.setFormatter(formatter)

        self._mme_log.addHandler(fileHandler2)
        self._mme_log.addHandler(fileHandler1)

    def get_logger(self):
        return self._mme_log

    def mkdir(self, path):
        dest_dir = path.rsplit("/", 1)[0]
        if not os.path.exists(dest_dir):
            try:
                os.makedirs(dest_dir)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                pass
