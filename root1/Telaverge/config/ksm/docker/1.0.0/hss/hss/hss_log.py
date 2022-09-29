"""
This module is used to add the csmlog.
"""

import os
import errno
import logging
from hss.hss.constants import Constants

class HSSLogMgr(object):
    """ This class update all csm log"""
    def __init__(self, cls_name):
        self._hss_log = logging.getLogger(cls_name)
        self.mkdir(Constants.HSS_DEBUG_LOG_PATH)
        self.mkdir(Constants.HSS_ERROR_LOG_PATH)
        self._hss_log.setLevel(logging.DEBUG)
        fileHandler1 = logging.FileHandler(Constants.HSS_DEBUG_LOG_PATH)
        fileHandler1.setLevel(logging.DEBUG)
        fileHandler2 = logging.FileHandler(Constants.HSS_ERROR_LOG_PATH)
        fileHandler2.setLevel(logging.ERROR)

        formatter = logging.Formatter(Constants.HSS_LOG_FORMAT)
        fileHandler2.setFormatter(formatter)
        fileHandler1.setFormatter(formatter)

        self._hss_log.addHandler(fileHandler2)
        self._hss_log.addHandler(fileHandler1)

    def get_logger(self):
        return self._hss_log

    def mkdir(self, path):
        dest_dir = path.rsplit("/", 1)[0]
        if not os.path.exists(dest_dir):
            try:
                os.makedirs(dest_dir)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                pass
