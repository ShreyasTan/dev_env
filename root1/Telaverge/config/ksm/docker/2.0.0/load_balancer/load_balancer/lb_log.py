"""
This module is used to add the csmlog.
"""

import os
import errno
import logging
from load_balancer.load_balancer.constants import Constants

class LBLogMgr(object):
    """ This class update all load balancer log"""
    def __init__(self, cls_name):
        self._lb_log = logging.getLogger(cls_name)
        self.mkdir(Constants.LB_DEBUG_LOG_PATH)
        self.mkdir(Constants.LB_ERROR_LOG_PATH)
        self._lb_log.setLevel(logging.DEBUG)
        fileHandler1 = logging.FileHandler(Constants.LB_DEBUG_LOG_PATH)
        fileHandler1.setLevel(logging.DEBUG)
        fileHandler2 = logging.FileHandler(Constants.LB_ERROR_LOG_PATH)
        fileHandler2.setLevel(logging.ERROR)

        formatter = logging.Formatter(Constants.LB_LOG_FORMAT)
        fileHandler2.setFormatter(formatter)
        fileHandler1.setFormatter(formatter)

        self._lb_log.addHandler(fileHandler2)
        self._lb_log.addHandler(fileHandler1)

    def get_logger(self):
        return self._lb_log

    def mkdir(self, path):
        dest_dir = path.rsplit("/", 1)[0]
        if not os.path.exists(dest_dir):
            try:
                os.makedirs(dest_dir)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                pass
