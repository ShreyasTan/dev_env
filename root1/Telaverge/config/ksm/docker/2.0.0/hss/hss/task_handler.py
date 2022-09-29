""" """
import sys
import os
import time
import threading
import traceback

from hss.hss.tcp_server import TcpServer
from hss.hss.constants import Constants
from hss.hss.rest_api import RESTAPIServer
from hss.hss.hss_log import HSSLogMgr

IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    from Queue import Queue
    from Queue import Empty
else:
    from queue import Queue
    from queue import Empty

class TaskHandler:
    """ """
    def __init__(self):
        self._log = HSSLogMgr("TaskHandler").get_logger()
        self._log.debug(">")

        self.regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self.regal_root_path:
            args = {
                'host': Constants.HOST_IP,
                'port': Constants.HSS_REST_API_PORT
            }
        else:
            args = {
                'host': Constants.HOST_IP,
                'port': Constants.HSS_REST_API_PORT
            }
        self._tcp_ser = TcpServer()
        self._rest_api = RESTAPIServer(self._tcp_ser)
        rest_app = self._rest_api.rest()
        self._rest_thread = threading.Thread(target=rest_app.run, kwargs=args)
        self._rest_thread.setName("RestThread")

    def run(self):
        """ Method start the threads """
        try:
            self._log.debug(">")
            self._rest_thread.start()
            self._tcp_ser.run()
            self._log.debug("<")
        except Exception as ex:
            self._log.error("Failed to execute the task ex: %s", ex)
            trace_back = traceback.format_exc()
            self._log.error("Trace back: %s". trace_back)
            self._log.debug("<")
        except KeyboardInterrupt:
            self._tcp_ser.stop()
            self.stop()
            self._log.debug("<")

    def stop(self):
        """ Method stops the rest thread and process"""
        self._log.debug(">")
        if self._rest_thread:
            self._rest_thread.join()
        self._log.debug("<")



if __name__ == "__main__":
    obj = TaskHandler()
    obj.run()
