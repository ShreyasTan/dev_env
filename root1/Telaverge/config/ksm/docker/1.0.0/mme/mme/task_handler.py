""" """
import sys
import os
import time
import threading
import traceback

from mme.mme.tcp_client import TcpClient
from mme.mme.constants import Constants
from mme.mme.rest_api import RESTAPIServer
from mme.mme.mme_log import MMELogMgr

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
        self._log = MMELogMgr("TaskHandler").get_logger()
        self._log.debug(">")
        self._task_runner = True
        self._task_queue = Queue()


        self.regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self.regal_root_path:
            args = {
                'host': Constants.HOST_IP,
                'port': Constants.MME_REST_API_PORT
            }
        else:
            args = {
                'host': Constants.HOST_IP,
                'port': Constants.MME_REST_API_PORT
            }
        self._tcp_cli = TcpClient()
        self._rest_api = RESTAPIServer(self._task_queue, self._tcp_cli)
        rest_app = self._rest_api.rest()
        self._rest_thread = threading.Thread(target=rest_app.run, kwargs=args)
        self._rest_thread.setName("RestThread")
        self._rest_thread.start()

        self._task_thread = threading.Thread(target=self.poll_task_runner,
                args=())
        self._task_thread.setName("TaskHandlerThread")
        self._task_thread.start()
        self._log.debug("<")

    def poll_task_runner(self):
        """ Method monitor for task in the queue
        """
        self._log.debug(">")
        try:
            while self._task_runner:
                try:
                    self.execute_task()
                    time.sleep(5)
                except Exception as ex:
                    self._log.error("Failed to execute the task ex: %s", ex)
                    trace_back = traceback.format_exc()
                    self._log.error("Trace back: %s". trace_back)
                    self._log.debug("<")
        except KeyboardInterrupt:
            self._log.debug("<")
            self._tcp_cli.stop_recv_thread()
            self.stop()

    def execute_task(self):
        """ Method execute the task which present in the
        queue

        Retuns:
            None

        """
        self._log.debug(">")
        if self._task_queue.empty():
            self._log.debug("<")
            return None
        try:
            data = self._task_queue.get(timeout=1)
        except Empty:
            pass

        if not data:
            self._log.debug("<")
            return
        if data["action"] == Constants.TRIGGER_REQUEST:
            args = data["args"]
            self._tcp_cli.send_message(args['msg'], args['brust_size'], args['duration'],
                    args['interval_time'])
        self._log.debug("<")

    def stop(self):
        """ Method stop the task and rest api thread

        Returns:
            None

        """
        self._log.debug(">")
        self._task_runner = False
        if self._task_thread:
            self._task_thread.join()
        if self._rest_thread:
            self._rest_thread.join()
        self._log.debug("<")

if __name__ == "__main__":
    obj = TaskHandler()
