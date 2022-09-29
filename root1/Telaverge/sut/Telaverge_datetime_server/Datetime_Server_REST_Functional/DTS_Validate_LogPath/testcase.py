"""
Validate if DateTimeServer is returning a valid log path by invoking REST API.
Fetch the log file from the host machine.

Test Steps
Start DateTimeServer application on  Node1 (datetime_server_node).
Verify if DateTimeServer application is running with "ps" command.
Get the log path by invoking REST API.
Fetch and validate the log file from the host machine.
Stop the TimeServer application.


Result
Pass if  log path returned by the DateTimeServer is valid.
"""

import time
from test_executor.test_executor.utility import GetRegal
import os
import sys
from Telaverge.helper.datetime_helper import DateTimeHelper
import regal_lib.corelib.custom_exception as exception


class DateTimeServerTest2(object):
    def __init__(self):
        log_mgr_obj = GetRegal().get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger("DateTimeServerTest")
        # self._failure_causes = []
        self._note = []
        self._topology = GetRegal().get_current_run_topology()
        self.tc_name = GetRegal().get_current_test_case()
        self.datetime_server_node = self._topology.get_node(
            "datetime_server_node")
        self.date_time = DateTimeHelper(
            GetRegal(), "datetime_server_node", "datetime_server")

        self._log.debug(">")

    def execute_test_case(self):
        """
        1.Start DateTimeServer application on  Node1 (datetime_server_node).
        2.Verify if DateTimeServer application is running with "ps" command.
        3.Get the log path by invoking REST API http://<datetimeserverip>:<portno>/log_path.
        4.Fetch and validate the log file from the host machine.
        5.Stop the TimeServer application.
        Returns(bool): True if test case is success.

        """
        self._log.debug(">")
        tc_name = os.path.basename(__file__)
        host = self.datetime_server_node.get_management_ip()
        try:
            # Start the datetime_server application.
            self.date_time.setup_stats()
            self.date_time.start_server()
            time.sleep(2)
            self.date_time.start_stats()
            self._tc_result = "Success"
            if not self.date_time.process_running("datetime_server"):
                self._log.debug("<")
                self._tc_result = "Failed"
                # self._failure_causes.append("Test case {} is failed due to:"
                #                             " datetime_server failed to start!".format(tc_name))
                raise exception.TestCaseFailed(self.tc_name, "Test case {} is failed due to: "
                                "datetime_server failed to start!".format(tc_name))

            # Get the log path by invoking REST API http://<datetimeserverip>:<portno>/log_path.
            count = 0
            while count <= 4:
                result = self.date_time.get_log_path()
                self._log.info("Log path on remote host %s : %s",
                                str(host), str(result))
                hosts = [host]
                file_name = result.split('/')[-1]
                # if GetRegal().get_deployment_mgr_client_obj().fetch_file(hosts, result, "/tmp/"):
                #     self._log.debug(
                #         "Log file %s fetched successfully from %s", file_name, str(host))
                #     self.date_time.start_stats()
                # else:
                #     self._tc_result = "Failed"
                #     self._failure_causes.append("Test case {} is failed :"
                #                                 " unable to fetch log file!".format(tc_name))
                try:
                    GetRegal().get_login_session_mgr_obj().copy_files_from_node(self.datetime_server_node, 
                                            result, "/tmp/")
                    self._log.info(
                        "========================================> Log file %s fetched successfully from %s", file_name, str(host))
                except:
                    # self._tc_result = "Failed"
                    # self._failure_causes.append("Test case {} is failed :"
                    #                             " unable to fetch log file!".format(tc_name))
                    raise exception.TestCaseFailed(self.tc_name, "Test case {} is failed :"
                                                " unable to fetch log file!".format(tc_name))                                                
                count = count + 1
                time.sleep(5)

        finally:
            # stop the datetime server
            self.date_time.stop_stats()
            self._stop_server()
            self.date_time.close_session()

    def _stop_server(self):
        host = self.datetime_server_node.get_management_ip()
        tc_name = os.path.basename(__file__)
        try:
            self.date_time.stop_server()
            if self.date_time.process_running("datetime_server"):
                self._log.debug("<")
                self._tc_result = "Failed"
                # self._failure_causes.append("Test case {} is failed due to: Failed to"
                #                             " stop datetime_server".format(tc_name))
                raise exception.TestCaseFailed(self.tc_name, "Test case {} is failed due to: Failed to "
                                " stop datetime_server!".format(tc_name))
        finally:
            # self._generate_report()
            pass

        self._log.debug("<")
        return True

    # def _generate_report(self):
    #     """ Generate the report """
    #     try:
    #         from Telaverge.helper.datetime_benchmark_report import DatetimeServerReport as report
    #         report(tc_result=self._tc_result,
    #                failure_causes=self._failure_causes).generate_report()
    #     except Exception as ex:
    #         self._log.error("Report is not generated due to %s", str(ex))
    #     finally:
    #         if "DatetimeServerReport" in sys.modules:
    #             del sys.modules["DatetimeServerReport"]


def execute():
    tc_obj = DateTimeServerTest2()
    tc_obj.execute_test_case()
