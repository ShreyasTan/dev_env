"""
 Validate if DateTimeServer prints the correct Time on invoking REST API.

Test Steps
Start DateTimeServer application on  Node1 (datetime_server_node).
Verify if DateTimeServer application is running with "ps" command.
Print the Time by invoking REST API.
Verify if the Time returned by the DateTimeServer matches with the current Time.
Stop the TimeServer application.

Result
Pass if  Time returned by the DateTimeServer matches with the current Time.
"""

import time
from datetime import timedelta, datetime
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
        1.Start DateTimeServer application on  Node1  with CentOS 7.5.
        2.Verify if DateTimeServer application is running with "ps" command.
        3.Print the Time by invoking REST API http://<datetimeserverip>:<portno>/date_and_time.
        4.Verify if the Time returned by the DateTimeServer matches with the current Time.
        5.Stop the TimeServer application.

        Returns(bool): True if test case is success.

        """
        self._log.debug(">")
        host = self.datetime_server_node.get_management_ip()
        tc_name = os.path.basename(__file__)
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
                raise exception.TestCaseFailed(self.tc_name, "Test case {} is failed due to:"
                                " datetime_server failed to start!".format(tc_name))

            # get the Date and Time from the current machine
            count = 0
            while count <= 4:
                current_time_obj = datetime.now()

                # get the time from the host by invoking REST API http://<datetimeserverip>:<portno>/date_and_time.
                console_output = self.date_time.get_date_time()
                host_datetime_obj = datetime.strptime(
                    console_output, '%d-%B-%Y %H:%M:%S')
                self._log.info("Date and time in datetime_server_node: %s", host_datetime_obj)
                self._log.info("Expected Date and time: %s", current_time_obj)
                current_lower = current_time_obj - timedelta(seconds=10)
                current_higher = current_time_obj + timedelta(seconds=10)
                # compare the current machine's time with the time printed by datetime_server on host.
                if host_datetime_obj > current_lower and host_datetime_obj < current_higher:
                    self._log.info(
                        "========================================> Date and Time found in host %s is correct", host)
                else:
                    self._log.error("Current time:%s, Host time:%s", str(
                        current_time_obj), str(host_datetime_obj))
                    self._log.debug("<")
                    self._tc_result = "Failed"
                    # self._failure_causes.append("Test case {} is failed due to: Date and Time"
                    #                             " found in host {} is not correct".format(tc_name, host))
                    raise exception.TestCaseFailed(self.tc_name, "Test case {} is failed due to: Date and Time"
                                    " found in host {} is not correct".format(tc_name, host))
                count = count + 1
                time.sleep(3)

        finally:
            # stop the datetime server
            self.date_time.stop_stats()
            self._stop_server()
            self.date_time.close_session()

    def _stop_server(self):
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
