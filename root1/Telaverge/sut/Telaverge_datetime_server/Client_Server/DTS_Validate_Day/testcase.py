"""
 Validate if DateTimeServer returns the  correct Day of the Month  on invoking REST API.
Test Steps
Start DateTimeServer application on  Node1 (datetime_server_node).
Verify if DateTimeServer application is running with "ps" command.
Print the Day of the Month  on  invoking REST API.
Verify if the Day of the Month returned by the DateTimeServer matches with the current Day of the Month.
Stop the TimeServer application.


Result
Pass if  Day of the Month returned by the DateTimeServer matches with the current Day of the Month.
"""
import time
from datetime import date
from test_executor.test_executor.utility import GetRegal
import os
import sys
from Telaverge.helper.datetime_helper import DateTimeHelper


class DateTimeServerTest2(object):
    def __init__(self):
        log_mgr_obj = GetRegal().get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger("DateTimeServerTest")
        self._failure_causes = []
        self._note = []
        self._topology = GetRegal().get_current_run_topology()
        self.server_node = self._topology.get_node("server")
        self.client_node = self._topology.get_node("client")
        self.server_helper = DateTimeHelper(
            GetRegal(), "server", "datetime_server")
        self.client_helper = DateTimeHelper(
            GetRegal(), "client", "datetime_server")

        self._log.debug(">")

    def execute_test_case(self):
        """
        1.Start DateTimeServer application on  Node1  with CentOS 7.5.
        2.Verify if DateTimeServer application is running with "ps" command.
        3.Print the Day of the Month  on  invoking REST API http://<datetimeserverip>:<portno>/day_of_month.
        4.Verify if the Day of the Month returned by the DateTimeServer matches with the current Day of the Month.
        5.Stop the TimeServer application

        Returns(bool): True if test case is success.

        """
        self._log.debug(">")
        host = self.server_node.get_management_ip()
        tc_name = os.path.basename(__file__)
        try:
            count = 10
            # Start the datetime_server application.
            self.server_helper.setup_stats()
            self.server_helper.start_snmpd()
            self.server_helper.start_server()
            self.client_helper.start_client(host, count)
            self._tc_result = "Success"
            if not self.server_helper.process_running("datetime_server"):
                self._log.debug("<")
                self._tc_result = "Failed"
                self._failure_causes.append("Test case {} is failed due to:"
                                            " datetime_server failed to start!".format(tc_name))
                raise Exception("Test case {} is failed due to: "
                                "datetime_server failed to start!".format(tc_name))

            print("The server started successfully")
            if not self.client_helper.process_running("datetime_client"):
                print("The client is not running")
                self._log.debug("<")
                self._tc_result = "Failed"
                self._failure_causes.append("Test case {} is failed due to:"
                                            " datetime_client failed to start!".format(tc_name))
                raise Exception("Test case {} is failed due to: "
                                "datetime_client failed to start!".format(tc_name))

            print("The client started successfully")
            # get the Day of the Month from the current machine
            # get the Day of the Month from the current machine
            count = 0
            while count <= 4:
                current_day_of_month = date.today().strftime("%d")
                # get the day_of_month from the host by invoking REST API http://<datetimeserverip>:<portno>/day_of_month.
                result = self.server_helper.get_day_of_month()

                # compare the current machine's day_of_month with the day_of_month printed by datetime_server on host.
                if current_day_of_month in result:
                    self._log.debug(
                        "Day of the Month found in host %s is correct", host)
                    self.server_helper.start_stats()
                else:
                    self._log.debug("<")
                    self._tc_result = "Failed"
                    self._failure_causes.append("Test case {} is failed due to: Day of the Month"
                                                " found in host {} is not correct".format(tc_name, host))
                    raise Exception("Test case {} is failed due to: "
                                    "Day of the Month found in host {} is not correct".format(tc_name, host))
                count = count + 1
                time.sleep(5)
        finally:
            # stop the datetime server
            self.server_helper.stop_stats()
            self.stop_client_and_server()

    def stop_client_and_server(self):
        try:
            self._stop_server()
            self._stop_client()
        finally:
            self._generate_report()

    def _stop_server(self):
        host = self.server_node.get_management_ip()
        tc_name = os.path.basename(__file__)
        self.server_helper.stop_server()
        if self.server_helper.process_running("datetime_server"):
            print("Failed to stop server")
            self._log.debug("<")
            self._tc_result = "Failed"
            self._failure_causes.append("Test case {} is failed due to: Failed to"
                                        " stop datetime_server".format(tc_name))
            raise Exception("Test case {} is failed due to: Failed to "
                            " stop datetime_server!".format(tc_name))
        self._log.debug("<")
        return True

    def _stop_client(self):
        host = self.client_node.get_management_ip()
        tc_name = os.path.basename(__file__)
        self.client_helper.stop_client()
        if self.server_helper.process_running("datetime_client"):
            print("Failed to stop client")
            self._log.debug("<")
            self._tc_result = "Failed"
            self._failure_causes.append("Test case {} is failed due to: Failed to"
                                        " stop datetime_client".format(tc_name))
            raise Exception("Test case {} is failed due to: Failed to "
                            " stop datetime_client!".format(tc_name))
        self._log.debug("<")
        return True

    def _generate_report(self):
        """ Generate the report """
        try:
            from Telaverge.helper.datetime_benchmark_report import DatetimeServerReport as report
            report(tc_result=self._tc_result,
                   failure_causes=self._failure_causes).generate_report()
        except Exception as ex:
            self._log.error("Report is not generated due to %s", str(ex))
        finally:
            if "DatetimeServerReport" in sys.modules:
                del sys.modules["DatetimeServerReport"]


def execute():
    tc_obj = DateTimeServerTest2()
    tc_obj.execute_test_case()
