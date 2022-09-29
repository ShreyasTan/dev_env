"""
Testcase for executing Unicorn testcase TC6
"""
from test_executor.test_executor.utility import GetRegal
import regal_lib.corelib.custom_exception as exception
from Telaverge.helper.unicorn_helper import UnicornHelper
from time import sleep


class UnicornServerClientTest:
    """ Unicorn test case with server and client nodes"""
    def __init__(self):
        """
        Constructor for initialising client and server nodes.
        """
        log_mgr_obj = GetRegal().get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger("UnicornServerClientTest")
        self._log.debug(">")
        self._topology = GetRegal().get_current_run_topology()
        self.server_node = self._topology.get_node("unicorn_server")
        self.client_node = self._topology.get_node("unicorn_client")
        self.server_helper = UnicornHelper(GetRegal(), "unicorn_server",
                                           "unicorn_installer")
        self.client_helper = UnicornHelper(GetRegal(), "unicorn_client",
                                           "unicorn_installer")
        self.server_config_dict = self.server_helper.generate_config_dict_from_topology()
        self.client_config_dict = self.client_helper.generate_config_dict_from_topology()
        self.sut_name = GetRegal().get_current_sut()
        self.ts_name = GetRegal().get_current_suite()
        self.tc_name = GetRegal().get_current_test_case()
        self._log.debug("<")

    def execute_test_case(self):
        """
        Function for executing Unicorn testcase.
        1. Configure the testcase configurations in both client and server
        nodes.
        2. Start the Unicorn application on both the nodes.
        3. First start the testcase execution in server.
        4. Then start the testcase execution in client.
        5. Check the status of testcase execution in both the nodes as long as
        the execution status is IN_PROGRESS.
        6. Raise TestcaseFailed exception if the execution status ends up as
        FAILED.
        7. Stop Unicorn on both the nodes.

        Args: None.

        Returns:
            None.
            Exception.
        """
        self._log.debug(">")
        try:
            self.setup_and_start_nodes()
            status_server_start, result_server = self.server_helper.start_tc_execution(
                    self.sut_name, self.ts_name, self.tc_name)
            status_client_start, result_client = self.client_helper.start_tc_execution(
                    self.sut_name, self.ts_name, self.tc_name)
            self.server_helper.start_stats()
            self.server_helper.check_stats()
            self.client_helper.start_stats()
            self.client_helper.check_stats()
            self._log.info("started unicorn test")
            if status_server_start and status_client_start:
                status_s, status_server = self.server_helper.get_tc_exec_status(
                    self.sut_name, self.ts_name, self.tc_name)
                status_c, status_client = self.client_helper.get_tc_exec_status(
                    self.sut_name, self.ts_name, self.tc_name)
                if status_s and status_c:
                    count=1
                    total_tps = 0
                    while (status_s and status_server["testStatus"] == "IN_PROGRESS") or\
                        (status_c and status_client["testStatus"] == "IN_PROGRESS"):
                        """
                        Commenting the below lines as this code was implemented before the 
                        implementation of graphs, since graphs scripts and the below operations 
                        use the same REST API for fetching the stats, and this below code was calling 
                        the APIs simultaneously so Stats scripts was not able to fetch the stats. 
                        """
                        # try:
                        #     status_c_stats, client_stats = self.client_helper.get_stats(
                        #         self.sut_name, self.ts_name, self.tc_name)
                        #     if status_c_stats:
                        #         client_stats_1 = client_stats.split('\n')
                        #         for stats_1 in client_stats_1:
                        #             client_stats_2 = stats_1.split(";")
                        #             for stats_2 in client_stats_2:
                        #                 if "Messages Sent=" in stats_2:
                        #                     messages_sent = stats_2.split("=")[1]
                        #                     self._log.info("Messages sent: {0}".format(messages_sent))
                        #                 elif "TPS=" in stats_2:
                        #                     total_tps = total_tps + int(stats_2.split("=")[1])
                        #                     count = count + 1
                        # except:
                        #     pass
                        status_s, status_server = self.server_helper.get_tc_exec_status(
                            self.sut_name, self.ts_name, self.tc_name)
                        status_c, status_client = self.client_helper.get_tc_exec_status(
                            self.sut_name, self.ts_name, self.tc_name)
                    # self._log.info("Average TPS: {0}".format(total_tps/count))
                    self.client_helper.stop_stats()
                    self.server_helper.stop_stats()
                    if status_server["testStatus"] != "PASSED":
                        self._log.error(status_server["testStatus"])
                        raise exception.TestCaseFailed(self.tc_name,
                                status_server["additionalInfo"])
                    if status_client["testStatus"] != "PASSED":
                        self._log.error(status_client["testStatus"])
                        raise exception.TestCaseFailed(self.tc_name,
                                status_client["additionalInfo"])
                elif not status_s:
                    result = status_server
                    raise exception.TestCaseFailed(self.tc_name,
                                                   str(result))
                elif not status_c:
                    result = status_client
                    raise exception.TestCaseFailed(self.tc_name,
                                                   str(result))
            elif not status_server_start:
                raise exception.TestCaseFailed(self.tc_name,
                                               str(result_server))
            elif not status_client_start:
                raise exception.TestCaseFailed(self.tc_name,
                                               str(result_client))
            self._log.debug("<")
        except Exception as ex:
            self._log.debug("<")
            raise exception.TestCaseFailed(self.tc_name, str(ex))

    def _apply_configuration(self):
        """Method used to setup the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Apply stats configuration in inprogress")
        self.server_helper.apply_configuration()
        self.client_helper.apply_configuration()
        self._log.info("Successfully applied stats configurations")
        self._log.debug("<")

    def setup_and_start_nodes(self):
        """
        Function to set testcase configuration and start Unicorn app on both
        the nodes.

        Args: None.

        Returns: None.
        """
        self._log.debug(">")
        test_dict = {"sut_name": self.sut_name, "ts_name": self.ts_name,
                   "tc_name": self.tc_name}
        self.server_helper.set_configuration_for_tc(
            self.server_config_dict, test_dict)
        self.client_helper.set_configuration_for_tc(
            self.client_config_dict, test_dict)
        self.server_helper.restart_unicorn()
        self.client_helper.restart_unicorn()
        self._log.info("Unicorn restarted.")
        self._apply_configuration()
        self._log.debug("<")

def execute():
    tc_obj = UnicornServerClientTest()
    tc_obj.execute_test_case()
