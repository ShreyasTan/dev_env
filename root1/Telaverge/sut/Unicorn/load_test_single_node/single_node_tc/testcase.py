"""
Testcase for executing Unicorn testcase TC6
"""
from Telaverge.helper.unicorn_helper import UnicornHelper
from test_executor.test_executor.utility import GetRegal
import regal_lib.corelib.custom_exception as exception


class UnicornServerClientTest:
    """ Unicorn single node tets case"""
    def __init__(self):
        """
        Constructor for initialising client and server nodes.
        """
        log_mgr_obj = GetRegal().get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger("UnicornServerClientTest")
        self._log.debug(">")
        self._topology = GetRegal().get_current_run_topology()
        self.server_client_node = self._topology.get_node("unicorn_server_client")
        self.server_client_helper = UnicornHelper(GetRegal(), "unicorn_server_client",
                                                  "unicorn_installer")
        self.config_dict = self.server_client_helper.generate_config_dict_from_topology()
        self._node_config = \
        GetRegal().get_current_test_case_configuration().get_test_case_config(
            "unicorn_server_client")["TCConfiguration"]
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
            self.server_client_helper.start_stats()
            self.server_client_helper.check_stats()
            status_start, result = self.server_client_helper.start_tc_execution(self.sut_name,
                    self.ts_name, self.tc_name)
            if status_start:
                status, status_server = self.server_client_helper.get_tc_exec_status(
                    self.sut_name, self.ts_name, self.tc_name)
                if status:
                    while status_server["testStatus"] == "IN_PROGRESS":
                        status, status_server = self.server_client_helper.get_tc_exec_status(
                            self.sut_name, self.ts_name, self.tc_name)
                        print("", status, status_server)
                    self.server_client_helper.stop_stats()
                    if status_server["testStatus"] != "PASSED":
                        self._log.error(status_server["testStatus"])
                        raise exception.TestCaseFailed(self.tc_name,
                                status_server["additionalInfo"])
                    self._log.info(status_server["testStatus"])
                else:
                    raise exception.TestCaseFailed(self.tc_name,
                                                   str(status_server))
            else:
                raise exception.TestCaseFailed(self.tc_name,
                                               str(result))
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
        self.server_client_helper.apply_configuration()
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
        self.server_client_helper.set_configuration_for_tc(
            self.config_dict, test_dict)
        self.server_client_helper.restart_unicorn()
        self._log.info("Unicorn restarted.")
        self._apply_configuration()
        self._log.debug("<")

def execute():
    tc_obj = UnicornServerClientTest()
    tc_obj.execute_test_case()
