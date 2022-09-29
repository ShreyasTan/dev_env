"""TPTF sample testcase code
"""

import time
import os
import traceback

import regal_lib.corelib.custom_exception as exception

class SingleNodeTc():
    """Testcase code"""
    def __init__(self):
        # test executor service libraries
        from test_executor.test_executor.utility import GetRegal
        from Telaverge.helper.tptf_unicorn_helper import TPTFUnicornHelper
        self.regal_api = GetRegal()
        self._log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self.server_client_helper = TPTFUnicornHelper(GetRegal(), "unicorn_server_client",
                                                  "TPTF")
        self._topology = GetRegal().get_current_run_topology()
        self.sut_name = GetRegal().get_current_sut()
        self.ts_name = GetRegal().get_current_suite()
        self.tc_name = GetRegal().get_current_test_case()
        management_ip = self.server_client_helper.get_management_ip()
        self.info_dict = {
            "SutName": self.sut_name,
            "SuiteName": self.ts_name,
            "TestcaseName": self.tc_name,
            "ip": management_ip
        }
        self.tptf_app = self.server_client_helper.get_tptf_app()
        self._log.debug("<")

    def configure_testcase(self):
        """ Method used to configure testcase related
        configuration before test case execution.

        Comments:
            1. Change the management ip in config

        """
        self._log.info("> Applying configuration for testcase")
        self.tptf_app.apply_configuration(self.info_dict)
        self._log.info("< Successfully applied the configuration for testcase")

    def execute_test_case(self):
        """ Method execute the testcase

        Comments:
            1. Using tptf application object execute testcase
                in the remote node

        """
        self._log.info("> Starting the testcase")
        result = self.tptf_app.run_test(self.info_dict)
        if not result[0]:
            err_msg = "Failed to start the test case %s ", result[1]
            self._log.error("err_msg")
            raise exception.TestCaseFailed(self.tc_name, err_msg)
        self._log.info("< Successfully started the testcase")

    def monitor_testcase(self):
        """ Method monitor for the testcase status

        Comments:
            1. Continously check for the INPROGRESS status
               of test case

        """
        self._log.info("Monitoring testcase for inprogress state")
        end_time = time.time() + 10
        while end_time > time.time():
            try:
                status = self.tptf_app.get_test_result(
                        self.info_dict)
                if not status[0]:
                    err_msg = "Test case is not started %s ", status[1]
                    raise exception.TestCaseFailed(self.tc_name, err_msg)
                break
            except exception.TestCaseFailed:
                pass

        while status[1][1]["testStatus"] == "IN_PROGRESS":
            status = self.tptf_app.get_test_result(
                        self.info_dict)
            time.sleep(2)
            self._log.info("Test case is Running")
        self._log.info("< Done with testcase state monitoring")

    def check_test_run_status(self):
        """ Method check the test result

        Comments:
            1. Get the test case result, is testcase
                PASSED or FAILED

        """
        self._log.info("Getting test run result")
        status = self.tptf_app.get_test_result(
                self.info_dict)
        if status[1][1]["testStatus"] != "PASSED":
            self._log.error(status[1][1]["testStatus"])
            raise exception.TestCaseFailed(self.tc_name,
                    status[1][1]["additionalInfo"])
        self._log.info("Test case successfully executed")

    def test_run(self):
        """
        Function for executing Unicorn testcase.
        1. Setup stats and restart the Unicorn on node
        2. Start the unicorn stats on node.
        3. Configure the testcase configurations.
        4. Start the testcase execution in server.
        5. Monitor the status of testcase execution(status is IN_PROGRESS).
        6. Check the test run result.
        7. Stop Unicorn and stats on the node.

        """
        self._log.debug(">")
        try:
            self.setup_and_start_nodes()
            self.server_client_helper.start_stats(["unicornstat"])
            self.configure_testcase()
            self.execute_test_case()
            time.sleep(3)
            self.monitor_testcase()
            self.check_test_run_status()
            self.server_client_helper.stop_stats(["unicornstat"])
            self._log.debug("<")
        except Exception as ex:
            self._log.debug("<")
            raise exception.TestCaseFailed(self.tc_name, str(ex))

    def setup_and_start_nodes(self):
        """
        Function to set testcase configuration and start Unicorn app on both
        the nodes.

        Args: None.

        Returns: None.
        """
        self._log.debug(">")
        self.server_client_helper.restart_unicorn()
        self._log.info("Unicorn restarted.")
        args_dict = {
            "unicorn_server_client": {"SingleNode": True}
        }
        self.server_client_helper.setup_stats(args_dict)
        self._log.debug("<")

def execute():
    """
    Create test instance and run the test
    """
    test = SingleNodeTc()
    test.test_run()
    test = None