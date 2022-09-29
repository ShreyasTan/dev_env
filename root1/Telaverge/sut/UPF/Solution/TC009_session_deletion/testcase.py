"""
Total 4-servers [UPF, SMF]
Testcase is to validate the pcap file captured in SMF node which is successfully generating the connection.
Steps:
    1. Start UPF node.
    2. Capture packets in SMF node.
    3. Start the SMF simulator.
    4. SMF simulator will send 2 packets towards UPF and UPF inturn will process and create some entries.
    5. UPF responds back towards SMF with the successful cause.
    6. AMF Simulator will start sending post request to SMF, SMF will send request to UPF for Session creation, Modification
        and Deletion and UPF inturn will process and create some entries.
    7. SMF and UPF will continue to exchange heartbeat messages at a periodic interval.
"""

import time
import traceback

import regal_lib.corelib.custom_exception as exception
from Telaverge.helper.upf_helper import UPFHelper
from Telaverge.telaverge_constans import UPFConstants
from test_executor.test_executor.utility import GetRegal

class TestCaseConstants:
    SLEEP_TIME = 5

class UPFTest():
    """
    Initialize all the required parameter to start the test case.
        1. Create the upf node object.
        2. Create smf node object.
    """

    def __init__(self):
        # test executor service libraries
        self.regal_api = GetRegal()
        log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self.upf_helper_obj = UPFHelper(self.regal_api, UPFConstants.UPF_NODE_NAME, UPFConstants.UPF_APP)
        self.smf_helper_obj = UPFHelper(self.regal_api, UPFConstants.SMF_NODE_NAME, UPFConstants.SMF_5G_APP)
        self.unicorn_helper_obj = UPFHelper(self.regal_api, UPFConstants.UNICORN_NODE_NAME, UPFConstants.UNICORN_APP)
        self._current_testcase_config = self.regal_api.get_current_test_case_configuration().get_test_case_config()
        self._test_run_duration = int(self._current_testcase_config["TestRunDuration"])
        self._log.debug("<")

    def _apply_configuration(self):
        """Method used to setup the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Apply stats configuration on all nodes is inProgress")
        self.upf_helper_obj.apply_configuration()
        self.smf_helper_obj.apply_configuration()
        self.unicorn_helper_obj.apply_configuration()
        self._log.info("Successfully applied stats configurations on all nodes")
        self._log.debug("<")

    def _check_stats(self):
        """Method used to check the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.upf_helper_obj.check_stats()
        self.smf_helper_obj.check_stats()
        self.unicorn_helper_obj.check_stats()
        self._log.debug("<")

    def _start_stats(self):
        """Method used to start the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.upf_helper_obj.start_stats()
        self._log.info("Started stats script on UPF node: '%s'", self.upf_helper_obj.get_management_ip())
        self.smf_helper_obj.start_stats()
        self._log.info("Started stats script on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self.unicorn_helper_obj.start_stats()
        self._log.info("Started stats script on Unicorn node: '%s'", self.unicorn_helper_obj.get_management_ip())
        self._log.debug("<")

    def _stop_stats(self):
        """Method used to stop the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.upf_helper_obj.stop_stats()
        self._log.info("Stopped stats script on UPF node: '%s'", self.upf_helper_obj.get_management_ip())
        self.smf_helper_obj.stop_stats()
        self._log.info("Stopped stats script on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self.unicorn_helper_obj.stop_stats()
        self._log.info("Started stats script on Unicorn node: '%s'", self.unicorn_helper_obj.get_management_ip())
        self._log.debug("<")

    def setup_scripts(self):
        """Method used to setup the scripts in remote node.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Started configuration of scripts on all nodes")
        self.upf_helper_obj.setup_script()
        self.smf_helper_obj.setup_real_node_script()
        self.unicorn_helper_obj.setup_real_node_script(UPFConstants.SESSION_DELETION)
        self._log.info("Completed configuration of scripts on all nodes")
        self._log.debug("<")

    def manage_script_services(self):
        """Method used to start the service in remote node.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.smf_helper_obj.manage_smf_server(True)
        self._log.info("Started SMF simulator to Capture tcpdump of PFCP association request and response between UPF and SMF nodes.")
        time.sleep(3)
        self._log.info("AMF simulator executing Session Deletion testcase.")
        self.unicorn_helper_obj.start_tc_execution()
        self._log.info("AMF simulator executed Session Deletion testcase.")
        self.smf_helper_obj.manage_smf_server(False)
        self._log.info("Stopped SMF simulator script and captured packets on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self._log.debug("<")

    def validate_pcap(self):
        """Method used to validate pcap file captured in remote node.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Copying pcap file from SMF node and validationg pcap traces.")
        self.smf_helper_obj.validate_real_node_pcap(UPFConstants.SESSION_DELETION, 8)
        self._log.info("Validated packets from captured pcap traces between UPF and SMF node successfully.")
        self._log.debug(">")

    def test_run(self):
        """Method used to execute the test run

        Args:
            None

        Returns:
            None
        """
        try:
            self._log.debug(">")
            self._apply_configuration()
            self._start_stats()
            self._check_stats()
            self.setup_scripts()
            self.upf_helper_obj.restart_upf_server()
            self.manage_script_services()
            self.validate_pcap()
            self._stop_stats()
            self._log.debug("<")
        except Exception as ex:
            trace_back = traceback.format_exc()
            self._log.error("Exception caught while running test %s", str(ex))
            self._log.error("Traceback: %s", str(trace_back))
            self._stop_stats()
            tc_name = self.regal_api.get_current_test_case()
            self._log.debug("<")
            raise exception.TestCaseFailed(tc_name, str(ex))


def execute():
    """
    Create testcase instance and execute the test

    Args:
        None

    Returns:
        None
    """
    test = UPFTest()
    test.test_run()
    test = None

