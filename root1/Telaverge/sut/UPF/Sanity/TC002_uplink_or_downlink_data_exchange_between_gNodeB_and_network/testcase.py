"""
Total 4-servers [UPF, SMF, DN, GNB]
Testcase is to validate the pcap file captured in SMF, DN and GNB node which is successfully generating the connection.
Steps:
    1. Bring up all the 4 nodes(UPF, SMF, DN and gNodeB)
    2. Start UPF node.
    3. Capture packets in all the 3 nodes(SMF, DN and gNodeB)
    4. Start the SMF simulator
    5. SMF simulator will send 2 packets towards UPF and UPF inturn will process and create some entries.
    6. UPF responds back towards SMF with the successful cause.
    7. SMF and UPF will continue to exchange heartbeat messages at a periodic interval.
    8. Start the DN simulator.
    9. Start the gNodeB simulator.
   10. gNodeB simulator will send a packet towards UPF.
   11. UPF will process it and send it towards DN.
   12. DN simulator upon receiving the packet, will send a packet towards UPF. 
   13. UPF will process the packet and send it towards gNodeB.
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
        3. Create the dn node object.
        4. Create the gnb node object.
    """

    def __init__(self):
        # test executor service libraries
        self.regal_api = GetRegal()
        log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self.upf_helper_obj = UPFHelper(self.regal_api, UPFConstants.UPF_NODE_NAME, UPFConstants.UPF_APP)
        self.smf_helper_obj = UPFHelper(self.regal_api, UPFConstants.SMF_NODE_NAME, UPFConstants.SMF_APP)
        self.dn_helper_obj = UPFHelper(self.regal_api, UPFConstants.DN_NODE_NAME, UPFConstants.DN_APP)
        self.gnb_helper_obj = UPFHelper(self.regal_api, UPFConstants.GNB_NODE_NAME, UPFConstants.GNB_APP)
        self._current_testcase_config = self.regal_api.get_current_test_case_configuration().get_test_case_config()
        self._test_run_duration = int(self._current_testcase_config["TestRunDuration"])
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
        self.dn_helper_obj.start_stats()
        self._log.info("Started stats script on DN node: '%s'", self.dn_helper_obj.get_management_ip())
        self.gnb_helper_obj.start_stats()
        self._log.info("Started stats script on gNodeB node: '%s'", self.gnb_helper_obj.get_management_ip())
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
        self.smf_helper_obj.setup_script()
        self.dn_helper_obj.setup_script()
        self.gnb_helper_obj.setup_script()
        self._log.info("Completed configuration of scripts on all nodes")
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
        self.dn_helper_obj.stop_stats()
        self._log.info("Stopped stats script on DN node: '%s'", self.dn_helper_obj.get_management_ip())
        self.gnb_helper_obj.stop_stats()
        self._log.info("Stopped stats script on gNodeB node: '%s'", self.gnb_helper_obj.get_management_ip())
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
        self.dn_helper_obj.apply_configuration()
        self.gnb_helper_obj.apply_configuration()
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
        self.dn_helper_obj.check_stats()
        self.gnb_helper_obj.check_stats()
        self._log.debug("<")

    def manage_script_services(self):
        """Method used to start the service in remote node.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.smf_helper_obj.start_services(True)
        self._log.info("Started pfcp_session configuration script to capture tcpdump of PFCP association and session establishment request and response between UPF and SMF nodes.")
        self.dn_helper_obj.start_services(True)
        self._log.info("Started N6_downlink_gtp configuration script to Capture tcpdump of uplink and downlink packets between UPF and DN nodes.")
        self.gnb_helper_obj.start_services(True)
        self._log.info("Started N3_uplink_gtp_1 configuration script to capture tcpdump of uplink and downlink packets between UPF and gNodeB nodes.")
        self._log.info("Waiting {} seconds for PFCP association, Session Establishment, uplink and downlink packets between UPF nodes(SMF, DN and gNodeB).".format(TestCaseConstants.SLEEP_TIME))
        time.sleep(TestCaseConstants.SLEEP_TIME)
        self.smf_helper_obj.stop_services(True)
        self._log.info("Stopped pfcp_session configuration script and captured PFCP association and session establishment packets on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self.dn_helper_obj.stop_services(True)
        self._log.info("Stopped N6_downlink_gtp configuration script and captured packets on DN node: '%s'", self.dn_helper_obj.get_management_ip())
        self.gnb_helper_obj.stop_services(True)
        self._log.info("Stopped N3_uplink_gtp_1 configuration script and captured packets on gNodeB node: '%s'", self.gnb_helper_obj.get_management_ip())
        self._log.debug("<")

    def validate_pcap(self):
        """Method used to validate pcap file captured in remote node.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Copying pcap files from SMF, DN and gNodeB node and validationg pcap traces.")
        self.smf_helper_obj.validate_pcap()
        self.dn_helper_obj.validate_pcap()
        self.gnb_helper_obj.validate_pcap()
        self._log.info("Validated packets from captured pcap traces between all the UPF nodes(SMF, DN, and gNodeB) successfully.")
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
