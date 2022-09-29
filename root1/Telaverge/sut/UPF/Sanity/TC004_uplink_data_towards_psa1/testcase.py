"""
Total 8-servers [ULCL, PSA1, PSA2, SMF, I_SMF, DN, LOCAL-DN GNB]
Testcase is to validate the pcap file captured in SMF, I_SMF, DN, LOCAL-DN GNB node which is successfully generating the connection.
Steps:
    1. Bring up all the 4 nodes(ULCL, PSA1, SMF, DN, gNodeB and I-SMF)
    2. Start ULCL and PSA1 nodes.
    3. Capture packets in all the 4 nodes(SMF, I-SMF, DN and gNodeB)
    4. Start the SMF simulator
    5. I-SMF simulator will ULCL and ULCL inturn will process and create some entries.
    6. ULCL responds back towards I-SMF with the successful cause.
    7. I-SMF and ULCL will continue to exchange heartbeat messages at a periodic interval.
    8. SMF simulator will send 3 packets towards PSA1 and PSA1 inturn will process and create some entries.
    9. PSA1 responds back towards I-SMF with the successful cause.
   10. I-SMF and PSA1 will continue to exchange heartbeat messages at a periodic interval.
   11. Start the DN simulator.
   12. Start the gNodeB simulator.
   13. gNodeB simulator will send a packet towards ULCL.
   14. ULCL will process it and send it towards PSA1.
   15. PSA1 will process it and send it towards DN.
   16. DN simulator upon receiving the packet, will send a packet towards PSA1.
"""

import time
import traceback

import regal_lib.corelib.custom_exception as exception
from Telaverge.helper.upf_helper import UPFHelper
from Telaverge.telaverge_constans import UPFConstants
from test_executor.test_executor.utility import GetRegal

class TestCaseConstants:
    SLEEP_TIME = 10
    SLEEP_TIME_FOR_DN = 5

class UPFTest():
    """
    Initialize all the required parameter to start the test case.
        1. Create the ul_cl node object.
        2. Create smf psa1 object.
        3. Create the i_smf node object.
        4. Create the smf node object.
        5. Create the dn node object
    """

    def __init__(self):
        # test executor service libraries
        self.regal_api = GetRegal()
        log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self.ul_cl_helper_obj = UPFHelper(self.regal_api, UPFConstants.ULCL_NODE_NAME, UPFConstants.UPF_APP)
        self.smf_helper_obj = UPFHelper(self.regal_api, UPFConstants.SMF_NODE_NAME, UPFConstants.SMF_APP)
        self.i_smf_helper_obj = UPFHelper(self.regal_api, UPFConstants.I_SMF_NODE_NAME, UPFConstants.SMF_APP)
        self.psa1_helper_obj = UPFHelper(self.regal_api, UPFConstants.PSA1_NODE_NAME, UPFConstants.UPF_APP)
        self.dn_helper_obj = UPFHelper(self.regal_api, UPFConstants.DN_NODE_NAME, UPFConstants.DN_APP)
        self.gnb_helper_obj = UPFHelper(self.regal_api, UPFConstants.GNB_NODE_NAME, UPFConstants.GNB_APP)
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
        self.ul_cl_helper_obj.apply_configuration()
        self.psa1_helper_obj.apply_configuration()
        self.smf_helper_obj.apply_configuration()
        self.i_smf_helper_obj.apply_configuration()
        self.dn_helper_obj.apply_configuration()
        self.gnb_helper_obj.apply_configuration()
        self._log.info("Successfully applied stats configurations on all nodes")
        self._log.debug("<")

    def _start_stats(self):
        """Method used to start the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.ul_cl_helper_obj.start_stats()
        self._log.info("Started stats script on ULCL node: '%s'", self.ul_cl_helper_obj.get_management_ip())
        self.psa1_helper_obj.start_stats()
        self._log.info("Started stats script on PSA1 node: '%s'", self.psa1_helper_obj.get_management_ip())
        self.smf_helper_obj.start_stats()
        self._log.info("Started stats script on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self.i_smf_helper_obj.start_stats()
        self._log.info("Started stats script on I-SMF node: '%s'", self.i_smf_helper_obj.get_management_ip())
        self.dn_helper_obj.start_stats()
        self._log.info("Started stats script on DN node: '%s'", self.dn_helper_obj.get_management_ip())
        self.gnb_helper_obj.start_stats()
        self._log.info("Started stats script on gNodeB node: '%s'", self.gnb_helper_obj.get_management_ip())
        self._log.debug("<")

    def _check_stats(self):
        """Method used to check the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.ul_cl_helper_obj.check_stats()
        self.psa1_helper_obj.check_stats()
        self.smf_helper_obj.check_stats()
        self.i_smf_helper_obj.check_stats()
        self.dn_helper_obj.check_stats()
        self.gnb_helper_obj.check_stats()
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
        self.ul_cl_helper_obj.setup_configuration_script()
        self.psa1_helper_obj.setup_configuration_script()
        self.smf_helper_obj.setup_configuration_script()
        self.i_smf_helper_obj.setup_configuration_script(True)
        self.dn_helper_obj.setup_configuration_script()
        self.gnb_helper_obj.setup_configuration_script()
        self._log.info("Completed configuration of scripts on all nodes")
        self._log.debug("<")

    def _stop_stats(self):
        """Method used to start the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.ul_cl_helper_obj.stop_stats()
        self._log.info("Stopped stats script on ULCL node: '%s'", self.ul_cl_helper_obj.get_management_ip())
        self.psa1_helper_obj.stop_stats()
        self._log.info("Stopped stats script on PSA1 node: '%s'", self.psa1_helper_obj.get_management_ip())
        self.smf_helper_obj.stop_stats()
        self._log.info("Stopped stats script on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self.i_smf_helper_obj.stop_stats()
        self._log.info("Stopped stats script on I-SMF node: '%s'", self.i_smf_helper_obj.get_management_ip())
        self.dn_helper_obj.stop_stats()
        self._log.info("Stopped stats script on DN node: '%s'", self.dn_helper_obj.get_management_ip())
        self.gnb_helper_obj.stop_stats()
        self._log.info("Stopped stats script on gNodeB node: '%s'", self.gnb_helper_obj.get_management_ip())
        self._log.debug("<")

    def manage_services(self):
        """Method used to manage the service

        Args:
            None

        Returns:
            None
        """
        self.i_smf_helper_obj.start_services(False)
        self._log.info("Started pfcp_ulcl configuration script and capturing tcpdump of PFD Management and PFCP association and session establishment request and response between ULCL and I-SMF nodes.")
        self.smf_helper_obj.start_services(True)
        self._log.info("Started pfcp_psa1 configuration script and capturing tcpdump of PFCP association and session establishment request and response between PSA1 and SMF nodes.")
        self._log.info("Waiting {} seconds for exchange PFD Management, PFCP association and session establishment packets between ULCL, PSA1, SMF and I_SMF nodes.".format(TestCaseConstants.SLEEP_TIME))
        time.sleep(TestCaseConstants.SLEEP_TIME)
        self.dn_helper_obj.start_services(True)
        self._log.info("Started capturing tcpdump of uplink and downlink packets between PSA1 and DN node")
        self.gnb_helper_obj.start_services(True)
        self._log.info("Started uplink_gtp_psa1 configuration script to capturing tcpdump of uplink and downlink packets between ULCL and GNodeB nodes.")
        self._log.info("Waiting {} seconds for exchange uplink and downlink packets between gNodeB, ULCL and DN nodes.".format(TestCaseConstants.SLEEP_TIME_FOR_DN))
        time.sleep(TestCaseConstants.SLEEP_TIME_FOR_DN)
        self.gnb_helper_obj.stop_services(True)
        self._log.info("Stopped uplink_gtp_psa1 configuration script to captured tcpdump of uplink and downlink packets between ULCL and GNodeB nodes: '%s'",self.gnb_helper_obj.get_management_ip())
        self.dn_helper_obj.stop_services(True)
        self._log.info("Stopped capturing uplink and downlink packets between PSA1 and DN node: '%s'",self.dn_helper_obj.get_management_ip())
        self.smf_helper_obj.stop_services(True)
        self._log.info("Stopped pfcp_psa1 configuration script and captured PFCP association and session establishment packets on SMF node: '%s'", self.smf_helper_obj.get_management_ip())
        self.i_smf_helper_obj.stop_services(False)
        self._log.info("Stopped pfcp_ulcl configuration script and captured PFCP association and session establishment packets on I-SMF node: '%s'", self.i_smf_helper_obj.get_management_ip())

    def validate_pcap(self):
        """Method used to validate pcap file captured in remote node.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Copying captured pcap files from SMF, I-SMF, DN and gNodeB nodes and validating pcap traces.")
        self.i_smf_helper_obj.validate_ulcl_pcap(True)
        self.smf_helper_obj.validate_ulcl_pcap()
        self.dn_helper_obj.validate_ulcl_pcap()
        self.gnb_helper_obj.validate_ulcl_pcap()
        self._log.info("Validated packets from captured pcap traces between all the UPF nodes(ULCL, PSA1, SMF, I-SMF, DN and gNodeB) successfully.")
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
            self.ul_cl_helper_obj.restart_upf_server()
            self.psa1_helper_obj.restart_upf_server()
            self.manage_services()
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
