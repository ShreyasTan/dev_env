"""
Third Party Test Framework connector plugin
"""
import os
try:
    from regal_lib.tools.tptf.plugin.tptf_base_plugin import TPTFBasePlugin
except:
    from tptf_base_plugin import TPTFBasePlugin

try:
    from regal_lib.corelib.common_utility import Utility
except:
    from utility import Utility

class TPTFConnectorPlugin(TPTFBasePlugin):
    """TPTF Connector plugin"""
    def __init__(self, service_store_obj=None):
        super(TPTFConnectorPlugin, self).__init__(service_store_obj)
        if service_store_obj:
            self.service_store_obj = service_store_obj
            self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
            self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        else:
            from tptf_log import TPTFLogMgr
            self._log = TPTFLogMgr("TPTFConnectorPlugin").get_logger()
        self._tc_obj = None

    def start_test_case(self, info_dict):
        """Method used to start the test case.

        Args:
            test_case_name(str): test case name
            test_suite_name(str): test suite name

        Returns:
            None
        """
        #Need to include plugin with actual code in next sprint
        self._log.debug(">")
        self._log.debug("<")
        return True

    def monitor_test(self, info_dict):
        """Method used to monitor the test case.

        Args:
            test_case_name(str): test case name
            test_suite_name(str): test suite name

        Returns:
            bool: True/False
        """
        #Need to include plugin with actual code in next sprint
        self._log.debug(">")
        self._log.debug("<")
        return True

    def get_test_result(self, info_dict):
        """Method used to fetch the test case result.

        Args:
            test_case_name(str): test case name
            test_suite_name(str): test suite name

        Returns:
            bool, reason(str): True/False and reason for failure if any
        """
        #Need to include plugin with actual code in next sprint
        self._log.debug(">")
        self._log.debug("<")
        return True

    def apply_configuration(self, info_dict):
        """ Method applies the test case configuration to trigger test run.

        Args:
            info_dict(dict): Contains info to apply the testcase config.

        Returns:
            None
        """
        #Need to include plugin with actual code in next sprint
        self._log.debug(">")
        self._log.debug(">")
        return True

    def run_test(self, info_dict):
        """Method used to start the test case.

        Args:
            test_case_name(str): test case name
            test_suite_name(str): test suite name

        Returns:
            None
        """
        #Need to include plugin with actual code in next sprint
        self._log.debug(">")
        self._log.debug(">")
        return True

    def generate_test_case(self, ts_tc_dict):
        """Method used to generate and returns the test case code.

        Args:
            ts_tc_dict(dict): contains testsuite name and testcase name
                              Ex:
                                  ts_tc_dict = {"testSuiteName": <suite_name>,
                                                "testCaseName": <testcase_name>}
        Returns:
            test_case_code(str): testcase code
        """
        self._log.debug("> Generating test case code for '%s'", str(ts_tc_dict))
        from regal_lib.corelib.common_utility import Utility
        root_path = os.getenv('REGAL_ROOT_PATH')
        if root_path:
            generate_tc_template_path = "{}/product/Telaverge/config/template/generate_testcase_code.txt".format(root_path)
        else:
            generate_tc_template_path = "regal_lib/product/Telaverge/config/template/generate_testcase_code.txt"
        tc_name = ts_tc_dict["testCaseName"]
        config_dict = {
                "class_name": ''.join(char for char in tc_name.title() if char.isalnum()),
                "test_case_name": tc_name,
                "test_suite_name": ts_tc_dict["testSuiteName"],
                "node_name": "tptf_node_01",
                "app_name": "TPTF",
                }
        template_obj = Utility.get_jinja2_template_obj(generate_tc_template_path)
        test_case_code = template_obj.render(config_dict)
        self._log.debug("< Generated test case code for '%s'", str(ts_tc_dict))
        return test_case_code
