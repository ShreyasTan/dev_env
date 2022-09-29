"""
This is the plugin class for TPTF Jmeter integration
"""
from ast import Str
import os
import re
import subprocess
import datetime
import traceback
import xml.etree.ElementTree as et

try:
    from regal_lib.tools.tptf.plugin.tptf_base_plugin import TPTFBasePlugin
except:
    from tptf_base_plugin import TPTFBasePlugin
try:
    from regal_lib.corelib.common_utility import Utility
except:
    from utility import Utility

class Constants:
    """
    Constants
    """
    JMETER_TEST_SUITE = "testSuite"
    JMETER_TEST_CASE = "testCase"
    JMETER_DIR = r'''"/root/apache-jmeter-5.2.1/bin/jmeter"'''
    CURRENT_PATH = None

class TPTFJmeterPlugin(TPTFBasePlugin):
    """
    Third Party Test Framework Manager class
    """
    def __init__(self, service_store_obj=None):
        """
        Initialization of TPTFJmeterPlugin class,
        """

        super(TPTFJmeterPlugin, self).__init__(service_store_obj)
        if service_store_obj:
            self.service_store_obj = service_store_obj
            self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
            self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        else:
            from tptf_log import TPTFLogMgr
            self._log = TPTFLogMgr("TPTFConnectorPlugin").get_logger()
        self.root_path = os.getenv('REGAL_ROOT_PATH')
        self._log.debug(">")
        self.test_case_info = {}
        self.tptf_file_path = None
        self._log.debug("<")

    def _generate_test_case(self, ts_tc_dict, template_path, info_dict):
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
        tc_name = ts_tc_dict["testCaseName"]
        config_dict ={
            "class_name": ''.join(char for char in tc_name.title() if char.isalnum()),
            "test_case_name": tc_name,
            "test_suite_name": ts_tc_dict["testSuiteName"]
        }
        config_dict.update(info_dict)
        template_obj = Utility.get_jinja2_template_obj(template_path)
        test_case_code = template_obj.render(config_dict)
        self._log.debug("< Generated test case code for '%s'", str(ts_tc_dict))
        return test_case_code

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
        self._log.debug(">")
        if self.root_path:
            generate_tc_template_path = \
            "{}/product/Telaverge/config/template/jmeter_single_node_tc_template.txt".format(self.root_path)
        else:
            generate_tc_template_path = \
            "regal_lib/product/Telaverge/config/template/jmeter_single_node_tc_template.txt"

        info_dict = {
            "node_name": "jmeter_node"
        }
        self._log.debug("<")
        return self._generate_test_case(ts_tc_dict, generate_tc_template_path,
                info_dict)


    def get_correlation_id(self):
        """Method to get the correlation id of task assigned"""
        self._log.debug(">")
        self._log.debug("<")
        return self.service_store_obj.get_correlation_id()

    def get_date_time(self):
        """
        Get Date Time object
        Args:
            None
        Returns:
            Datetime object
        """
        self._log.debug(">")
        self._log.debug("<")
        # return datetime.datetime.utcnow()
        return datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    def _validate_info_dict(self, info_dict):
        """
        """
        self._log.debug(">")
        valid_keys = [Constants.JMETER_TEST_SUITE, Constants.JMETER_TEST_CASE]
        self._log.debug("<")
        return True if all(key in info_dict for key in valid_keys) else False

    def _validate_ts_and_tc(self, info_dict, ts_name, ts_enabled, tc_name, tc_enabled):
        """
        Private method to validate if TS/TC is present and enabled.
        This is to generate separate error msgs for different scenarios.
        Args:
            info_dict: contains testSuite and testCase
            ts_name: Test Suite name fetched from framework
            ts_enabled(bool): Enabled status of Test Suite
            tc_name: Test Case name fetched from framework
            tc_enabled: Enabled status of Test Case
        Returns:
            None
        """
        # TODO: remember to change UML codes
        test_suite_name = info_dict['testSuite']
        test_case_name = info_dict['testCase']
        if test_suite_name != ts_name:
            error_msg = "Testsuite '{}' does not exist.".format(test_suite_name)
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

        if ts_enabled != "true":
            error_msg = "Testsuite '{}' is not enabled.".format(test_suite_name)
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

        if test_case_name != tc_name:
            error_msg = "Testcase '{}' does not exist.".format(test_case_name)
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

        if tc_enabled != "true":
            error_msg = "Testcase '{}' is not enabled.".format(test_case_name)
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

    def validate_test_case_details(self, tptf_file_path, test_suite_name, test_case_name):
        """
        Validates the test case details
        Args:
            tptf_file_path(str): TPTF plugin file path
            test_suite_name(str): Test Suite name
            test_case_name(str): Test Case name
        Returns:
            tuple(str, bool, str, bool): ts_name, ts_enabled, tc_name, tc_enabled
        """
        self._log.debug(">")
        for _, _, files in os.walk(tptf_file_path):
            for file_name in files:
                try:
                    ts_name = None
                    tc_name = None
                    ts_enabled = False
                    tc_enabled = False
                    if file_name.endswith(".jmx"):
                        tree = et.parse(Utility.join_path(tptf_file_path, file_name)) #JMX_FILE_NAME
                        root = tree.getroot()
                        self._log.debug("Checking file: {}".format(file_name))
                        for child in root:
                            for inChild in child:
                                if (inChild.tag != 'TestPlan'):
                                    for thread in inChild:
                                        if (thread.tag == 'ThreadGroup'):
                                            msg = "\t {} - {}".format(thread.attrib['testname'], thread.attrib['enabled'])
                                            # self._log.debug(msg)
                                            if thread.attrib['testname'] == test_case_name:
                                                tc_name = thread.attrib['testname']
                                                tc_enabled = thread.attrib['enabled']
                                        elif (thread.tag == 'TestFragmentController'):
                                            msg = "\t {} - {}".format(thread.attrib['testname'], thread.attrib['enabled'])
                                            # self._log.debug(msg)
                                else:
                                    msg = "{} - {}".format(inChild.attrib['testname'], inChild.attrib['enabled'])
                                    # self._log.debug(msg)
                                    if test_suite_name == inChild.attrib['testname']:
                                        ts_name = inChild.attrib['testname']
                                        ts_enabled = inChild.attrib['enabled']
                    # both ts_name and tc_name have been updated = JMX found
                    if ts_name != None and tc_name != None:
                        self._log.debug("{}: {} - {}, {} - {}".format(file_name, ts_name, ts_enabled, tc_name, tc_enabled))
                        self._log.debug("<")
                        return file_name, ts_name, ts_enabled, tc_name, tc_enabled
                # code reaches here = ts_name and tc_name has not been found.
                except Exception as ex:
                    self._log.error(str(ex) + "\n" + str(traceback.format_exc()))
                    raise Exception(str(ex))
        # code reaches here = no compatible jmx file has been found.
        error_msg = "No compatible JMX file found for TS '{}' and TC '{}'".format(test_suite_name, test_case_name)
        self._log.error(error_msg)
        self._log.debug("<")
        raise Exception(error_msg)

    def validate_request_body(self, info_dict):
        """
        Validates requested data for given test case
        Args:
            info_dict(dict): contains test_suite_name and test_case_name
        Returns:
            tptf_file_path(str): TPTF plugin file path
        """
        self._log.debug(">")
        # remove below validation if using swagger
        if not self._validate_info_dict(info_dict):
            error_msg = "Request body is missing required fields: ['{}', '{}']".format(Constants.JMETER_TEST_SUITE, Constants.JMETER_TEST_CASE)
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

        test_suite_name = info_dict.get("testSuite")
        test_case_name = info_dict.get("testCase")

        tptf_file_path = self.get_fw_code_path()
        if not tptf_file_path:
            error_msg = "TPTF Framework file path not found."
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)
        
        Constants.CURRENT_PATH = tptf_file_path
        try:
            file_name, ts_name, ts_enabled, tc_name, tc_enabled = self.\
                validate_test_case_details(tptf_file_path, test_suite_name, test_case_name)
        except Exception as ex:
            raise Exception(str(ex))

        self._validate_ts_and_tc(info_dict, ts_name, ts_enabled, tc_name, tc_enabled)
        full_tptf_file_path = Utility.join_path(tptf_file_path, file_name)
        self._log.debug("<")
        return full_tptf_file_path

    def apply_configuration(self, info_dict):
        """
        Apply configuration to JMX file
        Args:
            info_dict: containing ts name and tc name
        Returns:
            str: JMX file path
        """
        try:
            self._log.debug(">")
            tptf_file_path = self.validate_request_body(info_dict)
            self._log.debug("Received JMX file: {}".format(tptf_file_path))
            self.tptf_file_path = tptf_file_path

            tree = et.parse(tptf_file_path)
            for child in tree.find('hashTree/hashTree/ConfigTestElement'):
                if child.attrib["name"] == "HTTPSampler.domain":
                    child.text = str(info_dict['masterNodeIp'])
                elif child.attrib["name"] == "HTTPSampler.port":
                    child.text = str(info_dict['regalApiPort'])

            tree.write(tptf_file_path)
            self._log.debug("<")
            return tptf_file_path

        except Exception as ex:
            self._log.error(str(ex) + "\n" + str(traceback.format_exc()))
            self._log.debug("<")
            raise Exception(str(ex))

    def replace_loop_and_thread(self, tptf_file_path, Num_Threads, Loops):
        """
        Replace loop and threads
        Args:
            tptf_file_path: TPTF plugin file path
            Num_Threads: Number of threads
            Loops: loops
        Returns:
            str: tnp_jmx_file
        """
        self._log.debug(">")
        current_path = Constants.CURRENT_PATH
        file_name = et.ElementTree(file=tptf_file_path)
        data = file_name.getroot()
        for child in data:
            for inChild in child:
                if (inChild.tag != 'TestPlan'):
                    for thread in inChild:
                        if (thread.tag == 'ThreadGroup'):
                            for stringProp in thread:
                                if (stringProp.tag == "stringProp"):
                                    if stringProp.attrib['name'] == "ThreadGroup.num_threads":
                                        stringProp.text = "{}".format(Num_Threads)
                                        print("stringProp.text", stringProp.text)
                                elif (stringProp.tag == "elementProp"):
                                    for elementProp in stringProp:
                                        if (elementProp.tag == "stringProp"):
                                            if elementProp.attrib['name'] == "LoopController.loops":
                                                elementProp.text = "{}".format(Loops)
                                                print("elementProp.text", Loops, elementProp.text)
        now = self.get_date_time()
        tnp_jmx_file = current_path + r"/T{0}XL{1}{2}.jmx".format(
            Num_Threads, Loops, now)
        with open(tnp_jmx_file, "wb") as jmcFie:
            file_name.write(jmcFie)
        self._log.debug("<")
        return tnp_jmx_file

    def disable_jmx_num_threads(self, tptf_file_path, test_case_name):
        """
        Disable all threadgroups except 1
        Args:
            tptf_file_path: TPTF plugin file path
            Num_Threads: Number of threads
            Loops: loops
        Returns:
            str: tnp_jmx_file
        """
        self._log.debug(">")
        file_name = et.ElementTree(file=tptf_file_path)
        data = file_name.getroot()
        for child in data:
            for inChild in child:
                if (inChild.tag != 'TestPlan'):
                    for thread in inChild:
                        if (thread.tag == 'ThreadGroup'):
                            for stringProp in thread:
                                if (stringProp.tag == "stringProp"):
                                    if stringProp.attrib['name'] == "ThreadGroup.num_threads":
                                        # disabling all TGs except the 1 we are running
                                        if thread.attrib['testname'] == test_case_name:
                                            stringProp.text = "{}".format(1)
                                            self._log.debug("Enabled {}".format(thread.attrib['testname']))
                                        else:
                                            stringProp.text = "{}".format(0)
                                            self._log.debug("Disabled {}".format(thread.attrib['testname']))
        # replace JMX or create new temp jmx?
        with open(tptf_file_path, "wb") as jmx_file:
            file_name.write(jmx_file)
        self._log.debug("<")
        return tptf_file_path

    def set_tptf_jmeter_testcase_info(self, test_suite_name, test_case_name, is_tc_running):
        """
        Set testcase info
        Args:
            test_suite_name(str): Test Suite name
            test_case_name(str): Test Case name
            isTcRunning(bool): Test Case run status
        Returns:
            None
        """
        self._log.debug(">")
        self._log.debug("<")
        self.test_case_info = {
            "testSuiteName": test_suite_name,
            "testCaseName": test_case_name,
            "isTcRunning": is_tc_running,
            "operationState": None
        }

    def update_tptf_jmeter_testcase_info(self, update_dict):
        """
        Update testcase info
        Args:
            update_dict(dict): dict to update
        Returns:
            None
        """
        self._log.debug(">")
        self._log.debug("<")
        self.test_case_info.update(update_dict)

    #TODO: Check docstring
    def start_execute_testcase(self, exec_jmx_out_html):
        """
        Execute Jmeter testcase.
        Args:
            exec_jmx_out_html(str): subprocess command
        Returns:
            tuple(str, str/None): std_out_info, std_err_info 
        """
        self._log.debug(">")
        output = subprocess.Popen(
            exec_jmx_out_html, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
            universal_newlines=True
        )
        std_out_info, std_err_info = output.communicate()
        # check out output.status_code()
        return_code = output.returncode
        self._log.debug("output code : {}".format(return_code))
        self._log.debug("std_out : {}".format(std_out_info))
        self._log.debug("std_err : {}".format(std_err_info))
        self._log.debug("<")
        return std_out_info, std_err_info, return_code

    def get_test_result(self, info_dict):
        """
        Returns status of testcase 
        Args:
            info_dict(dict): contains test_suite_name and test_case_name
        Returns:
            str: status of given testcase based on response code
        """
        self._log.debug(">")
        if self.test_case_info:
            # check if currently running TS/TC matches with request
            if info_dict["testSuite"] != self.test_case_info["testSuiteName"]:
                error_msg = "Operation State for Test Suite '{}' not found.".format(info_dict['testSuite'])
                self._log.error(error_msg)
                self._log.debug("<")
                raise Exception(error_msg)
            elif info_dict["testCase"] != self.test_case_info["testCaseName"]:
                error_msg = "Operation State for Testcase '{}' not found.".format(info_dict['testCase'])
                self._log.error(error_msg)
                self._log.debug("<")
                raise Exception(error_msg)
            else:
                # checks passed, send operation state
                self._log.debug("{} - {}".format(self.test_case_info['testCaseName'], self.test_case_info['operationState']))
                return self.test_case_info['operationState']
        else:
            error_msg = "Test Suite '{}' and Testcase '{}' info does not exist.".format(info_dict['testSuite'], info_dict['testCase'])
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

    # same thing here as above
    def monitor_test(self, info_dict):
        """
        Check test case execution status based on flag
        Args:
            info_dict(dict): contains test_suite_name and test_case_name
        Returns:
            str: Result
        """
        if self.test_case_info:
            if info_dict["testSuite"] != self.test_case_info["testSuiteName"]:
                error_msg = "Testcase run status for Test Suite '{}' not found.".format(info_dict['testSuite'])
                self._log.error(error_msg)
                self._log.debug("<")
                raise Exception(error_msg)
            elif info_dict["testCase"] != self.test_case_info["testCaseName"]:
                error_msg = "Testcase run status for Testcase '{}' not found.".format(info_dict['testCase'])
                self._log.error(error_msg)
                self._log.debug("<")
                raise Exception(error_msg)
            else:
                self._log.debug("{} - {}".format(self.test_case_info['testCaseName'],self.test_case_info['isTcRunning']))
                return self.test_case_info['isTcRunning']
        else:
            error_msg = "Test Suite '{}' and Testcase '{}' info does not exist.".format(info_dict['testSuite'], info_dict['testCase'])
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

    def validate_execution_result(self, std_out_info, std_err_info, return_code):
        """
        """
        self._log.debug(">")
        if return_code == 0:
            # CLI call passed
            error_regex = 'summary =[\s].*Err:[ ]{0,10}([1-9]\d{0,10})[ ].*'
            match = re.search(error_regex, std_out_info)
            if not match:
                # TC passed
                self._log.debug("<")
                return {"operationState" : "Passed", "isTcRunning" : False}
        # either CLI call failed or TC failed
        self._log.debug("<")
        return {"operationState" : "Failed", "isTcRunning" : False}

    def run_test(self, info_dict):
        """
        Triggers given test case.
        Args:
            info_dict(dict): contains test_suite_name and test_case_name
        Returns:
            None
        """
        self._log.debug(">")
        test_suite_name = info_dict[Constants.JMETER_TEST_SUITE]
        test_case_name = info_dict[Constants.JMETER_TEST_CASE]
        
        tptf_file_path = self.tptf_file_path
        if not tptf_file_path:
            error_msg = "JMX file not found. Apply Config might have failed."
            self._log.error(error_msg)
            self._log.debug("<")
            raise Exception(error_msg)

        self.disable_jmx_num_threads(tptf_file_path, test_case_name)
        now = self.get_date_time()
        jmeter_dir = Constants.JMETER_DIR
        current_path = Constants.CURRENT_PATH
        csv_file_name = current_path + "/result{0}.csv".format(now)
        exec_jmx_out_html = "{} -n -t {} -l {}".format(jmeter_dir, tptf_file_path, csv_file_name)
        self._log.debug("Jmeter DIR: {}".format(jmeter_dir))
        self._log.debug("Current Path: {}".format(current_path))
        self._log.debug("CSV path: {}".format(csv_file_name))
        self._log.debug("Jmeter cmd: {}".format(exec_jmx_out_html))

        is_tc_running = True
        self.set_tptf_jmeter_testcase_info(test_suite_name, test_case_name, is_tc_running)

        std_out_info, std_err_info, return_code =  self.start_execute_testcase(exec_jmx_out_html)
        update_dict = self.validate_execution_result(std_out_info, std_err_info, return_code)
        self.update_tptf_jmeter_testcase_info(update_dict)
        self._log.debug("<")


class TPTFTRJmeterPlugin(TPTFJmeterPlugin):
    """
    Third Party Test Framework Manager class
    """
    def __init__(self, service_store_obj=None):
        """
        Initialization of TPTFJmeterPlugin class,
        """

        super(TPTFJmeterPlugin, self).__init__(service_store_obj)
        if service_store_obj:
            self.service_store_obj = service_store_obj
            self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
            self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        else:
            from tptf_log import TPTFLogMgr
            self._log = TPTFLogMgr("TPTFTRJmeterPlugin").get_logger()
        self.root_path = os.getenv('REGAL_ROOT_PATH')
        self.test_case_info = {}
        self.tptf_file_path = None


    def apply_configuration(self, info_dict):
        """
        Apply configuration to JMX file
        Args:
            info_dict: containing ts name and tc name
        Returns:
            str: JMX file path
        """
        try:
            self._log.debug(">")
            tptf_file_path = self.validate_request_body(info_dict)
            self._log.debug("Received JMX file: {}".format(tptf_file_path))
            self.tptf_file_path = tptf_file_path

            tree = et.parse(tptf_file_path)
            try:
                teleradiology_ip = info_dict["teleradiology"]
            except KeyError as ex:
                self._log.debug("Key teleradiology is not found in the information")

            for arguments in tree.find('hashTree/hashTree/Arguments'):
                for element_prop in arguments:
                    if element_prop[0].text == "BASE_URL_1":
                        element_prop[1].text = teleradiology_ip

            tree.write(tptf_file_path)
            self._log.debug("<")
            return tptf_file_path

        except Exception as ex:
            self._log.error(str(ex) + "\n" + str(traceback.format_exc()))
            self._log.debug("<")
            raise Exception(str(ex))
