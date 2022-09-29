"""
Third Party Test Framework connector plugin
"""
import os
import json
import requests

try:
    from regal_lib.tools.tptf.plugin.tptf_base_plugin import TPTFBasePlugin
except:
    from tptf_base_plugin import TPTFBasePlugin

try:
    from regal_lib.corelib.common_utility import Utility
except:
    from utility import Utility

try:
    from regal_lib.tools.tptf.constants import UnicornConstants
except:
    from constants import UnicornConstants

try:
    import regal_lib.tools.tptf.custom_exception as exception
except:
    import custom_exception as exception

class UnicornBase(TPTFBasePlugin):
    """TPTF Connector plugin"""
    def __init__(self, service_store_obj=None):
        super(UnicornBase, self).__init__(service_store_obj)
        if service_store_obj:
            self.service_store_obj = service_store_obj
            self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
            self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        else:
            from tptf_log import TPTFLogMgr
            self._log = TPTFLogMgr("TPTFConnectorPlugin").get_logger()
        self.root_path = os.getenv('REGAL_ROOT_PATH')
        self._tc_obj = None

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

    def get_sut_ts_tc_name(self, info_dict):
        """ Method returns the sut, suite and testcase name from
        the given dictionary

        Args:
            info_dict(dict): Dictionary which contains arguments.

        Returns:
            str: Sut, Suite and Testcase name

        """
        try:
            sut_name = info_dict["SutName"]
            ts_name = info_dict["SuiteName"]
            tc_name = info_dict["TestcaseName"]
        except KeyError as ex:
            err_msg = "Key %s is not given in info dict", ex
            self._log.error("%s", err_msg)
            self._log.debug("<")
            raise exception.KeyNotFound(err_msg)
        return sut_name, ts_name, tc_name

    def get_tc_file(self, info_dict):
        """ Method return the unicorn test case file

        Args:
            info_dict(dict): Dictionary which contains arguments

        Returns:
            str: path of unicorn test case

        """
        self._log.debug(">")
        sut_name, ts_name, tc_name = self.get_sut_ts_tc_name(info_dict)
        base_path = self.get_fw_code_path()
        tc_file = Utility.join_path(base_path, sut_name, ts_name, tc_name,
                UnicornConstants.UNICORN_TC_FILE_NAME)
        self._log.debug("<")
        return tc_file

    def send_rest_request(self, request_info, request_type=UnicornConstants.GET_REQUEST):
        """
        Send REST API GET Request
        Args:
            request_info(str): Information for which GET request is to be invoked

        Returns(str): Response

        """
        self._log.debug(">")
        try:
            host_port = 5000
            url = "http://localhost:{}/{}".format(UnicornConstants.UNICORN_REST_API_PORT,
                 request_info)
            if request_type == UnicornConstants.GET_REQUEST:
                req = requests.get(url, timeout=60)
            elif request_type == UnicornConstants.POST_REQUEST:
                req = requests.post(url, timeout=60)
            result = False
            if req.status_code is 200:
                result = True
                result_msg = req.json()
            else:
                result_msg = req.json()
            self._log.debug("The response for request %s is %s-%s", url, result, result_msg)
            self._log.debug("<")
            return result, result_msg
        except Exception as ex:
            self._log.error(ex)
            self._log.debug("<")
            raise Exception(str(ex))


    def run_test(self, info_dict):
        """
        Method to start the testcase execution in the node.

        Args:
            info_dict(dict): Dictionary which contains arguments

        Returns:
            list: Request's response.

        """
        self._log.debug(">")
        sut_name, ts_name, tc_name = self.get_sut_ts_tc_name(info_dict)
        argument = "tests/{}/{}/{}/START_TEST".format(sut_name, ts_name,
                                                      tc_name)
        status, msg = self.send_rest_request(argument, UnicornConstants.POST_REQUEST)
        self._log.debug("<")
        return [status, msg]

    def get_test_result(self, info_dict):
        """ Method to fetch the result of testcase execution in the node.

        Args:
            info_dict(dict): Dictionary which contains arguments

        Returns:
            list: Response result.

        """
        self._log.debug(">")
        sut_name, ts_name, tc_name = self.get_sut_ts_tc_name(info_dict)
        argument = "tests/{}/{}/{}/TEST_STATUS".format(sut_name, ts_name,
                                                       tc_name)
        status, msg = self.send_rest_request(argument)
        self._log.debug("<")
        return [status, msg]


    def apply_configuration(self, info_dict):
        """ Method apply the configuration for the unicorn test case

        Args:
            info_dict(dict): Dictionary which contains arguments

        Returns:
            list: Response result.

        """
        self._log.debug(">")
        tc_file = self.get_tc_file(info_dict)
        tc_data = Utility.read_json_file(tc_file)
        if not tc_data:
            err_msg = "The test case file %s \1. is not valid. \2. or is"\
                      "empty", tc_file
            self._log.error(err_msg)
            self._log.debug("<")
            return [False, err_msg]
        configured_ip = Utility.get_key_value_from_dict(tc_data, 'ip')
        tc_ip = info_dict["ip"]
        if not configured_ip:
            ip_config_list = Utility.get_key_value_from_dict(tc_data,
                    'endPoints')
            ip_config = ip_config_list[0]
            configured_ip = ip_config.split(":")[1]
            tc_ip = "//{}".format(tc_ip)
        tc_data_str = json.dumps(tc_data).replace(configured_ip, tc_ip)
        tc_data = json.loads(tc_data_str)
        Utility.write_pretty_json(tc_file, tc_data)
        self._log.debug("<")
        return [True, "Successfully applied the configuration"]


class UnicornOneNodeTPTFPlugin(UnicornBase):
    """ Unicorn base class """
    def __init__(self, service_store_obj=None):
        super(UnicornOneNodeTPTFPlugin, self).__init__(service_store_obj)
        if service_store_obj:
            self.service_store_obj = service_store_obj
            self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
            self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        else:
            from tptf_log import TPTFLogMgr
            self._log = TPTFLogMgr("UnicornOneNodePlugin").get_logger()
        self._tc_obj = None


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
            "{}/product/Telaverge/config/template/unicorn_single_node_tc_template.txt".format(self.root_path)
        else:
            generate_tc_template_path = \
            "regal_lib/product/Telaverge/config/template/unicorn_single_node_tc_template.txt"

        info_dict = {
            "node_name": "unicorn_server_client"
        }
        self._log.debug("<")
        return self._generate_test_case(ts_tc_dict, generate_tc_template_path,
                info_dict)



class UnicornTwoNodeTPTFPlugin(UnicornBase):
    """ Unicorn base class """
    def __init__(self, service_store_obj=None):
        super(UnicornTwoNodeTPTFPlugin, self).__init__(service_store_obj)
        if service_store_obj:
            self.service_store_obj = service_store_obj
            self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
            self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        else:
            from tptf_log import TPTFLogMgr
            self._log = TPTFLogMgr("UnicornTwoNodeTPTFPlugin").get_logger()
        self._tc_obj = None


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
            "{}/product/Telaverge/config/template/unicorn_two_node_tc_template.txt".format(self.root_path)
        else:
            generate_tc_template_path = \
            "regal_lib/product/Telaverge/config/template/unicorn_two_node_tc_template.txt"
        info_dict = {
            "client_node_name": "unicorn_client",
            "server_node_name": "unicorn_server"
        }
        self._log.debug("<")
        return self._generate_test_case(ts_tc_dict, generate_tc_template_path,
                info_dict)

