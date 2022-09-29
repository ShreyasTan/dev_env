"""
App tools for Unicorn.
"""
import os
import sys
import json
import traceback
import shutil
import tempfile
import requests
from jinja2 import Template
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants
from regal_lib.product.Regal.regal_constants import Constants as RegalConstants
from regal_lib.product.Regal.apps.appbase import AppBase
from regal_lib.corelib.constants import Constants
import regal_lib.corelib.custom_exception as exception
from regal_lib.corelib.common_utility import Utility

IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    FileExistsErr = OSError
else:
    FileExistsErr = FileExistsError


class UnicornTool(AppBase):
    """
    Class implemented for Unicorn tools plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UnicornTool, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"
        self._log.debug("<")

    def app_match(self, host):
        """This method is used to check if app version is matching in INITIALIZING state

        Args:
            host(str): ip_address of the machine

        Returns:
            bool: since default app, always returns true.

        Raises:
            exception.NotImplemented
            :param host:
        """
        try:
            self._log.debug(">")
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            self.update_persist_data(
                infra_ref, "found_version", None, self._sw_type)
            cmd = "ls /opt/"
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1)
            iptables_flush = "iptables -F"
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                iptables_flush, time_out=Constants.PEXPECT_TIMER)
            result = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                cmd, time_out=Constants.PEXPECT_TIMER)
            if "unicorn" not in result:
                self._log.debug("<")
                return False
            self.restart_unicorn_app()
            info = self.get_unicorn_version()
            if info != "":
                self._log.debug(
                    "Information derived from the \"%s\" node is \"%s\"", str(host), info)
                _found_version = info
                self._log.debug("The software type is %s", str(self._sw_type))
                self.update_persist_data(
                    infra_ref, "found_version", _found_version, self._sw_type)
                if self._version == _found_version:
                    self._log.debug("<")
                    return True
            self._log.warning(
                "Application for %s not found", self._version)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session()


    def install_correct_version(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            bool: since default app, always returns true.

        """
        self._log.debug(">")
        try:
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            self._log.debug("The software type is %s", str(self._sw_type))
            _found_version = self.get_persist_data(
                infra_ref, "found_version", self._sw_type)
            if _found_version is None:
                self._log.debug(
                    "application not found, performing fresh installation")
                self.install()
                self._log.debug("<")
                return True

            if _found_version == self._version:
                self._log.debug(
                    "application %s-%s already installed", self.name, self._version)
                self._log.debug("<")
                return True

            if _found_version > self._version:
                self._log.debug(
                    "Higher version(%s) of application found, downgrading to version %s",
                    _found_version, self._version)
                self.uninstall()
                self.install()
                self._log.debug("<")
                return True

            if _found_version < self._version:
                self._log.debug(
                    "Lower version(%s) of application found, upgradinging to version %s",
                    _found_version, self._version)
                self.uninstall()
                self.install()
                self._log.debug("<")
                return True
        except (exception.AnsibleException, exception.BuildNotFoundInRepo) as ex:
            self._log.warning("Exception %s", str(ex))
            self._log.debug("<")
            return False

    def add_slash(self, path):
        """
        Adds '/' to the path if not present
        Args:
            path: str
        Return:
            path: str
        """
        self._log.debug(">")
        if path[-1] == "/":
            res_path = path
        else:
            res_path = "{}{}".format(path, "/")
        self._log.debug("<")
        return res_path

    def create_temp_dir(self):
        """
        This method used to create temporary directory
        """
        self._log.debug(">")
        self._temp_dir = tempfile.mkdtemp(
            dir=os.path.dirname(os.path.abspath(__file__)))
        self._log.debug("<")
        return self._temp_dir

    def _delete_temp_dir(self):
        """
        This method used to delete temporary directory
        """
        self._log.debug(">")
        shutil.rmtree(self._temp_dir)
        self._log.debug("<")

    def _render_template(self, template, config_dict, dst_fname):
        """
        This method is used for rendering a configuration template for a
        dictionary of values.
        """
        self._log.debug(">")
        template_obj = Utility.get_jinja2_template_obj(template)
        configs = template_obj.render(config_dict)
        file_name = Utility.join_path(self._temp_dir, dst_fname)
        configs = self.process_config(configs)
        Utility.write_pretty_json(file_name, configs)
        self._log.debug(
            "Generated the configuration file under {}".format(file_name))
        self._log.debug("<")
        return file_name

    def process_config(self, config):
        """
        This method is used for processing the rendered configuration
        accordingly.
        """
        self._log.debug(">")
        node_name = self.get_node().get_name()
        config = json.loads(config)
        config = config[node_name]["TCConfiguration"]
        self._log.debug("<")
        return config

    def get_unicorn_version(self):
        """
        Method to start the testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            Request's response.
        """
        try:
            self._log.debug(">")
            msg = ""
            argument = "unicorn/GET_VERSION"
            status, msg = self.send_rest_get_request(argument)
            if status:
                self._log.debug("<")
                return msg["version"]
            else:
                raise Exception("Error")
        except Exception:
            self._log.debug("<")
            return msg

    def install(self):
        """
        This method installs the unicorn_insatller in the host machine.

        Returns:
            None.
        """
        self._log.debug(">")
        self._log.debug("Installing %s from repo %s",
                        self._name, self.get_repo_path())
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host, 'rep_path': self.get_repo_path()}
        tags = {'install-unicorn'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info(
            "Successfully installed the application %s", str(self._name))
        self._log.debug("<")

    def uninstall(self):
        """
        This method uninstalls the Unicorn app in the host.

        Returns:
            None.
        """
        self._log.debug(">")
        infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
        self._log.debug("The software type is %s", str(self._sw_type))
        _found_version = self.get_persist_data(
            infra_ref, "found_version", self._sw_type)
        self._log.debug("Uninstalling %s-%s", self._name, _found_version)
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host}
        tags = {'uninstall-unicorn'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info(
            "Successfully uninstalled the application %s", str(self._name))
        self._log.debug("<")

    def restart_unicorn_app(self, tag=None):
        """
        Start the datetime_server application on the Node
        Returns(bool):
            True if server is started, False otherwise

        """
        self._log.debug(">")
        restart_cmd = "systemctl restart unicorn"
        check_status = "systemctl status unicorn"
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(
            restart_cmd, tag=tag, time_out=Constants.PEXPECT_TIMER)
        output = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
            check_status, tag=tag, time_out=Constants.PEXPECT_TIMER)
        if "active (running)" not in str(output):
            self._log.debug("Unicorn service not running")
            self._log.debug("<")
            raise exception.FailedToStartService(
                "service Unicorn not running"
            )
        self._log.info("Successfully restarted the application Unicorn")
        self._log.debug("<")
        return True

    def set_configuration_for_tc(self, config_dict, test_dict):
        """
        Set configuration for the a particular testcase.
        Args:
            config_dict (dict): Dictionary IPs and subnets of all nodes in
                topology.
            test_dict (dict): Dictionary of testcase informations such as SUT
                name, testsuite name and testcase name.

        Returns():
            None.

        """
        try:
            self._log.debug(">")
            _temp_dir = self.create_temp_dir()
            os.chmod(_temp_dir, 0o775)
            # template_ = "../product/Telaverge/sut/{}/{}/{}/testcase_conf.json".format(

            template_ = "{}/product/Telaverge/sut/{}/{}/{}/testcase_conf.json".format(
                self.root_path, test_dict["sut_name"], test_dict["ts_name"], test_dict["tc_name"])
            host = self.get_node().get_management_ip()

            self._log.info(
                "Copying certificates to node %s", self._name)
            testcase_dir = "mkdir -p /opt/unicorn/testcases/{}/{}/{}/config/certificates".format(
                test_dict["sut_name"], test_dict["ts_name"], test_dict["tc_name"])
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1)
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                testcase_dir, time_out=Constants.PEXPECT_TIMER)
            config_dict = self.copy_certificates(
                host, config_dict, test_dict, template_)

            self._log.info(
                "Copying templates to node %s", self._name)
            config_dict = self.copy_templates(
                host, config_dict, test_dict, template_)

            self._log.info(
                "Genarating %s test configurations on node %s", self._name,
                host)

            file_name = self._generate_unicorn_tc(config_dict, template_)
            dest_path = "/opt/unicorn/testcases/{}/{}/{}/test_config.json".format(
                test_dict["sut_name"], test_dict["ts_name"], test_dict["tc_name"])
            self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(
                            self.get_node(), 
                            src_files=os.path.abspath(file_name), 
                            dest_file=dest_path,
                            time_out=Constants.PEXPECT_TIMER
                        )
            self._log.info(
                "Generated and copied the %s configurations to node %s",
                self._name, host)
        except Exception as ex:
            traceback_ = traceback.format_exc()
            self._log.error("Failed to generate test configuration files")
            self._log.error("Exception is - %s", str(ex))
            self._log.error("Traceback - %s", (traceback_))
            raise Exception(ex)
        finally:
            self._delete_temp_dir()
            self.service_store_obj.get_login_session_mgr_obj().close_session()
            self._log.debug("<")

    def render_template(self, render_dict, value_dict):
        """ Method get render given dict with value
            dict

        Args:
            render_dict(json): that needs to be rend
            vaiue_dict(json): json with values

        Returns:
            dict: rendered the json

        """
        self._log.debug(">")
        template_obj = Template(str(render_dict))
        configs = {}
        configs = template_obj.render(value_dict)
        self._log.debug("<")
        from ast import literal_eval
        return literal_eval(configs)

    def copy_certificates(self, host, config_dict, test_dict, template_):
        """
        Copy each certificate and key file to respective nodes for a particular testcase.
        Args:
            host (str): Host IP of the node.
            config_dict (dict): Dictionary IPs and subnets of all nodes in
                topology.
            test_dict (dict): Dictionary of testcase informations such as SUT
                name, testsuite name and testcase name.
            template_ (str): Path of template file.

        Returns():
            config_dict (dict): Dictionary IPs and subnets of all nodes in
                topology with path of certificates.

        """
        self._log.debug(">")
        node_name = self.get_node().get_name()
        configs = Utility.read_json_file(template_)
        node_json = configs[node_name]
        cert_file_list = self.render_template(node_json["CertificateFiles"],
                                              self.regal_path)
        dest_path = "/opt/unicorn/testcases/{}/{}/{}/config/certificates".format(
            test_dict["sut_name"], test_dict["ts_name"], test_dict["tc_name"])
        for file_name, file_path in cert_file_list.items():
            if os.path.exists(file_path):
                cert_file_name = file_path.split("/")[-1]
                config_dict[file_name] = os.path.join(dest_path,
                                                      cert_file_name)
                self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(
                                self.get_node(), 
                                src_files=os.path.abspath(file_path), 
                                dest_file=dest_path,
                                time_out=Constants.PEXPECT_TIMER
                            )
            else:
                self._log.debug("<")
                raise Exception("{} not added".format(file_name))
        self._log.debug("<")
        return config_dict

    def copy_templates(self, host, config_dict, test_dict, template_):
        """
        Copy each template file to respective nodes for a particular testcase.
        Args:
            host (str): Host IP of the node.
            config_dict (dict): Dictionary IPs and subnets of all nodes in
                topology.
            test_dict (dict): Dictionary of testcase informations such as SUT
                name, testsuite name and testcase name.
            template_ (str): Path of template file.

        Returns():
            config_dict (dict): Dictionary IPs and subnets of all nodes in
                topology with path of templates.

        """
        self._log.debug(">")
        node_name = self.get_node().get_name()
        configs = Utility.read_json_file(template_)
        node_json = configs[node_name]
        templates_list = self.render_template(
            node_json["TemplateFiles"], self.regal_path)
        dest_path = "/opt/unicorn/testcases/{}/{}/{}/config".format(
            test_dict["sut_name"], test_dict["ts_name"], test_dict["tc_name"])
        for file_name, file_path in templates_list.items():
            if os.path.exists(file_path):
                os.chmod(file_path, 0o775)
                templ_file_name = file_path.split("/")[-1]
                config_dict[file_name] = os.path.join(dest_path,
                                                      templ_file_name)
                self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(
                                self.get_node(), 
                                src_files=os.path.abspath(file_path), 
                                dest_file=dest_path,
                                time_out=Constants.PEXPECT_TIMER
                            )
            else:
                self._log.debug("<")
                raise Exception("{} not added".format(file_name))
        self._log.debug("<")
        return config_dict

    def _generate_unicorn_tc(self, config_dict, template_):
        """
        This method generates test configurations for unicorn.
        Args:
            config_dict (dict): dictionary of values to be rendered in the
                configuration template.
            template_ (str): Path of the template file.

        Returns:
            file_name(str): Path of the rendered config file.
        """
        self._log.debug(">")
        self._log.info(
            "Genarating %s test configuration file test_config.json", self._name)

        config_dict.update(self.regal_path)
        file_name = self._render_template(template_, config_dict,
                                          "test_config.json")
        self._log.info(
            "Genarated %s test configuration file test_config.json", self._name)
        self._log.debug("<")
        return file_name

    def generate_config_dict_from_topology(self, topology_obj):
        """
        This method returns a dictionary of nodes and their respective IP
        addreses along with their subnets/masks.

        Args:
            topology_obj(obj): Currently executing topology's object.

        Returns:
            config_dict(dict): Dictionary of Nodes' IPs and subnets.
        """
        self._log.debug(">")
        config_dict = {}
        nodes_list = topology_obj.get_node_list()
        for node in nodes_list:
            os_obj = node.get_os()
            node_name = node.get_name()
            node_ip = node.get_management_ip()
            subnets = node.get_subnets()
            config_dict[node_name] = {}
            config_dict[node_name]["ip"] = node_ip
            config_dict[node_name]["Subnets"] = {}
            for subnet_name, details in subnets.items():
                if subnet_name == "StateInfo":
                    continue
                subnet_ips = os_obj.get_ips_from_subnet_group(
                    node_ip, subnet_name)
                if subnet_ips:
                    config_dict[node_name]["Subnets"][subnet_name] = subnet_ips[0]

        self._log.debug("<")
        return config_dict

    def send_rest_get_request(self, request_info):
        """
        Send REST API GET Request
        Args:
            request_info(str): Information for which GET request is to be invoked

        Returns(str): Response

        """
        self._log.debug(">")
        try:
            host_ip = self.get_node().get_management_ip()
            host_port = 5000
            url = "http://" + str(host_ip) + ':' + \
                str(host_port) + '/' + request_info
            req = requests.get(url, timeout=60)
            result = False
            if req.status_code is 200:
                result = True
                result_msg = req.json()
            else:
                result_msg = req.json()
            self._log.debug("<")
            return result, result_msg
        except Exception as ex:
            self._log.debug("<")
            # self._log.error("Error is %s", ex)
            raise Exception(str(ex))

    def send_rest_post_request(self, request_info, data={}):
        """
        Send REST API POST Request
        Args:
            request_info(str): Information for which GET request is to be invoked

        Returns(str): Response

        """
        self._log.debug(">")
        try:
            host_ip = self.get_node().get_management_ip()
            host_port = 5000
            url = "http://" + str(host_ip) + ':' + \
                str(host_port) + '/' + request_info
            req = requests.post(url, data=data, timeout=60)
            result = False
            result_msg = "Request failed"
            if req.status_code is 200:
                result_msg = req.json()
                result = True
            else:
                result_msg = req.json()
            self._log.debug("<")
            return result, result_msg
        except Exception as ex:
            self._log.debug("<")
            raise Exception(str(ex))

    def get_sut_list(self):
        """
        Method to fetch the list of SUTs in the app.

        Args:
            None.

        Returns:
            Response result.
        """
        self._log.debug(">")
        argument = "tests/LIST_SUT"
        status, msg = self.send_rest_get_request(argument)
        self._log.debug("<")
        return status, msg

    def get_ts_list(self, sut_name):
        """
        Method to fetch the list of Testsuites in the specified SUT name.

        Args:
            sut_name (str): Name of the SUT.

        Returns:
            Response result.
        """
        self._log.debug(">")
        argument = "tests/{}/LIST_TEST_SUITES".format(sut_name)
        status, msg = self.send_rest_get_request(argument)
        self._log.debug("<")
        return status, msg

    def get_tc_list(self, sut_name, ts_name):
        """
        Method to fetch the list of Testcases in the testsuite of the specified
        SUT.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.

        Returns:
            Response result.
        """
        self._log.debug(">")
        argument = "tests/{}/{}/LIST_TEST_CASES".format(sut_name, ts_name)
        status, msg = self.send_rest_get_request(argument)
        self._log.debug("<")
        return status, msg

    def start_tc_execution(self, sut_name, ts_name, tc_name):
        """
        Method to start the testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            Request's response.
        """
        self._log.debug(">")
        argument = "tests/{}/{}/{}/START_TEST".format(sut_name, ts_name,
                                                      tc_name)
        status, msg = self.send_rest_post_request(argument)
        self._log.debug("<")
        return status, msg

    def stop_tc_execution(self, sut_name, ts_name, tc_name):
        """
        Method to start the testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            Request's response.
        """
        self._log.debug(">")
        argument = "tests/{}/{}/{}/STOP_TEST".format(sut_name, ts_name,
                                                     tc_name)
        status, msg = self.send_rest_post_request(argument)
        self._log.debug("<")
        return status, msg

    def get_tc_exec_status(self, sut_name, ts_name, tc_name):
        """
        Method to fetch the result of testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            Response result.
        """
        self._log.debug(">")
        argument = "tests/{}/{}/{}/TEST_STATUS".format(sut_name, ts_name,
                                                       tc_name)
        status, msg = self.send_rest_get_request(argument)
        self._log.debug("<")
        return status, msg

    def get_stats(self, sut_name, ts_name, tc_name):
        """
        Method to get the client stats.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            Request's response.
        """
        self._log.debug(">")
        argument = "tests/{}/{}/{}/CLIENT_TEST_STATISTICS".format(sut_name, ts_name,
                                                                  tc_name)
        result, msg = self.send_rest_get_request(argument)
        if result:
            msg = msg["stats"]
        self._log.debug("<")
        return result, msg
