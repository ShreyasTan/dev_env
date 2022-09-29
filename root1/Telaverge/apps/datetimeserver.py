"""
#Add module string
"""
import requests
from pexpect import pxssh
from regal_lib.corelib.common_db_util import CommonDBUtil
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants
from regal_lib.product.Regal.regal_constants import Constants as RegalConstants
from regal_lib.product.Regal.apps.appbase import AppBase
import regal_lib.corelib.custom_exception as exception
from regal_lib.repo_manager.repo_mgr_client import RepoMgrClient
from regal_lib.corelib.constants import Constants


FileExistsErr = FileExistsError


class Datetimeserver(AppBase):
    def __init__(self, service_store_obj, name, version):
        super(Datetimeserver, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self.repo_mgr_client_obj = RepoMgrClient(self.service_store_obj)
        self.common_db_util_obj = CommonDBUtil(self.service_store_obj)
        self.ssh_client = None
        self.time_server_bin = "/opt/{0}-{1}/datetime_server.py".format(
            name, version)
        self._started = False
        self.app_name = name

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
            self._log.debug("app_match >")
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            iptables_flush = "iptables -F"
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                iptables_flush, tag=self.app_name, time_out=Constants.PEXPECT_TIMER)
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            cmd = "ls /opt/ | grep 'datetime_server-' | cut -d '-' -f 2"
            self._log.debug("App match host is %s", str(host))
            self._log.debug("App match Command is %s", str(cmd))
            hosts = [host]
            info = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,self.app_name,time_out=Constants.PEXPECT_TIMER)
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
            else:
                self._log.debug(
                    "datetime_server is not present in \"%s\"", str(host))
                self._log.debug("The software type is %s", str(self._sw_type))
                self.update_persist_data(
                    infra_ref, "found_version", None, self._sw_type)
            self._log.warning(
                "Application %s not found, found version:%s", self._version, self._found_version)
            self._log.debug("<")
            return False
        except exception.AnsibleException as ex:
            self._log.warning("Exception %s", str(ex))
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)


    def install_correct_version(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            bool: since default app, always returns true.

        """
        try:
            self._log.debug("install_correct_version >")
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

    def install_dependencies(self, version='python2'):
        """
        """
        self._log.debug("install_dependencies >")
        host = self.get_node().get_management_ip()
        node_name = self.get_node().get_name()
        if version == 'python2':
            pip_url = self.repo_mgr_client_obj.get_repo_path('python2-pip')
            pip_ = 'pip2'
            extra_vars = {
                'host': host,
                'src_path': [pip_url]
            }
            tags = {'install-rpm'}
            self.get_deployment_mgr_client_wrapper_obj().run_playbook(RegalConstants.REGAL_PROD_DIR_NAME,
                                                                      extra_vars, tags)
        else:
            # python 3.6 is not supported now.
            raise exception.PythonVersionNotSupported(host, node_name, version)

        dependency_files = []
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("click"))
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("itsdangerous"))
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("Jinja2"))
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("MarkupSafe"))
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("Werkzeug"))
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("Flask"))
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("netsnmpagent"))

        extra_vars = {
            'host': host,
            'source_path': dependency_files
        }
        tags = {'install-python-dependencies'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(RegalConstants.REGAL_PROD_DIR_NAME,
                                                                  extra_vars, tags)
        self._log.debug("<")

    def _get_python_version(self, host):
        """This method return the version of the python installed in given host.

        Args:
            host(str): ipaddress of the machine

        Returns:
            str: Version of the python.

        """
        info = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                "python -c 'import sys; print((sys.version_info)<(3,0))'", self.app_name, time_out=Constants.PEXPECT_TIMER)
        if info == "False":
            return 'python3'
        return 'python2'

    def install(self):
        self._log.debug("Installing %s from repo %s",
                        self._name, self.get_repo_path())
        self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
        host = self.get_node().get_management_ip()
        version = self._get_python_version(host)
        self.install_dependencies(version)
        extra_vars = {'host': host, 'rep_path': self.get_repo_path()}
        tags = {'install-datetime-server'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
        self._log.info(
            "Successfully installed the application %s", str(self._name))

    def uninstall(self):
        self._log.debug("Uninstalling %s-%s", self._name, self._found_version)
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host}
        tags = {'uninstall-datetime-server'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info(
            "Successfully uninstalled the application %s", str(self._name))

    def start_server(self):
        """
        Start the datetime_server application on the Node
        Returns(bool):
            True if server is started, False otherwise

        """
        self._log.debug(">")
        try:
            ip_address = self.get_node().get_management_ip()
            query = {"managementIP": ip_address}
            db_machine_objs = self.common_db_util_obj.get_db_machine_objs_by_query_dict(
                query)
            db_machine_obj = db_machine_objs[0]
            machine_info = db_machine_obj.to_mongo().to_dict()
            username = machine_info['credentials']['user']
            password = machine_info['credentials']['password']
            decrypted_pass = (
                self.service_store_obj
                .get_password_obj()
                .get_decrypt_pass(password)
            )
            self.get_node()
            self.ssh_client = pxssh.pxssh()
            self.ssh_client.login(ip_address, username, decrypted_pass)
            self.ssh_client.sendline('python '+self.time_server_bin)
            self.ssh_client.prompt()
            self.ssh_client.expect("Enter choice*")
            self._started = True
            self._log.debug("<")
            return True
        except (pxssh.ExceptionPxssh, exception.MachineNotFound, KeyError) as e:
            print(e)
            self._log.debug("<")
            return False

    def stop_server(self):
        """
        Stop the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        try:
            op = self.enter_choice('6')
            self.ssh_client.close()
            # self.s.prompt()
            self._log.debug("<")
            self._started = False
            return True
        except (pxssh.ExceptionPxssh, exception.MachineNotFound, KeyError) as e:
            print(e)
            self._log.debug("<")
            self._started = False
            return True

    def enter_choice(self, choice):
        """
        Enters the choice and returns the output printed
        Args:
            choice(str): choice string

        Returns(str):


        """
        self._log.debug(">")
        try:
            self.ssh_client.sendline(choice)
            if choice != "6":
                self.ssh_client.expect("Enter choice*")
            # self.s.prompt()
            self._log.debug("<")
            return str(self.ssh_client.before).splitlines()[-1]
        except pxssh.ExceptionPxssh as e:
            print(e)
            self._log.debug("<")
            raise e

    def process_running(self, process, tag=None):
        """
        Checks if process is running
        Args:
            process(str): process name

        Returns(bool): True if process is running, False if its not running

        """
        self._log.debug(">")
        host = self.get_node().get_management_ip()
        hosts = [host]
        cmd = f"ps -eaf|grep '{process}.py'| grep -v grep"
        output = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                    cmd, tag=tag, time_out=Constants.PEXPECT_TIMER)
        if output:
            self._log.debug("<")
            return True
        self._log.debug("<")
        return False


class DateTimeServerV200(Datetimeserver):
    def __init__(self, service_store_obj, name, version):
        super(DateTimeServerV200, self).__init__(
            service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self.ssh_client = None
        self.time_server_bin = "/opt/datetime_server-2.0.0/datetime_server.py"
        self._client_config_file = \
            "/opt/datetime_server-3.0.0/client_config.json"

    def start_server(self, tag=None):
        """
        Start the datetime_server application on the Node
        Returns(bool):
            True if server is started, False otherwise

        """
        self._log.debug(">")
        host_ip_address = self.get_node().get_management_ip()
        start_cmd = "systemctl start datetime-server"
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                    start_cmd, tag=tag, time_out=Constants.PEXPECT_TIMER)
        check_status = "systemctl status datetime-server"
        output = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
            check_status, tag=tag, time_out=Constants.PEXPECT_TIMER)
        if "active (running)" in str(output):
            self._log.info("datetime-server started successfully")
            self._log.debug("<")
            return True
        self._log.debug("<")
        return False

    def stop_server(self, tag=None):
        """
        Stop the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        host_ip_address = self.get_node().get_management_ip()
        stop_cmd = "systemctl stop datetime-server"
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                    stop_cmd, tag=tag, time_out=60)
        check_status = "systemctl status datetime-server"
        output = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
            check_status, tag=tag, time_out=Constants.PEXPECT_TIMER)
        if "active (running)" not in str(output):
            self._log.info("datetime-server stopped successfully")
            self._log.debug("<")
            return True
        self._log.debug("<")
        return False

    def get_year(self):
        """
        Invoke REST API GET Request for http://<datetimeserverip>:<portno>/year
        Returns(str): Year

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.send_rest_request('year')

    def send_rest_request(self, request_info):
        """
        Send REST API Get Request
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
            req = requests.get(url)
            result = "request failed"
            if req.status_code is 200:
                result = req.text
            else:
                result = str(req)
            self._log.debug("<")
            return result
        except Exception as ex:
            self._log.debug("<")
            return str(ex)

    def get_month(self):
        """
         Invoke REST API GET Request for http://<datetimeserverip>:<portno>/month
        Returns(str): month

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.send_rest_request('month')

    def get_day_of_month(self):
        """
         Invoke REST API GET Request for http://<datetimeserverip>:<portno>/day_of_month
        Returns(str): day of the month

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.send_rest_request('day_of_month')

    def get_time(self):
        """
         Invoke REST API GET Request for http://<datetimeserverip>:<portno>/time
        Returns(str): time

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.send_rest_request('time')

    def get_date_time(self):
        """
        Invoke REST API GET Request for http://<datetimeserverip>:<portno>/date_and_time
        Returns(str): time

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.send_rest_request('date_and_time')

    def get_log_path(self):
        """
        Invoke REST API GET Request for http://<datetimeserverip>:<portno>/log_path
        Returns(str): log_path

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.send_rest_request('log_path')


class DateTimeServerV400(DateTimeServerV200):
    def __init__(self, service_store_obj, name, version):
        super(DateTimeServerV400, self).__init__(
            service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._client_config_file = \
            "/opt/datetime_server-4.0.0/client_config.json"

    def start_client(self, server_host, exe_count):
        """
        """
        self._log.debug(">")
        host = self.get_node().get_management_ip()
        args_dict = {
            "ServerIp": server_host,
            "ExecutionCount": exe_count
        }
        extra_vars = {
            "host": host,
            "json_data": args_dict,
            "dest_file_name": self._client_config_file
        }
        tags = {'copy-content'}
        try:
            self.get_deployment_mgr_client_wrapper_obj().run_playbook(
                RegalConstants.REGAL_PROD_DIR_NAME, extra_vars, tags)
        except exception.AnsibleException:
            pass
        self._log.debug("<")
        return self.get_deployment_mgr_client_wrapper_obj().start_service(host, "datetime-client")

    def stop_client(self):
        """
        Stop the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        host = self.get_node().get_management_ip()
        self._log.debug("<")
        return self.get_deployment_mgr_client_wrapper_obj().stop_service(host, "datetime-client")

    def start_snmpd(self):
        """
        Start the datetime_server application on the Node
        Returns(bool):
            True if server is started, False otherwise

        """
        self._log.debug(">")
        host_ip_address = self.get_node().get_management_ip()
        start_cmd = "systemctl start snmpd"
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                    start_cmd, tag=tag, time_out=Constants.PEXPECT_TIMER)
        check_status = "systemctl status snmpd"
        output = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
            check_status, tag=tag, time_out=Constants.PEXPECT_TIMER)
        if "active (running)" in str(output):
            self._log.info("snmpd started successfully")
            self._log.debug("<")
            return True
        self._log.debug("<")
        return False    