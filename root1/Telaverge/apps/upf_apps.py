"""
App tools for Unicorn.
"""
import os
import sys
import traceback
from Regal.regal_constants import Constants as RegalConstants
from Regal.apps.appbase import AppBase
from Telaverge.apps.app_constants import Constants as AppConstants
import regal_lib.corelib.custom_exception as exception
import Telaverge.apps.upf_exception as upf_exception
from Telaverge.telaverge_constans import Constants as TVConstants, UPFConstants
from regal_lib.corelib.common_utility import Utility
from regal_lib.corelib.constants import Constants
from regal_lib.helper.common_helper import CommonHelper
from regal_lib.repo_manager.repo_mgr_client import RepoMgrClient


class UPFAppBase(AppBase):
    """
    Class implemented for UPF app plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UPFAppBase, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._started = False
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"
        self.required_version = version
        self.app_name = name
        self.app_version = version
        self.scapy_installed = False
        self._upf_found_version = None
        self.python3_installed = False
        self.repo_mgr_client_obj = RepoMgrClient(self.service_store_obj)
        self._log.debug("<")

    def get_repository_path(self, app_name, app_version=None):
        """Method used to get_before_output repo path of given app name
        and app version

        Args:
            app_name(str): Name of the package
            app_version(str): Version of the package

        Returns:
            repo_path(str): repo path of the given package

        Raises:
            exception.BuildNotFoundInRepo

        """
        try:
            self._log.debug(">")
            repo_path = self.repo_mgr_client_obj.get_repo_path(
                app_name, app_version)
            self._log.debug("<")
            return repo_path
        except exception.BuildNotFoundInRepo as ex:
            repo_path = None
            self._log.critical('%s', str(ex))
            self._log.debug("<")
            raise upf_exception.InstallFailed(str(ex))

    def app_match(self, host):
        """ Method perform application match for the given node

        Args:
            host(str): Managament IP of the node

        Returns:
            bool: True = If app is already installed in the node
                  False = If app is not installed or correct version of the app
                            is not installed

        """
        self._log.debug(">")
        infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
        self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
        python3_installed = self._check_python3_is_installed(host)
        if not python3_installed:
            self.update_persist_data(infra_ref, "python3_installed", python3_installed, self._sw_type)
            self._log.debug("<")
            return False
        self.update_persist_data(infra_ref, "python3_installed", python3_installed, self._sw_type)
        scapy_installed = self._check_scapy_is_installed(host)
        self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
        self.update_persist_data(infra_ref, "scapy_installed", scapy_installed, self._sw_type)
        self._log.debug("<")
        return scapy_installed

    def _check_python3_is_installed(self, host):

        self._log.debug(">")
        cmd = "python3 --version"
        try:
            b_output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,
                    self.app_name, time_out=Constants.PEXPECT_TIMER)
            self._log.debug("< before output %s", str(b_output))
            if "Python 3.6" in b_output:
                self._log.debug("< Python 3.6 present")
                return True
            self._log.debug("<")
            return False
        except exception.AnsibleException as ex:
            trace_back = traceback.format_exc()
            error_mag = "Python3 not installed {} - {}: Traceback: {}".\
                format(host, str(ex), trace_back)
            self._log.error(error_mag)
            self._log.debug("<")
            return False
        
 
    def _check_scapy_is_installed(self, host):
        """ Method check the is scapy python module is installed
            and scapy script present in the in the given host

        Args:
            host(str): Management IP of the node

        Returns:
            bool: True = If scapy is installed and script is present
                  False = If scapy is not installed or script is not present

        """
        self._log.debug(">")
        cmd = "ls -lrth /opt/upf/ | grep {}-{} | wc -l".format("scapy",
                "2.4.5")
        b_output = \
        self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,
                self.app_name, time_out=Constants.PEXPECT_TIMER)
        self._log.debug("< before output %s", str(b_output))
        if b_output != "1":
            err_msg = "The scapy is not installed in the node %s", host
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        self._log.debug("<")
        return True

    def install_correct_version(self):
        """ Method install the correct version of the application
            in the node

        Returns:
            bool: True = If installation is success
                  False = if installation is failed

        """
        self._log.debug(">")
        try:
            node_ip = self.get_node().get_management_ip()
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            python3_installed = self.get_persist_data(
                infra_ref, "python3_installed", self._sw_type)
            if not python3_installed:
                error_mag = "Deployment Failed on node {}, doesn't have python3".format(
                    node_ip)
                self._log.error(error_mag)
                self._log.debug("<")
                return False
            scapy_installed = self.get_persist_data(
                infra_ref, "scapy_installed", self._sw_type)
            if not scapy_installed:
                self._install_scapy(node_ip)
            self._log.debug("<")
            return True
        except exception.AnsibleException as ex:
            trace_back = traceback.format_exc()
            error_mag = "Installation failed on node {} - {}: Traceback: {}".\
                format(node_ip, str(ex), trace_back)
            self._log.error(error_mag)
            self._log.debug("<")
            return False

    def _install_scapy(self, node_ip):
        """ Method install the scapy python module on the given node

        Args:
            node_ip(str): Management IP of the node

        Returns:
            None

        """
        self._log.debug(">")
        extra_vars = {
            'host': node_ip,
            'scapy_tar_file': self.get_repository_path(self.app_name),
            'scapy_version': "2.4.5"
        }
        tag = {'install-scapy'}
        self._log.info("executing the playbook : install-scapy")
        self.get_deployment_mgr_client_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tag)
        self._log.debug("<")

    def _copy_scapy_script(self, node_ip):
        """ Method copy the scapy script to the given node

        Args:
            node_ip(str): Management IP of the node

        Returns:
            None

        """
        self._log.debug(">")
        repo_path = self.get_repository_path(self.app_name, self.app_version)
        extra_vars = {
            'host': node_ip,
            'dest_extract_path': AppConstants.DEST_SCRIPT_PATH,
            'tar_file': repo_path
        }
        tag = {'install-tarfile'}
        self.get_deployment_mgr_client_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tag)
        self._log.debug("<")


class UPFApp(UPFAppBase):
    """
    Class implemented for UPF app plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UPFApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._started = False
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"

    def app_match(self, host):
        """This method is used to check if app version is matching in INITIALIZING state

        Args:
            host(str): ip_address of the machine

        Returns:
            bool: True = If Upf is installed.
                  False = If Upf is not installed

        """
        self._log.debug(">")
        try:
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            self.update_persist_data(infra_ref, "_upf_found_version", None, self._sw_type)
            self.check_upf_installed()
            self.update_persist_data(infra_ref, "_upf_found_version", True, self._sw_type)
            self._log.debug("<")
            return True
        except upf_exception.InstallFailed as ex:
            trace_back = traceback.format_exc()
            err_msg = "UPF up is not Installed {}: Trace Back: {}".format(
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
        
    def check_upf_installed(self):
        """ Method check the UPF is installed or not
        """
        self._log.debug(">")
        self._check_docker_status()
        self._check_upf_container_status()
        self._check_dpdk_interfaces_bind_status()
        self._log.debug("<")

    def _check_docker_status(self):
        """ Method check docker is installed and is active

        Raises:
            InstallFailed: if docker is not installed or it is not active

        """
        self._log.debug(">")
        try:
            cmd = "systemctl status {}".format(AppConstants.DOCKER_SERVICE_NAME)
            b_output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,
                    self.app_name, time_out=Constants.PEXPECT_TIMER)
            self._log.debug("< before output %s", str(b_output))
            if "active (running)" not in str(b_output):
                self._log.debug("< service not running")
                raise upf_exception.FailedToStartService(
                    "service {} not running".format(AppConstants.DOCKER_SERVICE_NAME)
                )
        except upf_exception.FailedToStartService as ex:
            err_msg = "Failed to get the status of {} service: Exception is "\
                      "{}".format(AppConstants.DOCKER_SERVICE_NAME, ex)
            self._log.warning(err_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(err_msg)

    def _check_upf_container_status(self):
        """ Method check the docker container(smu, lbu and fpu) status is up

        Raises:
            InstallFailed: if docker container is not up

        """
        self._log.debug(">")
        try:
            cmd = AppConstants.SMU_CONTAINER_STATUS
            smu_status = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,\
                    self.app_name, time_out=Constants.PEXPECT_TIMER)
            self._log.debug("before output %s", str(smu_status))
            
            cmd = AppConstants.LBU_CONTAINER_STATUS
            lbu_status = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,\
                    self.app_name, time_out=Constants.PEXPECT_TIMER)
            self._log.debug("before output %s", str(lbu_status))

            cmd = AppConstants.FPU_CONTAINER_STATUS
            fbu_status = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,\
                    self.app_name, time_out=Constants.PEXPECT_TIMER)
            self._log.debug("before output %s", str(fbu_status))
        except exception.AnsibleException as ex:
            err_msg = "Failed to get the status of smu fbu and lbu"\
                " docker containers service. Ex: %s", str(ex)
            self._log.warning(err_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(err_msg)
        if "Up" not in smu_status or "Up" not in lbu_status or "Up" not in fbu_status:
            err_msg = "smu or lbu of fbu container is not up "
            self._log.warning(err_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(err_msg)

    def _check_dpdk_interfaces_bind_status(self):
        """ Method check the interfaces are binded to the dpdk or not

        Returns:
            bool: True if interfaces are binded to the dpdk

        Raises:
            InstallFailed: if docker container is not up

        """
        self._log.debug(">")
        try:
            cmd = AppConstants.DPDK_BIND_INTERFACES
            output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(cmd,
                    self.app_name, time_out=Constants.PEXPECT_TIMER)
            self._log.debug("< before output %s", str(output))

            if not output:
                err_msg = "Interfaces are not binded dpdk"
                self._log.warning(err_msg)
                self._log.debug("<")
                raise upf_exception.InstallFailed(err_msg)

            data = output.split("\n")
            binded_interfaces_count = 0
            for line in data:
                if AppConstants.BIND_TO_DRIVER in line:
                    binded_interfaces_count += 1
            if binded_interfaces_count != 3:
                err_msg = "The dpdk is not binded to 3 interfaces"
                self._log.warning(err_msg)
                self._log.debug("<")
                raise upf_exception.InstallFailed(err_msg)
            self._log.debug("<")
            return True
        except exception.AnsibleException as ex:
            err_msg = "Failed to get the dpdk binded interfaces count"\
                " ex: %s", str(ex)
            self._log.warning(err_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(err_msg)

    def install_correct_version(self):
        """ Method install in the correct version of the UPF

        Returns:
            bool: True if installation of upf is success viceversa.

        """
        try:
            self._log.debug(">")
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            node_ip = self.get_node().get_management_ip()
            status = self._install_correct_upf(node_ip)
            self._log.debug("<")
            return status
        except exception.RegalException as ex:
            traceback_ = traceback.format_exc()
            self._log.error(
                "Correction failed on node %s - %s ", node_ip, str(ex))
            self._log.error("Traceback %s", str(traceback_))
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)

    def _install_correct_upf(self, node_ip):
        """
        Method used to install correct version of UPF.

        Args:
            node_ip(str): Management IP of the node

        Return:
            bool: True if installation is success viceversa

        """
        self._log.debug(">")
        infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
        self._log.debug("The software type is %s", str(self._sw_type))
        _upf_found_version = self.get_persist_data(
            infra_ref, "_upf_found_version", self._sw_type)
        if _upf_found_version is None:
            self._log.info(
                "UPF not found, performing fresh"
                " installation on node - %s", node_ip)
            self.install_upf(node_ip)
            self._log.debug("<")
            return True

        if (_upf_found_version and CommonHelper.check_version_equal(
                _upf_found_version, self.required_version)):
            self._log.info(
                "UPF is already installed to the configured"
                " version on node %s", node_ip)
            self._log.debug("<")
            return True
        self._log.info(
            "UPF is already installed but version\
            configured is not matching on node - %s", node_ip)
        # as of version support is not provided
        # self.uninstall()
        # self.install()
        self._log.debug("<")
        return True

    def install_upf(self, node_ip):
        """ Method install the upf on the given node

        Args:
            node_ip(str): Managament Ip of the node

        Raises:
            InstallFailed: if any exception while installing the upf

        """
        self._log.debug(">")
        try:
            binded = self._check_dpdk_interfaces_bind_status()
        except upf_exception.InstallFailed as ex:
            self._log.debug("Interfaces are not binded to dpdk")
            binded = False
        if binded:
            self._log.debug("Interfaces are already binded to dpdk,"
                            "so unbinding from dpdk and bind to kernal before"
                            " installation")
            pci_addresses = self._get_dpdk_binded_interfaces_pci_address()
            self._bind_interfaces_to_kernal(pci_addresses)

        self._log.debug(
            "Installing UPF APP from repo %s",
            self.get_repository_path(self.app_name))
        extra_vars = {
            'host': node_ip,
            'upf_tar_file': self.get_repository_path(self.app_name)
        }
        tag = {'install-upf'}
        try:
            self._log.info("executing the playbook : install-upf")
            self.get_deployment_mgr_client_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tag)
            pci_addresses, smu_interface = self.bind_interfaces_to_dpdk(node_ip)
            self.configure_dpdk_docker(pci_addresses, smu_interface)
            self.start_upf(node_ip)
            self._log.info(
                "Successfully installed UPF on node - %s", node_ip)
            self._log.debug("<")

        except exception.AnsibleException as ex:
            trace_back = traceback.format_exc()
            error_msg = "Installation failed on node {} - {} TraceBack: {}".\
                format(node_ip, str(ex), trace_back)
            self._log.error(error_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(error_msg)

    def start_upf(self, node_ip):
        """ Method start the UPF on the node

        Args:
            node_ip(str): Managament IP of the node

        """
        self._log.debug(">")
        extra_vars = {
            'host': node_ip
        }
        tag = {'start-upf'}
        self._log.info("executing the playbook : start-upf")
        self.get_deployment_mgr_client_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tag)
        self._check_upf_container_status()
        self._log.debug("<")

    def configure_dpdk_docker(self, pci_addresses, smu_interface):
        """ Method replace the jinja template of the docker file
        and copy the configured file to the upf node

        Args:
            pci_addresses(list): List of the pci addresses
            smu_interface(str): Name of the interface

        Returns:
            None

        """
        self._log.debug(">")
        if self._regal_root_path:
            docker_src_file = AppConstants.K8_SRC_DPDK_DOCKER_FILE
            smu_src_file = AppConstants.K8_SRC_SMU_FILE
        else:
            docker_src_file = AppConstants.SRC_DPDK_DOCKER_FILE
            smu_src_file = AppConstants.SRC_SMU_FILE

        self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self.get_node(), 
                        docker_src_file, AppConstants.DEST_DPDK_DOCKER_FILE, self._get_docker_dpdk_dict(pci_addresses))
        self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self.get_node(), 
                        smu_src_file, AppConstants.DEST_SMU_FILE, self._get_smu_config_dict(smu_interface))
        
        self._log.debug("< ")

    def _get_docker_dpdk_dict(self, pci_addresses):
        """ Private method to get the dpdk configuartion dict

        Args:
            pci_addresses(list): List of the pci address of the dpdk interfaces

        Returns:
            dict: Dictionary of key value pair of pciaddress

        """
        self._log.debug(">")
        dpdk_docker_config = {}
        dpdk_docker_config = {
            "lbu_ext_dev": pci_addresses[0],
            "lbu_int_dev": pci_addresses[1],
            "fbu_dev": pci_addresses[2]
        }
        self._log.debug("<")
        return dpdk_docker_config

    def _get_smu_config_dict(self, smu_interface):
        """ Private method to get the smu config dict

        Args:
            smu_interface(str): Name of the smu interface

        Returns:
            dict: key value pair of the smu interface

        """
        self._log.debug(">")
        smu_config = {}
        smu_config = {
            "smu_interface": smu_interface
        }
        self._log.debug("<")
        return smu_config

    def bind_interfaces_to_dpdk(self, dpdk_interfaces):
        """ Method bind the interfaces to the DPDK

        Args:
            dpdk_interfaces(list): List of the dpdk interfaces

        Returns:
            list, str: List of the pci address and smu interface

        """
        self._log.debug(">")
        dpdk_interfaces, smu_interface = self._get_dpdk_bind_interfaces()
        self._bring_interface_down(dpdk_interfaces)
        pci_addresses = self._get_pci_address_for_interfaces(dpdk_interfaces)
        for pci_address in pci_addresses:
            bind_cmd =  "{} {}".format(AppConstants.DPDK_BIND_CMD, pci_address)
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                    bind_cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)

        self._log.debug("<")
        return pci_addresses, smu_interface

    def _get_pci_address_for_interfaces(self, dpdk_interfaces):
        """ Method get the pci address for the given interfaces

        Args:
            dpdk_interfaces(list): List of the interface names

        Returns:
            list: List of the pci address for given interfaces

        """
        self._log.debug(">")
        pci_address_list = []
        for interface in dpdk_interfaces:
            cmd = "{} -s | grep {} | cut -d ' ' -f 1".format(AppConstants.DPDK_BIND_SCRIPT, interface)
            pci_address = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                    cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
            pci_address_list.append(pci_address.strip())
        self._log.debug("<")
        return pci_address_list

    def _bring_interface_down(self, interfaces):
        """ Method bring down the interfaces

        Args:
            interfaces(str): List of the interface

        Returns:
            None

        """
        self._log.debug(">")
        node_ip = self.get_node().get_management_ip()
        for interface_name in interfaces:
            command = "ifconfig {} down".format(interface_name)
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(
                    command, self.app_name, time_out=Constants.PEXPECT_TIMER)
        self._log.debug("<")

    def _get_dpdk_bind_interfaces(self):
        """ Method get the interfaces that needs to be bind to the dpdk

        Returns:
            list, str: list of dpdk interface and smu interface

        """
        self._log.debug(">")
        os_obj = self.get_node().get_os()
        node_ip = self.get_node().get_management_ip()
        internal_subnet = AppConstants.UPF_INNER_TRAFFIC_SUBNET_NAME
        external_subnet = AppConstants.UPF_EXTERNAL_TRAFFIC_SUBNET_NAME
        interfaces_1 = os_obj.get_interface_name_from_subnet_group(node_ip,
                                                                   external_subnet)
        if not interfaces_1:
            err_msg = "Interface name not forund for the group {} in node "\
                      " {}".format(external_subnet, node_ip)
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(err_msg)

        interfaces_2 = os_obj.get_interface_names_from_subnet_group(node_ip,
                                                                    internal_subnet)
        if not interfaces_2 or len(interfaces_2) != 3:
            err_msg = "Interface names not found for the group {} in node "\
                      " {}, expected interface name count {} found "\
                      " {}".format(internal_subnet, node_ip,
                                   3, interfaces_2)
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.InstallFailed(err_msg)

        smu_interface = interfaces_2.pop(-1)
        interfaces_2.insert(0, interfaces_1)
        self._log.debug("<")
        return interfaces_2, smu_interface

    def stop_upf_server(self):
        """ Method use to stop upf server
        """
        command = "cd {} && {}".format(AppConstants.UPF_SCRIPT_PATH, AppConstants.UPF_SCRIPT)
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(command, self.app_name,
                time_out=Constants.PEXPECT_TIMER)
        self._log.debug("<")

    def cleanup(self):
        """  Method used to unbind the interface from dpdk and bind
        to the kernal

        """
        self._log.debug(">")
        self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
        self.stop_upf_server()
        pci_addresses = self._get_dpdk_binded_interfaces_pci_address()
        self._bind_interfaces_to_kernal(pci_addresses)
        self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
        self._log.debug("<")
        return True

    def _bind_interfaces_to_kernal(self, pci_addresses):
        """ Method bind the interfaces to the dpdk

        Args:
            pci_addresses(str): list of pci address of the dpdk interfaces

        Returns:
            None

        """
        self._log.debug(">")
        for pci_address in pci_addresses:
            command =  "{} {}".format(AppConstants.UNBIND_INTERFACE_CMD, pci_address)
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(command, self.app_name,
                    time_out=Constants.PEXPECT_TIMER)
            command =  "{} {}".format(AppConstants.BIND_TO_KERNAL_CMD, pci_address)
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(command, self.app_name,
                    time_out=Constants.PEXPECT_TIMER)
        self._log.debug("<")

    def _get_dpdk_binded_interfaces_pci_address(self):
        """ Method get the pci address of the dpdk binded interfaces

        Returns:
            list: List of the pci address of the dpdk interfaces

        """
        self._log.debug(">")
        cmd = AppConstants.DPDK_BIND_INTERFACES
        output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                    cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
        if not output:
            self._log.warning("Interfaces are not binded to the dpdk")
            self._log.debug("<")
            return

        data = output.split("\n")
        pci_address = []
        for line in data:
            if AppConstants.BIND_TO_DRIVER in line:
                pci_address.append(line.split(' ')[0])
        self._log.debug("<")
        return pci_address

    def uninstall(self):
        """ Method uninstall the upf application """
        self._log.debug(">")
        try:
            node_ip = self.get_node().get_management_ip()
            pci_addresses = self._get_dpdk_binded_interfaces_pci_address()
            self._bind_interfaces_to_kernal(pci_addresses)
            extra_vars = {
                'host': node_ip,
            }
            tag = {'uninstall-upf'}
            self.get_deployment_mgr_client_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tag)
            self._log.debug("<")
        except exception.AnsibleException as ex:
            trace_back = traceback.format_exc()
            error_msg = "Un-Installation failed on node {} - {} TraceBack: {}".\
                format(node_ip, str(ex), trace_back)
            self._log.error(error_msg)
            self._log.debug("<")
            #raise upf_exception.InstallFailed(error_msg)


class GNodeBApp(UPFAppBase):
    """
    Class implemented for UPF GNodeB plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(GNodeBApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._started = False
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        self.scapy_file_name = AppConstants.GNODEB_SCAPY_FILE
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"


class SMFApp(UPFAppBase):
    """
    Class implemented for UPF SMFApp plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(SMFApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._started = False
        self.scapy_file_name = AppConstants.SMU_SCAPY_FILE
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"


class DataNetworkApp(UPFAppBase):
    """
    Class implemented for UPF DataNetworkApp plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(DataNetworkApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._started = False
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        self.scapy_file_name = AppConstants.DN_SCAPY_FILE
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"
