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

class UDMUDRAppBase(AppBase):
    """
    Class implemented for CommonAppBase plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UDMUDRAppBase, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self.app_name = name
        self.app_version = version
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        if self._regal_root_path:
            self.regal_path = {"regal_root_path": self._regal_root_path}
            self.root_path = self._regal_root_path
        else:
            self.regal_path = {"regal_root_path": "./regal_lib"}
            self.root_path = "./regal_lib"
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

    def check_java_is_installed(self):
        """
        """
        self._log.debug(">")
        cmd = "java -version"
        output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                    cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
        if "build 11.0.16.1+1-LTS" not in str(output):
            err_msg = "java is not installed"
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        self._log.debug("<")
        return True

    def check_service_status(self, service_name):
        """This method is used to check if app version is matching in INITIALIZING state

        Args:
            host(str): ip_address of the machine

        Returns:
            bool: True = If service is up.
        
        Raise:
            raise exception when service is not running
        """
        self._log.debug(">")
        cmd = "systemctl status {}".format(service_name)
        output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                    cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
        if "active (running)" not in output:
            err_msg = "{} service not running".format(service_name)
            self._log.warning(err_msg)
            self._log.debug("<")
            raise upf_exception.ServiceNotRunning(err_msg)
        self._log.debug("<")
        return True

    def install_app(self, service_name):
        """
        """
        self._log.debug(">")
        tar_file_path = self.get_repository_path(self.app_name)
        dir_path = "/home/telaverge/{}/".format(service_name)
        cmd = "mkdir {}".format(dir_path)
        #creare directory
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(cmd, self.app_name, 
                    time_out=UPFConstants.PEXPECT_TIMER)
        #copy tar file
        self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(self.get_node(), tar_file_path, dir_path)
        #untar file
        tar_file_name = tar_file_path.split("/")
        cmd = "cd {}; tar -xf {}".format(dir_path, tar_file_name[-1])
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(cmd, self.app_name, 
                    time_out=UPFConstants.PEXPECT_TIMER)
        #copy_service_file
        service_file_path = Utility.join_path(self.root_path, UPFConstants.SERVICE_FILE)
        self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self.get_node(), service_file_path,  
                UPFConstants.DEST_PATH_FOR_SERVICE + service_name + ".service", {"service_name": service_name})
        #enable service
        cmd = "systemctl enable {}".format(service_name)
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(cmd, self.app_name, 
                    time_out=UPFConstants.PEXPECT_TIMER)
        #reload system
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(UPFConstants.RELOAD_SYSTEM, self.app_name, 
                    time_out=UPFConstants.PEXPECT_TIMER)
        #start service
        cmd = "systemctl start {}".format(service_name)
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(cmd, self.app_name, 
                    time_out=UPFConstants.PEXPECT_TIMER)
        cmd = "systemctl status {}".format(service_name)
        output = \
            self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                    cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
        if "active (running)" not in output:
            err_msg = "Unable to start services {}".format(service_name)
            self._log.warning(err_msg)
            self._log.debug("<")
            raise upf_exception.FailedToStartService(err_msg)
        self._log.debug("<")

class RealSMFApp(UDMUDRAppBase):
    """
    Class implemented for RealSMFApp plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(RealSMFApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self.app_name = name
        self.app_version = version
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
            self.update_persist_data(infra_ref, "file_exist", None, self._sw_type)
            self.check_files_are_exist()
            self.update_persist_data(infra_ref, "file_exist", True, self._sw_type)
            self._log.debug("<")
            return True
        except upf_exception.FileDoesNotExist as ex:
            trace_back = traceback.format_exc()
            err_msg = "SMF is not Installed {}: Trace Back: {}".format(
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

    def check_files_are_exist(self):
        """This method is used to check files are exist/not .

        Args:
            host(str): ip_address of the machine

        Returns:
            None

        Exception:
            raise excpetion when file does not exist."
        """
        self._log.debug(">")
        for file in UPFConstants.FILES:
            cmd = "test -f ..{} && echo '$FILE exists.'".format(file)
            self._log.debug(" command %s", cmd)
            output = \
                self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                        cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
            if "exists" not in output:
                err_msg = "{} File does not exist".format(file)
                self._log.debug(" file status %s", err_msg)
                self._log.warning(err_msg)
                self._log.debug("<")
                raise upf_exception.FileDoesNotExist(err_msg)
        self._log.debug("<")

    def install_correct_version(self):
        """ Method install in the correct version of the UPF

        Returns:
            bool: True if installation of smf is success viceversa.

        """
        self._log.debug(">")
        try:
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            smf_installed = self.get_persist_data(
                infra_ref, "file_exist", self._sw_type)
            if not smf_installed:
                self.install_smf_app()
                self._log.debug("<")
            self._log.debug("<")
            return True
        except Exception as ex:
            self._log.debug("< %s", str(ex))
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

    def install_smf_app(self):
        """ Method to install SMF application
        """
        self._log.debug(">")
        remote_src_path =  self.get_repository_path(self.app_name)
        self._log.debug("< %s", str(remote_src_path))
        self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(self.get_node(),
                                remote_src_path, "/")
        tar_file_name = remote_src_path.split('/')
        cmd = "cd ..; gunzip -c ../{} | tar -xvf -".format(tar_file_name[-1])
        self._log.debug("< %s", str(cmd))
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(cmd, self.app_name, 
                    time_out=UPFConstants.PEXPECT_TIMER)
        self._log.debug("<")

class UDRPApp(UDMUDRAppBase):
    """
    Class implemented for RealSMFApp plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UDRPApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self.app_name = name
        self.app_version = version
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
            #check_java_is_installed
            self.update_persist_data(infra_ref, "java_installed", None, "java")
            status = self.check_java_is_installed()
            self.update_persist_data(infra_ref, "java_installed", status, "java")
            #check_mongo_status
            self.update_persist_data(infra_ref, "mongo_installed", None, UPFConstants.MONGO)
            self.check_service_status(UPFConstants.MONGO)
            self.update_persist_data(infra_ref, "mongo_installed", True, UPFConstants.MONGO)
            #check_udrp_status
            self.update_persist_data(infra_ref, "udrp_installed", None, self._sw_type)
            self.check_service_status(UPFConstants.UDRP)
            self.update_persist_data(infra_ref, "udrp_installed", True, self._sw_type)
            self._log.debug("<")
            return True
        except upf_exception.ServiceNotRunning as ex:
            trace_back = traceback.format_exc()
            err_msg = "{} is not Installed {}: Trace Back: {}".format(UPFConstants.UDRP,
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

    def install_correct_version(self):
        """ Method install in the correct version of the UPF

        Returns:
            bool: True if installation of smf is success viceversa.

        """
        try:
            self._log.debug(">")
            node_ip = self.get_node().get_management_ip()
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            java_installed = self.get_persist_data(
                infra_ref, "java_installed", "java")
            if not java_installed:
                error_mag = "Deployment Failed on node {}, doesn't have java".format(
                    node_ip)
                self._log.error(error_mag)
                self._log.debug("<")
                return False
            mongo_installed = self.get_persist_data(
                infra_ref, "mongo_installed", UPFConstants.MONGO)
            if not mongo_installed:
                self.install_mongo(node_ip)
                self._log.debug("<")
            udrp_installed = self.get_persist_data(
                infra_ref, "udrp_installed", self._sw_type)
            if not udrp_installed:
                self.install_app(UPFConstants.UDRP)
                self._log.debug("<")
            return True
        except upf_exception.FailedToStartService as ex:
            trace_back = traceback.format_exc()
            err_msg = "{} Installation failed {}: Trace Back: {}".format(UPFConstants.UDRP,
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

    def install_mongo(self, node_ip):
        """ Method to install mongo db
        """
        self._log.debug(">")
        extra_vars = {
            'host': node_ip,
            'mongo_repo_file': Utility.join_path(self.root_path, UPFConstants.MONGO_FILE_PATH),
            "destination_path": UPFConstants.MONGO_DEST_PATH,
            "service":UPFConstants.MONGO,
            "operation":UPFConstants.ACTION_STARTED
        }
        self._log.debug("> extra_vars  %s", str(extra_vars))
        self._log.debug("> root_path %s", str(self.root_path))
        tag = {'install-mongo'}
        self._log.info("executing the playbook : install-mongo")
        self.get_deployment_mgr_client_obj().run_playbook(
           TVConstants.TV_PROD_DIR_NAME, extra_vars, tag)
        self._log.debug("<")

class UDRApp(UDMUDRAppBase):
    """
    Class implemented for RealSMFApp plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UDRApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self.app_name = name
        self.app_version = version
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
            #check_udr_status
            self.update_persist_data(infra_ref, "udr_installed", None, self._sw_type)
            self.check_service_status(UPFConstants.UDR)
            self.update_persist_data(infra_ref, "udr_installed", True, self._sw_type)
            self._log.debug("<")
            return True
        except upf_exception.ServiceNotRunning as ex:
            trace_back = traceback.format_exc()
            err_msg = "{} is not Installed {}: Trace Back: {}".format(UPFConstants.UDR,
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

    def install_correct_version(self):
        """ Method install in the correct version of the UPF

        Returns:
            bool: True if installation of smf is success viceversa.

        """
        try:
            self._log.debug(">")
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            udrp_installed = self.get_persist_data(
                infra_ref, "udr_installed", UPFConstants.UDR)
            if not udrp_installed:
                self.install_app(UPFConstants.UDR)
                self._log.debug("<")
                return True
        except upf_exception.FailedToStartService as ex:
            trace_back = traceback.format_exc()
            err_msg = "{} Installation failed {}: Trace Back: {}".format(UPFConstants.UDR,
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

class UDMApp(UDMUDRAppBase):
    """
    Class implemented for UDMApp plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(UDMApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self.app_name = name
        self.app_version = version
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
            #check_java_is_installed
            self.update_persist_data(infra_ref, "java_installed", None, "java")
            status = self.check_java_is_installed()
            self.update_persist_data(infra_ref, "java_installed", status, "java")
            #check_udm_status
            self.update_persist_data(infra_ref, "udm_installed", None, self._sw_type)
            self.check_service_status(UPFConstants.UDM)
            self.update_persist_data(infra_ref, "udm_installed", True, self._sw_type)
            self._log.debug("<")
            return True
        except upf_exception.ServiceNotRunning as ex:
            trace_back = traceback.format_exc()
            err_msg = "{} is not Installed {}: Trace Back: {}".format(UPFConstants.UDM,
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")

    def install_correct_version(self):
        """ Method install in the correct version of the UPF

        Returns:
            bool: True if installation of UDM is success viceversa.

        """
        try:
            self._log.debug(">")
            node_ip = self.get_node().get_management_ip()
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            java_installed = self.get_persist_data(
                infra_ref, "java_installed", "java")
            if not java_installed:
                error_mag = "Deployment Failed on node {}, doesn't have java".format(
                    node_ip)
                self._log.error(error_mag)
                self._log.debug("<")
                return False
            udrp_installed = self.get_persist_data(
                infra_ref, "udm_installed", UPFConstants.UDM)
            if not udrp_installed:
                self.install_app(UPFConstants.UDM)
                self._log.debug("<")
            return True
        except upf_exception.FailedToStartService as ex:
            trace_back = traceback.format_exc()
            err_msg = "{} Installation failed {}: Trace Back: {}".format(UPFConstants.UDM,
                ex, trace_back)
            self._log.warning(err_msg)
            self._log.debug("<")
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)
            self._log.debug("<")