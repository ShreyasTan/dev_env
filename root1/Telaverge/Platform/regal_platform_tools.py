"""
Module with Regal Platform tools
"""
import sys
import json
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants
from regal_lib.product.Regal.regal_constants import Constants as RegalConstants
from regal_lib.product.Regal.Platform.platformbase import PlatformBase
import regal_lib.corelib.custom_exception as exception
from regal_lib.corelib.common_utility import Utility
from regal_lib.repo_manager.repo_mgr_client import RepoMgrClient

#from regal_controller.regal_controller.repo_manager.repo_manager import RepoMgr

#from regal.utility import GetRegal
#import regal.logger.logger as logger
#import regal.custom_exception as exception
#from Telaverge.telaverge_constans import Constants as TVConstants
#from Regal.regal_constants import Constants as RegalConstants
#from Regal.Platform.platformbase import PlatformBase

IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    FileExistsErr = OSError
else:
    FileExistsErr = FileExistsError

class RegalPlatformTools(PlatformBase):
    """
    Class consists of functions necessary to perform Regal package related
    operations.
    """
    def __init__(self,service_store_obj, name, version):
        """
        Initializes logger object

        Args:
            name(str): Name of the Platform
            version(str): Version of the Platform
        """
        super(RegalPlatformTools, self).__init__(service_store_obj,name, version)
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self.repo_mgr_client_obj =  RepoMgrClient(self.service_store_obj)
        self._found_version = None

    def platform_match(self, host):
        """This method is used to check if platform version is matching in INITIALIZING state

        Args:
            host(str): ip_address of the machine

        Returns:
            bool: since default platform, always returns true.

        Raises:
            exception.NotImplemented
            :param host:
        """
        try:
            cmd = "cat /opt/regal/config/regal_version.json"
            self._log.debug("Platform match host is %s", str(host))
            self._log.debug("Platform match Command is %s", str(cmd))
            hosts = [host]
            info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(cmd, hosts)
            version_json = json.loads(info)
            self._log.debug(
                "Information derived from the \"%s\" node is \"%s\"", str(host), info)
            self._found_version = "{}.{}.{}.{}".format(
                version_json["REGAL_MAJOR"], version_json["REGAL_MINOR"],
                version_json["REGAL_RELEASE"], version_json["REGAL_PATCH"])
            if self._version == self._found_version:
                return True
            self._log.warning(
                "Platform %s not found, found version:%s", self._version, self._found_version)
            return False
        except exception.AnsibleException as ex:
            self._log.warning("Platform not installed")
            return False

    def install_correct_version(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            bool: since default platform, always returns true.

        """
        try:
            if self._found_version is None:
                self._log.debug(
                    "platform not found, performing fresh installation")
                self.install()
                return True

            elif self._found_version == self._version:
                self._log.debug(
                    "platform %s-%s already installed", self.name, self._version)
                return True

            elif self._found_version > self._version:
                self._log.debug(
                    "Higher version(%s) of platform found, downgrading to version %s",
                    self._found_version, self._version)
                self.stop_regal()
                self.uninstall()
                self.install()
                return True

            elif self._found_version < self._version:
                self._log.debug(
                    "Lower version(%s) of platform found, upgrading to version %s",
                    self._found_version, self._version)
                self.stop_regal()
                self.install()
                return True
        except (exception.AnsibleException, exception.BuildNotFoundInRepo) as ex:
            self._log.warning("Exception %s", str(ex))
            return False

    def install_dependencies(self, version):
        """
        Method for installing dependency before Regal installation.

        Returns:
            None
        """
        host = self.get_node().get_management_ip()
        node_name = self.get_node().get_name()
        if version == 'python2':
            rpm_urls = []
            rpm_urls.append(self.repo_mgr_client_obj.get_repo_path('python2-pip'))
            rpm_urls.append(self.repo_mgr_client_obj.get_repo_path('dpkg'))
            rpm_urls.append(self.repo_mgr_client_obj.get_repo_path('python-devel'))
            extra_vars = {
                'host': host,
                'src_path': rpm_urls
            }
            tags = {'install-rpm'}
            self.get_deployment_mgr_client_wrapper_obj().run_playbook(RegalConstants.REGAL_PROD_DIR_NAME,
                                                     extra_vars, tags)
        else:
            raise exception.PythonVersionNotSupported(host, node_name, version)
        #repo_mgr = RepoMgr()
        dependency_files = []
        dependency_files.append(
            self.repo_mgr_client_obj.get_repo_path("packaging"))
        extra_vars = {
            'host': host,
            'source_path': dependency_files
        }
        tags = {'install-python-dependencies'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(RegalConstants.REGAL_PROD_DIR_NAME,
                                                 extra_vars, tags)

    def _get_python_version(self, host):
        """This method return the version of the python installed in given host.

        Args:
            host(str): ipaddress of the machine

        Returns:
            str: Version of the python.

        """
        info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
            "python -c 'import sys; print((sys.version_info)<(3,0))'", host)
        if info == "False":
            return 'python3'
        return 'python2'

    def install(self):
        """
        Method to install Regal package in the host node.

        Returns:
            None
        """
        self._log.debug("Installing %s from repo %s", self._name, self.get_repo_path())
        host = self.get_node().get_management_ip()
        version = self._get_python_version(host)
        self.install_dependencies(version)
        extra_vars = {'host': host, 'rep_path': self.get_repo_path()}
        tags = {'install-regal'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully installed the platform %s", str(self._name))

    def uninstall(self):
        """
        Method to uninstall the Regal package present in the host node.

        Returns:
            None
        """
        self._log.debug("Uninstalling %s-%s", self._name, self._found_version)
        self.stop_regal()
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host}
        tags = {'uninstall-regal'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully uninstalled the platform %s", str(self._name))

    def start_regal(self):
        """
        Method to start Regal service.

        Returns:
            None
        """
        self._log.debug("Starting Regal service")
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host}
        tags = {'start-regal'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully started the platform %s", str(self._name))

    def stop_regal(self):
        """
        Method to stop Regal service.

        Returns:
            None
        """
        self._log.debug("Stopping the Regal service")
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host}
        tags = {'stop-regal'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully stopped the platform %s", str(self._name))

    def restart_regal(self):
        """
        Method to restart Regal service.

        Returns:
            None
        """
        self._log.debug("Restarting the Regal service")
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host}
        tags = {'restart-regal'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars,
                                    tags)
        self._log.info("Successfully stopped the platform %s",
                       str(self._name))

    def update_configuration(self, config_file, config):
        """
        Method to update a configuration file in Regal.

        Args:
            config_file(str): Name of the config file
            config(dict): Configuration data

        Returns:
            None
        """
        self._log.debug("Updating configuration")
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host, 'file_name': config_file, 'data': config}
        tags = {'update-configuration'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully updated configuration")
