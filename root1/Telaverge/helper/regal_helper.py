"""Helper plugin for Regal package"""

#from regal.utility import GetRegal
#import regal.custom_exception as exception
#import regal.logger.logger as logger
from regal_lib.corelib.common_utility import Utility
import regal_lib.corelib.custom_exception as exception
from regal_lib.client.deployment_mgr.deployment_mgr_client.deployment_mgr_client import DeploymentMgrClient


class Constants(object):
    """This class define all constants used for Regal"""
    DFI = "DFI"
    DIAMETRIQ = "Diametriq"
    NETNUMBER = "NetNumber"
    REGAL = "Regal"
    TELAVERGE = "Telaverge"
    HYPERVISOR_CONF_FILE = "hypervisor_config.json"
    UIA_CONF_FILE = "uia_config.json"


class RegalHelper(object):
    """
    Class consists of helper functions that'll be necessary for handling Regal
    package related operations.
    """
    def __init__(self,service_store_obj,name, node_name, app_name):
        """
        Initializes RegalTools object.

        Args:
            node_name(str): Name of the node
            platform_name(str): Name of the platform
        """
        super(RegalHelper, self).__init__(service_store_obj,name, node_name, app_name)
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self.deployment_mgr_client_obj = DeploymentMgrClient(self.service_store_obj)
        self._log.debug(">")
        self._node_name = node_name
        self._topology = GetRegal().GetCurrentRunTopology()#============
        self._node_obj = self._topology.get_node(node_name)
        self._os = self._node_obj.get_os()
        self._platform = self._os.platform
        self._regal_app = self._platform.get_app(app_name)
        self._regal_platform = self._platform.get_app(app_name)
        self._log.debug("<")

    def start_regal(self):
        """
        Method for starting Regal platform in host node.

        Returns:
            None
        """
        self._log.debug(">")
        self._regal_platform.start_regal()
        self._log.debug("<")

    def stop_regal(self):
        """
        Method for stopping Regal platform in the host node.

        Returns:
            None
        """
        self._log.debug(">")
        self._regal_platform.stop_regal()
        self._log.debug("<")

    def restart_regal(self):
        """
        Method for restarting Regal platform in host node.

        Returns:
            None
        """
        self._log.debug(">")
        self._regal_platform.restart_regal()
        self._log.debug("<")

    def add_repo_packages(self, product, packages):
        """
        Method copies the specified packages to Regal which is installed in the
        host node.

        Args:
            product(str): Name of the product to which the packages belong
            packages(dict): A dictionary of package and its specific version

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Adding packages: {}".format(packages.keys()))
        for package, version in packages.items():
            self._regal_app.add_repo_package(product, package, version)
        self._regal_platform.restart_regal()
        self._log.debug("<")

    def remove_repo_packages(self, product):
        """
        Method to remove repo packages for a product present in Regal.

        Args:
            product(str): Name of the product

        Returns:
            None
        """
        self._log.debug(">")
        self._regal_app.remove_all_repo_packages_of_product(
            product)
        self._regal_platform.restart_regal()
        self._log.info("Successfully removed product %s repo", product)
        self._log.debug("<")

    def update_configuration(self, config_file, config):
        """
        Method to update a configuration file in Regal.

        Args:
            config_file(str): Name of the configuration file
            config(dict): Configuration data

        Returns:
            None
        """
        self._log.debug(">")
        self._regal_platform.update_configuration(config_file, config)
        self._regal_platform.restart_regal()
        self._log.info("Successfully updated %s", config_file)
        self._log.debug("<")

    def check_gui_is_running(self):
        """
        Method to validate Regal GUI service state.

        Returns:
            None
        """
        self._log.debug(">")
        cmd = "systemctl status regalgui"
        hosts = [self._node_obj.get_management_ip()]
        info = self.deployment_mgr_client_obj.execute_shell(cmd, hosts)
        if "running" not in info:
            self._log.debug("<")
            return False
        self._log.debug("<")
        return True

    def check_regal_is_running(self):
        """
        Method to validate Regal service state.

        Returns:
            None
        """
        self._log.debug(">")
        cmd = "systemctl status regal"
        hosts = [self._node_obj.get_management_ip()]
        info = self.deployment_mgr_client_obj.execute_shell(cmd, hosts)
        if "running" not in info:
            self._log.debug("<")
            return False
        self._log.debug("<")
        return True
