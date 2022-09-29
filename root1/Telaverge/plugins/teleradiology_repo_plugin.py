"""
Repo plugin for Teleradiology App
"""
import re
from distutils.version import LooseVersion

# from regal_controller.regal_controller.utility import GetServiceStore
from regal_lib.repo_manager.repo_plugin_interfaces import RepoPlugin
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants


class TeleradiologyRepoPlugin(RepoPlugin):
    '''# Add doc string '''
    _user_string = "Teleradiology_repo_plugin"

    def __init__(self, service_store_obj):
        self.service_store_obj = service_store_obj
        logger = self.service_store_obj.get_log_mgr_obj()
        self._log = logger.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self._log.debug("<")

    def get_package_details(self, package_name, package_path):
        """This method will extract the Name and Version of the build provided in package_name

        Args:
            package_name (str): File name of the package
            package_path (str): package path

        Returns:
            package_details: dict containing the details of the package
        """
        self._log.debug(">")
        package_details = {"Name": None, "Version": None, "Type": None}

        if re.search("teleradiolgy-react-app-*", package_name):
            _package = re.compile("teleradiolgy-react-app-(.*).tar.gz")
            res = _package.match(package_name)
            package_details['Version'] = str(res.group(1))
            package_details['Name'] = "teleradiolgy-react-app"
            package_details['Type'] = TVConstants.APPLICATION

        elif re.search("keycloak_keycloak-*", package_name):
            _package = re.compile("keycloak_keycloak-(.*).tar.gz")
            res = _package.match(package_name)
            package_details['Version'] = str(res.group(1))
            package_details['Name'] = "keycloak_keycloak"
            package_details['Type'] = TVConstants.APPLICATION
            
        elif re.search("Teleradiology-*", package_name):
            _package = re.compile("Teleradiology_backend-(.*).tar.gz")
            res = _package.match(package_name)
            package_details['Version'] = str(res.group(1))
            package_details['Name'] = "Teleradiology_backend"
            package_details['Type'] = TVConstants.APPLICATION

        self._log.debug("<")
        return package_details
