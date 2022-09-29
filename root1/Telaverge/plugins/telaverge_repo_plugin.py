import re
import os
import tarfile
import sys
import subprocess
from distutils.version import LooseVersion
import zipfile

# from regal_controller.regal_controller.utility import GetServiceStore
from regal_lib.repo_manager.repo_plugin_interfaces import RepoPlugin
from regal_lib.corelib.constants import PackageTypes
import regal_lib.corelib.custom_exception as exception

class TelavergeRepoPlugin(RepoPlugin):
    '''# Add doc string '''
    _user_string = "Telaverge_repo_plugin"

    def __init__(self, service_store_obj):
        self.service_store_obj = service_store_obj
        logger = self.service_store_obj.get_log_mgr_obj()
        self._log = logger.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self._log.debug("<")

    def get_package_details(self, package_name, package_path):
        '''
        This method will extract the Name and Version of the build provided in package_name
        Args:
            package_name(str): File name of the package
            package_path(str): package path

        Returns:
            dict: Name and Version of the package

        '''
        self._log.debug(">")
        package_details = {"Name": None, "Version": None}
        if re.search(".*\.whl$", package_name):
            package_details = self._get_whl_details(package_path)
        elif re.search(".*\.rpm$", package_name):
            package_details = self._get_rpm_details(package_path)
        elif re.search(r".*\.tgz$", package_name):
            if "mme-hss" in package_name:
                match = re.search('mme-hss-(.*).tgz$', package_name)
                if match:
                    package_details["Name"] = "mme-hss"
                    package_details["Version"] =  match.group(1)
                    package_details["Type"] = PackageTypes.USER_DEFINED_TYPE
                    package_details[PackageTypes.USER_DEFINED_TYPE] = "k8HelmCharts"
        self._log.debug("<")
        return package_details

