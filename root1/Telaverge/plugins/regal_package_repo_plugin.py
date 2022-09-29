"""Repo plugin for Regal package"""

import re

# from regal_controller.regal_controller.utility import GetServiceStore
from regal_lib.repo_manager.repo_plugin_interfaces import RepoPlugin
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants

class RegalPackageRepoPlugin(RepoPlugin):
    '''# Add doc string '''
    _user_string = "Regal_package_repo_plugin"

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

        '''
        self._log.debug(">")
        package_details = {"Name": None, "Version": None, "Type": None}
        if re.search("regal-*", package_name):
            if "dfi" in package_name:
                pkg = re.compile("regal-dfi-suts-v(.*)-x86_64-py2.7.sh")
                res = pkg.match(package_name)
                package_details['Version'] = str(res.group(1))
                package_details['Name'] = "regal-dfi-suts"
                package_details['Type'] = TVConstants.APPLICATION
            elif "diametriq" in package_name:
                pkg = re.compile("regal-diametriq-suts-v(.*)-x86_64-py2.7.sh")
                res = pkg.match(package_name)
                package_details['Version'] = str(res.group(1))
                package_details['Name'] = "regal-diametriq-suts"
                package_details['Type'] = TVConstants.APPLICATION
            elif "netnumber" in package_name:
                pkg = re.compile("regal-netnumber-suts-v(.*)-x86_64-py2.7.sh")
                res = pkg.match(package_name)
                package_details['Version'] = str(res.group(1))
                package_details['Name'] = "regal-netnumber-suts"
                package_details['Type'] = TVConstants.APPLICATION
            elif "regal-regal" in package_name:
                pkg = re.compile("regal-regal-suts-v(.*)-x86_64-py2.7.sh")
                res = pkg.match(package_name)
                package_details['Version'] = str(res.group(1))
                package_details['Name'] = "regal-regal-suts"
                package_details['Type'] = TVConstants.APPLICATION
            elif "telaverge" in package_name:
                pkg = re.compile("regal-telaverge-suts-v(.*)-x86_64-py2.7.sh")
                res = pkg.match(package_name)
                package_details['Version'] = str(res.group(1))
                package_details['Name'] = "regal-telaverge-suts"
                package_details['Type'] = TVConstants.APPLICATION
            else:
                pkg = re.compile("regal-(.*)-x86_64-py2.7.sh")
                res = pkg.match(package_name)
                package_details['Version'] = str(res.group(1))
                package_details['Name'] = "regal_package"
                package_details['Type'] = TVConstants.PLATFORM
        elif re.search("(.*).tar.gz", package_name):
                match = re.search("(.*)-(.*).tar.gz$", package_name)
                package_details["Name"] = match.group(1)
                package_details["Version"] = match.group(2)                  
                package_details['Type'] = TVConstants.APPLICATION

        self._log.debug("<")
        return package_details
