"""
Module with Regal tools
"""
import sys
from version_utils import rpm
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants
from regal_lib.product.Regal.apps.appbase import AppBase
import regal_lib.corelib.custom_exception as exception
from regal_lib.repo_manager.repo_mgr_client import RepoMgrClient


IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    FileExistsErr = OSError
else:
    FileExistsErr = FileExistsError


class RegalTools(AppBase):
    """
    Class consists of functions necessary to perform product package related
    operations.
    """

    def __init__(self, service_store_obj, name, version):
        """
        Initializes logger object

        Args:
            name(str): Name of the App
            version(str): Versin of the app
        """
        super(RegalTools, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self.repo_mgr_client_obj = RepoMgrClient(self.service_store_obj)

        self._found_version = None
        self.version_list = []

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
            if "netnumber" in self._name:
                installed_app_name = "netnumber"
            elif "diametriq" in self._name:
                installed_app_name = "diametriq"
            elif "dfi" in self._name:
                installed_app_name = "dfi"
            elif "regal-regal" in self._name:
                installed_app_name = "regal-regal"
            elif "telaverge" in self._name:
                installed_app_name = "telaverge"
            else:
                raise exception.ProductNotPresent(self._name)
            cmd = "rpm -qa | grep {}".format(installed_app_name)
            self._log.debug("App match host is %s", str(host))
            self._log.debug("App match Command is %s", str(cmd))
            hosts = [host]
            package_info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
                cmd, hosts)
            info = package_info.split("\n")
            for each_product_info in info:
                sys_package = rpm.package(each_product_info)
                self._found_version = sys_package.version
                if self._found_version not in self.version_list:
                    self.version_list.append(self._found_version)
                    self._log.debug(
                        "Information derived from \"%s\" node is \"%s\"", str(host), package_info)
            if self._version in self.version_list:
                return True
            self._log.warning(
                "App %s not found, found versions:%s", self._version, self.version_list)
            return False
        except exception.AnsibleException as ex:
            self._log.warning("App not installed")
            return False

    def install_correct_version(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            bool: since default app, always returns true.

        """
        try:
            if not self.version_list:
                self._log.debug(
                    "app not found, performing fresh installation")
                self.install(self._name, self._version)
                return True

            if self._version in self.version_list:
                self._log.debug(
                    "app %s-%s already installed", self._name, self._version)
                return True

            self.version_list.sort()
            if self._version < self.version_list[0]:
                for each_version in self.version_list:
                    self._log.debug(
                        "Higher version(%s) of app found, uninstalling this app version",
                        each_version)
                    self.uninstall(self._name, each_version)
                self._log.debug(
                    "Downgrading to version(%s) of app", self._version)
                self.install(self._name, self._version)
                return True

            elif self._version > self.version_list[-1]:
                self._log.debug(
                    "Upgrading to version(%s) of app", self._version)
                self.install(self._name, self._version)
                return True

            else:
                for each_version in self.version_list:
                    if self._version < each_version:
                        self._log.debug(
                            "Higher version(%s) of app found, uninstalling this app version",
                            each_version)
                        self.uninstall(self._name, each_version)
                    else:
                        self._log.debug(
                            "Lower version(%s) of app found, uninstalling this app version",
                            each_version)
                        self.uninstall(self._name, each_version)
                self._log.debug("Installing version(%s) of app", self._version)
                self.install(self._name, self._version)
                return True

        except (exception.AnsibleException, exception.BuildNotFoundInRepo) as ex:
            self._log.warning("Exception %s", str(ex))
            return False

    def install(self, name, version):
        """
        Method for installing a product package in the Regal installed on the
        host node.
        Returns:
            None
        """
        self._log.debug(">")
        self._log.debug("Stopping Regal service")
        self._log.debug("Installing product %s", name)
        self.install_product(name, version)
        self._log.info("Successfully installed the product %s", name)
        self._log.debug("Starting Regal service")
        self._log.debug("<")

    def uninstall(self, name, version):
        """
        Method to uninstall the product package present in the host node.
        Returns:
            None
        """
        self._log.debug(">")
        self._log.debug("Stopping Regal service")
        self._log.debug("Uninstalling %s-%s", name, version)

        if "netnumber" in name:
            name = "netnumber"
        elif "diametriq" in name:
            name = "diametriq"
        elif "dfi" in name:
            name = "dfi"
        elif "regal-regal" in name:
            name = "regal-regal"
        elif "telaverge" in name:
            name = "telaverge"
        else:
            raise exception.ProductNotPresent(name)
        self.uninstall_product(name, version)
        self.remove_all_repo_packages_of_product(name)
        self._log.info("Successfully uninstalled the product %s", str(name))
        self._log.debug("Starting Regal service")
        self._log.debug("<")

    def install_product(self, product, prod_version):
        """
        Method to install product package in the installed Regal.

        Args:
            product(str): Name of the product
            prod_version(str): Version of the product

        Returns:
            None
        """
        self._log.debug("Installing %s", product)
        prod_path = self.repo_mgr_client_obj.get_repo_path(
            product, prod_version)
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host, 'rep_path': prod_path}
        tags = {'install-product'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully installed the product %s", str(product))

    def uninstall_product(self, product, version):
        """
        Method to uninstall the product in Regal.

        Args:
            product(str): Name of the product

        Returns:
            None
        """
        self._log.debug("Uninstalling %s", product)
        product = product.lower()
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host, 'prod_name': product,
                      'prod_version': version}
        tags = {'uninstall-product'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully uninstalled the application %s",
                       str(product))

    def add_repo_package(self, product, package, packg_version):
        """
        Method to add repo packages for a particular product.

        Args:
            product(str): Name of the product
            package(str): Name of the package
            packg_version(str): Version of the specified package

        Returns:
            None
        """
        host = self.get_node().get_management_ip()
        packg_path = self.repo_mgr_client_obj.get_repo_path(package,
                                                            packg_version)
        self._log.debug("Adding %s from repo %s", package, packg_path)
        extra_vars = {'host': host,
                      'rep_path': packg_path, 'prod_name': product}
        tags = {'add-repo-package'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info("Successfully added the application %s", str(package))

    def remove_all_repo_packages_of_product(self, product):
        """
        Method to remove repo packages for a particular product.

        Args:
            product(str): Name of the product

        Returns:
            None
        """
        self._log.debug("Removing %s repo packages", product)
        host = self.get_node().get_management_ip()
        extra_vars = {'host': host, 'prod_name': product}
        tags = {'remove-repo-packages'}
        self.get_deployment_mgr_client_wrapper_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
        self._log.info(
            "Successfully removed repo packages for %s", str(product))
