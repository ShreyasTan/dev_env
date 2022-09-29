"""OS Base module for Regal"""
from regal_lib.product.Regal.OS.centos import CentOSBase
import regal_lib.corelib.custom_exception as exception
from regal_lib.corelib.common_utility import Utility
from regal_lib.corelib.constants import Constants

#from regal.constants import Constants
#from regal.utility import GetRegal
#import regal.custom_exception as exception
#from Regal.OS.centos import CentOSBase


class RegalOSBase(CentOSBase):
    """
    This class consists of functions that verify and validates the OS and
    required libraries of a machine before assigning it for Regal package
    installation.
    """

    def __init__(self, service_store_obj, name, version):
        """
        Initializes parent class CentOSBase.

        Args:
            name(str): Name of the os
            version(str): Version of the OS
        """
        super(RegalOSBase, self).__init__(service_store_obj, name, version)
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self.common_db_util_obj = self.service_store_obj.get_common_db_util_obj()
        self._found_version = None

    # def os_match(self, host):
    #     """This method is used to check if os version is matching in INITIALIZING state

    #     Args:
    #         host(str): ip_address of the machine

    #     Returns:
    #         True or False

    #     Raises:
    #         exception.NotImplemented
    #         :param host:
    #     """
    #     try:
    #         hosts = [host]
    #         machine_name = self.get_machine_name_from_ip(host)
    #         db_machine_objs = self.common_db_util_obj.get_machine_objs(machine_name)
    #         db_machine_obj = db_machine_objs[0]
    #         #machine_info = db_machine_obj.to_dict()
    #         #db_machine_ref = machine_info['credential']['machine_name']
    #         #db_machine_ref = db_machine_obj.machineName
    #         #db_machine_ref = GetRegal().GetMachinePoolMgr().get_machines()[machine_name]
    #         db_machine_ref = db_machine_obj
    #         info = db_machine_ref.get_os_info(self._classname)
    #         if info is None:
    #             try:
    #                 info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
    #                     'head -n 1 /extras/release', hosts)
    #                 db_machine_ref.set_os_info(info, self._classname)
    #             except exception.AnsibleException:
    #                 pass
    #             info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
    #                 "head -n 1 /etc/redhat-release", hosts)
    #             db_machine_ref.set_os_info(info, self._classname)
    #         self._log.debug("Information fetched from the node %s is %s", str(host), str(info))
    #         self._found_version = info
    #         self._log.debug("Expected version of %s is %s", str(self._name), str(self._version))
    #         if self._version in info:
    #             return True

    #         return False
    #     except (exception.InvalidConfiguration, exception.IndeterminateException,
    #             exception.MachineNotFound, exception.AnsibleException) as ex:
    #         self._found_version = None
    #         self.update_state_info(Constants.NOT_FOUND)
    #         self._log.warning("Exception catch at the centos %s", str(ex))
    #         self._log.debug("<")
    #         return False

    def os_package_match(self, host):
        """
        This method checks for the required packages in a particular node.

        Args:
            host(str): IP of the node

        Returns:
            bool: True/False
        """
        try:
            self._log.debug(">")
            hosts = [host]
            rpm = ["gcc", "gcc-c++", "mongodb-org", "nodejs-10.18.1",
                   "java-1.8.0-openjdk", "libselinux", "libvirt", "libvirt-devel"]
            match = True
            for i in rpm:
                cmd = "rpm -qa | grep {}".format(i)
                info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(cmd, hosts)
                if info:
                    self._log.debug("rpm \"%s\" is installed", i)
            self._log.debug("Verifying Helm")
            try:
                helm_cmd = "helm version"
                info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
                    helm_cmd, hosts)
                if info:
                    self._log.debug("Helm is installed")
            except exception.AnsibleException as ex:
                self._log.warning("Helm is not installed ")
                return False
            return match
        except exception.AnsibleException as ex:
            self._log.warning("Exception %s rpm is not installed ", i)
            return False

    def package_correction(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            bool: True or False

        """
        return False
