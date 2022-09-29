"""
App tools for  teleradiology.
"""
import traceback
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants
from regal_lib.product.Regal.apps.appbase import AppBase
import regal_lib.corelib.custom_exception as exception


class TeleRadiologyApp(AppBase):
    """
    Class implemented for teleradiology tools plugin.
    """

    def __init__(self, service_store_obj, name, version):
        super(TeleRadiologyApp, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._log.debug("<")

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
        self._log.debug(">")
        infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
        found_version = self.get_persist_data(
            infra_ref, "found_version", self._sw_type)
        if found_version:
            self.update_persist_data(
                infra_ref, "found_version", None, self._sw_type)
            self._log.debug("<")
            return True
        self._log.debug("<")
        return False

    def install_correct_version(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            bool: return the true or false

        """
        try:
            self._log.debug(">")
            infra_ref = self.service_store_obj.get_current_infra_profile().get_db_infra_profile_obj()
            self._log.debug("The software type is %s", str(self._sw_type))
            host = self.get_node().get_management_ip()
            extra_vars = {'host': host}
            tags = {'install-tele-radiology'}
            self.get_deployment_mgr_client_obj().run_playbook(
            TVConstants.TV_PROD_DIR_NAME, extra_vars, tags)
            self.update_persist_data(
                infra_ref, "found_version", True, self._sw_type)
            self._log.debug("<")
            return True
        except exception.AnsibleException as ex:
            self._log.warning("Exception %s", str(ex))
            self._log.debug("<")
            return False
