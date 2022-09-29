"""
Helper plugin for Teleradiology app
"""

class TeleradiologyHelper(object):
    """
    Class for implementing Teleradiology helper functions.
    """
    def __init__(self,service_store_obj, node_name, app_name):
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self._topology = self.service_store_obj.get_current_run_topology()
        self._node_obj = self._topology.get_node(node_name)
        self.tc_config = self.service_store_obj.get_current_test_case_configuration().get_test_case_config()
        self._log.debug("<")

    def get_url(self):
        """
        Method to fetch the url for Teleradiology UI.

        Args:
            None.

        Returns:
            url(string): URL for Teleradiology UI
        """
        self._log.debug(">")
        node_ip = self._node_obj.get_management_ip()
        port = self.tc_config["Radiology_Credentials"]["Port"]
        url = f"http://{node_ip}:{port}/"
        self._log.debug("<")
        return url