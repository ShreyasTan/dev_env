"""
Helper plugin for Jmeter app
"""
# from regal_lib.result.statistics_import import StatisticsImport
# from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants

class TPTFJmeterHelper(object):
    """
    Class for implementing Jmeter helper functions.
    """
    def __init__(self,service_store_obj, node_name, app_name):
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self._node_name = node_name
        self._stats_mgr = self.service_store_obj.get_stat_mgr_obj()
        self._topology = self.service_store_obj.get_current_run_topology()
        self._node_obj = self._topology.get_node(node_name)
        self._os = self._node_obj.get_os()
        self._platform = self._os.platform
        self._tptf_app = self._platform.get_app(app_name)
        self._log.debug("<")

    def get_tptf_app(self):
        """
        """
        return self._tptf_app

    def get_management_ip(self):
        """
        """
        return self._node_obj.get_management_ip()
