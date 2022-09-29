"""
Helper plugin for Unicorn app
"""
from regal_lib.result.statistics_import import StatisticsImport
from regal_lib.product.Telaverge.telaverge_constans import Constants as TVConstants

class TPTFUnicornHelper(object):
    """
    Class for implementing Unicorn helper functions.
    """
    def __init__(self,service_store_obj, node_name, app_name):
        #super(UnicornHelper, self).__init__(service_store_obj, node_name, app_name)
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
        self.unicorn_stats = StatisticsImport(service_store_obj, node_name)
        self._log.debug("<")

    def get_tptf_app(self):
        """ Method return the TPTF application Object

        Returns:
            Object: Instance of the TPTF App

        """
        return self._tptf_app

    def get_management_ip(self):
        """ Method return the management of the node

        Retuns:
            str: Management ip of the node

        """
        return self._node_obj.get_management_ip()

    def setup_stats(self, stat_args_dict=None):
        """This method sets up the stats"""
        self._log.debug(">")
        self._log.info("Setting up the stats on nodes %s",
                       str(self._node_name))
        if not stat_args_dict:
            stat_args_dict = {}
            stat_args_dict[self._node_name] = self.unicorn_stats.get_stats_argumnts()
        self._stats_mgr.install_stats_tarfile(stat_args_dict)
        self._log.info("Set up the stats on nodes %s is successful.",
                       str(self._node_name))
        self._log.debug("<")

    def start_stats(self, stats_list=None):
        """ This method starts the stats service script in the mapped machine.

        Returns:
            None

        """
        self._log.debug(">")
        if not stats_list:
            stats_list = self.unicorn_stats.get_stats_list()
        self._stats_mgr.start_services(
            self._node_obj.get_management_ip(), stats_list)
        self._log.info("Started the stats successfully on nodes %s",
                       str(self._node_name))
        self._log.debug("<")

    def stop_stats(self, stats_list= None):
        """ this method stops the stats service script in the mapped machine.

        returns:
            none

        """
        self._log.debug(">")
        if not stats_list:
            stats_list = self.unicorn_stats.get_stats_list()
        self._stats_mgr.stop_services(
            self._node_obj.get_management_ip(), stats_list)
        self._log.debug("<")

    def restart_unicorn(self):
        """
        Start the datetime_server application
        Returns(bool):
            ret(bool): True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        host = self._node_obj.get_management_ip()
        extra_vars = {'host': host}
        tags = {'restart-unicorn'}
        self._tptf_app.get_deployment_mgr_client_wrapper_obj().run_playbook(TVConstants.TV_PROD_DIR_NAME, extra_vars,
                                                    tags)
        self._log.info("Successfully restarted the application unicorn on %s",
                       str(host))
        self._log.debug("<")
        return True
