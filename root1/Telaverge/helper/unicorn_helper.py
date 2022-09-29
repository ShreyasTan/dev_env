"""
Helper plugin for Unicorn app
"""
from Regal.regal_constants import Constants as RegalConstants
from regal_lib.result.statistics_import import StatisticsImport

class UnicornHelper(object):
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
        self._unicorn_app = self._platform.get_app(app_name)
        self.unicorn_stats = StatisticsImport(service_store_obj, node_name)
        self._log.debug("<")

    def apply_configuration(self, stat_args_dict=None):
        """This method sets up the stats"""
        self._log.debug(">")
        self._log.info("Setting up the stats on nodes %s",
                       str(self._node_name))
        if not stat_args_dict:
            stat_args_dict = {}
            stat_args_dict[self._node_name] = self.unicorn_stats.get_stats_argumnts()
        stats_app = self._os.platform.get_app(RegalConstants.STATS_APP_NAME)
        stats_app.apply_configuration(stat_args_dict)
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
        stats_app = self._platform.get_app(RegalConstants.STATS_APP_NAME)
        stats_app.start_service(stats_list)
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
        stats_app = self._platform.get_app(RegalConstants.STATS_APP_NAME)
        stats_app.stop_service(stats_list)
        self._log.debug("<")

    def check_stats(self, stats_list= None):
        """ This method checks the stats service script in the mapped machine.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        if not stats_list:
            stats_list = self.unicorn_stats.get_stats_list()
        stats_app = self._platform.get_app(RegalConstants.STATS_APP_NAME)
        stats_app.check_service_status(stats_list)
        self._log.debug("All stats successfully checked on node %s", str(self._node_name))
        self._log.debug("<")

    def generate_config_dict_from_topology(self):
        """
        Function to generate config_dict.

        Args:
            None.

        Returns:
            config (dict): Dictionary of node IPs and subnets.
        """
        self._log.debug(">")
        config_dict = self._unicorn_app.generate_config_dict_from_topology(
            self._topology)
        self._log.debug("<")
        return config_dict

    def restart_unicorn(self):
        """
        Start the datetime_server application
        Returns(bool):
            ret(bool): True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        self.service_store_obj.get_login_session_mgr_obj().create_session(self._node_obj, 1, tag="restart_unicorn")
        ret  = self._unicorn_app.restart_unicorn_app(tag="restart_unicorn")
        self.service_store_obj.get_login_session_mgr_obj().close_session(tag="restart_unicorn")
        self._log.debug("<")
        return ret

    def set_configuration_for_tc(self, config_dict, test_dict):
        """
        Set configuration for the a particular testcase.
        Args:
            unicorn_server (str): IP address of the assigned Unicorn server
            node.
            test_dict (dict): Dictionary of testcase informations such as SUT
            name, testsuite name and testcase name.

        Returns:
            None.

        """
        self._log.debug(">")
        self._unicorn_app.set_configuration_for_tc(
            config_dict, test_dict)
        self._log.debug("<")

    def get_sut_list(self):
        """
        Method to fetch the list of SUTs in the app.

        Args:
            None.

        Returns:
            ret(list): List of available SUTs.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.get_sut_list()
        self._log.debug("<")
        return status, msg

    def get_ts_list(self, sut_name):
        """
        Method to fetch the list of Testsuites in the specified SUT name.

        Args:
            sut_name (str): Name of the SUT.

        Returns:
            ret(list): List of testsuite in the SUT.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.get_ts_list(sut_name)
        self._log.debug("<")
        return status, msg

    def get_tc_list(self, sut_name, ts_name):
        """
        Method to fetch the list of Testcases in the testsuite of the specified
        SUT.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.

        Returns:
            ret(list): List of testcases in the testsuite of the specified SUT.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.get_tc_list(sut_name, ts_name)
        self._log.debug("<")
        return status, msg

    def start_tc_execution(self, sut_name, ts_name, tc_name):
        """
        Method to start the testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            ret (str): Request's response.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.start_tc_execution(sut_name, ts_name, tc_name)
        self._log.debug("<")
        return status, msg

    def stop_tc_execution(self, sut_name, ts_name, tc_name):
        """
        Method to start the testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            ret(str): Request's response.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.stop_tc_execution(sut_name, ts_name, tc_name)
        self._log.debug("<")
        return status, msg

    def get_tc_exec_status(self, sut_name, ts_name, tc_name):
        """
        Method to fetch the result of testcase execution in the node.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            ret(str): Response result.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.get_tc_exec_status(sut_name, ts_name, tc_name)
        self._log.debug("<")
        return status, msg

    def get_stats(self, sut_name, ts_name, tc_name):
        """
        Method to fetch the client stats.

        Args:
            sut_name (str): Name of the SUT.
            ts_name (str): Name of the Testsuite.
            tc_name (str): Testcase name.

        Returns:
            ret(str): Response result.
        """
        self._log.debug(">")
        status, msg = self._unicorn_app.get_stats(sut_name, ts_name, tc_name)
        self._log.debug("<")
        return status, msg
