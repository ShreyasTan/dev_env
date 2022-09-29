from regal_lib.result.statistics_import import StatisticsImport
from Regal.regal_constants import Constants as RegalConstants


class DateTimeHelper(object):
    def __init__(self, service_store_obj, node_name, app_name):
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger(class_name)
        self._log.debug(">")
        self._node_name = node_name
        self._stats_mgr = self.service_store_obj.get_stat_mgr_obj()
        self._topology = self.service_store_obj.get_current_run_topology()
        self._node_obj = self._topology.get_node(node_name)
        self._os = self._node_obj.get_os()
        self._platform = self._os.platform
        self._datetime_server_app = self._platform.get_app(app_name)
        self.date_time = StatisticsImport(self.service_store_obj, node_name)
        self.service_store_obj.get_login_session_mgr_obj().create_session(self._node_obj, 1, self._node_name)
        self._log.debug("<")

    def setup_stats(self):
        """This method sets up the stats"""
        self._log.debug(">")
        stat_args_dict = {}
        stat_args_dict[self._node_name] = self.date_time.get_stats_argumnts()
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
            stats_list = self.date_time.get_stats_list()
        stats_app = self._platform.get_app(RegalConstants.STATS_APP_NAME)
        stats_app.start_service(stats_list)
        self._log.info("Started the stats successfully on nodes %s",
                       str(self._node_name))
        self._log.debug("<")

    def stop_stats(self, stats_list=None):
        """ this method stops the stats service script in the mapped machine.

        returns:
            none

        """
        self._log.debug(">")
        if not stats_list:
            stats_list = self.date_time.get_stats_list()
        stats_app = self._platform.get_app(RegalConstants.STATS_APP_NAME)
        stats_app.stop_service(stats_list)
        self._log.info("Stopped the stats successfully on nodes %s",
                       str(self._node_name))
        self._log.debug("<")

    def close_session(self):
        """ Method used to close the login session of node. 
        
        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self.service_store_obj.get_login_session_mgr_obj().close_session(self._node_name)
        self._log.debug("<")

    def process_running(self, process):
        """
        Checks if process is running
        Args:
            process(str): process name

        Returns(bool): True if process is running, False if its not running

        """
        self._log.debug(">")
        is_running = self._datetime_server_app.process_running(process, tag=self._node_name)
        self._log.debug("<")
        return is_running

    def start_server(self):
        """
        Start the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        return self._datetime_server_app.start_server(tag=self._node_name)

    def start_snmpd(self):
        """
        Start the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        return self._datetime_server_app.start_snmpd(tag=self._node_name)

    def start_client(self, host, exec_count):
        """
        Start the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        return self._datetime_server_app.start_client(host, exec_count)

    def stop_server(self):
        """
        Stop the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        return self._datetime_server_app.stop_server(tag=self._node_name)

    def stop_client(self):
        """
        Stop the datetime_server application
        Returns(bool):
            True if datetime_server is stopped or not running

        """
        self._log.debug(">")
        return self._datetime_server_app.stop_client()

    def get_date_time(self):
        """
        Invoke REST API GET Request for http://<datetimeserverip>:<portno>/date_and_time
        Returns(str): time

        """
        self._log.debug(">")
        self._log.debug("<")
        return self._datetime_server_app.send_rest_request('date_and_time')

    def get_year(self):
        """
        Invoke REST API GET Request for http://<datetimeserverip>:<portno>/year
        Returns(str): Year

        """
        self._log.debug(">")
        self._log.debug("<")
        return self._datetime_server_app.send_rest_request('year')

    def get_log_path(self):
        """
        Invoke REST API GET Request for http://<datetimeserverip>:<portno>/log_path
        Returns(str): log_path

        """
        self._log.debug(">")
        self._log.debug("<")
        return self._datetime_server_app.send_rest_request('log_path')

    def get_month(self):
        """
         Invoke REST API GET Request for http://<datetimeserverip>:<portno>/month
        Returns(str): month

        """
        self._log.debug(">")
        self._log.debug("<")
        return self._datetime_server_app.send_rest_request('month')

    def get_day_of_month(self):
        """
         Invoke REST API GET Request for http://<datetimeserverip>:<portno>/day_of_month
        Returns(str): day of the month

        """
        self._log.debug(">")
        self._log.debug("<")
        return self._datetime_server_app.send_rest_request('day_of_month')

    def get_time(self):
        """
         Invoke REST API GET Request for http://<datetimeserverip>:<portno>/time
        Returns(str): time

        """
        self._log.debug(">")
        self._log.debug("<")
        return self._datetime_server_app.send_rest_request('time')
