import regal_lib.corelib.custom_exception as exception
from regal_lib.product.Regal.OS.centos import CentOSBase
from regal_lib.client.deployment_mgr.deployment_mgr_client.deployment_mgr_client import DeploymentMgrClient
from regal_lib.corelib.constants import Constants


class DatetimeServerStatsNotPresentInDB(exception.RegalException):
    """ Exception will be thrown when no datetime server stats are present in the DB. """

    def __init__(self, message):
        exception.RegalException.__init__(self)
        self.message = message

    def __str__(self):
        """ Return the exception string """
        return "{}".format(self.message)


class DateTimeOSBase(CentOSBase):
    def __init__(self, service_store_obj, name, version):
        super(DateTimeOSBase, self).__init__(service_store_obj, name, version)
        class_name = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(class_name)
        self.common_db_util_obj = self.service_store_obj.get_common_db_util_obj()
        self.app_name = name

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
    #         db_machine_ref = db_machine_obj
    #         #db_machine_ref = GetRegal().GetMachinePoolMgr().get_machines()[machine_name]
    #         #info = db_machine_ref.get_os_info(self._classname)
    #         #if info is None:
    #            # try:
    #             #     info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
    #             #         'head -n 1 /extras/release', hosts)
    #             #     db_machine_ref.set_os_info(info, self._classname)
    #             # except (exception.AnsibleException):
    #             #     pass
    #             # info = self.get_deployment_mgr_client_wrapper_obj().execute_shell(
    #             #     "head -n 1 /etc/redhat-release", hosts)
    #             # db_machine_ref.set_os_info(info, self._classname)
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
        try:
            self._log.debug(">")
            self.service_store_obj.get_login_session_mgr_obj().create_session(self.get_node(), 1, self.app_name)
            rpm = ["net-snmp-libs-5.7.2", "net-snmp-agent-libs-5.7.2",
                   "net-snmp-5.7.2", "net-snmp-utils-5.7.2"]
            match = True
            for i in rpm:
                cmd = "rpm -qa | grep {}".format(i)
                hosts = [host]
                info = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                        cmd, self.app_name, time_out=Constants.PEXPECT_TIMER)
                if info:
                    self._log.debug("rpm \"%s\" is installed", i)
            return match
        except exception.AnsibleException as ex:
            self._log.warning("Exception %s rpm is not installed ", i)
            return False
        finally:
            self.service_store_obj.get_login_session_mgr_obj().close_session(self.app_name)


    def package_correction(self):
        """This method is invoked in CORRECTION state to take corrective actions

        Returns:
            True or False

        """
        return True
# class DBDatetimeServerStatsMgr(StatisticsImport):
#    """This class is defined to handle the datetime server stats
#    _user_string - user should use this string to access this class.
#    """
#    _user_string = "datetime_server_stat"
#
#    def __init__(self,service_store_obj, db_connection, sut, testsuite, testcase, run_count):
#        """Initialization of this class takes the below parameter.
#
#        Args:
#            db_connection(Database): Object of the Database class.
#            sut(str): Name of the SUT.
#            testsuite(str): Name of the Testsuite.
#            testcase(str): Name of the Testcase.
#            run_count(int): Run_count of the testcase.
#
#        Returns:
#            None
#        """
#        super(DBDatetimeServerStatsMgr, self).__init__(service_store_obj,db_connection, sut, testsuite, testcase, run_count)
#        self._classname = self.__class__.__name__
#        self.service_store_obj = service_store_obj
#        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
#        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
#        self.deployment_mgr_client_obj = DeploymentMgrClient(self.service_store_obj)
#        self._db = db_connection
#        self._sut = sut
#        self._testsuite = testsuite
#        self._testcase_name = testcase
#        self._run_count = run_count
#
#    def __str__(self):
#        return "<DBDatetimeServerStatsMgr obj>"
#
#
#    def get_stats(self):
#        pass
#
#    def _get_utilization(self, node_name, resource, tag):
#        """This mehod returns the tuple of tim and resource given..
#
#        Args:
#            node_name(str): Name of the node
#            resource(str): Name field
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Value of time and field
#
#        """
#        query = {
#            "NodeName": node_name,
#            "SUTName": self._get_sut_name(),
#            "TestsuiteName": self._get_testsuite_name(),
#            "TestcaseName": self._get_testcase_name(),
#            "RunCount": self._get_run_count(),
#        }
#        if tag != "-NA-":
#            query.update({"Tag": tag})
#        doc_list = self._db.get_documents(OsConstants.DATETIME_SERVER_STATS_COLLECTION, query)
#        if doc_list == []:
#            self._log.error("No data found for the datetime server stats in the db for the query %s", query)
#            raise DatetimeServerStatsNotPresentInDB("Datetime server stats are not available "\
#                   "for node: {}. ".format(node_name))
#        utilization = []
#        for doc in doc_list:
#            epoch_time = Utility.convert_utc_epochtime(doc["Timestamp"])
#            tuple_ = (epoch_time, float(doc[resource]))
#            utilization.append(tuple_)
#        return utilization
#
#    def get_year_request_count(self, node_name, tag="-NA-"):
#        """This method return the cpu utilization.
#
#        Args:
#            node_name(str): Name of the node
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Vlaue of time and field
#
#        """
#        return self._get_utilization(node_name, "YearRequestCount", tag)
#
#    def get_month_request_count(self, node_name, tag="-NA-"):
#        """This method return the rss utilization.
#
#        Args:
#            node_name(str): Name of the node
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Vlaue of time and field
#
#        """
#        return self._get_utilization(node_name, "MonthRequestCount", tag)
#
#    def get_day_request_count(self, node_name, tag="-NA-"):
#        """This method return the jvm utilization.
#
#        Args:
#            node_name(str): Name of the node
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Vlaue of time and field
#
#        """
#        return self._get_utilization(node_name, "DayRequestCount", tag)
#
#    def get_time_request_count(self, node_name, tag="-NA-"):
#        """This method return the vsz utilization.
#
#        Args:
#            node_name(str): Name of the node
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Vlaue of time and field
#
#        """
#        return self._get_utilization(node_name, "TimeRequestCount", tag)
#
#    def get_date_and_time_request_count(self, node_name, tag="-NA-"):
#        """This method return the load utilization.
#
#        Args:
#            node_name(str): Name of the node
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Vlaue of time and field
#
#        """
#        return self._get_utilization(node_name, "DateAndTimeRequestCount", tag)
#
#    def get_log_path_request_count(self, node_name, tag="-NA-"):
#        """This method return the load utilization.
#
#        Args:
#            node_name(str): Name of the node
#            tag(str): tag for the specific testcase.
#
#        Returns:
#            tuple: Vlaue of time and field
#
#        """
#        return self._get_utilization(node_name, "LogPathRequestCount", tag)
#
#    def _get_sut_name(self):
#        """This method return SUT name.
#
#        Returns:
#            str: Name of the SUT.
#
#        """
#        return self._sut
#
#    def _get_testsuite_name(self):
#        """This method return testsuite name.
#
#        Returns:
#            str: Name of the testsuite.
#
#        """
#        return self._testsuite
#
#    def _get_testcase_name(self):
#        """This method return testcase name.
#
#        Returns:
#            str: Name of the testcase.
#
#        """
#        return self._testcase_name
#
#    def _get_run_count(self):
#        """This method return runcount.
#
#        Returns:
#            int: Run count.
#
#        """
#        return self._run_count
