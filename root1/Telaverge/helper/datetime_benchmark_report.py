from regal_lib.helper.common_hepler import ReportHelper
from regal_lib.product.Telaverge.helper.datetimedoc import DatetimeDoc
from regal_lib.product.Telaverge.telaverge_constans import Constants as TelavergeConstants
from regal_lib.corelib.common_utility import Utility
import regal_lib.corelib.custom_exception as exception
from collections import namedtuple
import datetime
import matplotlib
matplotlib.use('Agg')  # to change the backend to not use tkinter

#import regal.logger.logger as logger
#from regal.utility import Utility, GetRegal
#import regal.custom_exception as exception


# TODO
# change the global count and make use of a temporary file for images
# (matplotlib image)


# Graph object creator
Graph = namedtuple('Graph', 'xlabel, ylabel, points, title')


class DatetimeServerReport(ReportHelper):
    """ Test case based report"""

    def __init__(self, service_store_obj, tc_result="Success", system_alerts=[], failure_causes=[], note=[]):
        super(DatetimeServerReport, self).__init__(service_store_obj,)
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self._tc_result = tc_result
        self._system_alerts = system_alerts
        self._failure_causes = failure_causes
        self.note = note

    def generate_report(self):
        """ This method generates the report of a test case.

        Args:
            self(instance): it refers to the variables and methods of the
            same class

        Returns:
            None

        """
        self._log.debug('> Entering the generate report')
        self._log.info(
            "Generating the report for testcase %s", str(self.get_testcase_name()))

        if not GetRegal().GetResultMgr().get_result_sut_from_db(self.get_sut_name(),
                                                                self._trigger_id,
                                                                self.get_run_count()):
            self._log.debug(
                "sut %s, result is not created in the db", self.get_sut_name())
            return

        run_result_obj = GetRegal().GetResultMgr().add_test_run_result(self.get_sut_name(),
                                                                       self._trigger_id,
                                                                       self.get_run_count())
        (status, data) = run_result_obj.check_testsuite_result_present_in_db(
            self.get_suite_name())
        if status is False:
            self._log.debug("sut %s testsuite %s, result is not created in the db",
                            self.get_sut_name(), self.get_suite_name())
            return

        testsuite_result = run_result_obj.get_testsuite_result(
            self.get_suite_name())
        topology_obj = testsuite_result.get_topology_template(self.get_sut_name(),
                                                              self.get_suite_name(),
                                                              self.get_run_count())

        (status, data) = testsuite_result.check_testcase_result_present_in_db(
            self.get_testcase_name())
        if status is False:
            self._log.debug("sut %s testsuite %s testcase %s, result is not created in the db",
                            self.get_sut_name(), self.get_suite_name(), self.get_testcase_name())
            return

        testcase_result_obj = testsuite_result.get_testcase_result(
            self.get_testcase_name())

        # Is check for topology state required??
        node_list = topology_obj.get_node_list()
        data = {}
        data['result'] = self._tc_result
        data['ssinfo'] = self.get_software_stack_details()
        data['dependencies'] = self.get_dependencies(node_list)
        data['environments'] = self.get_environment_details(node_list)
        data['scenarios'] = self.get_testcase_scenario()
        data['benchmarks'] = self.get_benchmark_details(
            node_list, testcase_result_obj)
        if not self._failure_causes:
            data['failurecauses'] = ["-NA-"]
        else:
            data['failurecauses'] = self._failure_causes
        if not self._system_alerts:
            data['systemalerts'] = ["-NA-"]
        else:
            data['systemalerts'] = self._system_alerts
        if self.note:
            data["note"] = self.note
        else:
            data["note"] = ["-NA-"]
        day_time = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")

        self._log.debug("Data to report is %s", data)
        report_gen_path = self.create_and_get_report_generation_path()
        datetime_doc = DatetimeDoc(TelavergeConstants.TEMPLATE_PATH, data)
        datetime_doc.create("{}/Datetime_Server_REST_Functional_{}-{}.docx".format(
            report_gen_path, self.get_testcase_name(), day_time))
        self._log.info(
            "Report for %s is generated successfully", str(self.get_testcase_name()))
        self._log.debug('<')

    def get_datetime_version(self, node_obj_list):
        """ This returns version of the stp.

        Args:
            node_obj_list(list): list of the node objects.

        Returns:
            str: version of the stp application.

        """
        self._log.debug(">")
        for node_obj in node_obj_list:
            if "datetime_server_node" in node_obj.get_name():
                datetime_obj = node_obj
                break
        self._log.debug("<")
        return self._get_app_version("datetime_server_node", datetime_obj.get_node_info()["OS"]["Platform"]["Applications"])

    def get_benchmark_details(self, node_obj_list, tc_obj):
        """ This detailes of the graphs cpu and tps of the nodes..

        Args:
            node_obj_list(list): list of the node objects.
            tc_obj(): object of current testcase run result.

        Returns:
            dict: information of the benchmark details of the test case.

        """
        self._log.debug(">")
        datetimestat = tc_obj.get_db_stat("datetime_server_stat")
        banch_mark_data = []
        banch_mark_info = {}

        graphs = []
        data = {}
        info = ""
        for node_obj in node_obj_list:
            if "datetime_server_node" in node_obj.get_name():
                try:
                    year_request_count_tuple_list = datetimestat.get_year_request_count(
                        node_obj.get_name())
                    month_request_count_tuple_list = datetimestat.get_month_request_count(
                        node_obj.get_name())
                    day_request_count_tuple_list = datetimestat.get_day_request_count(
                        node_obj.get_name())
                    time_request_count_tuple_list = datetimestat.get_time_request_count(
                        node_obj.get_name())
                    date_and_time_request_count_tuple_list = datetimestat.get_date_and_time_request_count(
                        node_obj.get_name())
                    log_path_request_count_tuple_list = datetimestat.get_log_path_request_count(
                        node_obj.get_name())
                    graph = Graph("Time", "YearRequestCount",
                                  year_request_count_tuple_list, "YearRequestCount")
                    graphs.append(graph)
                    graph = Graph("Time", "MonthRequestCount",
                                  month_request_count_tuple_list, "MonthRequestCount")
                    graphs.append(graph)
                    graph = Graph("Time", "DayRequestCount",
                                  day_request_count_tuple_list, "DayRequestCount")
                    graphs.append(graph)
                    graph = Graph("Time", "TimeRequestCount",
                                  time_request_count_tuple_list, "TimeRequestCount")
                    graphs.append(graph)
                    graph = Graph("Time", "DateAndTimeRequestCount",
                                  date_and_time_request_count_tuple_list, "DateAndTimeRequestCount")
                    graphs.append(graph)
                    graph = Graph("Time", "LogPathRequestCount",
                                  log_path_request_count_tuple_list, "LogPathRequestCount")
                    graphs.append(graph)
                except Exception as ex:
                    import traceback
                    trace_back = traceback.format_exc()
                    self._log.error(trace_back)
                    self.note.append(str(ex))

                data["result"] = info
                data["graphs"] = [dict(graph._asdict()) for graph in graphs]
                banch_mark_data.append(data)

        banch_mark_info["header"] = "Datetime Server SNMP Stats"
        banch_mark_info["data"] = banch_mark_data
        self._log.debug("<")
        return banch_mark_info

    def get_dependencies(self, node_obj_list):
        """ This  dependencies of the test case example list of apps,
            platform etc

        Args:
            node_obj_list(list): list of the node objects.

        Returns:
            list: list of dependencies of test case.

        """
        self._log.debug(">")
        dependencies_list = []
        datetime_node_obj = None
        for node_obj in node_obj_list:
            if "datetime_server_node" in node_obj.get_name():
                datetime_node_obj = node_obj
        if not datetime_node_obj:
            return dependencies_list
        node_details_dict = datetime_node_obj.get_node_info()
        platform_dependencies_list = self.get_platform_details(
            node_details_dict["OS"]["Platform"])
        app_dependencies_list = self.get_app_list(node_details_dict
                                                  ["OS"]["Platform"]["Applications"])
        os_details_list = self.get_os_details(node_details_dict["OS"])
        dependencies_list = os_details_list + \
            app_dependencies_list + platform_dependencies_list
        self._log.debug("<")
        return dependencies_list

    def get_environment_details(self, node_obj_list):
        self._log.debug(">")
        datetime_nodes_info = []
        datetime_nodes_dict = {}
        for node_obj in node_obj_list:
            node_info_dict = {}
            if "datetime_server_node" in node_obj.get_name():
                node_info_dict = self.get_node_hardware_info(
                    node_obj.get_name())
                node_info_dict["vips"] = ["NA"]
                datetime_nodes_info.append(node_info_dict)

        datetime_nodes_dict["head"] = "DATETIME - 1 Node"
        datetime_nodes_dict["data"] = datetime_nodes_info
        return [datetime_nodes_dict]
