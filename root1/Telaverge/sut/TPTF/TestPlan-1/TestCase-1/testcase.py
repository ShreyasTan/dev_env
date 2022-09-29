"""TPTF sample testcase code
"""

from distutils.log import error
import time
import os
import traceback

import regal_lib.corelib.custom_exception as exception

class Testcase1():
    """Testcase code"""
    def __init__(self):
        # test executor service libraries
        from test_executor.test_executor.utility import GetRegal
        from Telaverge.helper.tptf_jmeter_helper import TPTFJmeterHelper
        self.regal_api = GetRegal()
        self._log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self.tptf_jmeter_helper = TPTFJmeterHelper(GetRegal(), "jmeter_node",
                                                  "TPTF")
        self._topology = GetRegal().get_current_run_topology()
        self.sut_name = GetRegal().get_current_sut()
        self.ts_name = GetRegal().get_current_suite()
        self.tc_name = GetRegal().get_current_test_case()
        management_ip = self.tptf_jmeter_helper.get_management_ip()
        self.info_dict = {
            "testSuite": self.ts_name,
            "testCase": self.tc_name
        }
        self.tptf_app = self.tptf_jmeter_helper.get_tptf_app()
        self._log.debug("<")

    def run_test(self, info_dict):
        """
        """
        try:
            self.tptf_app.run_test(info_dict)
        except Exception as ex:
            error_msg = f"Failed to start the test case. Reason: {str(ex)}"
            raise exception.TestCaseFailed(self.tc_name, error_msg)

    def monitor_test(self, info_dict):
        """
        """
        try:
            status = self.tptf_app.monitor_test(info_dict)
            if not status[0]:
                # above api call returned exception
                error_msg = "Failed to monitor test. Reason: {}".format(status[1])
                self._log.error(error_msg)
                raise exception.TestCaseFailed(self.tc_name, error_msg)
            # above api call returned success response
            # status[1] = isTcRunning, might be True or False
            return status[1]
        except Exception as ex:
            raise Exception(str(ex))

    def get_test_result(self, info_dict):
        """
        """
        try:
            status = self.tptf_app.get_test_result(info_dict)
            self._log.debug("TC STATUS: {}".format(status))
            if not status[0]:
                error_msg = "Failed to get test result. Reason: {}".format(status[1])
                self._log.error(error_msg)
                raise exception.TestCaseFailed(self.tc_name, error_msg)
            if status[1] == "Passed":
                self._log.debug(f"Test case '{self.tc_name}' passed.")
            else:
                error_msg = f"Test case '{self.tc_name}' failed."
                self._log.error(error_msg)
                raise exception.TestCaseFailed(self.tc_name, error_msg)
        except Exception as ex:
            error_msg = f"Test case is not started. Reason: {str(ex)}"
            self._log.error(error_msg)
            raise exception.TestCaseFailed(self.tc_name, error_msg)

    def test_run(self):
        """
        """
        self._log.debug(">")
        try:
            # self.tptf_app.apply_configuration(self.info_dict)
            # start test
            # try:
            #     self.tptf_app.run_test(self.info_dict)
            # except Exception as ex:
            #     error_msg = f"Failed to start the test case. Reason: {str(ex)}"
            #     raise exception.TestCaseFailed(self.tc_name, error_msg)

            # get test status
            # time.sleep(5)
            # try:
            #     status = self.tptf_app.get_test_result(self.info_dict)
            #     print(status)
            #     self._log.debug("TC STATUS: {}".format(status))
            #     if not status[0]:
            #         error_msg = "Failed to get test result. Reason: {}".format(status[1])
            #         self._log.error(error_msg)
            #         raise exception.TestCaseFailed(self.tc_name, error_msg)
            #     if status[1] == "Passed":
            #         self._log.debug(f"Test case '{self.tc_name}' passed.")
            #     else:
            #         error_msg = f"Test case '{self.tc_name}' failed."
            #         self._log.error(error_msg)
            #         raise exception.TestCaseFailed(self.tc_name, error_msg)
            # except Exception as ex:
            #     error_msg = f"Test case is not started. Reason: {str(ex)}"
            #     self._log.error(error_msg)
            #     raise exception.TestCaseFailed(self.tc_name, error_msg)
            ####################################################################
            self.run_test(self.info_dict)

            # monitor test case run status, wait until finished
            while(True):
                exception_counter = 0
                try:
                    is_tc_running = self.monitor_test(self.info_dict)
                    self._log.debug("Is TC '{}' running: - {}".format(self.tc_name, is_tc_running))
                    if not is_tc_running:
                        break
                except Exception as ex:
                    # info might not have been updated yet, keep waiting
                    if exception_counter >= 5: # wait 10secs
                        error_msg = "Monitoring timeout exceeded"
                        self._log.error(error_msg + str(ex))
                        raise Exception(error_msg)
                    self._log.debug(str(ex))
                    time.sleep(2)
                    exception_counter += 1
                    continue

            self.get_test_result(self.info_dict)
            self._log.debug("<")
        except Exception as ex:
            self._log.error(str(ex))
            self._log.debug("<")
            raise exception.TestCaseFailed(self.tc_name, str(ex))

def execute():
    """
    Create test instance and run the test
    """
    test = Testcase1()
    test.test_run()
    test = None
