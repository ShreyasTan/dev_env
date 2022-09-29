"""A UIA testcase to validate Regal GUI login."""

import os
import regal.logger.logger as logger
import regal.custom_exception as exception
from regal.utility import GetRegal
from Telaverge.helper.regal_helper import RegalHelper


class RegalUITest(object):
    """Class to perform Regal UI test."""
    def __init__(self):
        """
        Initialization
        """
        self._log = logger.GetLogger("RegalUITest")
        self._log.debug(">")
        self._topology = GetRegal().GetCurrentRunTopology()
        self._regal_helper = RegalHelper("regal_node", "regal-netnumber-suts")
        #self._regal_helper = RegalHelper("regal_node", "default_app")
        self.regal_node = self._topology.get_node("regal_node")
        uiac_obj = GetRegal().GetUIAClientObj()
        self.uia_session_obj = uiac_obj.create_session()
        self.id_ = self.uia_session_obj.id_
        self.xpath = self.uia_session_obj.xpath
        self.tc_name = os.path.basename(__file__).split(".")[0]
        self._log.debug("<")

    def execute_ui_test(self):
        """
        Method executes GUI test.

        Returns:
            None
        """
        self._log.debug(">")
        gui_status = self._regal_helper.check_gui_is_running()
        if not gui_status:
            self._log.error("GUI not up")
            self._log.debug("<")
            raise Exception("GUI failed to start")
        self.login()
        self._log.debug("<")

    def login(self):
        """
        Method to automate Login.

        Returns:
            None
        """
        self._log.debug(">")
        web_address = "http://{}/".format(
            self.regal_node.get_management_ip())
        self.uia_session_obj.get_page(web_address)
        self._log.info("--> In Log in page")
        self.id_.find_by_id_and_send_keys("user-name",
                                          "admin")
        self.id_.find_by_id_and_send_keys("password",
                                          "admin")
        self.xpath.find_by_xpath_and_click("//span[contains(text(),'Login')]")
        try:
            self.xpath.find_by_xpath_and_get_text(
                "//label[contains(text(),'REGAL')]")
            self._log.info("Successfully logged in")
        except:
            self._log.debug("<")
            raise Exception("Unsuccessful login")
        self._log.debug("<")


    def start_test(self):
        """
        Method starts the testing process.

        Returns:
            None
        """
        try:
            self._log.debug(">")
            self.execute_ui_test()
            self._log.info("Test completed")
        except Exception as ex:
            self._log.error("Exception caught while running test: %s", str(ex))
            self._log.debug("<")
            raise exception.TestCaseFailed(self.tc_name, str(ex))
        finally:
            self.uia_session_obj.end_session()
            self._log.debug("<")


def execute():
    """
    Testcase executor
    """
    regal_test = RegalUITest()
    regal_test.start_test()
