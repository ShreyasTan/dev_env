import os
import time
import regal.logger.logger as logger
import regal.custom_exception as exception
from regal.utility import GetRegal
from Telaverge.helper.regal_helper import RegalHelper

class RegalUITest():
  """ Class to perform Regal UI test. """
  def __init__(self):
    """ Initialization """
    self._log = logger.GetLogger("RegalUITest")
    self._log.debug(">")
    self._topology = GetRegal().GetCurrentRunTopology()
    self._regal_helper = RegalHelper('regal_node', 'regal-netnumber-suts')
    self.regal_node = self._topology.get_node('regal_node')
    uiac_obj = GetRegal().GetUIAClientObj()
    self.uia_session_obj = uiac_obj.create_session()
    self._id = self.uia_session_obj.get_id_obj()
    self.xpath = self.uia_session_obj.get_xpath_obj()
    self.class_name = self.uia_session_obj.get_class_name_obj()
    self.tc_name = os.path.basename(__file__).split(".")[0]
    self._log.debug("<")

  def execute_UI_test(self):
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
    result = self.add_server()
    if not result:
      self._log.debug("<")
      raise Exception("Failed to add server")
    self._log.debug("<")

  def login(self):
    """
    Method to automate Login.

            Returns:
                None
    """
    self._log.debug(">")
    web_address = "http://{}/".format(self.regal_node.get_management_ip())

    self.uia_session_obj.get_page(web_address)
    self._log.info("--> In Login page")
    self._id.find_by_id_and_send_keys('user-name', 'admin', )
    self._id.find_by_id_and_send_keys('password', 'admin', )
    self.xpath.find_by_xpath_and_click("//span[contains(text(),'Login')]", )
    try:
      regal = self.xpath.find_by_xpath_and_get_text("//label[contains(text(),'REGAL')]", )
      self._log.info("Successfully logged in")
    except:
      self._log.debug("<")
      raise Exception("Unsuccessful login")
    self._log.info("--> In Dashboard page")
    self._log.debug("<")

  def add_server(self):
    """
    Method to add servers in server page.

            Returns:
                bool: State of the server addition operation
    """
    self._log.debug(">")
    state = False
    self._log.info("Adding Server")
    self.xpath.find_by_xpath_and_click("//p[contains(text(),'Servers')]", )
    self._log.info("--> In Server page")
    self.class_name.find_by_class_name_and_click('floating-add-button ', )
    self.xpath.find_by_xpath_and_send_keys("//input[@placeholder='Machine IP']", '172.16.8.26', )
    self.xpath.find_by_xpath_and_send_keys("//input[@placeholder='Machine Name']", 'test_1', )
    self.xpath.find_by_xpath_and_send_keys("//input[@placeholder='User Name']", 'root', )
    self.xpath.find_by_xpath_and_send_keys("//input[@placeholder='Password']", 'tel@123', )
    self.xpath.find_by_xpath_and_click("//button[@title='Add']", )
    self.xpath.find_by_xpath_and_click("//button[@title='Ok']", )
    state = self.check_status()
    self._log.debug("<")
    return state

  def delete_server(self):
    """
    Method to delete the added server.

            Returns:
                None
    """
    self._log.debug(">")
    self.xpath.find_by_xpath_and_click("//p[contains(text(),'Servers')]", )
    self._log.info("--> In Server page")
    self._log.info("Deleting server")
    rows = self.uia_session_obj.find_elements_by_class_name('rt-tr-group', )
    for row in rows:
      cell_text = row.get_text().split("\n")

      if cell_text[1] == 'test_1':
        desired_row = row
        break
    delete_button = desired_row.find_element_by_xpath("//div[@title='Delete this machine']", )
    delete_button.click()
    self.xpath.find_by_xpath_and_click("//label[contains(text(),'Delete')]", )
    self.xpath.find_by_xpath_and_click("//button[@title='OK']", )
    self._log.debug("<")

  def check_status(self):
    """
    Method to check status of the server after adding it.

            Resturns:
                bool: Result of the operation
    """
    self._log.debug(">")
    desired_row = None
    result = False
    time.sleep(4)
    rows = self.uia_session_obj.find_elements_by_class_name('rt-tr-group', )
    for row in rows:
      cell_text = row.get_text().split("\n")

      if cell_text[1] == 'test_1':
        desired_row = row
        break
    if desired_row:
      while True:
        status = desired_row.find_element_by_xpath("//div[@data-for='test_1']", )
        try:
          state = status.get_text()
        except:
          pass
        if state == 'NOT ASSIGNED':
          result = True
          self._log.info("Server added successfully")
          break
        elif state == 'FAILED':
          self._log.error("Server addition unsuccessful")
          break
      self._log.debug("<")
      return result
    raise Exception("Server not added")

  def start_test(self):
    """
    Method starts the testing process.

            Returns:
                None
    """
    self._log.debug(">")
    try:
      self._log.debug(">")
      self._log.info("Test complete")
    except Exception as ex:
      self._log.error("Exception caught while running test: %s", str(ex))
      self._log.debug("<")
      raise exception.TestCaseFailed(self.tc_name, str(ex))
    finally:
      #self.uia_session_obj.end_session()
      self._log.debug("<")
      self._log.debug("<")

def execute():
  """ Testcase executor """
  regal_node = RegalUITest()
  regal_node.start_test()
  regal_node.login()
  regal_node.add_server()
  time.sleep(30)
  regal_node.delete_server()
