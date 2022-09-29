"""This modules hepls to get information of current running test case for
report generation """
from infra_dt_mgr.infra_dt_mgr.utility import GetServiceStore
from collections import defaultdict
from regal_lib.corelib.common_utility import Utility
#import regal.logger.logger as logger
#from regal.utility import GetRegal, Utility
OFF_SET_TIME = 70

class Benchmarkreport(object):
    """ Class stores the general infomation to create report
    """
    def __init__(self):
        
        self.service_store_obj = GetServiceStore()
        logger = self.service_store_obj.get_log_mgr_obj()
        self._log = logger.get_logger("Benchmarkreport")
        self._log.debug('>')
        self._run_mgr_obj = self.service_store_obj.GetRunMgr()
        self._topology_mgr_obj = GetRegal().GetTopologyMgr()#==========
        self._cur_topology_obj = GetRegal().GetCurrentRunTopology()#=====
        self.run_count = self.service_store_obj.GetCurrentRunCount()
        self.sut_name = self.service_store_obj.GetCurrentSutName()
        self._trigger_id = self._run_mgr_obj.get_runner(self.run_count, self.sut_name).get_trigger_id()
        self.suite_name = GetRegal().GetRunMgr().get_runner(self.run_count, self.sut_name).get_suite_name()#=====
        self.tc_name = GetRegal().GetRunMgr().get_runner(self.run_count, self.sut_name).get_tc_name()
        self.tc_iter_count = GetRegal().GetRunMgr().get_runner(self.run_count,
                                                               self.sut_name).get_tc_iteration_num()#=========
        self.tc_config = self._get_testcase_configuration()
        self.mc_pool_obj = GetRegal().GetMachinePoolMgr()
        self._log.debug('<')

    def get_software_stack_details(self):
        """ This method used the currently used software stack name and
        version.

        Returns:
            str: name and version.

        """
        ss_name = self._cur_topology_obj.get_software_stack_name()
        ss_version = self._cur_topology_obj.get_software_stack_version()
        return "{}-{}".format(ss_name, ss_version)

    def get_run_count(self):
        """ This method return the run cont

        Returns:
            int: run count

        """
        return int(self.run_count)

    def get_sut_name(self):
        """ This method return the sut name


        Returns:
            str: sut name

        """
        return self.sut_name

    def get_suite_name(self):
        """ This method return the suite name


        Returns:
            str: suite name

        """
        return self.suite_name

    def get_testcase_name(self):
        """ This method return the testcase name


        Returns:
            str: testcase name

        """
        return self.tc_name

    def get_tc_iter_count(self):
        """ This method return the testcase iteration count


        Returns:
            int: testcase iteration count

        """
        return self.tc_iter_count

    def get_testcase_config(self):
        """ This method return the testcase name


        Returns:
            str: testcase name

        """
        return self.tc_config

    def get_platform_details(self, platform_details):
        """ This method retutns the platform details.

        Args:
            platform_details(dict): platform details

        Returns:
            list: infomation

        """
        self._log.debug('> Platform details')
        platform_details_list = []
        platform_details_list.append(
            "{}-{}".format(platform_details['Name'], platform_details['Version']))
        self._log.debug('< ')
        return platform_details_list

    def get_os_details(self, os_info):
        """ This method return the os details.

        Args:
            os_info(dict): Os information.

        Return:
            list: Information of the OS.

        """
        self._log.debug(">")
        os_details = []
        os_details.append("{}-{}".format(os_info["Name"], os_info["Version"]))
        self._log.debug("<")
        return os_details

    def get_app_list(self, apps):
        """ This method lists and returns all the app details.

        Args:
            apps(list): list of apps configured in topology.

        Returns:
            list: app information

        """
        self._log.debug('> app details')
        app_list = []
        for app in apps:
            string = "{} {}".format(app['Name'], app['Version'])
            app_list.append(string)
        self._log.debug('< ')
        return app_list

    def get_module_list(self, node_details_dict):
        """ This method lists and returns all the app details.

        Args:
            node_details_dict(list): list of node details configured in topology.

        Returns:
            list: module list

        """
        self._log.debug('> module details')
        module_list = []
        modules = node_details_dict['Modules']
        for module in modules:
            string = module['Name']+module['Version']
            module_list.append(string)
        self._log.debug('< ')
        return module_list

    def _get_version(self, app_name, apps_list):
        """ This method returns the version of the app from app_list of the
        given app name

        Args:
            app_name(str): name of the app for which app version required
            apps_list(list): app list

        Returns:
            str: app version if found or else empty string

        """
        self._log.debug('>')
        version = ""
        for app in apps_list:
            if app['Name'] == app_name:
                self._log.debug('< ')
                version = app['Version']
        self._log.debug('< ')
        return version

    def _get_machine_obj(self, node_name):
        """ This method returns the management ip of the node

        Args:
            node_name(str): name of the node

        Returns:
            object: machine object

        """
        self._log.debug(">")
        cur_topology_name = self._run_mgr_obj.get_current_runner_topology()
        cur_software_stack_details = self._run_mgr_obj.get_current_runner_software_stack_details()
        topology_obj = GetRegal().GetTopologyMgr().get_topology(cur_topology_name, cur_software_stack_details)#=========
        node_obj = topology_obj.get_node(node_name)
        machine_obj = node_obj.get_assigned_machine()
        self._log.debug("<")
        return machine_obj

    def _get_testcase_configuration(self):
        """ This method returns test case confuguration.

        Returns:
            dict: current test case configuration.

        """
        self._log.debug(">")
        testconfig_obj = GetRegal().GetCurrentTestConfiguration()#===========
        test_config = testconfig_obj.get_testcase_config()
        self._log.debug("<")
        return test_config


    def get_testcase_scenario(self):
        """ This method returns the test case description.

        Returns:
            str: test case description.

        """
        self._log.debug(">")
        sut_mngr_obj = GetRegal().GetSUTMgr()
        db_sut_obj = sut_mngr_obj.get_sut_by_name(self.get_sut_name())
        db_suite_obj = db_sut_obj.get_testsuite_by_name(self.get_suite_name())
        db_testcase_obj = db_suite_obj.get_db_testcase_by_name(self.get_testcase_name())
        description = db_testcase_obj.get_testcase_description()
        if not description:
            self._log.debug("Configuration for testcase %s is not present", self.get_testcase_name())
            self._log.debug("<")
            return []
        scenario = Utility.remove_empty_lines_in_list(description)#==========
        self._log.debug("<")
        return scenario

    def get_node_hardware_info(self, node_name):
        """ This method returns the dictionary of harware info of the given
        node ex cpu, clock and ram.


        Args:
            node_anme(str): name of the node.

        Returns:
            dict: dictionary of node_name, ram size, clock speed and cpu.

        """
        self._log.debug(">")
        mc_obj = self._get_machine_obj(node_name)
        node_info_dict = {}
        node_info_dict["nodename"] = node_name
        node_info_dict["ram"] = mc_obj.get_ram_size()
        node_info_dict["clock"] = mc_obj.get_clock_speed()
        node_info_dict["cpu"] = mc_obj.get_cpu_count()
        self._log.debug("<")
        return node_info_dict
