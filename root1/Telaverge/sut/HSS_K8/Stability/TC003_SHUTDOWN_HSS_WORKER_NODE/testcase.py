"""
Testcase is used to reschedule the pods from one workernode(2)
to other workernode(4), If assigned workernode(2) is down

Steps involved in testcase:
        1. Invoke resource events update with the help of application deployment object
        2. Fetch pod objects from workernode02 and workernode04
        3. Pods on workernode04 will be empty
        4. Stop the workernode02
        5. Invoke resource events update with the help of application deployment object
        6. Fetch the pod objects from the workernode04
        7. The pods which were present on the workernode02 will be rescheduled to workernode04
        8. Start the workernode02
"""

import time
import traceback
import sys

from test_executor.test_executor.utility import GetRegal
sys.path.append("/opt/regal/product/")
import Telaverge.helper.helper_exception as exception
from Telaverge.helper.cluster_helper import ClusterHelper
from Telaverge.sut.HSS_K8.Stability.suite import Constants
import Telaverge.sut.HSS_K8.Stability.suite as BeforeSuite

class PodsReschedule(object):
    """ Module handles the functions which is related to test case
    """
    def __init__(self):
        self.regal_api = GetRegal()
        log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger("PodsReschedule")
        self._log.debug(">")
        self.cluster_hepler_obj = ClusterHelper(GetRegal())
        self._current_testcase_config = self.regal_api.get_current_test_case_configuration()
        self._current_testcase_config = self._current_testcase_config.get_test_case_config()
        self._monitor_time = int(self._current_testcase_config["MonitorTime"])
        self._interval_time = int(self._current_testcase_config["IntervalTime"])
        self._hss_pod_count = int(self._current_testcase_config["HssPodCount"])
        self._resource_update_time = int(self._current_testcase_config["ResourceUpdateTime"])
        self._sleep_time = int(self._current_testcase_config["SleepTime"])
        self._log.debug("<")

    def execute_test(self):
        """ logic to execute the test case

        Comments:
            1. Update the current deployment state
            2. Verify HSS pods are running on workernode2
            3. Bring down the workernode2
            4. Sleep for 70 seconds
            5. Update the current deployment state
            6. Verify and get the HSS pods on workernode3
            7. Verify 2 HSS pods from the workernode2 are shifted to workernode3
            8. Monitor for the run state of 4 HSS pods on workernode3

        """
        self._log.debug(">")
        self._log.info("Starting test execution")
        try:
            self.cluster_hepler_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)

            pod_objs = self.cluster_hepler_obj.verify_and_get_scheduled_pods(
                Constants.WORKER_NODE2, Constants.RELEASE_NAME,
                Constants.HSS_SERVICES)

            pod_list = []
            for obj in pod_objs:
                pod_list.append(obj.get_resource_name())
            self._log.info("HSS pods running on %s node are : %s", Constants.WORKER_NODE2, str(pod_list))

            #stopping workernode2
            self.cluster_hepler_obj.stop_node(Constants.WORKER_NODE2)

            BeforeSuite.update_resource_till_machine_stops(Constants.WORKER_NODE2)

            pod_objs = self.cluster_hepler_obj.verify_and_get_scheduled_pods(
                    Constants.WORKER_NODE3, Constants.RELEASE_NAME,
                    Constants.HSS_SERVICES)

            pod_list = []
            for obj in pod_objs:
                pod_list.append(obj.get_resource_name())
            self._log.info("HSS pods running on %s node are after stopping the node: %s", Constants.WORKER_NODE3, str(pod_list))

            if len(pod_objs) != self._hss_pod_count:
                err_msg = "The all hss pods are not restarted on node "\
                          " {}, {}".format(Constants.WORKER_NODE3, len(pod_objs))
                self._log.error(err_msg)
                self._log.debug("<")
                raise exception.PodsNotScheduled(err_msg)
            self._log.info("Monitoring hss pods to come running state")
            self.cluster_hepler_obj.monitor_pods_run_status(
                    Constants.RELEASE_NAME, Constants.HSS_SERVICES, pod_objs, self._monitor_time)
            self._log.info("HSS pods shifted to %s node and are in running state", Constants.WORKER_NODE3)

            pod_list = []
            for obj in pod_objs:
                pod_list.append(obj.get_resource_name())
            self._log.info("HSS pods running on %s node are : %s", Constants.WORKER_NODE3, str(pod_list))

            self._log.info("Successfully executed the test case")
        except (Exception, exception.PodsScheduleTimeOut, exception.PodsNotScheduled) as error:
            self._log.error(error)
            trace_back = traceback.format_exc()
            self._log.error(trace_back)
            self._log.debug("<")
            raise exception.TestcaseError(str(error))
        finally:
            # finally staring the workernode02
            self.cluster_hepler_obj.start_node(Constants.WORKER_NODE2)
            BeforeSuite.update_resource_state_with_intervals(self._resource_update_time)
            self._log.debug("<")

def execute():
    """ Execution starts from this method """
    test = PodsReschedule()
    test.execute_test()
    test = None
