"""
Testcase verifies that pods are restarted successfully on
the same node after deleting the pod [hss]
Steps involved in testcase:
        1. Invoke resource events update with the help of application deployment object
        2. Fetch the pod objects (hss) from worker02
        3. Delete the hss pod in worker02
        4. Invoke resource events update with the help of application deployment object
        5. Fetch the pod objects from the worker02
        6. The pods which were present on the worker02 will be restarted on
        workernode02
"""

import time
import traceback
import sys

from test_executor.test_executor.utility import GetRegal
from regal_lib.infra_profile.topology.k8.k8_constants import K8Constants

sys.path.append("/opt/regal/product/")
import Telaverge.helper.helper_exception as exception
from Telaverge.helper.cluster_helper import ClusterHelper
from Telaverge.sut.HSS_K8.Performance.suite import Constants
import Telaverge.sut.HSS_K8.Performance.suite as BeforeSuite

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
        self._log.debug("<")

    def delete_pods(self, release_name, pod_objs_list):
        """ Method delete the given pod

        Args:
            release_name(str): Name of the reelase
            pod_objs_list(list): List of tuples:

        Returns:
            None

        Comments:
            1. Delete the given pods from the cluster.
            2. This testcase delete the workernode2 HSS pods

        """
        self._log.debug(">")
        for pod_info in pod_objs_list:
            microservice_name = pod_info[0]
            pod_objs = pod_info[1]
            for pod_obj in pod_objs:
                self._log.info("Deleting the pod %s of micro service %s and"\
                               " release %s", pod_obj.get_resource_name(),
                               microservice_name, release_name)
                pod_obj.execute_command(K8Constants.CMD_DELETE)
                self._log.info("Successfully deleted the pod %s of micro service %s and"\
                               " release %s", pod_obj.get_resource_name(),
                               microservice_name, release_name)
        self._log.debug("<")

    def execute_test(self):
        """ logic to execute the test case

        Comments:
            1. Update the current deployment state
            2. Verify HSS pods are running on workernode2 and
            get the HSS pods
            3. Delete the workernode2 HSS pods
            4. Update the deployment state after deleting pods
            5. Verify HSS pods are restarted and running on workernode2

        """
        self._log.debug(">")
        self._log.info("Starting test execution")
        try:
            self.cluster_hepler_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)

            hss_service_pods = []
            pod_objs = self.cluster_hepler_obj.verify_and_get_scheduled_pods(
                    Constants.WORKER_NODE2, Constants.RELEASE_NAME,
                    Constants.HSS_SERVICES)
            pod_list = []
            for obj in pod_objs:
                pod_list.append(obj.get_resource_name())
            self._log.info("Before hss pod is deleted, available pods on %s are: %s",\
                             Constants.WORKER_NODE2, str(pod_list))

            hss_service_pods.append((Constants.HSS_SERVICES, [pod_objs[0]]))

            exist_pod = pod_objs[1]
            exist_pod_name = exist_pod.get_resource_name()

            self.delete_pods(Constants.RELEASE_NAME, hss_service_pods)
            BeforeSuite.update_resource_state_with_intervals(self._monitor_time,
                    self._interval_time)


            pod_objs = self.cluster_hepler_obj.verify_and_get_scheduled_pods(
                    Constants.WORKER_NODE2, Constants.RELEASE_NAME,
                    Constants.HSS_SERVICES)
            new_pod = []
            for pod_obj in pod_objs:
                if pod_obj.get_resource_name() != exist_pod_name:
                    new_pod.append(pod_obj)
                    break

            pod_list = []
            for obj in pod_objs:
                pod_list.append(obj.get_resource_name())
            self._log.info("After 1 hss pod is deleted, available pods on %s node are: %s",\
                             Constants.WORKER_NODE2, str(pod_list))

            self.cluster_hepler_obj.monitor_pods_run_status(
                    Constants.RELEASE_NAME, Constants.HSS_SERVICES, new_pod,
                    self._monitor_time)

            self._log.info("Successfully executed the test case")
        except (Exception, exception.PodsScheduleTimeOut, exception.PodsNotScheduled) as error:
            self.cluster_hepler_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)
            self._log.error(error)
            trace_back = traceback.format_exc()
            self._log.error(trace_back)
            self._log.debug("<")
            raise exception.TestcaseError(str(error))
        finally:
            self.cluster_hepler_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)
            self._log.debug("<")

def execute():
    """ Execution starts from this method """
    test = PodsReschedule()
    test.execute_test()
    test = None
