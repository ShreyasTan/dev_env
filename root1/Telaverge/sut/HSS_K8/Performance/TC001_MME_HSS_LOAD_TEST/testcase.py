"""
Testcase is used to send traffic from client to server(mme-to-hss) through load balancer

Steps involved in testcase:
        1. Invoke resource events update with the help of application deployment object
        2. Fetch pod objects from worker01
        3. Reset the stats in the mme pod.
        4. Send the traffic from mme to hss
        5. Get the status of load sent and recevied
        6. Calculate sent and recevied tps
"""

import time
import traceback
import sys

from test_executor.test_executor.utility import GetRegal

sys.path.append("/opt/regal/product/")
import Telaverge.helper.helper_exception as exception
from Telaverge.helper.cluster_helper import ClusterHelper
from Telaverge.sut.HSS_K8.Performance.suite import Constants

class TCConstants:
    """
    """
    MME_PORT = 30800
    HSS_PORT = 30820

REQUEST_BUFF = b'\x01\x00\x02\xb4\xc0\x00\x01\x3c\x01\x00\x00\x23\x28\x8a\xd7\x52\xd1\xab\x15\xc6\x00\x00\x01\x07\x40\x00\x00\x28\x6d\x6d\x65\x30\x31\x2e\x6e\x65\x74\x6e\x75\x6d\x62\x65\x72\x2e\x63\x6f\x6d\x3b\x33\x38\x34\x39\x32\x39\x36\x37\x39\x36\x3b\x31\x00\x00\x01\x15\x40\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x01\x08\x40\x00\x00\x1b\x6d\x6d\x65\x30\x31\x2e\x6e\x65\x74\x6e\x75\x6d\x62\x65\x72\x2e\x63\x6f\x6d\x00\x00\x00\x01\x28\x40\x00\x00\x15\x6e\x65\x74\x6e\x75\x6d\x62\x65\x72\x2e\x63\x6f\x6d\x00\x00\x00\x00\x00\x01\x1b\x40\x00\x00\x15\x6e\x65\x74\x6e\x75\x6d\x62\x65\x72\x2e\x63\x6f\x6d\x00\x00\x00\x00\x00\x00\x01\x40\x00\x00\x19\x31\x40\x33\x67\x70\x70\x6e\x74\x65\x77\x6f\x72\x6b\x2e\x6f\x72\x67\x00\x00\x00\x00\x00\x05\x7d\xc0\x00\x00\x10\x00\x00\x28\xaf\x00\x00\x00\x0a\x00\x00\x05\x7f\xc0\x00\x00\x10\x00\x00\x28\xaf\x35\x36\x37\x38\x00\x00\x04\x08\xc0\x00\x00\x10\x00\x00\x28\xaf\x00\x00\x03\xeb\x00\x00\x01\x04\x40\x00\x00\x20\x00\x00\x01\x0a\x40\x00\x00\x0c\x00\x00\x28\xaf\x00\x00\x01\x02\x40\x00\x00\x0c\x01\x00\x00\x23\x00\x00\x06\x4f\x80\x00\x00\x10\x00\x00\x28\xaf\x00\x00\x00\x00\x00\x00\x05\xd5\x80\x00\x00\x10\x00\x00\x28\xaf\x00\x00\x00\x00\x00\x00\x09\x65\x80\x00\x00\x12\x00\x00\x28\xaf\x00\x01\x05\x05\x05\x05\x00\x00\x00\x00\x06\x4c\x80\x00\x01\x80\x00\x00\x28\xaf\x00\x00\x05\x8f\xc0\x00\x00\x10\x00\x00\x28\xaf\x00\x00\x00\x0a\x00\x00\x01\xed\x40\x00\x00\x1a\x53\x65\x72\x76\x69\x63\x65\x5f\x53\x65\x6c\x65\x63\x74\x69\x6f\x6e\x31\x00\x00\x00\x00\x01\xe6\x40\x00\x00\x68\x00\x00\x01\x4e\x40\x00\x00\x0e\x00\x01\x01\x01\x01\x01\x00\x00\x00\x00\x01\x5c\x40\x00\x00\x30\x00\x00\x01\x1b\x40\x00\x00\x16\x69\x6e\x74\x65\x6c\x6c\x69\x6e\x65\x74\x2e\x63\x6f\x6d\x00\x00\x00\x00\x01\x25\x40\x00\x00\x0f\x73\x65\x72\x76\x65\x72\x41\x00\x00\x00\x00\x7d\x40\x00\x00\x1d\x4d\x49\x50\x36\x5f\x48\x6f\x6d\x65\x5f\x4c\x69\x6e\x6b\x5f\x50\x72\x65\x66\x69\x78\x00\x00\x00\x00\x00\x02\x58\x80\x00\x00\x26\x00\x00\x28\xaf\x56\x69\x73\x69\x74\x65\x64\x5f\x4e\x65\x74\x77\x6f\x72\x6b\x5f\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72\x00\x00\x00\x00\x05\xc0\xc0\x00\x00\xb8\x00\x00\x28\xaf\x00\x00\x01\xed\x40\x00\x00\x1a\x53\x65\x72\x76\x69\x63\x65\x5f\x53\x65\x6c\x65\x63\x74\x69\x6f\x6e\x31\x00\x00\x00\x00\x01\xe6\x40\x00\x00\x68\x00\x00\x01\x4e\x40\x00\x00\x0e\x00\x01\x01\x01\x01\x01\x00\x00\x00\x00\x01\x5c\x40\x00\x00\x30\x00\x00\x01\x1b\x40\x00\x00\x16\x69\x6e\x74\x65\x6c\x6c\x69\x6e\x65\x74\x2e\x63\x6f\x6d\x00\x00\x00\x00\x01\x25\x40\x00\x00\x0f\x73\x65\x72\x76\x65\x72\x41\x00\x00\x00\x00\x7d\x40\x00\x00\x1d\x4d\x49\x50\x36\x5f\x48\x6f\x6d\x65\x5f\x4c\x69\x6e\x6b\x5f\x50\x72\x65\x66\x69\x78\x00\x00\x00\x00\x00\x02\x58\x80\x00\x00\x26\x00\x00\x28\xaf\x56\x69\x73\x69\x74\x65\x64\x5f\x4e\x65\x74\x77\x6f\x72\x6b\x5f\x49\x64\x65\x6e\x74\x69\x66\x69\x65\x72\x00\x00'

class MMEHSSTrafficRouting(object):
    """ Module handles the functions which is related to test case
    """
    def __init__(self):
        self.regal_api = GetRegal()
        log_mgr_obj = self.regal_api.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger("MMEHSSTrafficRouting")
        self._log.debug(">")
        self.cluster_hepler_obj = ClusterHelper(GetRegal())
        self._current_testcase_config = self.regal_api.get_current_test_case_configuration()
        self._current_testcase_config = self._current_testcase_config.get_test_case_config()
        self._test_run_duration = int(self._current_testcase_config["TestRunDuration"])
        self._burst = int(self._current_testcase_config["Burst"])
        self._sleep_time = int(self._current_testcase_config["SleepTime"])
        self._buffer_time = int(self._current_testcase_config["BufferTime"])
        self._log.debug("<")

    def calculate_sent_tps(self, duration, sleep_time, burst_size, thread_num=1, total_cli=1):
        """ Method calculate the sent tps

        Args:
            duration(int): Duration which messages are sent
            sleep_time(int): Sleep time between messages to send
            burst_size(int): Size of the messages
            thread_num(int): Number of threads sending traffic
            total_cli(int): Number of client(mme) sending traffic

        Returns:
            None

        Comments:
            1. Method to calculate the tps using tps formula

        """
        self._log.debug(">")
        sent_tps = (1000/sleep_time) * (thread_num) * (total_cli) * burst_size
        self._log.info("Overall sent TPS : {:.2f}".format(sent_tps))
        self._log.debug("<")

    def send_message(self):
        """ Method trigger the request to MME to send the traffic to HSS

        Returns:
            None

        Comments:
            1. Method send the ULR buffer to the MME application.
            2. MME application encode the ULR Message and send it to
            Loadbalancer application with given DURATION, BRUST and SLEEP_TIME

        """
        self._log.debug(">")
        self.cluster_hepler_obj.send_msg(Constants.WORKER_NODE1, TCConstants.MME_PORT,
                self._burst,
                self._sleep_time, self._test_run_duration, REQUEST_BUFF)
        self._log.debug("<")

    def _get_hss_pod_names(self):
        """ Method return the all hss pods in the cluster

        Returns:
            list: list of hss pod names

        Comments:
            1. Get the hss pod objects from workernode2 and workernode3 of
            cluster.
            2. From hss pod objects get the pod names and return the all hss
            pod names on the cluster

        """
        self._log.debug(">")
        pods_obj = []
        pod_names = []
        pods_obj = self.cluster_hepler_obj.verify_and_get_scheduled_pods(Constants.WORKER_NODE2,
                Constants.RELEASE_NAME, Constants.HSS_SERVICES)
        pods_obj.extend(self.cluster_hepler_obj.verify_and_get_scheduled_pods(Constants.WORKER_NODE3,
            Constants.RELEASE_NAME, Constants.HSS_SERVICES))
        for pod_obj in pods_obj:
            pod_names.append(pod_obj.get_resource_name())
        self._log.info("The hss pods on cluster are %s", pod_names)
        self._log.debug("<")
        return pod_names

    def reset_counter(self):
        """ Method trigger the request to MME and HSS to reset the stats before sending traffic to HSS

        Returns:
            None

        Comments:
            1. Send http request to 1 instance of MME to set the sent and
            recevied stats count to zero.
            2. Send http request to 4 instance of HSS to set the sent and
            recevied stats count to zero

        """
        self._log.debug(">")
        self._log.info("Intializing stats count to 0 in mme")
        self.cluster_hepler_obj.reset_counter(Constants.WORKER_NODE1, TCConstants.MME_PORT)
        self._log.info("Successfully set stats count to 0 in mme")

        self._log.info("Intializing stats count to 0 in hss")
        pod_names = self._get_hss_pod_names()

        while len(pod_names) > 0:
            pod_name = self.cluster_hepler_obj.reset_counter(Constants.WORKER_NODE2, TCConstants.HSS_PORT)
            if pod_name in pod_names:
                self._log.info("Successfully reseted the ULA and ULR count to 0 in hss pod <%s>",pod_name)
                pod_names.remove(pod_name)
        self._log.info("Successfully set stats count to 0 in all hss pods")
        self._log.debug("<")

    def claculate_hss_ula_ulr_count(self):
        """ Method calculate the total ula and ula transcation count

        Return:
            None

        Comments:
            1. Calculate the total ULR messages recevied and ULA messages sent
            in the 4 instances of HSS

        """
        self._log.debug(">")
        pod_names = self._get_hss_pod_names()
        sent_count = 0
        recv_count = 0
        while len(pod_names) > 0:
            sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE2, TCConstants.HSS_PORT)
            self._log.info("HSS < {} > ULA sent count: {}, ULR received count:\
                    {} on node {}". format(pod_name, sent, received, Constants.WORKER_NODE2))
            if pod_name in pod_names:
                pod_names.remove(pod_name)
                sent_count = sent_count + sent
                recv_count = recv_count + received

        self._log.info("HSS total ULR Recevied count: %s, ULA Sent count: %s", recv_count, sent_count)
        self._log.debug("<")

    def get_status(self):
        """ Method get the status of the stats sent and recevied

        Returns:
            sent, recevied: sent and recevied message count

        Comments:
            1. Get the status of ULR sent and ULA recevied count in the 1 MME
            instance for every 10 seconds
            2. Get the status of ULR received and ULA sent count in the 4 HSS
            instance for every 10 seconds

        """
        self._log.debug(">")
        self._log.info("Sending Diameter traffic from mme to hss")
        end_time = time.time() + self._test_run_duration + self._buffer_time
        while time.time() < end_time:
            sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE1, TCConstants.MME_PORT)
            self._log.info("MME < {} > ULR sent count: {}, ULA received count:\
                         {} on node {}". format(pod_name, sent, received, Constants.WORKER_NODE1))

            sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE2, TCConstants.HSS_PORT)
            self._log.info("HSS < {} > ULA sent count: {}, ULR received count:\
                    {}". format(pod_name, sent, received))

            sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE2, TCConstants.HSS_PORT)
            self._log.info("HSS < {} > ULA sent count: {}, ULR received count:\
                    {}". format(pod_name, sent, received))

            sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE2, TCConstants.HSS_PORT)
            self._log.info("HSS < {} > ULA sent count: {}, ULR received count:\
                    {}". format(pod_name, sent, received))

            sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE2, TCConstants.HSS_PORT)
            self._log.info("HSS < {} > ULA sent count: {}, ULR received count:\
                    {}". format(pod_name, sent, received))

            #sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE3, TCConstants.HSS_PORT)
            #self._log.info("HHS-2 < {} > ULA sent count: {}, ULR received count:\
            #        {} on node {}". format(pod_name, sent, received, Constants.WORKER_NODE3))

            time.sleep(10)

        sent, received, pod_name = self.cluster_hepler_obj.get_status(Constants.WORKER_NODE1, TCConstants.MME_PORT)
        self._log.info("Diameter traffic is stopped")
        if sent != received:
            self._log.debug("<")
            raise exception.SentRcvdMesgsCountNotEqual("ULR sent count:\
                    {} not matching with ULA received count:\
                    {}".format(sent, received))
        self._log.info("MME < {} > ULR sent count: {}, ULA received count:\
                    {} on node {}". format(pod_name, sent, received, Constants.WORKER_NODE1))
        self.claculate_hss_ula_ulr_count()
        self._log.debug("<")
        return sent, received

    def _apply_configuration(self):
        """Method used to setup the stats

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.info("Apply stats configuration on all nodes is inprogress")
        self.cluster_hepler_obj.apply_configuration()
        self._log.info("Successfully applied stats configurations on all nodes")
        self._log.debug("<")

    def execute_test(self):
        """ logic to execute the test case

        Comments:
            1. Update the current deployment state
            2. Reset the stats in both MME and HSS application
            3. Send traffic from MME to HSS
            4. Get the stats status from both MME and HSS applications for
            every 10 seconds
            5. Calculate the sent tps.

        """
        self._log.debug(">")
        self._log.info("Starting test execution")
        self._apply_configuration()
        self._log.info("Setup stats successful on all nodes")
        try:
            self.cluster_hepler_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)

            pod_objs = self.cluster_hepler_obj.verify_and_get_scheduled_pods(
                Constants.WORKER_NODE1, Constants.RELEASE_NAME,
                Constants.MME_SERVICES)

            self.reset_counter()
            self.cluster_hepler_obj.start_stats()
            self.cluster_hepler_obj.check_stats()
            self._log.info("Successfully started stats on all nodes")
            self.send_message()
            sent, received = self.get_status()
            self.calculate_sent_tps(self._test_run_duration, self._sleep_time, self._burst)

            self._log.info("Successfully executed the test case")
        except (Exception, exception.PodsScheduleTimeOut, exception.PodsNotScheduled, exception.SentRcvdMesgsCountNotEqual) as error:
            self._log.error(error)
            trace_back = traceback.format_exc()
            self._log.error(trace_back)
            self._log.debug("<")
            raise exception.TestcaseError(str(error))
        finally:
            self.cluster_hepler_obj.stop_stats()
            self._log.info("Successfully stopped stats on all nodes")
            self._log.debug("<")

def execute():
    """ Execution starts from this method """
    test = MMEHSSTrafficRouting()
    test.execute_test()
    test = None
