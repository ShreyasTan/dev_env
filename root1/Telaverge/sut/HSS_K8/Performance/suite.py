""" Module to perform the pre checks and post checks
    1. before suite and test case execution.
    2. after suite and test case execution
"""
import sys
import time
import json
import traceback

class Constants:
    """ Constants class """
    WORKER_NODE1 = "worker01"
    WORKER_NODE2 = "worker02"
    WORKER_NODE3 = "worker03"
    MASTER_NODE1 = "master01"

    HSS_SERVICES = "hss"
    MME_SERVICES = "mme"
    RELEASE_NAME = "mmehss-4node-release"
    HSS_NODE_POD_COUNT = 2
    HSS_TOTAL_POD_COUNT = 4
    NAMESPACE = "mme-hss"
    HSS_DEPLOYMENT_NAME = "hss"
    MONITOR_TIME = 60
    POD_TERMINATION_TIME = 90


def before_suite():pass

def after_suite():pass

from test_executor.test_executor.utility import GetRegal
sys.path.append("/opt/regal/product/")
from Telaverge.helper.cluster_helper import ClusterHelper
import Telaverge.helper.helper_exception as exception

regal_api = GetRegal()
log_mgr_obj = regal_api.get_log_mgr_obj()
log = log_mgr_obj.get_logger("before_testcase")
cluster_helper_obj = ClusterHelper(GetRegal())

def update_resource_state_with_intervals(total_wait_time=100, intervals=4):
    """ Method to update resources events for given total time after
    every interval

    Args:
        total_wait_time(int): total wait time for which updating of resource should
                             happen (default 100 s)
        intervals(int): After every interval update happens

    Retuns:
        None

    """
    log.debug(">")
    log.info("Updating resources with help of resource events from cluster "\
             "for %s's duation with interval of %s's", str(total_wait_time), str(intervals))
    end_time = time.time() + total_wait_time
    while end_time > time.time():
        time.sleep(intervals)
        cluster_helper_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)
    log.info("Updated resources with latest info")
    log.debug("<")

def wait_for_pod_termination(node_name, micro_service_name):
    """
    """
    log.debug(">")
    pod_objs = cluster_helper_obj.verify_and_get_scheduled_pods(node_name,
            Constants.RELEASE_NAME, micro_service_name)
    log.info("Checking termination state of %s %s pods on node %s", len(pod_objs), micro_service_name, node_name)
    count = len(pod_objs)
    pods_name = []
    end_time = Constants.POD_TERMINATION_TIME + time.time()
    while count:
        cluster_helper_obj.get_deployment_object().update_resource_state(Constants.RELEASE_NAME)
        for pod_obj in pod_objs:
            try:
                pod_obj.check_is_deleted()
                log.info("%s pod is been montring for termination", pod_obj.get_resource_name())
            except K8Exception.DeletedResource as ex:
                pods_name.append(pod_obj.get_resource_name())
                log.info("%s pod <%s> is Terminated", micro_service_name, pod_obj.get_resource_name())
                count = count - 1
            time.sleep(5)
        if end_time < time.time():
            log.warning("The %s pods on node %s are not terminated", micro_service_name, node_name)
            return False
    log.info("%s Pods %s on node %s are terminated successfully", micro_service_name, pods_name, node_name)
    log.debug("<")


def get_pods(node_name, release_name, microservice_name):
    """ Method returns the pods on the given for given micro service

    Args:
        node_name(str): name of the node
        release_name(str): Release name of the deployment
        microservice_name(str): The service name

    Returns:
        list: List pod objects

    """
    log.debug(">")
    try:
        cluster_helper_obj.get_deployment_object().update_resource_state(release_name)
        pod_objs = cluster_helper_obj.verify_and_get_scheduled_pods(node_name,
                release_name, microservice_name)
        log.debug("<")
        return pod_objs
    except Exception as ex:
        log.warning("%s", ex)
        log.warning("trace back: %s", traceback.format_exc())
        log.debug("<")
        return []

def monitor_for_hss_pods(node_name, pods_count, content):
    """ Method monitor for te hss pods on given node for specifi
    number of pods

    Args:
        node_name(str): Name of the node
        pods_count(int): number of pods
        content(dict): the replica config

    Returns:
        None

    """
    log.debug(">")
    end_time = time.time() + Constants.MONITOR_TIME
    while time.time() < end_time:
        pods = get_pods(node_name, Constants.RELEASE_NAME, Constants.HSS_SERVICES)
        log.debug("the pods on node %s are %s", node_name, pods)
        if len(pods) == pods_count:
            break
        time.sleep(5)

    if len(pods) != pods_count:
        err_msg = "The pods count not equal to {} after applying replica"\
                   " config {}".format(pods_count, content)
        log.error(err_msg)
        log.debug("<")
        raise exception.PodsNotScheduled(err_msg)
    log.debug("<")


def update_hss_deployment(pod_running_node, pod_shift_node):
    """ Method start the pods on the given node

    Args:
        pod_running_node(str): Node name where pods are running
        pod_shift_node(str): Node name for which pods to be moved

    Retuns:
        None

    """
    log.debug(">")
    body = {"spec" : {"replicas" : 2}}
    content = json.dumps(body)
    cluster_helper_obj.update_deployment(Constants.HSS_DEPLOYMENT_NAME, Constants.NAMESPACE, content)
    monitor_for_hss_pods(pod_running_node, Constants.HSS_NODE_POD_COUNT, content)
    body = {"spec" : {"replicas" : 4}}
    content = json.dumps(body)
    cluster_helper_obj.update_deployment(Constants.HSS_DEPLOYMENT_NAME, Constants.NAMESPACE, content)
    monitor_for_hss_pods(pod_shift_node, Constants.HSS_NODE_POD_COUNT, content)
    log.debug("<")

def check_and_correct_cluster_initial_state():
    """ Method check the is cluster state is correct or not
    before starting the test case

    Retuns:
        None

    """
    log.debug(">")
    log.info("Checking cluster is in initial state")
    w2_hss_pods = get_pods(Constants.WORKER_NODE2, Constants.RELEASE_NAME,
            Constants.HSS_SERVICES)
    w3_hss_pods = get_pods(Constants.WORKER_NODE3, Constants.RELEASE_NAME,
            Constants.HSS_SERVICES)
    if not w2_hss_pods and len(w3_hss_pods) == 4:
        log.info("Cluster is not in initial state")
        log.info("Setting up the cluster to initial state")
        update_hss_deployment(Constants.WORKER_NODE3, Constants.WORKER_NODE2)
        log.info("Successfully setted the cluster to initial state, proceedings with test case")
        return
    if not w3_hss_pods and len(w2_hss_pods) == 4:
        log.info("Cluster is not in initial state")
        log.info("Setting up the cluster to initial state")
        update_hss_deployment(Constants.WORKER_NODE2, Constants.WORKER_NODE3)
        log.info("Successfully setted the cluster to initial state, proceedings with test case")
        return
    log.info("Cluster already in initial state, proceedings with test case")
    log.debug("<")

def before_testcase():
    check_and_correct_cluster_initial_state()
    pass

def after_testcase(): pass
