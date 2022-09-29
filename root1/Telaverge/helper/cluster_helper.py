""" Module used to handle the cluster topology releated API
"""
import time
import requests
import json
from datetime import date, datetime, timedelta
from regal_lib.infra_profile.topology.k8.k8_constants import K8Constants
from regal_lib.corelib.constants import Constants as CommonConstants
from regal_lib.client.ksm.ksm_client.swagger_client.api.k8_resource_api_api import K8ResourceAPIApi
import Telaverge.helper.helper_exception as exception
import regal_lib.corelib.custom_exception as customexception
from Regal.regal_constants import Constants as RegalConstants


class InvalidConfiguration(Exception):
    """ Exception will be thrown when configuration is invalid
    """
    def __init__(self, err_msg):
        super(InvalidConfiguration, self).__init__()
        self._error_msg = err_msg

    def __str__(self):
        """ Return exception string. """
        return "{}".format(self._error_msg)

class InsufficientHelperConfig(Exception):
    """ Exception will be thrown when insufficient configuration key
    """
    def __init__(self, node_name, key):
        super(InsufficientHelperConfig, self).__init__()
        self._key = key
        self._node_name = node_name

    def __str__(self):
        """ Return exception string. """
        return "Key {} for Diameter helper is not configured for node {}".format(
                self._key, self._node_name)

class Constants(object):
    """ Class used to define the constants
    """
    DEPLOYMENT = "Deployment"
    PRE_DEPLOYMENT = "PreDeployment"
    OPERATION_STATUS_INTERVAL_TIME = 5
    RUNNING = "Running"
    GET_NODES_CMD = "kubectl get nodes"
    ACCESS_DENIED_MSG_1 = "was refused - did you specify the right host or port"
    ACCESS_DENIED_MSG_2 = "Unable to connect to the server: dial tcp"
    KEEPALIVED = "keepalived"
    MME_PORT = "30600"

class ClusterHelper(object):
    """ class defined as wrapper to access the k8 and cluster topology objects
    """
    def __init__(self, service_store_obj):
        self.service_store_obj = service_store_obj
        log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = log_mgr_obj.get_logger(self.__class__.__name__ )
        self._log.debug(">")
        self._config = None
        self._stats_mgr = self.service_store_obj.get_stat_mgr_obj()
        self.child_topology_obj = self.service_store_obj.get_current_run_topology()
        self.parent_topology_obj = self.child_topology_obj.get_parent_topology_obj()
        self.child_topology_name = self.child_topology_obj.get_topology_name()
        self.parent_topology_name = self.parent_topology_obj.get_topology_name()
        self.k8_config_obj = self.child_topology_obj.get_config_obj()
        self.hypervisor_manager_obj = self.service_store_obj.get_hypervisor_mgr_obj()
        self.nodes_list = self.parent_topology_obj.get_node_list()
        for node_obj in self.nodes_list:
            self.service_store_obj.get_login_session_mgr_obj().create_session(node_obj, 1, node_obj.get_name())
        self._log.debug("<")

    def __del__(self, service_store_obj):
        for node_obj in self.nodes_list:
            self.service_store_obj.get_login_session_mgr_obj().close_session(node_obj.get_name())

    def __new__(cls, service_store_obj):
        if not hasattr(cls, 'instance'):
            cls.instance = super(ClusterHelper, cls).__new__(cls)
        return cls.instance

#    def _get_machine_object(self, management_ip):
#        """ Method retun the machine objcet for the
#        given management ip
#
#        Args:
#            management_ip(str): IP Address of the machine
#
#        Retuns:
#            instance: Machine object instance(AWS, AZURE or Local)
#
#        """
#        self._log.debug("> Getting machine object for ip %s", management_ip)
#        machine_obj = GetRegal().GetMachinePoolMgr().get_machine_obj_by_ip(management_ip)
#        self._log.debug("< ")
#        return machine_obj

    def get_cluster_topology_machine_source(self):
        """ Method return the machine source of the cluster
        topology

        Returns:
            str: Machine source of the topology(AWS, AZURE, LOCAL)

        """
        self._log.debug(">")
        topology_obj = self.get_parent_topology()
        machine_source = topology_obj.get_machine_category()
        self._log.debug(" < Machine source foe topology %s is %s",
                        topology_obj.get_topology_name(), machine_source)
        return machine_source

    def get_child_topology(self):
        """ Method to return the child topology object
        that is current running topology object

        Returns:
            instance: Object of the topology

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.child_topology_obj

    def get_parent_topology(self):
        """ Method to return the parent topology object
        that is current running topology object

        Returns:
            instance: Object of the topology

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.parent_topology_obj

    def get_child_topology_name(self):
        """ Method to return the child topology name
        that is current running topology object

        Returns:
            instance: name of the topology

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.child_topology_name

    def get_parent_topology_name(self):
        """ Method to return the parent topology name
        that is current running topology object

        Returns:
            instance: name of the topology

        """
        self._log.debug(">")
        self._log.debug("<")
        return self.parent_topology_name

    def get_deployment_object(self):
        """ Method to return the deployment(application) object

        Returns:
            instance: Object of Deployment

        """
        self._log.debug(">")
        self._log.debug("Getting deployment object for topology %s",
                       self.child_topology_name)
        deployment_obj = self.k8_config_obj.get_deployment_obj()
        self._log.debug("Deployment object for topology %s is %s",
                       self.child_topology_name, deployment_obj)
        self._log.debug("<")
        return deployment_obj

    def get_pre_deployment_object(self):
        """ Method to return the PreDeployment(platform) object

        Returns:
            instance: Object of PreDeployment

        """
        self._log.debug(">")
        self._log.debug("Getting PreDeployment object for topology %s",
                        self.child_topology_name)
        pre_deployment_obj = self.k8_config_obj.get_pre_deployment_obj()
        self._log.debug("PreDeployment object for topology %s is %s",
                       self.child_topology_name, pre_deployment_obj)
        self._log.debug("<")
        return pre_deployment_obj

    def get_releases(self, platfrom_kind):
        """ Method to get the releases on particular deployment object

        Returns:
            dict: Dict of release name and object

        """
        self._log.debug(">")
        if platfrom_kind == Constants.PRE_DEPLOYMENT:
            deployment_obj = self.get_pre_deployment_object()
        elif platfrom_kind == Constants.DEPLOYMENT:
            deployment_obj = self.get_deployment_object()
        self._log.debug("Getting releases for topology %s",
                       self.child_topology_name)
        releases = deployment_obj.get_releases()
        self._log.debug("Releases for topology %s are %s",
                       self.child_topology_name, releases)
        self._log.debug("<")
        return releases

    def get_microservices(self, release_name, platfrom_kind):
        """ Method to get the all micro services objects dict
        of given release_name

        Args:
            release_name(str): Name of the release

        Returns:
            dict: Dictionary of microservice name and there objects

        """
        self._log.debug(">")
        self._log.debug("Getting micro services for topology %s of release %s",
                       self.child_topology_name, release_name)
        microservices = self.get_releases(platfrom_kind)[release_name].get_micro_services()
        self._log.debug("Micro services for topology %s of release %s are %s",
                       self.child_topology_name, release_name, microservices)
        self._log.debug("<")
        return microservices

    def get_microservice(self, release_name, microservice_name, platfrom_kind):
        """ Method to get the micro service object for the given micro
        service name under given release name

        Args:
            release_name(str): Name of the release
            microservice_name(str): Name of the micro service

        Returns:
            instance: Object of the MicroService

        """
        self._log.debug(">")
        self._log.debug("Getting micro service object for micro service %s,"\
                       " of release %s for topology %s", microservice_name, release_name,
                       self.child_topology_name)
        microservice_obj = self.get_microservices(release_name, platfrom_kind)[microservice_name]
        self._log.debug("microservice object is %s for microservice name %s of release %s"\
                       " for topology %s", microservice_obj, microservice_name,
                       release_name, self.child_topology_name)
        self._log.debug("<")
        return microservice_obj


    def get_pods_for_microservice(self, release_name, microservice_name,
                                  platfrom_kind):
        """ Method to get the pod resource obj of given release name and micro
        service name

        Args:
            release_name(str): Name of the release
            microservice_name(str): Name of the micro service

        Returns:
            list: list of the pod resource objects

        """
        self._log.debug(">")
        self._log.debug("Getting PODs resource objects of release %s and"\
                       " microservice %s of topology %s",
                       release_name, microservice_name, self.child_topology_name)
        pod_objs = self.get_microservice(release_name, microservice_name,
                                         platfrom_kind).get_resource("Pod")
        self._log.debug("PODs resource objects of release %s and "\
                       "micro service %s of topology %s are %s", release_name,
                       microservice_name, self.child_topology_name, pod_objs)
        self._log.debug("<")
        return pod_objs

    def get_filtered_pods(self, pods_list, node_name):
        """ Method to filter the given pod resource object based
        on the given node name

        Args:
            pods_list(lit): List of pods objects
            node_name(str): Name of the node

        Returns:
            list: List of pod obj

        """
        self._log.debug(">")
        self._log.debug("Filtering PODs %s for node %s",
                        pods_list, node_name)
        pod_objs = []
        for pod in pods_list:
            if pod.get_node_name() == node_name:
                pod_objs.append(pod)
        self._log.debug("PODs belongs to node %s are %s", node_name, pod_objs)
        self._log.debug("<")
        return pod_objs

    def get_management_ip(self, node_name):
        """ Method to get the management ip for the given node name
        from the reference topology object

        Args:
            node_name(str): Name of the node

        Returns:
            str: ip of the given node

        """
        self._log.debug(">")
        node_obj = self.parent_topology_obj.get_node(node_name)
        management_ip = node_obj.get_management_ip()
        self._log.debug("Mangement IP for node %s is %s", node_name,
                        management_ip)
        self._log.debug("<")
        return management_ip

    def start_node(self, node_name):
        """ Method to start the vm with the given name

        Args:
            node_name(str): Name of the node

        Returns:
            None

        """
        self._log.debug(">")
        self._log.info("Starting node %s", node_name)
        management_ip = self.get_management_ip(node_name)
        machine_source = self.get_cluster_topology_machine_source()
        if machine_source == CommonConstants.LOCAL_MACHINE:
            self.hypervisor_manager_obj.start_VM(management_ip)
        #elif machine_source == CommonConstants.AWS_MACHINE:
            #machine_obj = self._get_machine_object(management_ip)
            #machine_obj.start_machine()
        while True:
            if self.is_machine_running(node_name):
                break
        self._log.info("Started node %s", node_name)
        self._log.debug("<")

    def is_machine_running(self, node_name):
        """ method to check whether machine is running or not

        Args:
            node_name(str): Name of the node

        Returns:
            boolean(True/False)

        """
        self._log.debug(">")
        self._log.debug("Getting the status of node %s", node_name)
        management_ip = self.get_management_ip(node_name)
        machine_source = self.get_cluster_topology_machine_source()
        if machine_source == CommonConstants.LOCAL_MACHINE:
            boolean = self.hypervisor_manager_obj.is_domain_running(management_ip)
        #elif machine_source == CommonConstants.AWS_MACHINE:
            #machine_obj = self._get_machine_object(management_ip)
            #instance_id = machine_obj.get_instance_id()
            #boolean = machine_obj._aws_platform.is_instance_started(instance_id)
        self._log.debug("<")
        return boolean

    def is_machine_stopped(self, node_name):
        """ method to check whether machine is stopped or not

        Args:
            node_name(str): Name of the node

        Returns:
            boolean(True/False)

        """
        self._log.debug(">")
        self._log.debug("Getting the status of node %s", node_name)
        management_ip = self.get_management_ip(node_name)
        machine_source = self.get_cluster_topology_machine_source()
        if machine_source == CommonConstants.LOCAL_MACHINE:
            boolean = self.hypervisor_manager_obj.is_domain_shutoff(management_ip)
        #elif machine_source == CommonConstants.AWS_MACHINE:
            #machine_obj = self._get_machine_object(management_ip)
            #instance_id = machine_obj.get_instance_id()
            #boolean = machine_obj._aws_platform.is_instance_stopped(instance_id)
        self._log.debug("<")
        return boolean

    def stop_node(self, node_name):
        """ Method to stop the vm with the given name

        Args:
            node_name(str): Name of the node

        Returns:
            None

        """
        self._log.debug(">")
        self._log.info("Stopping node %s", node_name)
        management_ip = self.get_management_ip(node_name)
        machine_source = self.get_cluster_topology_machine_source()
        if machine_source == CommonConstants.LOCAL_MACHINE:
            self.hypervisor_manager_obj.stop_VM(management_ip)
        #elif machine_source == CommonConstants.AWS_MACHINE:
            #machine_obj = self._get_machine_object(management_ip)
            #machine_obj.stop_machine()
        self._log.info("Stopped node %s", node_name)
        self._log.debug("<")

    def reboot_node(self, node_name):
        """ Method to reboot the vm with the given name

        Args:
            node_name(str): Name of the node

        Returns:
            None

        """
        self._log.debug(">")
        self._log.info("Rebooting node %s", node_name)
        management_ip = self.get_management_ip(node_name)
        machine_source = self.get_cluster_topology_machine_source()
        if machine_source == CommonConstants.LOCAL_MACHINE:
            self.hypervisor_manager_obj.reboot_VM(management_ip)
        #elif machine_source == CommonConstants.AWS_MACHINE:
            #machine_obj = self._get_machine_object(management_ip)
            #machine_obj.reboot_machine()
        self._log.info("Rebooted node %s", node_name)
        self._log.debug("<")

    def get_pods_on_node(self, release_name, microservice_name, node_name,
                         platfrom_kind=Constants.DEPLOYMENT):
        """ Method to get the pod resource objects for the given release name,
        microservice name for given nodename

        Args:
            release_name(str): Name of the release
            microservice_name(str): Name of the micro service
            node_name(str): Node name

        Returns:
            list: resources of type pod.

        """
        self._log.debug(">")
        pod_objs = self.get_pods_for_microservice(release_name,
                                                  microservice_name,
                                                  platfrom_kind)
        pod_objs = self.get_filtered_pods(pod_objs, node_name)
        self._log.debug("<")
        return pod_objs

    def get_node_pods(self, node_name, release_name,
                      platfrom_kind=Constants.DEPLOYMENT):
        """
        """
        self._log.debug(">")
        self._log.debug("Getting the pod object for the node %s of kind"\
                        " %s and release %s", node_name, platfrom_kind,
                        release_name)
        if platfrom_kind == Constants.DEPLOYMENT:
            deploy_obj = self.get_deployment_object()
        elif platfrom_kind == Constants.PRE_DEPLOYMENT:
            deploy_obj = self.get_pre_deployment_object()

        release_obj = deploy_obj.get_releases(release_name)
        microservice_obj_dict = release_obj.get_micro_services()
        node_pods = []
        for microservice_name, microservice_obj in list(microservice_obj_dict.items()):
            pod_resource_objs = microservice_obj.get_resources()["Pod"]
            for pod_obj in pod_resource_objs:
                pod_node_name = pod_obj.get_node_name()
                if pod_node_name != node_name:
                    continue
                node_pods.append(pod_obj)
        self._log.debug("Pod object for the node %s of kind"\
                        " %s and release %s are  %s", node_name, platfrom_kind,
                        release_name, node_pods)
        return node_pods

    def retry_execute_command_on_pod(self, pod_obj, command, max_retry=4):
        """ Method to retry command on pod
        Args:
            pod_obj(object):
            command(list): list of commands
            max_retry(int) : maximum retry
        """
        self._log.debug(">")
        retry_count = 1
        while True:
            try:
                output = pod_obj.execute_command(K8Constants.CMD_EXEC, command)
                self._log.debug("<")
                return output
            except Exception as err:
                if retry_count > max_retry:
                    self._log.debug("<")
                    raise err
                retry_count = retry_count + 1
                self._log.debug("Retrying for %s time to execute command %s on pod_obj %s",
                                str(retry_count), str(command), str(pod_obj))
                continue

    def get_pod_obj_by_name(self, release_name, pod_name, platform_kind):
        """ Method get the pod objevt from the pod name

        Args:
            release_name(str): Name of the release
            pod_name(str): Name of the pod
            platform_kind(str): Kind of the platform

        Returns:
            instance: Object of the pod

        """
        self._log.debug(">")
        release_obj_dict = self.get_releases(platform_kind)
        release_obj = release_obj_dict[release_name]
        microservice_obj_dict = release_obj.get_micro_services()
        for microservice_name, microservice_obj in list(microservice_obj_dict.items()):
            pod_obj_list = microservice_obj.get_resource("Pod")
            for pod_obj in pod_obj_list:
                resource_name = pod_obj.get_resource_name()
                if pod_name == resource_name:
                    self._log.debug("<")
                    return pod_obj
        err_msg = "Resource object of with name {} not found under given"\
                  " release {} and for platform {}".format(pod_name, release_name,
                                                           platform_kind)
        self._log.error(err_msg)
        self._log.debug("<")

    def delete_pod(self, release_name, pod_name,
                   platform_kind=Constants.DEPLOYMENT):
        """ Method delete the pod.

        Args:
            release_name(str): Name of the relase
            pod_name(str): Name of the pod
            platform_kind(str): Kind of the platform

        Returns:
            None

        """
        self._log.debug(">")
        pod_obj = self.get_pod_obj_by_name(release_name, pod_name,
                                           platform_kind)
        output = pod_obj.execute_command(K8Constants.CMD_DELETE)
        self._log.debug("the delete pod %s output is %s", pod_name, output)
        self._log.debug("<")

    def execute_command_on_pod(self, release_name, pod_name,
                   command, platform_kind=Constants.DEPLOYMENT):
        """ Method execute given command on the pod.

        Args:
            release_name(str): Name of the relase
            pod_name(str): Name of the pod
            platform_kind(str): Kind of the platform


        Returns:
            None

        """
        self._log.debug(">")
        pod_obj = self.get_pod_obj_by_name(release_name, pod_name,
                                           platform_kind)
        output = pod_obj.execute_command(K8Constants.CMD_EXEC, command)
        self._log.debug("the output of command %s execution on pod %s output"\
                        " is %s", command, pod_name, output)
        self._log.debug("<")


    def get_specific_pod_objs_by_name(self, release_name, platfrom_kind,
                                     pod_name):
        """ Method return the name of the rook-ceph-tools pod name

        Args:
            release_name(str): Name of the reelase
            platfrom_kind(str): Kind of the platform
            pod_name(str): Name of the pod

        Returns:
            list: list of Object of the pod

        """
        self._log.debug(">")
        release_obj_dict = self.get_releases(platfrom_kind)
        release_obj = release_obj_dict[release_name]
        microservice_obj_dict = release_obj.get_micro_services()
        rook_ceph_tool_pods = []
        for microservice_name, microservice_obj in list(microservice_obj_dict.items()):
            pod_obj_list = microservice_obj.get_resource("Pod")
            for pod_obj in pod_obj_list:
                resource_name = pod_obj.get_resource_name()
                if pod_name in resource_name:
                    self._log.debug("the pod obj name start with given pod"\
                                    "name %s is %s", pod_name, resource_name)
                    rook_ceph_tool_pods.append(pod_obj)

        if not rook_ceph_tool_pods:
            err_msg = "Resource object of rook-ceph-tool not found under given"\
                      " release {} and for platform {}".format(release_name,
                                                               platfrom_kind)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.PodNotFound(err_msg)
        self._log.debug("<")
        return rook_ceph_tool_pods

        #for pod_obj in rook_ceph_tool_pods:
        #    try:
        #        pod_obj.check_is_deleted()
        #        self._log.debug("<")
        #        return pod_obj
        #    except customexception.DeletedResource as ex:
        #        #self._log.warning(str(ex))
        #        self._log.debug(str(ex))
        #err_msg = "All pods of with name %s are deleted", pod_name
        #raise exception.PodNotFound(err_msg)

    def get_specific_pod_obj_by_name(self, release_name, platfrom_kind,
                                     pod_name):
        """ Method return the name of the rook-ceph-tools pod name

        Args:
            release_name(str): Name of the reelase
            platfrom_kind(str): Kind of the platform
            pod_name(str): Name of the pod

        Returns:
            list: list of Object of the pod

        """
        self._log.debug(">")
        pod_objs = self.get_specific_pod_objs_by_name(release_name,
                platfrom_kind, pod_name)
        for pod_obj in pod_objs:
            try:
                pod_obj.check_is_deleted()
                self._log.debug("<")
                return pod_obj
            except customexception.DeletedResource as ex:
                self._log.warning(str(ex))
                self._log.debug(str(ex))
        err_msg = "All pods of with name %s are deleted", pod_name
        raise exception.PodNotFound(err_msg)

    def _get_cluster_node_os_obj(self, node_name):
        """ Method return the os object of the given node from the
        cluster topology

        Args:
            node_name(str): Name of the node


        Returns:
            instance: os Object

        """
        self._log.debug(">")
        topology_obj = self.get_parent_topology()
        node_objs = topology_obj.get_node_list()
        node_object = None
        for node_obj in node_objs:
            if node_obj.get_name() == node_name:
                node_object = node_obj

        if not node_object:
            err_msg = "Node with given name {} is not present in the topology"\
                      " {}".format(node_name, topology_obj.get_topology_name())
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.NodeNotFound(err_msg)
        os_obj = node_object.get_os()
        self._log.debug("<")
        return os_obj

    def start_cluster_service(self, node_name, service_name):
        """ Method the start the given service on the given cluster node

        Args:
            node_name(str): Name of the node
            service_name(str): Name of the service

        Returns:
            None

        """
        self._log.debug(">")
        self._log.info("Starting the service %s on node %s", service_name,
                node_name)
        os_obj = self._get_cluster_node_os_obj(node_name)
        status = os_obj.start_service(service_name, tag=node_name)
        if not status:
            err_msg = "Failed to start the service {} on node"\
                      " {}".format(service_name, node_name)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.FailedToStartService(err_msg)
        self._log.info("Successfully started the service %s on node %s", service_name,
                node_name)
        self._log.debug("<")

    def stop_cluster_service(self, node_name, service_name):
        """ Method the stop the given service on the given cluster node

        Args:
            node_name(str): Name of the node
            service_name(str): Name of the service

        Returns:
            None

        """
        self._log.debug(">")
        self._log.info("Stoping the service %s on node %s", service_name,
                node_name)
        os_obj = self._get_cluster_node_os_obj(node_name)
        if service_name == "haproxy" or "keepalived":
            commad = "systemctl stop {}".format(service_name)
            self.execute_command_on_cluster_node(node_name,
                                                 commad)
            status = True
            #commad = "ps -eaf | grep '{}' | wc -l".format(service_name)
            #output = self.execute_command_on_cluster_node(node_name,
            #        commad)

        else:
            status = os_obj.stop_service(service_name, tag=node_name)
        if not status:
            err_msg = "Failed to stop the service {} on node"\
                      " {}".format(service_name, node_name)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.FailedToStopService(err_msg)
        self._log.info("Successfully stopped the service %s on node %s", service_name,
                node_name)
        self._log.debug("<")

    def check_cluster_service_running(self, node_name, service_name):
        """Method return the status of the given service

        Args:
            node_name(str): Name of the node
            service_name(str): Name of the service

        Returns:
            str: ouput of service status

        """
        self._log.debug(">")
        os_obj = self._get_cluster_node_os_obj(node_name)
        shell_output = os_obj.get_service_status(service_name, tag=node_name)
        if "active (running)" not in shell_output:
            err_msg = "The service {} on node {} is not "\
                      " running".format(service_name, node_name)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.ServiceNotRunning(err_msg)
        self._log.debug("<")

    def enable_and_start_cluster_service(self, node_name, service_name):
        """ Method enable and start the given service and nodename

        Args:
            node_name(str): Name of the node
            service_name(str): Name of the service

        Retuns:
            None

        """
        self._log.debug(">")
        os_obj = self._get_cluster_node_os_obj(node_name)
        enable_cmd = "systemctl enable {}".format(service_name)
        self.execute_command_on_cluster_node(node_name, enable_cmd)
        shell_output = os_obj.start_service(service_name, tag=node_name)
        if not shell_output:
            err_msg = "The service {} on node {} is failed not "\
                      " running".format(service_name, node_name)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.ServiceNotRunning(err_msg)

        self._log.debug("<")

    def execute_command_on_cluster_node(self, node_name, commad):
        """ Method execute the command on the node

        Args:
            node_name(str): Name of the node
            commad(str): Command need to be executed

        Retuns:
            str: output of the command

        """
        self._log.debug(">")
        os_obj = self._get_cluster_node_os_obj(node_name)
        cmd_output = os_obj.execute_shell_command(commad, tag=node_name)
        self._log.debug("<")
        return cmd_output

    def get_configured_cluster_vip(self, node_name, app_name):
        """ Method get the virtual ip configured in the topology
        for the given node

        Args:
            node_name(str): Name of the node

        Returns:
            str: vip of the node

        """
        self._log.debug(">")
        os_obj = self._get_cluster_node_os_obj(node_name)
        app_obj = os_obj.platform.get_app(app_name)
        app_info = app_obj.get_app_info()
        virtual_ip = app_info["virtualIP"]
        self._log.debug("The virtual ip for the node %s is %s ", node_name,
                        virtual_ip)
        self._log.debug("<")
        return virtual_ip

    def verify_and_get_scheduled_pods(self, node_name, release_name,
                                      microservice_name):
        """ Method use to check whether pods are scheduled for given
        microservice name

        Args:
            release_name(str): Name of the release
            node_name(str): Name of th node
            microservice_name(str): Name of the micro service

        Returns:
            None

        Raises:
            raise PodsNotScheduled exception if pods are not scheduled

        """
        self._log.debug(">")
        self._log.debug("Getting the %s pods on node %s for relase %s",
                       microservice_name, node_name, release_name)
        pod_objs = self.get_pods_on_node(release_name, microservice_name,
                                         node_name)
        if not pod_objs:
            err_msg = "The {} pods are not scheduled on the node {} of release"\
                  " {}".format(microservice_name, node_name, release_name)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.PodsNotScheduled(err_msg)
        self._log.debug("The %s pods on node %s for release %s are %s",
                       microservice_name, node_name, release_name, pod_objs)
        self._log.debug("<")
        return pod_objs

    def monitor_pods_run_status(self, release_name, microservice_name,
                                pod_objs, monitor_time):
        """Method used to monitor the given pods are in running state or not

        Args:
            release_name(str): Name of the release
            microservice_name(str): Name of the microservice
            pod_objs(list): List of pods objects
            monitor_time(int): Total number of seconds needs to monitor
            pods running status

        Returns:
            None

        Raises:
            PodsScheduleTimeOut exception will be raised if the pods status
            not running within specified time

        """
        self._log.debug(">")
        self._log.info("Monitoring %s pods %s run status",
                       microservice_name, str(pod_objs))

        operation_start_time = time.time()
        while True:
            self.get_deployment_object().update_resource_state(release_name)
            active_pod_count = 0
            for pod_obj in pod_objs:
                status = pod_obj.get_phase()
                if status == Constants.RUNNING:
                    active_pod_count = active_pod_count + 1
            if len(pod_objs) == active_pod_count:
                for pod_obj in pod_objs:
                    self._log.info("%s pod of release %s is Running",
                                pod_obj.get_resource_name(), release_name)
                self._log.debug("<")
                return
            elif (time.time() - operation_start_time) >= monitor_time:
                err_msg = " {} pods are not running phase, time out"\
                          " ocuured".format(microservice_name)
                self._log.error(err_msg)
                self._log.debug("<")
                raise exception.PodsScheduleTimeOut(err_msg)
            time.sleep(Constants.OPERATION_STATUS_INTERVAL_TIME)

    def verify_scheduled_pods(self, node_name, release_name,
                              microservice_names, monitor=False, monitor_time=None):
        """ Method verify the pods are scheduled or not and monitor if monitor
        falg is set

        Args:
            node_name(str): Name of the  node
            release_name(str): Name of the relase
            microservice_names(list): list of microservice names
            monitor(bool): True if need to monitor for pod status

        Retuns:
            None

        """
        self._log.debug(">")
        for microservice_name in microservice_names:
            pod_objs = self.verify_and_get_scheduled_pods(node_name, release_name, microservice_name)
            if monitor:
                self.monitor_pods_run_status(
                    release_name, microservice_name, pod_objs, monitor_time)
        self._log.debug("<")

    def check_service_access(self, node_name):
        """ Method check any service access is allowed oe denied in the
        given node

        Args:
            node_name(str): Name of the node

        Returns:
            None

        Raises:
            ServiceAccessDenied: if service access is denied

        """
        self._log.debug(">")
        self._log.info("Checking cluster access for node %s", node_name)
        try:
            output = self.execute_command_on_cluster_node(
            node_name, Constants.GET_NODES_CMD)
        except customexception.AnsibleException as error:
            if Constants.ACCESS_DENIED_MSG_1 in str(error) or \
            Constants.ACCESS_DENIED_MSG_2 in str(error):
                err_msg = "The service access denied for node {}".format(node_name)
                self._log.error(err_msg)
                self._log.debug("<")
                raise exception.ServiceAccessDenied(err_msg)
            self._log.debug("<")
            raise customexception.AnsibleException(error)
        self._log.info("Able to access cluster services on node %s", node_name)
        self._log.debug("<")

    def check_vip_on_node(self, node_name):
        """ Method check the vip is present on the given node
        or not

        Args:
            node_name(str): Name of the node

        Retuns:
            None

        Raises:
            VIPNotPresent: If vip is not present on the given node

        """
        self._log.debug(">")
        virtual_ip = self.get_configured_cluster_vip(node_name, Constants.KEEPALIVED)
        vip_cmd = "ip address show | grep {}".format(virtual_ip)
        try:
            self.execute_command_on_cluster_node(node_name, vip_cmd)
        except customexception.AnsibleException:
            err_msg = "The virtual ip is not present on the node "\
                      " {}".format(node_name)
            self._log.error(err_msg)
            self._log.debug("<")
            raise exception.VIPNotPresent(err_msg)
        self._log.debug("<")

    def send_msg(self, node_name, port, burst_size, sleep_time, duration,
                 req_buff):
        """Method used to send the message to HSS from MME.
        Will send request to MME node to send the message, Then MME will send
        message to HSSS.

        Args:
            node_name(str): node name
            burst_size(int): Interval time will be set based on the burst size
                             count.
                             Ex: If burst_size=20, after 20 messages will go for
                             sleep.
            sleep_time(int): Sleep time in second
            duration(int): Message will be sent till the duration given.
            req_buff(bytes): request buffer/encoded message in bytes

        Returns:
            None
        """
        self._log.debug(">")
        management_ip = self.get_management_ip(node_name)
        self._log.debug("Sending message to node: '%s' with burst_size: '%d', "\
                        " sleep_time: '%d', duration: '%d'", node_name, burst_size,
                        sleep_time, duration)
        url = \
        "http://{}:{}/send_message?brust_size={}&interval_time={}&duration={}".format(management_ip,
                port,
                burst_size, sleep_time, duration)
        response = requests.post(url, data=req_buff)
        resp = json.loads(response.content)
        self._log.debug("< %s", resp["data"])

    def get_status(self, node_name, port):
        """Method used to get the status for the given node

        Args:
            node_name(str): node name

        Returns:
            int, int: Contains sent message count and recevived message
                 count
        """
        self._log.debug("> Getting status for node: '%s'", node_name)
        management_ip = self.get_management_ip(node_name)
        url = "http://{}:{}/get_status".format(management_ip, port)
        response = requests.get(url)
        resp = json.loads(response.content)
        data = resp["data"]
        self._log.debug("< Sent message is: '%d' and Received message is: '%d'",
                        data[0], data[1])

        return data[0], data[1], data[2]

    def reset_counter(self, node_name, port):
        """Method used to reset the counter for the given node.

        Args:
            node_name(str): node name

        Returns:
            None
        """
        self._log.debug("> Resetting counter for node: '%s'", node_name)
        management_ip = self.get_management_ip(node_name)
        url = "http://{}:{}/reset_counter".format(management_ip,
                port)
        response = requests.post(url)
        resp = json.loads(response.content)
        self._log.debug("< %s", resp["data"])
        return resp["data"]

    def update_deployment(self, deploy_name, name_space, content):
        """ Method call KSM API to set cluster to initial state.

        Args:
            node_name(str): Name of the node
            name_space(str): Name space of deployment
            content(dict): The json data

        Returns:
            None

        """
        self._log.debug(">")
        cluster_name = self.get_deployment_object().get_cluster_name()
        K8ResourceAPIApi().update_deployment_resource_on_cluster(cluster_name,
                deploy_name, name_space, content)
        self._log.debug("<")

    def apply_configuration(self):
        """ This method sets up the stats service rpms in the mapped machine.

        Returns:
            None

        """
        self._log.debug(">")
        self._config = self.service_store_obj.get_current_test_case_configuration()
        for nodes in self.nodes_list:
            node_name = nodes.get_name()
            self._log.info("Setting up the stats on node %s",
                    str(node_name))
            stat_args_dict = {}
            stats_args_dict = self._get_stats_argumnts(node_name)
            self._log.debug("stats_args_dict - %s, node_name - %s", stats_args_dict, node_name)
            stat_args_dict[node_name] = stats_args_dict
            app_obj = self._get_cluster_node_os_obj(node_name).platform.get_app(RegalConstants.STATS_APP_NAME)
            app_obj.apply_configuration(stat_args_dict)
            self._log.info("Set up the stats on nodes %s is successful.",
                    str(node_name))
        self._log.debug("<")

    def get_config_value(self, data_dict, node_name):
        """ This method the titan configuration such as template file
        name and tag_dict.

        Args:
            data_dict(dict): configuration dict.

        Returns:
            str: value of requeted field.

        Raise:
            exception.InvalidConfiguration

        """
        try:
            if data_dict["Type"] == "constant":
                return data_dict["Value"]
        except KeyError as ex:
            raise InvalidConfiguration("{} at node {}".format(ex,
                node_name))

    def _get_stats_argumnts(self, node_name):
        """ This private method returns the stats arguments.
         Args:
            node_name(str): node name.

        Returns:
            dict: arguments of stats.

        Raise:
            InvalidConfiguration

        """
        self._log.debug(">")
        args_dict = {}
        data_dict = self._get_stats_info(node_name)
        self._log.info("Stat_info dict is {}".format(data_dict))
        if "Arguments" in data_dict:
            data_dict = data_dict["Arguments"]
            args_dict = self.get_config_value(data_dict, node_name)
            if not isinstance(args_dict, dict):
                raise InvalidConfiguration(
                        "Excpected a dict type of value for stats arguments of node {}".format(
                            node_name))
        self._log.debug("<")
        return args_dict

    def _get_stats_info(self, node_name):
        """ This private method returns the stats from configuration.
        Args:
            node_name(str): node name.

        Returns:
            dict: complete stats information.

        Raise:
            InsufficientHelperConfig
            InvalidConfiguration

        """
        self._log.debug(">")
        node_config = self._config.get_test_case_config(node_name)
        if node_config != '-NA-':
            if "StatsInfo" in node_config:
                self._log.debug("<")
                return node_config["StatsInfo"]
            else:
                self._log.debug("<")
                raise InsufficientHelperConfig(node_name, "StatsInfo")
        else:
            self._log.debug("<")
            raise InsufficientHelperConfig(node_name, node_name)

    def start_stats(self):
        """ This method starts the stats service script in the mapped machine.

        Returns:
            None

        """
        self._log.debug(">")
        for nodes in self.nodes_list:
            node_name = nodes.get_name()
            all_stats_list = self._get_stats_list(node_name)
            app_obj = self._get_cluster_node_os_obj(node_name).platform.get_app(RegalConstants.STATS_APP_NAME)
            app_obj.start_service(all_stats_list)
            self._log.info("Started the stats successfully on node %s", str(node_name))
        self._log.debug("<")

    def check_stats(self):
        """ This method check the stats service script in the mapped machine.

        Returns:
            None

        """
        self._log.debug(">")
        for nodes in self.nodes_list:
            node_name = nodes.get_name()
            all_stats_list = self._get_stats_list(node_name)
            app_obj = self._get_cluster_node_os_obj(node_name).platform.get_app(RegalConstants.STATS_APP_NAME)
            app_obj.check_service_status(all_stats_list)
            self._log.info("Started the stats successfully on node %s", str(node_name))
        self._log.debug("<")

    def stop_stats(self):
        """ This method stops the stats service script in the mapped machine.

        Returns:
            None

        """
        self._log.debug(">")
        for nodes in self.nodes_list:
            node_name = nodes.get_name()
            all_stats_list = self._get_stats_list(node_name)
            app_obj = self._get_cluster_node_os_obj(node_name).platform.get_app(RegalConstants.STATS_APP_NAME)
            app_obj.stop_service(all_stats_list)
            self._log.info("Stopped the stats successfully on node %s", str(node_name))
        self._log.debug("<")

    def _get_stats_list(self, node_name):
        """ This private method returns the stats list value configured in the
        configuartion.
        Args:
            node_name(str): node name.

        Returns:
            list: configured list value.

        Raise:
            InsufficientHelperConfig
            InvalidConfiguration

        """
        self._log.debug(">")
        data_dict = self._get_stats_info(node_name)
        if "Stats" in data_dict:
            data_dict = data_dict["Stats"]
            output = self.get_config_value(data_dict, node_name)
            if isinstance(output, list):
                self._log.debug("<")
                return output
            raise InvalidConfiguration(
                    "Excpected a list type of value for stats list of node {}".format(
                        node_name))
        else:
            self._log.debug("<")
            raise InsufficientHelperConfig(node_name, "Stats")

#    def check_reachability_of_machine(self, node_name):
#        """ Method to check machine reachability
#
#        Args:
#            node_name(str)
#
#        Returns:
#            bool(True/False)
#
#        """
#        self._log.debug(">")
#        ip = self.get_management_ip(node_name)
#        reachable = GetRegal().GetAnsibleUtil().check_reachability(ip)
#        if reachable:
#            self._log.debug("< Machine %s is reachable", str(node_name))
#            return True
#        self._log.debug("< Machine %s is not reachable", str(node_name))
#        return False
