import os
from Telaverge.telaverge_constans import UPFConstants
from regal_lib.corelib.common_utility import Utility
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.contrib.pfcp import PFCP
from Regal.regal_constants import Constants as RegalConstants
# from regal_lib.pcap.pcap_helper import PcapHelper
import Telaverge.apps.upf_exception as upf_exception
from test_executor.test_executor.utility import GetRegal


class PcapHelper:
    def __init__(self, service_store_obj):
        """ """
        self.service_store_obj = service_store_obj
        self.log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self.log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug("> ")
        self._log.debug("< ")

    def get_udp_packet_src_dest_ip_list(self, pcap_file_name):
        """ Method read the pcap file and filter for the UDP packets
        and list the source and destination ip of the packets

        Args:
            pcap_file_name(str): File path of the pcap

        Returns:
            List: list of tuples with src and dest ip

        """
        self._log.debug(">")
        self._log.debug("Reading pcap file %s", pcap_file_name)
        tcp_packet_src_dest_ip_list = []
        for pkt_data in rdpcap(pcap_file_name):
            if (pkt_data.haslayer(UDP)):
                if (pkt_data.haslayer(IP)):
                    src =  pkt_data[IP].src
                    dest = pkt_data[IP].dst
                    tcp_packet_src_dest_ip_list.append([src, dest])
        self._log.debug("The src dest ip list of udp packets %s",
                str(tcp_packet_src_dest_ip_list))
        self._log.debug("<")
        return tcp_packet_src_dest_ip_list

    def get_src_and_dest_details_of_pfcp_pcap_file(self, file_name):
        """ Method read the pcap file and filter for the UDP packets
        and list the source and destination ip of the packets

        Args:
            file_name(str): File path of the pcap

        Returns:
            List: list of list with cause, src and dest ip

        """
        self._log.debug(">")
        packet_details = []
        pkts = rdpcap(file_name)
        self._log.debug("%s Pcap file packets%s", file_name, pkts)
        for pkt in pkts:
            if (pkt.haslayer(UDP)):
                if (pkt.haslayer(IP)):
                    if pkt.haslayer("PFCP Association Setup Request"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst])

                    if pkt.haslayer("PFCP Association Setup Response"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst, pkt["IE Cause"].cause])

                    if pkt.haslayer("PFCP Session Establishment Request"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst])    

                    if pkt.haslayer("PFCP Session Establishment Response"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst, pkt["IE Cause"].cause])

                    if pkt.haslayer("PFCP Session Modification Request"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst])

                    if pkt.haslayer("PFCP Session Modification Response"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst, pkt["IE Cause"].cause])
                    
                    if pkt.haslayer("PFCP Session Deletion Request"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst])    

                    if pkt.haslayer("PFCP Session Deletion Response"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst, pkt["IE Cause"].cause])

        self._log.debug("< ")
        return packet_details

    def get_src_and_dest_details_of_pfd_pcap_file(self, file_name):
        """ Method read the pcap file and filter for the UDP packets
        and list the source and destination ip of the packets

        Args:
            file_name(str): File path of the pcap

        Returns:
            List: list of list with cause, src and dest ip

        """
        self._log.debug(">")
        packet_details = []
        pkts = rdpcap(file_name)
        for pkt in pkts:
            if (pkt.haslayer(UDP)):
                if (pkt.haslayer(IP)):
                    if pkt.haslayer("PFCP PFD Management Request"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst])    

                    if pkt.haslayer("PFCP PFD Management Response"):
                        packet_details.append([pkt[IP].src, pkt[IP].dst, pkt["IE Cause"].cause])

        self._log.debug("< ")
        return packet_details

class UPFBaseHelper(object):
    """
    Class for implementing UPF helper functions.
    """
    def __init__(self, service_store_obj, node_name, app_name):
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self._log.debug(">")
        self._node_name = node_name
        self._topology = self.service_store_obj.get_current_run_topology()
        self._node_obj = self._topology.get_node(node_name)
        self._os_obj = self._node_obj.get_os()
        self._platform = self._os_obj.platform
        self._app_obj = self._platform.get_app(app_name)
        self._app_name = app_name
        self._regal_root_path = os.getenv("REGAL_ROOT_PATH")
        self._stats_mgr = self.service_store_obj.get_stat_mgr_obj()
        self._topology = self.service_store_obj.get_current_run_topology()
        self._topology_node_list = self._topology.get_node_list()
        self._pcap_helper = PcapHelper(self.service_store_obj)
        self._stats_app = self._platform.get_app(RegalConstants.STATS_APP_NAME)
        self.sut_name = GetRegal().get_current_sut()
        self.ts_name = GetRegal().get_current_suite()
        self.tc_name = GetRegal().get_current_test_case()
        if self._regal_root_path :
            self.root_path = self._regal_root_path
        else:
            self.root_path = "./regal_lib"
        self._config = self.service_store_obj.get_current_test_case_configuration()
        self.service_store_obj.get_login_session_mgr_obj().create_session(self._node_obj, 1, self._node_name)
        self._log.debug("<")

    def __del__(self):
        """ Method used to close the login session of node. 
        
        Args:
            None

        Returns:
            None
        """
        self.service_store_obj.get_login_session_mgr_obj().close_session(self._node_name)

    def get_deployment_mgr_client_obj(self):
        """ Method return the deployment mgr client object
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        self._log.debug("<")
        return self._app_obj.get_deployment_mgr_client_obj()

    def restart_upf_server(self):
        """ Method to restart the upf server.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        command = "cd {} && {}".format(UPFConstants.UPF_SCRIPT_PATH, UPFConstants.UPF_SCRIPT)
        self.start_upf_server(command, UPFConstants.EXPECTED_STRING)
        self._log.debug("<")

    def start_upf_server(self, command, expected_output):
        """This method is used to restart upf server

        Args:
            command(str): command to execute in remote host. 
            expected_output(str): 

        Returns:
            None
        """
        self.service_store_obj.get_login_session_mgr_obj().execute_command(command, self._node_name)
        self.service_store_obj.get_login_session_mgr_obj().expected_match(
            [expected_output], UPFConstants.PEXPECT_TIMER, self._node_name)

    def start_services(self, upf_service):
        """ Method to start capturing tcpdump and script of smf, dn and gnb server.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        if upf_service:
            commands = [UPFConstants.UPF_TCP_DUMP_SERVICE_NAME, UPFConstants.UPF_SERVICE_NAME]
        else:
            commands = [UPFConstants.ULCL_TCP_DUMP_SERVICE_NAME, UPFConstants.ULCL_SERVICE_NAME]
        self.manage_services(commands, "start")
        self._log.debug("<")

    def stop_services(self, upf_service):
        """ Method to start capturing tcpdump and script of smf, dn and gnb server.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        if upf_service:
            commands = [UPFConstants.UPF_TCP_DUMP_SERVICE_NAME, UPFConstants.UPF_SERVICE_NAME]
        else:
            commands = [UPFConstants.ULCL_TCP_DUMP_SERVICE_NAME, UPFConstants.ULCL_SERVICE_NAME]
        self.manage_services(commands, "stop")
        self._log.debug("<")

    def manage_services(self, services, action):
        """Method used to get repo path of given app name
        and app version

        Args:
            services(list): Commands to start the services in remote host.


        Returns:
            repo_path(str): repo path of the given package
        """
        self._log.debug("> ")
        for service in services:
            command = "systemctl {} {}".format(action, service)
            self.service_store_obj.get_login_session_mgr_obj().perform_operation(command,
                     self._node_name, time_out=UPFConstants.PEXPECT_TIMER)
            if action == "start":
                check_status = "systemctl status {}".format(service)
                before_output = self.service_store_obj.get_login_session_mgr_obj().execute_cmd_and_get_output(
                        check_status, self._node_name, time_out=UPFConstants.PEXPECT_TIMER)
                if "active (running)" not in str(before_output):
                    self._log.debug("< service is not running")
                    raise upf_exception.FailedToStartService(
                        "Unable start service {}".format(service)
                    )
        self._log.debug("< ")

    def copy_pcap_file_from_remote_file(self, node_name, pcap_file_name):
        """Method used to copy the file from remote host to regal.

        Args:
            None
        
        Returns:
            None
        """
        self._log.debug(">")
        current_dir = self.service_store_obj.get_workspace_dir_path()
        dest_path = current_dir + "/"
        if isinstance(pcap_file_name, list):
            remote_src_path_ulcl = Utility.join_path(UPFConstants.DEST_PATH_FOR_SCRIPTS, pcap_file_name[0])
            remote_src_path_psa2 = Utility.join_path(UPFConstants.DEST_PATH_FOR_SCRIPTS, pcap_file_name[1])
            self.service_store_obj.get_login_session_mgr_obj().copy_files_from_node(self._node_obj, 
                [remote_src_path_ulcl, remote_src_path_psa2], dest_path)
        else:
            remote_src_path = Utility.join_path(UPFConstants.DEST_PATH_FOR_SCRIPTS, pcap_file_name)
            self.service_store_obj.get_login_session_mgr_obj().copy_files_from_node(self._node_obj, 
                                remote_src_path, dest_path)
        self._log.debug("< Copied pcap file from %s to regal path %s", node_name, dest_path)
        return current_dir

    def copy_multiple_template_scripts(self, src_paths, dest_paths, template_args, tcp_dump_config):
        """ Method replace the args in the template with values
        and copy to the remote host
        remote host

        Args:
            src_path(str): Source template file path
            dest_path(str): destination file path
            template_arg(dict): The template args values
            tcp_dump_config(dict): contains template args.

        Returns:
            None

        """
        self._log.debug(">")
        args_dict = {}
        args_dict.update(template_args)
        args_dict.update(tcp_dump_config)
        for src_file in src_paths[0]:
            self._log.debug("< {}-{}".format(src_file, dest_paths[0]))
            self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self._node_obj, 
                        src_file, dest_paths[0], args_dict)

        for src_file in src_paths[1]:
            self._log.debug("< {}-{}".format(src_file, dest_paths[0]))
            self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self._node_obj, 
                        src_file, dest_paths[1], args_dict)
        self._log.debug("<")

    def _get_node_config(self):
        """Method used to get the node config for the give node name

        Args:
            None

        Returns:
            node_config(dict): node config dict
        """
        self._log.debug(">")
        node_config = self._config.get_test_case_config(self._node_name)
        self._log.debug("<")
        return node_config

    def get_management_ip(self, node_name=None):
        """ This private method returns the management ip of teh node given.

        Args:
            node_name(str): name of the node.

        Returns:
            str: management ip

        Raise:
            exception.InvalidConfiguration

        """
        self._log.debug(">")
        if not node_name:
            self._log.debug("<")
            return self._node_obj.get_management_ip()
        for node_obj in self._topology_node_list:
            if node_obj.get_name() == node_name:
                self._log.debug("<")
                return node_obj.get_management_ip()
        self._log.debug("<")
        raise upf_exception.InvalidConfiguration(
                "node {} is not having management_ip".format(node_name))

    def get_os_obj_from_node_name(self, node_name):
        """ This private method returns the os object of the node given.

        Args:
            node_name(str): name of the node.

        Returns:
            str: management ip

        Raise:
            exception.InvalidConfiguration

        """
        self._log.debug(">")
        node_obj = self._topology.get_node(node_name)
        os_obj = node_obj.get_os()
        self._log.debug("<")
        return os_obj

    def get_smu_interface_name(self):
        """ Method used to get interface names from TestCase Configuration.

        Args:
            None

        Returns:
            list: interface names for the smu config node

        """
        self._log.debug(">")
        smu_upf_config = self._get_node_config()["SMUIniConfig"]
        interfaces_names = self.get_config_value(smu_upf_config["SmuInterfaceName"])
        self._log.debug("< binded interfaces %s", str(interfaces_names))
        return interfaces_names[-1]

    def get_config_value(self, data_dict):
        """ This method used to get the config value for given info.

        Args:
            data_dict(dict): configuration dict.

        Returns:
            str: value for the given field

        Raise:
            exception.InvalidConfiguration
        """
        self._log.debug(">")
        try:
            if data_dict["Type"] == "constant":
                self._log.debug("<")
                return data_dict["Value"]
            elif data_dict["Type"] == "interface_name":
                node_name = data_dict["Node"]
                node_mip = self.get_management_ip(node_name)
                subnet = data_dict["Subnet"]
                os_obj = self.get_os_obj_from_node_name(node_name)
                self._log.debug("<")
                return os_obj.get_interface_name_from_subnet_group(node_mip, subnet)
            elif data_dict["Type"] == "interface_names":
                node_name = data_dict["Node"]
                node_mip = self.get_management_ip(node_name)
                subnet = data_dict["Subnet"]
                os_obj = self.get_os_obj_from_node_name(node_name)
                interface_names = os_obj.get_interface_names_from_subnet_group(node_mip, subnet)
                self._log.debug("< %s", interface_names)
                return interface_names
            elif data_dict["Type"] == "ip":
                node_name = data_dict["Node"]
                node_mip = self.get_management_ip(node_name)
                subnet = data_dict["Subnet"]
                os_obj = self.get_os_obj_from_node_name(node_name)
                output = os_obj.get_ips_from_subnet_group(node_mip,
                        subnet)
                if output:
                    self._log.debug("<")
                    return output[0]
                self._log.debug("<")
                raise upf_exception.InvalidConfiguration(
                        "No ip found for subnet {}".format(subnet))
            elif data_dict["Type"] == 'management_ip':
                node_name = data_dict["Node"]
                self._log.debug("<")
                return self.get_management_ip(node_name)
        except KeyError as ex:
            self._log.debug("<")
            raise upf_exception.InvalidConfiguration("{} at node {}".format(ex,
                self._node_name))

    def _get_stats_arguments(self):
        """ This private method returns the stats arguments.


        Returns:
            dict: arguments of stats.

        Raise:
            InvalidConfiguration

        """
        self._log.debug(">")
        args_dict = {}
        data_dict = self._get_stats_info()
        self._log.debug("Stat_info dict is {}".format(data_dict))
        if "Arguments" in data_dict:
            data_dict = data_dict["Arguments"]
            args_dict = self.get_config_value(data_dict)
            if not isinstance(args_dict, dict):
                raise upf_exception.InvalidConfiguration(
                        "Expected a dict type of value for stats arguments of node {}".format(
                            self._node_name))
        self._log.debug("<")
        return args_dict

    def _get_stats_info(self):
        """ This private method returns the stats from configuration.


        Returns:
            dict: complete stats information.

        Raise:
            InsufficientHelperConfig
            InvalidConfiguration

        """
        self._log.debug(">")
        self._log.debug("All testcase_config %s", str(self._config.get_test_case_config))
        node_config = self._config.get_test_case_config(self._node_name)
        if node_config != '-NA-':
            if "StatsInfo" in node_config:
                self._log.debug("<")
                return node_config["StatsInfo"]
            raise upf_exception.InsufficientHelperConfig(self._node_name, "StatsInfo")
        raise upf_exception.InsufficientHelperConfig(self._node_name, self._node_name)

    def start_stats(self):
        """ This method starts the stats service script in the mapped machine.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        all_stats_list = self._get_stats_list()
        self._stats_app.start_service(all_stats_list)
        self._log.debug("<")

    def check_stats(self):
        """ This method checks the stats service script in the mapped machine.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        all_stats_list = self._get_stats_list()
        self._stats_app.check_service_status(all_stats_list)
        self._log.debug("All stats successfully started on node %s", str(self._node_name))
        self._log.debug("<")

    def _get_stats_list(self):
        """ This private method returns the stats list value configured in the configuration.


        Returns:
            list: configured list value.

        Raise:
            InsufficientHelperConfig
            InvalidConfiguration

        """
        self._log.debug(">")
        data_dict = self._get_stats_info()
        if "Stats" in data_dict:
            data_dict = data_dict["Stats"]
            output = self.get_config_value(data_dict)
            if isinstance(output, list):
                self._log.debug("<")
                return output
            raise upf_exception.InvalidConfiguration(
                    "Expected a list type of value for stats list of node {}".format(
                        self._node_name))
        raise upf_exception.InsufficientHelperConfig(self._node_name, "Stats")

    def stop_stats(self):
        """ This method stops the stats service script in the mapped machine.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        all_stats_list = self._get_stats_list()
        self._stats_app.stop_service(all_stats_list)
        self._log.debug("<")
        
    def apply_configuration(self):
        """This the Method to apply configuration on nodes to start/stop the stats service.

        Args:
            None

        Returns:
            None
        """
        self._log.debug(">")
        self._log.debug("Setting up the stats on nodes %s",
                str(self._node_name))
        stat_args_dict = {}
        stats_args_dict = self._get_stats_arguments()
        stat_args_dict[self._node_name] = stats_args_dict
        self._stats_app.apply_configuration(stat_args_dict)
        self._log.debug("Set up the stats on nodes %s is successful.",
                str(self._node_name))
        self._log.debug("<")

    def _get_lbu_and_smu_config_values(self):
        """Method used to copy the script and service files to upf node.

        Args:
            None

        Returns:
            lbu_template_args(dict)
            smu_template_args(dict)
        """
        self._log.debug(">")
        lbu_upf_config = self._get_node_config()["LBUIniConfig"]
        lbu_template_args = {
            "lbu_n3_ip_v4":str(self.get_config_value(lbu_upf_config["N3Ipv4"])),
            "lbu_n4_ip_v4":str(self.get_config_value(lbu_upf_config["N4Ipv4"])),
            "lbu_n6_ip_v4":str(self.get_config_value(lbu_upf_config["N6Ipv4"])),
            "lbu_n9_ip_v4":str(self.get_config_value(lbu_upf_config["N9Ipv4"])),
            "lbu_ip_v4_gateway":str(self.get_config_value(lbu_upf_config["IPv4Gateway"]))
        }
        smu_upf_config = self._get_node_config()["SMUIniConfig"]
        smu_template_args = {
            "smu_n3_ip_v4":str(self.get_config_value(smu_upf_config["N3Ipv4"])),
            "smu_n4_ip_v4":str(self.get_config_value(smu_upf_config["N4Ipv4"])),
            "smu_n6_ip_v4":str(self.get_config_value(smu_upf_config["N6Ipv4"])),
            "smu_n9_ip_v4":str(self.get_config_value(smu_upf_config["N9Ipv4"])),
            "smu_interface":str(self.get_smu_interface_name())
        }
        self._log.debug("<")
        return lbu_template_args, smu_template_args

    def _get_smf_config_values(self):
        """Method used to copy the script and service files to smf node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        smf_config = self._get_node_config()["SMFConfig"]
        template_args = {
                "ue_ip_v4": str(self.get_config_value(smf_config["UeIpv4"])),
                "gnb_traffic_interface_ip": str(self.get_config_value(smf_config["gNodeBInterfaceIp"])),
                "n3_ip_v4": str(self.get_config_value(smf_config["N3Ipv4"])),
                "smf_traffic_interface_ip" : str(self.get_config_value(smf_config["SmfInterfaceIp"])),
                "n4_ip_v4":str(self.get_config_value(smf_config["N4Ipv4"])),
                "smf_interface":str(self.get_config_value(smf_config["SmfInterfaceName"])),
                "dn_traffic_interface_ip" : str(self.get_config_value(smf_config["DnInterfaceIp"])),
                "template_script_path" : str(self.get_config_value(smf_config["TemplateScriptPath"]))
        }
        self._log.debug("< smf args %s", str(template_args))
        return template_args

    def _get_dn_config_values(self):
        """Method used to copy the script and service files to dn node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        dn_config = self._get_node_config()["DNConfig"]
        template_args = {
                "ue_ip_v4": str(self.get_config_value(dn_config["UeIpv4"])),
                "gnb_traffic_interface_ip": str(self.get_config_value(dn_config["gNodeBInterfaceIp"])),
                "n3_ip_v4": str(self.get_config_value(dn_config["N3Ipv4"])),
                "dn_traffic_interface_ip" : str(self.get_config_value(dn_config["DnInterfaceIp"])),
                "dn_interface":str(self.get_config_value(dn_config["DnInterfaceName"])),
                "template_script_path" : str(self.get_config_value(dn_config["TemplateScriptPath"]))
        }
        self._log.debug("< dn args %s", str(template_args))
        return template_args

    def _get_gnb_config_values(self):
        """Method used to copy the script and service files to gnb node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        gnb_config = self._get_node_config()["GNBConfig"]
        template_args = {
                "ue_ip_v4": str(self.get_config_value(gnb_config["UeIpv4"])),
                "gnb_traffic_interface_ip": str(self.get_config_value(gnb_config["gNodeBInterfaceIp"])),
                "n3_ip_v4": str(self.get_config_value(gnb_config["N3Ipv4"])),
                "dn_traffic_interface_ip" : str(self.get_config_value(gnb_config["DnInterfaceIp"])),
                "gnb_interface": str(self.get_config_value(gnb_config["gNodeBInterfaceName"])),
                "template_script_path" : str(self.get_config_value(gnb_config["TemplateScriptPath"]))
        }
        self._log.debug("<")
        return template_args

    def _get_ulcl_smf_config_values(self):
        """Method used to copy the script and service files to SMF node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        self._log.debug(">")
        smf_config = self._get_node_config()["SMFConfig"]
        template_args = {
                "smf_interface": str(self.get_config_value(smf_config["SmfInterfaceName"])),
                "smf_traffic_interface_ip": str(self.get_config_value(smf_config["SmfInterfaceIp"])),
                "psa1_n3_ip_v4": str(self.get_config_value(smf_config["Psa1N3Ipv4"])),
                "psa1_n4_ip_v4": str(self.get_config_value(smf_config["Psa1N4Ipv4"])),
                "psa1_n9_ip_v4": str(self.get_config_value(smf_config["Psa1N9Ipv4"])),
                "psa1_ue_ip_v4": str(self.get_config_value(smf_config["Psa1UeIpv4"])),
                "template_script_path": str(self.get_config_value(smf_config["TemplateScriptPath"])),
                "gnb_traffic_interface_ip": str(self.get_config_value(smf_config["gNodeBInterfaceIp"])),
                "upf_n9_ip_v4": str(self.get_config_value(smf_config["UpfN9Ipv4"]))
        }
        self._log.debug("< ulcl smf args %s", str(template_args))
        return template_args

    def _get_ulcl_i_smf_config_values(self):
        """Method used to copy the script and service files to I_SMF node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        self._log.debug(">")
        i_smf_config = self._get_node_config()["ISMFConfig"]
        template_args = {
                "ulcl_interface_name": str(self.get_config_value(i_smf_config["UlclInterfaceName"])),
                "ulcl_traffic_interface_ip": str(self.get_config_value(i_smf_config["UlclInterfaceIp"])),
                "psa2_interface_name": str(self.get_config_value(i_smf_config["Psa2InterfaceName"])),
                "psa2_traffic_interface_ip": str(self.get_config_value(i_smf_config["Psa2InterfaceIp"])),
                "local_dn_traffic_interface_ip": str(self.get_config_value(i_smf_config["LocalDnInterfaceIp"])),
                "ulcl_n3_ip_v4": str(self.get_config_value(i_smf_config["UlclN3Ipv4"])),
                "ulcl_n4_ip_v4": str(self.get_config_value(i_smf_config["UlclN4Ipv4"])),
                "ulcl_n9_ip_v4": str(self.get_config_value(i_smf_config["UlclN9Ipv4"])),
                "ulcl_ue_ip_v4": str(self.get_config_value(i_smf_config["UlclUeIpv4"])),
                "psa2_n3_ip_v4": str(self.get_config_value(i_smf_config["Psa2N3Ipv4"])),
                "psa2_n4_ip_v4": str(self.get_config_value(i_smf_config["Psa2N4Ipv4"])),
                "psa2_n9_ip_v4": str(self.get_config_value(i_smf_config["Psa2N9Ipv4"])),
                "psa2_ue_ip_v4": str(self.get_config_value(i_smf_config["Psa2UeIpv4"])),
                "psa2_template_script_path": str(self.get_config_value(i_smf_config["Psa2TemplateScriptPath"])),
                "ulcl_template_script_path": str(self.get_config_value(i_smf_config["UlclTemplateScriptPath"])),
                "gnb_traffic_interface_ip": str(self.get_config_value(i_smf_config["gNodeBInterfaceIp"])),
                "psa1_upf_n9_ip_v4": str(self.get_config_value(i_smf_config["Psa1UpfN9Ipv4"])),
                "psa2_upf_n9_ip_v4": str(self.get_config_value(i_smf_config["Psa2UpfN9Ipv4"]))
        }
        self._log.debug("< i_smf args %s", str(template_args))
        return template_args

    def _get_ulcl_dn_config_values(self):
        """Method used to copy the script and service files to DN node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        self._log.debug(">")
        dn_config = self._get_node_config()["DNConfig"]
        template_args = {
                "dn_interface": str(self.get_config_value(dn_config["DnInterfaceName"])),
                "dn_traffic_interface_ip": str(self.get_config_value(dn_config["DnInterfaceIp"])),
                "template_script_path": str(self.get_config_value(dn_config["TemplateScriptPath"])),
                "psa1_ue_ip_v4": str(self.get_config_value(dn_config["Psa1UeIpv4"]))
        }
        self._log.debug("< dn args %s", str(template_args))
        return template_args

    def _get_ulcl_local_dn_config_values(self):
        """Method used to copy the script and service files to LOCAL-DN node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        self._log.debug(">")
        local_dn_config = self._get_node_config()["LOCALDNConfig"]
        template_args = {
                "local_dn_interface": str(self.get_config_value(local_dn_config["LocalDnInterfaceName"])),
                "local_dn_traffic_interface_ip": str(self.get_config_value(local_dn_config["LocalDnInterfaceIp"])),
                "template_script_path": str(self.get_config_value(local_dn_config["TemplateScriptPath"])),
                "psa2_ue_ip_v4": str(self.get_config_value(local_dn_config["Psa2UeIpv4"]))
        }
        self._log.debug("< local-dn args %s", str(template_args))
        return template_args

    def _get_ulcl_gnb_config_values(self):
        """Method used to copy the script and service files to GNB node.

        Args:
            None

        Returns:
            template_args(dict)
        """
        self._log.debug(">")
        gnb_config = self._get_node_config()["GNBConfig"]
        template_args = {
                "gnb_interface": str(self.get_config_value(gnb_config["gNodeBInterfaceName"])),
                "dn_traffic_interface_ip": str(self.get_config_value(gnb_config["DnInterfaceIp"])),
                "local_dn_traffic_interface_ip": str(self.get_config_value(gnb_config["LocalDnInterfaceIp"])),
                "n3_ip_v4": str(self.get_config_value(gnb_config["UPFN3Ipv4"])),
                "ue_ip_v4": str(self.get_config_value(gnb_config["UeIpv4"])),
                "template_script_path": str(self.get_config_value(gnb_config["TemplateScriptPath"])),
                "gnb_traffic_interface_ip": str(self.get_config_value(gnb_config["gNodeBInterfaceIp"]))
        }
        self._log.debug("< gNodeB args %s", str(template_args))
        return template_args

    def manage_smf_server(self, start_server=None):
        """Method used to start the SMF server.

        Args:
            None

        Returns:
            template_args(dict)
        """
        self._log.debug(">")
        if start_server:
            self.manage_services([UPFConstants.UPF_TCP_DUMP_SERVICE_NAME, UPFConstants.SHELL_SCRIPT_SERVICE], "start")
            self._log.debug("<")
            return 
        self.manage_services([UPFConstants.UPF_TCP_DUMP_SERVICE_NAME, UPFConstants.SHELL_SCRIPT_SERVICE], "stop")
        self._log.debug("<")

    def _copy_files_to_node(self, remote_src_paths, dest_path, template_args):
        """
        Method used to copy files to the assigned node.

        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        files_src_path = self._get_upf_script_and_service_files_path(remote_src_paths[0])
        self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(self._node_obj, 
                        files_src_path[0], dest_path[0])
        template_src_path = self._get_upf_script_and_service_files_path(remote_src_paths[1])
        self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self._node_obj, 
                        template_src_path[0], dest_path[1], template_args)
        self._log.debug("<")

    def start_tc_execution(self):
        """
        Method to start the testcase execution in the node.

        Args:
            api_operation (str): Name of the API.
    
        Returns:
            Request's response.
        """
        self._log.debug(">")
        argument = "tests/{}/{}/{}/START_TEST".format(self.sut_name, self.ts_name, self.tc_name)
        status, msg = self._app_obj.send_rest_post_request(argument)
        self._log.debug("< {}-{}".format(status, msg))