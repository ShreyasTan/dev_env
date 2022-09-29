import os
from Telaverge.telaverge_constans import UPFConstants
from regal_lib.corelib.common_utility import Utility

from Regal.regal_constants import Constants as RegalConstants
import Telaverge.apps.upf_exception as upf_exception
from Telaverge.helper.upf_base_helper import UPFBaseHelper


class UPFHelper(UPFBaseHelper):
    """
    Class for implementing UPF helper functions.
    """

    def setup_script(self):
        """ Method used to copy the template, scripts and service file from regal to nodes.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        if self._node_name == UPFConstants.UPF:
            lbu_template_args, smu_template_args = self.get_template_arguments(UPFConstants.UPF)
            self._copy_script_files(lbu_template_args, smu_template_args)
            self._log.debug("< Template scripts of UPF Node copied successfully.")

        if self._node_name == UPFConstants.SMF:
            template_args = self.get_template_arguments(UPFConstants.SMF)
            script_name = template_args["template_script_path"].split("/")
            script_path = Utility.join_path(UPFConstants.DEST_PATH_FOR_SCRIPTS, script_name[-1])
            tcp_dump_config = {"execute_upf_scripts":script_path,
                                "interface_name_1":template_args["smf_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of SMF Node copied successfully.")

        if self._node_name == UPFConstants.DN:
            template_args = self.get_template_arguments(UPFConstants.DN)
            tcp_dump_config = {"execute_upf_scripts":UPFConstants.N6_DOWNLINK_GTP,
                                "interface_name_1":template_args["dn_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of DN Node copied successfully.")

        if self._node_name == UPFConstants.GNB:
            template_args = self.get_template_arguments(UPFConstants.GNB)
            tcp_dump_config = {"execute_upf_scripts":UPFConstants.N3_UPLINK_GTP,
                                "interface_name_1":template_args["gnb_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of GNB Node copied successfully.")

    def setup_configuration_script(self, psa2_not_required=None):
        """ Method used to copy the template, scripts and service file from regal to nodes.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")

        if self._node_name in [UPFConstants.UL_CL, UPFConstants.PSA1, UPFConstants.PSA2]:
            lbu_template_args, smu_template_args = self.get_template_arguments_of_ulcl(self._node_name)
            self._copy_script_files(lbu_template_args, smu_template_args)
            self._log.debug("< Template scripts of %s Node copied successfully.", self._node_name)

        if self._node_name == UPFConstants.SMF:
            template_args = self.get_template_arguments_of_ulcl(UPFConstants.SMF)
            tcp_dump_config = {"execute_upf_scripts":UPFConstants.PFCP_PSA1,
                                "interface_name_1":template_args["smf_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of SMF Node copied successfully.")

        if self._node_name == UPFConstants.I_SMF:
            template_args = self.get_template_arguments_of_ulcl(UPFConstants.I_SMF)
            tcp_dump_config = {"execute_upf_scripts":UPFConstants.PFCP_PSA2,
                                "execute_ulcl_scripts":UPFConstants.PFCP_ULCL,
                                "interface_name_1":template_args["psa2_interface_name"],
                                "interface_name_2":template_args["ulcl_interface_name"]}
            self._copy_script_files(template_args, tcp_dump_config, psa2_not_required)
            self._log.debug("< Template scripts and service files of I-SMF Node copied successfully.")

        if self._node_name == UPFConstants.DN:
            template_args = self.get_template_arguments_of_ulcl(UPFConstants.DN)
            tcp_dump_config = {"execute_upf_scripts":UPFConstants.DOWNLINK_GTP_PSA1,
                                "interface_name_1":template_args["dn_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of DN Node copied successfully.")

        if self._node_name == UPFConstants.LOCAL_DN:
            template_args = self.get_template_arguments_of_ulcl(UPFConstants.LOCAL_DN)
            tcp_dump_config = {"execute_upf_scripts":UPFConstants.DOWNLINK_GTP_PSA2,
                                "interface_name_1":template_args["local_dn_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of Local-DN Node copied successfully.")

        if self._node_name == UPFConstants.GNB:
            template_args = self.get_template_arguments_of_ulcl(UPFConstants.GNB)
            script_name = template_args["template_script_path"].split("/")
            script_path = Utility.join_path(UPFConstants.DEST_PATH_FOR_SCRIPTS, script_name[-1])
            tcp_dump_config = {"execute_upf_scripts":script_path,
                                "interface_name_1":template_args["gnb_interface"]}
            self._copy_script_files(template_args, tcp_dump_config)
            self._log.debug("< Template scripts and service files of Local-DN Node copied successfully.")

    def _get_upf_script_and_service_files_path(self, host_file_paths):
        """ Method used to join the paths with root_path
        
        Args:
            host_file_paths: It contains list of host node script and service paths.

        Return:
            list: path_list
        """
        self._log.debug(">")
        path_list = []
        if not isinstance(host_file_paths, list):
            path_list.append(Utility.join_path(self.root_path, host_file_paths))
        else:
            for path in host_file_paths:
                path_list.append(Utility.join_path(self.root_path, path))
        self._log.debug("<")
        return path_list

    def _copy_required_script_files_to_upf_local_nodes(self, template_args, tcp_dump_config):
        """Method used to copy the script and service files to destination node.

        Args:
            tcp_dump_config: contains node info and file names.
            template_args(dict): template info

        Returns:
            None
        """
        self._log.debug(">")
        file_list_1 = self._get_upf_script_and_service_files_path([template_args["template_script_path"],
                                UPFConstants.RUN_SERVICE_TCP_DUMP_UPF])
        file_list_2 = self._get_upf_script_and_service_files_path([UPFConstants.TCP_DUMP_SERVICE_FILE_PATH_UPF,
                                UPFConstants.UPF_SCRIPT_SERVICE_FILE_PATH])
        dest_paths = [UPFConstants.DEST_PATH_FOR_SCRIPTS, UPFConstants.DEST_PATH_FOR_SERVICE]
        src_paths = [file_list_1, file_list_2]
        tcp_dump_config.update({"execute_upf_tcpdump_file":UPFConstants.RUN_TCP_DUMP_UPF})
        tcp_dump_config.update({"file_name_1":UPFConstants.DEST_PATH_FOR_SCRIPTS + self._node_name + "_pcap.pcap"})
        self.copy_multiple_template_scripts(src_paths, dest_paths, template_args, tcp_dump_config)
        self._log.debug("<")

    def _copy_required_configuration_files_to_upf_nodes(self, template_args, tcp_dump_config):
        """Method used to copy the configuration files to upf nodes.

        Args:
            tcp_dump_config: contains node info and file names.
            template_args(dict): template info

        Returns:
            None
        """
        self._log.debug(">")
        file_list_1 = self._get_upf_script_and_service_files_path(UPFConstants.UPF_NODE_SOURCE_LBU)
        file_list_2 = self._get_upf_script_and_service_files_path(UPFConstants.UPF_NODE_SOURCE_SMU)
        src_paths = [file_list_1, file_list_2]
        dest_paths = [UPFConstants.UPF_NODE_DEST_LBU, UPFConstants.UPF_NODE_DEST_SMU]
        self.copy_multiple_template_scripts(src_paths, dest_paths, template_args, tcp_dump_config)
        self._log.debug("<")

    def _copy_required_script_files_to_i_smf_node(self, template_args, tcp_dump_config, psa2_not_required):
        """Method used to copy the script and service files to destination node.

        Args:
            tcp_dump_config(dict): contains node info and file names.
            template_args(dict): template info
            pas2_not_require(bool): Contains True/False

        Returns:
            None
        """
        self._log.debug(">")
        if not psa2_not_required:
            file_list_1 = self._get_upf_script_and_service_files_path([template_args["psa2_template_script_path"], 
                    template_args["ulcl_template_script_path"], UPFConstants.RUN_SERVICE_TCP_DUMP_UPF, UPFConstants.RUN_SERVICE_TCP_DUMP_ULCL])
            file_list_2 = self._get_upf_script_and_service_files_path([UPFConstants.TCP_DUMP_SERVICE_FILE_PATH_UPF, 
                    UPFConstants.TCP_DUMP_SERVICE_FILE_PATH_ULCL, UPFConstants.UPF_SCRIPT_SERVICE_FILE_PATH, UPFConstants.ULCL_SCRIPT_SERVICE_FILE_PATH])
        else:
            file_list_1 = self._get_upf_script_and_service_files_path([template_args["ulcl_template_script_path"], 
                            UPFConstants.RUN_SERVICE_TCP_DUMP_ULCL])
            file_list_2 = self._get_upf_script_and_service_files_path([UPFConstants.TCP_DUMP_SERVICE_FILE_PATH_ULCL, 
                            UPFConstants.ULCL_SCRIPT_SERVICE_FILE_PATH])
        dest_paths = [UPFConstants.DEST_PATH_FOR_SCRIPTS, UPFConstants.DEST_PATH_FOR_SERVICE]
        src_paths = [file_list_1, file_list_2]
        tcp_dump_config.update({"file_name_1":UPFConstants.DEST_PATH_FOR_SCRIPTS + UPFConstants.PSA2 + "_pcap.pcap",
                                "file_name_2":UPFConstants.DEST_PATH_FOR_SCRIPTS + UPFConstants.UL_CL + "_pcap.pcap",
                                "execute_upf_tcpdump_file":UPFConstants.RUN_TCP_DUMP_UPF,
                                "execute_ulcl_tcpdump_file":UPFConstants.RUN_TCP_DUMP_ULCL})
        self.copy_multiple_template_scripts(src_paths, dest_paths, template_args, tcp_dump_config)
        self._log.debug("<")

    def _copy_script_files(self, template_args, tcp_dump_config, psa2_not_required=None):
        """Method used to copy the script and service files to destination node.

        Args:
            tcp_dump_config(dict): contains node info and file names.
            template_args(dict): template info
            pas2_not_require(bool): Contains True/None

        Returns:
            None
        """
        self._log.debug(">")
        if self._node_name in [UPFConstants.SMF, UPFConstants.GNB, UPFConstants.DN, UPFConstants.LOCAL_DN]:
            self._copy_required_script_files_to_upf_local_nodes(template_args, tcp_dump_config)
            self._log.debug("<")
        if self._node_name in [UPFConstants.UL_CL, UPFConstants.PSA1, UPFConstants.PSA2, UPFConstants.UPF]:
            self._copy_required_configuration_files_to_upf_nodes(template_args, tcp_dump_config)
            self._log.debug("<")
        if self._node_name == UPFConstants.I_SMF:
            self._copy_required_script_files_to_i_smf_node(template_args, tcp_dump_config, psa2_not_required)
            self._log.debug("<")
        self._log.debug("<")   

    def get_template_arguments(self, node_name):
        """ Method used to get arguments from Topology and TestCase Configuration.

        Args:
            node_name(dict): Name of the node.

        Returns:
            dict: values for the given node

        """
        self._log.debug(">")
        if node_name == UPFConstants.UPF:
            self._log.debug("<")
            return self._get_lbu_and_smu_config_values()

        if node_name == UPFConstants.SMF:
            self._log.debug("<")
            return self._get_smf_config_values()

        if node_name == UPFConstants.DN:
            self._log.debug("<")
            return self._get_dn_config_values()
            
        if node_name == UPFConstants.GNB:
            self._log.debug("<")
            return self._get_gnb_config_values()

    def validate_pcap(self):
        """ Method used to copy the pcap files from remote nodes and validate the status of it.

        Args:
            None

        Returns:
            None

        Raises:
            Exception: TestCaseFailed

        """
        self._log.debug("> ")
        
        if self._node_name == UPFConstants.SMF:
            self._log.debug("<")
            return self._check_smf_reachablility_status()

        if self._node_name == UPFConstants.DN:
            self._log.debug("<")
            return self._check_uplink_and_downlink_reachablility_status()

        if self._node_name == UPFConstants.GNB:
            self._log.debug("<")
            return self._check_gnb_uplink_and_downlink_reachablility_status()
        
    def validate_connection_of_smf_pcap_file(self, smf_packet_details, validation_ip_details):
        """ Method used to validate the connection between upf and smf node.

        Args:
            smf_packet_details(list): UDP packets.
            validation_ip_details(dict): node details.

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        association_request_reached = False
        association_response_reached = False
        session_request_reached = False
        session_response_reached = False

        if smf_packet_details:
            for pkt_address in smf_packet_details:
                if pkt_address[0] == validation_ip_details["smf_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["n4_ip_v4"]:
                        association_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["smf_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            association_response_reached = True
                        
                if pkt_address[0] == validation_ip_details["smf_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["n4_ip_v4"]:
                        session_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["smf_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            session_response_reached = True
                        
            packet_status = [association_request_reached, association_response_reached, session_request_reached, 
                            session_response_reached]
            status = self.check_status_of_packets_reachability(packet_status)
            self._log.debug("< SMF Reachability %s", str(status))
            return status

        self._log.debug("< SMF Reachability %s", str(False))
        return False

    def validate_ulcl_pcap(self, psa2_not_required=None):
        """ Method used to copy the pcap files from remote nodes and validate the status of it.

        Args:
            None

        Returns:
            None

        Raises:
            Exception: TestCaseFailed

        """
        self._log.debug("> ")
    
        if self._node_name == UPFConstants.SMF:
            self._log.debug("<")
            return self._check_smf_reachablility_status(True)

        if self._node_name == UPFConstants.I_SMF:
            self._log.debug("<")
            return self._check_i_smf_reachablility_status(psa2_not_required)

        if self._node_name == UPFConstants.DN:
            self._log.debug("<")
            return self._check_uplink_and_downlink_reachablility_status(True)
    
        if self._node_name == UPFConstants.LOCAL_DN:
            self._log.debug("<")
            return self._check_uplink_and_downlink_reachablility_status(True)

        if self._node_name == UPFConstants.GNB:
            self._log.debug("<")
            return self._check_gnb_uplink_and_downlink_reachablility_status(True)

    def validate_connection_of_uplink_psa1_and_psa2_pcap_file(self, packet_details, validation_ip_details):
        """ Method used to validate the connection between upf and smf node.

        Args:
            packet_details(list): UDP packets.
            validation_ip_details(dict): node details.

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        gnode_to_ulcl_status = False
        psa1_to_dn_status = False
        dn_to_psa1_status = False
        psa2_to_local_dn_status = False
        local_dn_to_psa2_status = False

        for pkt_address in packet_details:
    
            if self._node_name == UPFConstants.DN:
                if pkt_address[0] == validation_ip_details["psa1_ue_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["dn_traffic_interface_ip"]:
                        psa1_to_dn_status = True

                if pkt_address[0] == validation_ip_details["dn_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa1_ue_ip_v4"]:
                        dn_to_psa1_status = True

                if psa1_to_dn_status and dn_to_psa1_status:
                    self._log.debug("<")
                    return True
                
            if self._node_name == UPFConstants.LOCAL_DN:
                if pkt_address[0] == validation_ip_details["psa2_ue_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["local_dn_traffic_interface_ip"]:
                        psa2_to_local_dn_status = True

                if pkt_address[0] == validation_ip_details["local_dn_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa2_ue_ip_v4"]:
                        local_dn_to_psa2_status = True

                if psa2_to_local_dn_status and local_dn_to_psa2_status:
                    self._log.debug("<")
                    return True

            if self._node_name == UPFConstants.GNB:
                if pkt_address[0] == validation_ip_details["gnb_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["n3_ip_v4"]:
                        gnode_to_ulcl_status = True
                if gnode_to_ulcl_status:
                    self._log.debug("<")
                    return True

        self._log.debug("<")
        return False
        
    def validate_connection_of_psa1_pcap_file(self, psa1_packet_details, validation_ip_details):
        """ Method used to validate the connection between upf and smf node.

        Args:
            smf_packet_details(list): UDP packets.
            validation_ip_details(dict): node details.

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        association_request_reached = False
        association_response_reached = False
        session_request_reached = False
        session_response_reached = False

        if psa1_packet_details:
            for pkt_address in psa1_packet_details:
                if pkt_address[0] == validation_ip_details["smf_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa1_n4_ip_v4"]:
                        association_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["psa1_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["smf_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            association_response_reached = True
                        
                if pkt_address[0] == validation_ip_details["smf_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa1_n4_ip_v4"]:
                        session_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["psa1_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["smf_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            session_response_reached = True

            packet_status = [association_request_reached, association_response_reached, session_request_reached, 
                            session_response_reached]
            status = self.check_status_of_packets_reachability(packet_status)
            self._log.debug("< PSA1 Reachability %s", str(status))
            return status

        self._log.debug("< PSA1 Reachability %s", str(False))
        return False

    def validate_connection_of_psa2_pcap_file(self, psa2_packet_details, validation_ip_details):
        """ Method used to validate the connection between upf and smf node.

        Args:
            smf_packet_details(list): UDP packets.
            validation_ip_details(dict): node details.

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        association_request_reached = False
        association_response_reached = False
        session_request_reached = False
        session_response_reached = False
        management_request_reached = False
        management_response_reached = False

        if psa2_packet_details:
            for pkt_address in psa2_packet_details:
                if pkt_address[0] == validation_ip_details["psa2_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa2_n4_ip_v4"]:
                        association_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["psa2_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["psa2_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            association_response_reached = True
                        
                if pkt_address[0] == validation_ip_details["psa2_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa2_n4_ip_v4"]:
                        session_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["psa2_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["psa2_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            session_response_reached = True

                if pkt_address[0] == validation_ip_details["psa2_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["psa2_n4_ip_v4"]:
                        management_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["psa2_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["psa2_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            management_response_reached = True

            packet_status = [association_request_reached, association_response_reached, session_request_reached, 
                            session_response_reached, management_request_reached, management_response_reached]
            status = self.check_status_of_packets_reachability(packet_status, UPFConstants.PSA2)
            self._log.debug("< PSA2 Reachability %s", str(status))
            return status

        self._log.debug("< PSA2 Reachability %s", str(False))
        return False

    def validate_connection_of_ul_cl_pcap_file(self, ulcl_packet_details, validation_ip_details):
        """ Method used to validate the connection between upf and smf node.

        Args:
            smf_packet_details(list): UDP packets.
            validation_ip_details(dict): node details.

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        association_request_reached = False
        association_response_reached = False
        session_request_reached = False
        session_response_reached = False
        management_request_reached = False
        management_response_reached = False

        if ulcl_packet_details:
            for pkt_address in ulcl_packet_details:
                if pkt_address[0] == validation_ip_details["ulcl_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["ulcl_n4_ip_v4"]:
                        association_request_reached = True
                        
                if pkt_address[0] == validation_ip_details["ulcl_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["ulcl_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            association_response_reached = True
                        
                if pkt_address[0] == validation_ip_details["ulcl_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["ulcl_n4_ip_v4"]:
                        session_request_reached = True
                                   
                if pkt_address[0] == validation_ip_details["ulcl_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["ulcl_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            session_response_reached = True

                if pkt_address[0] == validation_ip_details["ulcl_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["ulcl_n4_ip_v4"]:
                        management_request_reached = True   
                        
                if pkt_address[0] == validation_ip_details["ulcl_n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["ulcl_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            management_response_reached = True

            packet_status = [association_request_reached, association_response_reached, session_request_reached, 
                            session_response_reached, management_request_reached, management_response_reached]
            status = self.check_status_of_packets_reachability(packet_status, UPFConstants.UL_CL)
            self._log.debug("< ULCL Reachability %s", str(status))
            return status

        self._log.debug("< ULCL Reachability %s", str(False))
        return False

    def check_status_of_packets_reachability(self, packet_status, node=None):

        self._log.debug(">")
        association_status = False
        session_status = False
        management_status = False
        if not node:
            if packet_status[0] and packet_status[1]:
                association_status = True
                
            if packet_status[2] and packet_status[3]:
                session_status = True

            if association_status and session_status:
                self._log.debug("<")
                return True 
        else:
            if packet_status[0] and packet_status[1]:
                association_status = True
                
            if packet_status[2] and packet_status[3]:
                session_status = True

            if packet_status[4] and packet_status[5]:
                management_status = True

            if association_status and session_status and management_status:
                self._log.debug("<")
                return True 

    def validate_pcap_file_of_gnb_or_dn(self, packet_details, validation_ip_details):
        """ Method used to validate the connection between upf and smf node.

        Args:
            packet_details(list): UDP packets.
            validation_ip_details(dict): node details.
            node(str): Node Name either gNodeB or Dn

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        gnode_to_upf_status = False
        upf_to_dn_status = False
        dn_to_upf_status = False
        upf_to_gnb_status = False

        for pkt_address in packet_details:
    
            if self._node_name == UPFConstants.DN:
                if pkt_address[0] == validation_ip_details["ue_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["dn_traffic_interface_ip"]:
                        upf_to_dn_status = True
                if pkt_address[0] == validation_ip_details["dn_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["ue_ip_v4"]:
                        dn_to_upf_status = True
                if (dn_to_upf_status == True) and (upf_to_dn_status == True):
                    self._log.debug("<")
                    return True

            if self._node_name == UPFConstants.GNB:
                if pkt_address[0] == validation_ip_details["gnb_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["n3_ip_v4"]:
                        gnode_to_upf_status = True
                if pkt_address[0] == validation_ip_details["n3_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["gnb_traffic_interface_ip"]:
                        upf_to_gnb_status = True
                if (gnode_to_upf_status == True) and (upf_to_gnb_status == True):
                    self._log.debug("<")
                    return True

        self._log.debug("<")
        return False

    def get_template_arguments_of_ulcl(self, node_name):
        """ Method used to get arguments from Topology and TestCase Configuration.

        Args:
            node_name(dict): Name of the node.

        Returns:
            dict: values for the given node

        """
        self._log.debug(">")
        if node_name in [UPFConstants.UL_CL, UPFConstants.PSA1, UPFConstants.PSA2]:
            self._log.debug("<")
            return self._get_lbu_and_smu_config_values()

        if node_name == UPFConstants.SMF:
            self._log.debug("<")
            return self._get_ulcl_smf_config_values()
            
        if node_name == UPFConstants.I_SMF:
            self._log.debug("<")
            return self._get_ulcl_i_smf_config_values()

        if node_name == UPFConstants.DN:
            self._log.debug("<")
            return self._get_ulcl_dn_config_values()
            
        if node_name == UPFConstants.LOCAL_DN:
            self._log.debug("<")
            return self._get_ulcl_local_dn_config_values()

        if node_name == UPFConstants.GNB:
            self._log.debug("<")
            return self._get_ulcl_gnb_config_values()

    def _check_smf_reachablility_status(self, ulcl_node=None):
        """Method used to copy the pcap file and validate the pcap traces UPF.

        Args:
            ulcl_node(bool): Containes True/False

        Returns:
            None
        """
        self._log.debug(">")
        pcap_file_path = self.copy_pcap_file_from_remote_file(UPFConstants.SMF, UPFConstants.SMF_PCAP_FILE_NAME)
        packet_details = self._pcap_helper.get_src_and_dest_details_of_pfcp_pcap_file(
                        Utility.join_path(pcap_file_path, UPFConstants.SMF_PCAP_FILE_NAME))
        if not ulcl_node:
            node = "SMF"
            validation_ip_details = self.get_template_arguments(UPFConstants.SMF)
            packet_status = self.validate_connection_of_smf_pcap_file(packet_details, 
                                validation_ip_details)
        else:
            node = "PSA1"
            validation_ip_details = self.get_template_arguments_of_ulcl(UPFConstants.SMF)
            packet_status = self.validate_connection_of_psa1_pcap_file(packet_details,
                                validation_ip_details)
        Utility.delete_directory_recursively(pcap_file_path)
        if not packet_status:
            err_msg = "{} Packets are missing".format(node)
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.TestCaseFailed(err_msg)
        self._log.debug("The {} node packets are valid {}".format(node, str(packet_details)))
        self._log.debug("<")

    def _check_i_smf_reachablility_status(self, psa2_not_required):
        """Method used to copy the pcap file and validate the pcap traces UPF.

        Args:
            psa2_not_required(bool): Containes True/False
            
        Returns:
            None
        """
        self._log.debug(">")
        psa2_pcap_present = False
        validation_ip_details = self.get_template_arguments_of_ulcl(UPFConstants.I_SMF)
        if not psa2_not_required:
            pcap_file_path = self.copy_pcap_file_from_remote_file(UPFConstants.I_SMF, [UPFConstants.PSA2_PCAP_FILE_NAME, UPFConstants.UL_CL_PCAP_FILE_NAME])
            psa2_pcap_present = True
        else:
            pcap_file_path = self.copy_pcap_file_from_remote_file(UPFConstants.I_SMF, UPFConstants.UL_CL_PCAP_FILE_NAME)
        ul_cl_packet_details = self._pcap_helper.get_src_and_dest_details_of_pfcp_pcap_file(
                            Utility.join_path(pcap_file_path, UPFConstants.UL_CL_PCAP_FILE_NAME))
        ul_cl_pfd_details = self._pcap_helper.get_src_and_dest_details_of_pfd_pcap_file(
                            Utility.join_path(pcap_file_path, UPFConstants.UL_CL_PCAP_FILE_NAME))
        self._log.debug("The ULCL node  %s", str(ul_cl_packet_details + ul_cl_pfd_details))
        ul_cl_packet_status = self.validate_connection_of_ul_cl_pcap_file(ul_cl_packet_details + ul_cl_pfd_details, 
                                validation_ip_details)
        if not ul_cl_packet_status:
            err_msg = "ULCL Packets are missing"
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.TestCaseFailed(err_msg)
        self._log.debug("The ULCL node packets are valid %s", str(ul_cl_packet_details))
        if psa2_pcap_present:
            psa2_packet_details = self._pcap_helper.get_src_and_dest_details_of_pfcp_pcap_file(
                                Utility.join_path(pcap_file_path, UPFConstants.PSA2_PCAP_FILE_NAME))
            psa2_pfd_details = self._pcap_helper.get_src_and_dest_details_of_pfd_pcap_file(
                                Utility.join_path(pcap_file_path, UPFConstants.PSA2_PCAP_FILE_NAME))
            self._log.debug("The PSA2 node  %s", str(psa2_packet_details + psa2_pfd_details))
            psa2_packet_status = self.validate_connection_of_psa2_pcap_file(psa2_packet_details + psa2_pfd_details, 
                                validation_ip_details)
            if not psa2_packet_status:
                err_msg = "PSA2 Packets are missing"
                self._log.error(err_msg)
                self._log.debug("<")
                raise upf_exception.TestCaseFailed(err_msg)
            self._log.debug("The PSA2 node packets are valid %s", str(psa2_packet_details))
        Utility.delete_directory_recursively(pcap_file_path)
        self._log.debug("<")

    def _check_uplink_and_downlink_reachablility_status(self, ulcl_node=None):
        """Method used to copy the pcap file and validate the pcap traces UPF.

        Args:
            ulcl_node(bool): Containes True/False
            
        Returns:
            None
        """
        self._log.debug(">")
        node = None
        if self._node_name == UPFConstants.LOCAL_DN:
            pcap_file_name = UPFConstants.LOCAL_DN_PCAP_FILE_NAME
            node = UPFConstants.LOCAL_DN
        else:
            pcap_file_name = UPFConstants.DN_PCAP_FILE_NAME
            node = UPFConstants.DN

        pcap_file_path = self.copy_pcap_file_from_remote_file(node, pcap_file_name)
        packet_details = self._pcap_helper.get_udp_packet_src_dest_ip_list(
                        Utility.join_path(pcap_file_path, pcap_file_name))
        if not ulcl_node:
            validation_ip_details = self.get_template_arguments(UPFConstants.DN)
            packet_status = self.validate_pcap_file_of_gnb_or_dn(packet_details, 
                                validation_ip_details)
        else:
            if node == self._node_name:
                validation_ip_details = self.get_template_arguments_of_ulcl(node)
            else:
                validation_ip_details = self.get_template_arguments_of_ulcl(node)
            packet_status = self.validate_connection_of_uplink_psa1_and_psa2_pcap_file(packet_details,
                                validation_ip_details)
        Utility.delete_directory_recursively(pcap_file_path)
        if not packet_status:
            err_msg = "{} Packets are missing".format(node)
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.TestCaseFailed(err_msg)
        self._log.debug("The {} node packets are valid {}".format(node, str(packet_details)))
        self._log.debug("<")

    def _check_gnb_uplink_and_downlink_reachablility_status(self, ulcl_node=None):
        """Method used to copy the pcap file and validate the pcap traces UPF.

        Args:
            ulcl_node(bool): Containes True/False
            
        Returns:
            None
        """
        self._log.debug(">")
        pcap_file_path = self.copy_pcap_file_from_remote_file(UPFConstants.GNB, UPFConstants.GNB_PCAP_FILE_NAME)
        gnb_packet_details = self._pcap_helper.get_udp_packet_src_dest_ip_list(
                            Utility.join_path(pcap_file_path, UPFConstants.GNB_PCAP_FILE_NAME))
        if not ulcl_node:
            validation_ip_details = self.get_template_arguments(UPFConstants.GNB)
            gnb_packet_status = self.validate_pcap_file_of_gnb_or_dn(gnb_packet_details, 
                                validation_ip_details)
        else:
            validation_ip_details = self.get_template_arguments_of_ulcl(UPFConstants.GNB)
            gnb_packet_status = self.validate_connection_of_uplink_psa1_and_psa2_pcap_file(gnb_packet_details, 
                                validation_ip_details)
        Utility.delete_directory_recursively(pcap_file_path)
        if not gnb_packet_status:
            err_msg = "GNB Packets are missing"
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.TestCaseFailed(err_msg)
        self._log.debug("The GNB node packets are valid %s", str(gnb_packet_details))
        self._log.debug("<")
        
    def setup_real_node_script(self, api_operation=None):
        """ Method used to copy the template, scripts and service file from regal to nodes.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        tcp_dump_config = {}
        host_ip = self.get_management_ip()
        tcp_dump_config.update({"smf_management_ip":host_ip})
        if self._node_name == UPFConstants.SMF:
            template_args = self.get_template_arguments(UPFConstants.SMF)
            tcp_dump_config.update({"execute_upf_tcpdump_file":UPFConstants.RUN_TCP_DUMP_UPF,\
                                    "interface_name_1":template_args["smf_interface"],\
                                       "file_name_1":UPFConstants.DEST_PATH_FOR_SCRIPTS + self._node_name + "_pcap.pcap" ,\
                                            "run_smf_script": UPFConstants.RUN_SMF_SCRIPT})
            file_list_1 = self._get_upf_script_and_service_files_path([template_args["template_script_path"]])
            file_list_2 = self._get_upf_script_and_service_files_path([UPFConstants.TCP_DUMP_SERVICE_FILE_PATH_UPF, \
                            UPFConstants.SHELL_SCRIPT_SERVICE_PATH])
            dest_paths = [UPFConstants.REAL_SMF_DEST_PATH_SCRIPT, UPFConstants.DEST_PATH_FOR_SERVICE]
            src_paths = [file_list_1, file_list_2]
            self.copy_multiple_template_scripts(src_paths, dest_paths, template_args, tcp_dump_config)
            src_path = [UPFConstants.SHELL_SCRIPT_SRC_PATH, UPFConstants.RUN_SERVICE_TCP_DUMP_UPF]
            dest_path = [UPFConstants.DEST_PATH_FOR_SCRIPTS, UPFConstants.DEST_PATH_FOR_SCRIPTS]
            self._copy_files_to_node(src_path, dest_path, tcp_dump_config)
            self._log.debug("<")

        if self._node_name == UPFConstants.UNICORN:
            self._copy_api_request_and_client_files_to_unicorn_node(api_operation)
            self._log.debug("<")

    def _copy_api_request_and_client_files_to_unicorn_node(self, api_operation):
        """ Method used to copy the files required for running unicorn testcases.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        src_path = []
        template_args = {}
        node_ip = self.get_management_ip(UPFConstants.SMF)
        if api_operation == UPFConstants.SESSION_CREATION:
            template_args = self.get_arguments_for_session_creation()
            src_path = [[UPFConstants.SESSION_CREATION_JSON_PATH], UPFConstants.CLIENT_CREATION_JSON_PATH]
        if api_operation == UPFConstants.SESSION_MODIFICATION:
            template_args = self.get_arguments_for_session_modification()
            src_path = [[UPFConstants.SESSION_CREATION_JSON_PATH, UPFConstants.SESSION_MODIFICATION_JSON_PATH], 
                            UPFConstants.CLIENT_MODIFICATION_JSON_PATH]
        if api_operation == UPFConstants.SESSION_DELETION:
            template_args = self.get_arguments_for_session_deletion()
            src_path = [[UPFConstants.SESSION_CREATION_JSON_PATH, UPFConstants.SESSION_MODIFICATION_JSON_PATH,
                            UPFConstants.SESSION_DELETION_JSON_PATH], UPFConstants.CLIENT_DELETION_JSON_PATH]
        template_args.update({"host_ip":node_ip, "uuid":'{{.uuid}}'})
        self._copy_unicorn_testcase(src_path, template_args)
        self._log.debug("<")

    def _copy_unicorn_testcase(self, src_path, template_args):
        """
        Method used to copy unicorn testcases.

        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        request_body_dest_path = "/opt/unicorn/testcases/{}/{}/{}/config/".format(self.sut_name, self.ts_name, self.tc_name)
        client_request_dest_path =  "/opt/unicorn/testcases/{}/{}/{}/test_config.json".format(self.sut_name, self.ts_name, self.tc_name)
        #removing old testcases
        remove_cmd = "rm -rf /opt/unicorn/testcases/{}/".format(self.sut_name)
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(remove_cmd,
                        self._node_name, time_out=UPFConstants.PEXPECT_TIMER)
        #creating new testcases
        mkdir_cmd = "mkdir -p /opt/unicorn/testcases/{}/{}/{}/config".format(self.sut_name, self.ts_name, self.tc_name)
        self.service_store_obj.get_login_session_mgr_obj().perform_operation(mkdir_cmd,
                        self._node_name, time_out=UPFConstants.PEXPECT_TIMER)
        #copying files to the node
        for path in src_path[0]:
            files_src_path = self._get_upf_script_and_service_files_path(path)
            self._log.debug("< request_body_dest_path %s-%s", str(files_src_path), str(request_body_dest_path))
            self.service_store_obj.get_login_session_mgr_obj().copy_files_to_node(self._node_obj, 
                            files_src_path[0], request_body_dest_path)
        #copying template file to the node
        template_src_path = self._get_upf_script_and_service_files_path(src_path[1])
        self._log.debug("< client_request_dest_path %s-%s", str(template_src_path), str(client_request_dest_path))
        self.service_store_obj.get_login_session_mgr_obj().copy_template_to_node(self._node_obj, \
                        template_src_path[0], client_request_dest_path, template_args)
        self._log.debug("<")

    def get_arguments_for_session_creation(self):
        """ Method used to create curl command and return args for client request body.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        template_args = {}
        session_creation_request_body = "/opt/unicorn/testcases/{}/{}/{}/config/{}".format(self.sut_name, self.ts_name, self.tc_name, 
                        UPFConstants.SESSION_CREATION_FILENAME)
        template_args.update({"session_creation_request_body": session_creation_request_body})
        self._log.debug("<")
        return template_args

    def get_arguments_for_session_modification(self):
        """ Method used to create curl command and return args for client request body.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        session_modification_request_body = "/opt/unicorn/testcases/{}/{}/{}/config/{}".format(self.sut_name, self.ts_name, self.tc_name,
                         UPFConstants.SESSION_MODIFICATION_FILENAME)
        template_args = self.get_arguments_for_session_creation()
        template_args.update({"session_modification_request_body": session_modification_request_body})
        self._log.debug("<")
        return template_args

    def get_arguments_for_session_deletion(self):
        """ Method used to create curl command and return args for client request body.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        template_args = {}
        session_deletion_request_body = "/opt/unicorn/testcases/{}/{}/{}/config/{}".format(self.sut_name, self.ts_name, self.tc_name, 
                    UPFConstants.SESSION_DELETION_FILENAME)
        template_args = self.get_arguments_for_session_creation()
        template_args.update(self.get_arguments_for_session_modification())
        template_args.update({"session_deletion_request_body": session_deletion_request_body})
        self._log.debug("<")
        return template_args
        
    def validate_real_node_pcap(self, smf_operation, pkt_count):
        """ Method used to validate the pcap traces between nodes.
        
        Args:
            None

        Return:
            None
        """
        self._log.debug(">")
        validation_ip_details = self.get_template_arguments(UPFConstants.SMF)
        pcap_file_path = self.copy_pcap_file_from_remote_file(UPFConstants.SMF, UPFConstants.SMF_PCAP_FILE_NAME)
        packet_details = self._pcap_helper.get_src_and_dest_details_of_pfcp_pcap_file(
                        Utility.join_path(pcap_file_path, UPFConstants.SMF_PCAP_FILE_NAME))
        packet_status = self.validate_connection_of_real_node_smf_pcap_file(packet_details, validation_ip_details, 
                            smf_operation, pkt_count)
        Utility.delete_directory_recursively(pcap_file_path)
        if not packet_status:
            err_msg = "{} node {} Packets are missing".format(UPFConstants.SMF, smf_operation)
            self._log.error(err_msg)
            self._log.debug("<")
            raise upf_exception.TestCaseFailed(err_msg)
        self._log.debug("The {} node {} packets are valid {}".format(UPFConstants.SMF, smf_operation, str(packet_details)))
        self._log.debug("<")
        

    def validate_connection_of_real_node_smf_pcap_file(self, packet_details, validation_ip_details, smf_operation, pkt_count):
        """ Method used to validate the connection between upf and smf node.

        Args:
            smf_packet_details(list): UDP packets.
            validation_ip_details(dict): node details.

        Returns:
            bool: True or False.

        """
        self._log.debug("> ")
        count = 0
        if packet_details:
            for pkt_address in packet_details:
                if pkt_address[0] == validation_ip_details["smf_traffic_interface_ip"]:
                    if pkt_address[1] == validation_ip_details["n4_ip_v4"]:
                        self._log.debug("Request_reached")
                        count = count + 1
                        
                if pkt_address[0] == validation_ip_details["n4_ip_v4"]:
                    if pkt_address[1] == validation_ip_details["smf_traffic_interface_ip"]:
                        if pkt_address[2] == 1:
                            self._log.debug("Response_reached")
                            count = count + 1
           
        if count >= pkt_count:
            self._log.debug("< {} reached with successful cause.".format(smf_operation))
            return True
        self._log.debug("< {} not Reached upf".format(smf_operation))
        return False