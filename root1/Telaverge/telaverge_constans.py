class Constants(object):
    """This class define all constants used for product Telaverge"""
    TV_PROD_DIR_NAME = "Telaverge"
    PLATFORM = "Platform"
    APPLICATION = "Application"
    OS_PACKAGE = "OsPackage"
    PLATFORM_PACKAGE = "PlatformPackage"
    SNMP_RELEASE_VERSION = "3.0.0"
    TELAVERGE_PROD_DIR_NAME = "Telaverge"
    TEMPLATE_PATH = '../product/Telaverge/config/template/datetime_benchmark_template.docx'
    DUMMY_CONST = 'HI ADBHASGD'
    K8_HELM_CHARTS = "k8HelmCharts"

class UPFConstants(object):
    UPF = "UPF"
    SMF = "SMF"
    DN = "DN"
    GNB = "gNodeB"
    UL_CL = "ULCL"
    I_SMF = "I-SMF"
    PSA1 = "PSA1"
    PSA2 = "PSA2"
    LOCAL_DN = "LOCAL-DN"
    UNICORN = "Unicorn"
    UPF_NODE_SOURCE_SMU = "product/Telaverge/config/sut/UPF/smu_docker.ini"
    UPF_NODE_SOURCE_LBU = "product/Telaverge/config/sut/UPF/lbu_docker.ini"
    UPF_NODE_DEST_LBU = "/root/upf/config/lbu/"
    UPF_NODE_DEST_SMU = "/root/upf/config/smu/"
    SMF_TEMPLATE_SCRIPT = "product/Telaverge/config/sut/UPF/pfcp_session_.py"
    DN_TEMPLATE_SCRIPT = "product/Telaverge/config/sut/UPF/N6_downlink_gtp.py"
    GNB_TEMPLATE_SCRIPT = "product/Telaverge/config/sut/UPF/N3_uplink_gtp_1.py"

    RUN_SERVICE_TCP_DUMP_UPF = "product/Telaverge/config/sut/UPF/run_tcp_dump_upf.py"
    RUN_SERVICE_TCP_DUMP_ULCL = "product/Telaverge/config/sut/UPF/run_tcp_dump_ulcl.py"
    RUN_TCP_DUMP_UPF = "/opt/upf/run_tcp_dump_upf.py"
    RUN_TCP_DUMP_ULCL = "/opt/upf/run_tcp_dump_ulcl.py"
    TCP_DUMP_SERVICE_FILE_PATH_UPF = "product/Telaverge/config/sut/UPF/run_tcp_dump_service_upf.service"
    TCP_DUMP_SERVICE_FILE_PATH_ULCL = "product/Telaverge/config/sut/UPF/run_tcp_dump_service_ulcl.service"
    UPF_SCRIPT_SERVICE_FILE_PATH = "product/Telaverge/config/sut/UPF/upf_script_service.service"
    ULCL_SCRIPT_SERVICE_FILE_PATH = "product/Telaverge/config/sut/UPF/ulcl_script_service.service"

    UPF_SCRIPT_PATH = "/root/upf/install/script/"
    UPF_SCRIPT = "./restart_upf.sh"
    DEST_PATH_FOR_SCRIPTS = "/opt/upf/"
    DEST_PATH_FOR_SERVICE = "/usr/lib/systemd/system/"
    UPF_TCP_DUMP_SERVICE_NAME = "run_tcp_dump_service_upf"
    UPF_SERVICE_NAME = "upf_script_service"
    ULCL_TCP_DUMP_SERVICE_NAME = "run_tcp_dump_service_ulcl"
    ULCL_SERVICE_NAME = "ulcl_script_service"
    ACTION_STARTED = "started"
    ACTION_STOPPED = "stopped"
    DN_PCAP_FILE = "/opt/upf/dn_pcap.pcap"
    GNB_PCAP_FILE = "/opt/upf/gnb_pcap.pcap"
    SMF_PCAP_FILE = "/opt/upf/smf_pcap.pcap"

    DN_PCAP_FILE_NAME = "DN_pcap.pcap"
    GNB_PCAP_FILE_NAME = "gNodeB_pcap.pcap"
    SMF_PCAP_FILE_NAME = "SMF_pcap.pcap"
    UL_CL_PCAP_FILE_NAME = "ULCL_pcap.pcap"
    PSA2_PCAP_FILE_NAME = "PSA2_pcap.pcap"
    DN_PCAP_FILE_NAME = "DN_pcap.pcap"
    LOCAL_DN_PCAP_FILE_NAME = "LOCAL-DN_pcap.pcap"


    UL_CL_PCAP_FILE = "/opt/upf/ul_cl_pcap.pcap"
    PSA1_PCAP_FILE = "/opt/upf/psa1_pcap.pcap"
    PSA2_PCAP_FILE = "/opt/upf/psa2_pcap.pcap"

    UPF_SERVER_SCRIPT_REMOTE_PATH = "/opt/upf/run_upf_scripts.py"
    UPF_NODE_NAME = "UPF"
    GNB_NODE_NAME = "gNodeB"
    DN_NODE_NAME = "DN"
    SMF_NODE_NAME = "SMF"
    UNICORN_NODE_NAME = "Unicorn"
    ULCL_NODE_NAME = "ULCL"
    PSA1_NODE_NAME = "PSA1"
    PSA2_NODE_NAME = "PSA2"
    I_SMF_NODE_NAME = "I-SMF"
    GNB_NODE_NAME = "gNodeB"
    DN_NODE_NAME = "DN"
    LOCAL_DN_NODE_NAME = "LOCAL-DN"
    UPF_APP = "upf"
    SMF_APP = "smf"
    DN_APP = "dn"
    GNB_APP = "gNB"
    SMF_5G_APP = "5G_SMF"
    UNICORN_APP = "unicorn_installer"
    N6_DOWNLINK_GTP = "/opt/upf/N6_downlink_gtp.py"
    N3_UPLINK_GTP = "/opt/upf/N3_uplink_gtp_1.py"
    PFCP_SESSION = "/opt/upf/pfcp_session_.py"

    PFCP_PSA1 = "/opt/upf/pfcp_psa1.py"
    PFCP_ULCL = "/opt/upf/pfcp_ulcl.py"
    PFCP_PSA2 = "/opt/upf/pfcp_psa2.py"
    UPLINK_GTP_PSA1 = "/opt/upf/uplink_gtp_psa1.py"
    DOWNLINK_GTP_PSA1 = "/opt/upf/downlink_gtp_psa1.py"
    DOWNLINK_GTP_PSA2 = "/opt/upf/downlink_gtp_psa2.py"
    UPLINK_GTP_PSA2 = "/opt/upf/uplink_gtp_psa2.py"

    UL_CL_PCAP_FILE = "/opt/upf/ul_cl_pcap.pcap"
    PSA1_PCAP_FILE = "/opt/upf/psa1_pcap.pcap"
    PSA2_PCAP_FILE = "/opt/upf/psa2_pcap.pcap"

    EXPECTED_STRING = "Start UPF complete."

    PEXPECT_TIMER = 20

    FILES = ["/SMF/cmd/log/smfsslkey.log", "/SMF/config/TLS/smf.pem", "/SMF/config/TLS/smf.key", "/SMF/config/smfcfg.yaml", 
                "/SMF/config/uerouting.yaml", "/SMF/cmd/SMF"]
    REAL_SMF_DEST_PATH = "/root/"
    SERVICE_FILE = "product/Telaverge/config/sut/UPF/service_file.service"
    RELOAD_SYSTEM = "systemctl daemon-reload"
    UDRP = "UDRP"
    UDR = "UDR"
    UDM = "UDM"
    MONGO = "mongod"
    MONGO_FILE_PATH = "product/Telaverge/config/sut/UPF/mongodb-org-4.repo"
    MONGO_DEST_PATH = "/etc/yum.repos.d/"

    REAL_SMF_DEST_PATH_SCRIPT = "/../SMF/config/"
    SMF_PATH = "./SMF/cmd/"
    SHELL_SCRIPT_SERVICE_PATH = "product/Telaverge/config/sut/UPF/run_shell_script_service.service"
    SHELL_SCRIPT_SRC_PATH = "product/Telaverge/config/sut/UPF/run_smf_script.sh"
    SHELL_SCRIPT_SERVICE = "run_shell_script_service"
    RUN_TCP_DUMP_REAL_SMF_PATH = "../SMF/config/run_tcp_dump_upf.py"
    ASSOCIATION_SETUP = "association_setup"
    SESSION_CREATION = "session_creation"
    SESSION_MODIFICATION = "session_modification"
    SESSION_DELETION = "session_deletion"
    SESSION_CREATION_JSON_PATH = "product/Telaverge/config/sut/UPF/session_creation_request.json"
    SESSION_MODIFICATION_JSON_PATH = "product/Telaverge/config/sut/UPF/session_modification_request.json" 
    SESSION_DELETION_JSON_PATH = "product/Telaverge/config/sut/UPF/session_deletion_request.json"
    CLIENT_CREATION_JSON_PATH = "product/Telaverge/config/sut/UPF/client_config.json"
    SESSION_CREATION_FILENAME = "session_creation_request.json"
    SESSION_MODIFICATION_FILENAME = "session_modification_request.json" 
    SESSION_DELETION_FILENAME = "session_deletion_request.json"
    RUN_SMF_SCRIPT = DEST_PATH_FOR_SCRIPTS + "run_smf_script.sh"