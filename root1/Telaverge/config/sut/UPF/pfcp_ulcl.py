#!/usr/bin/python3

from datetime import datetime
import time
import uuid
from random import getrandbits
from scapy.contrib.pfcp import CauseValues, IE_ApplyAction, IE_Cause, \
    IE_CreateFAR, IE_CreatePDR, IE_CreateURR, IE_DestinationInterface, \
    IE_DurationMeasurement, IE_EndTime, IE_EnterpriseSpecific, IE_FAR_Id, \
    IE_ForwardingParameters, IE_FSEID, IE_MeasurementMethod,IE_OuterHeaderCreation, \
    IE_NetworkInstance, IE_NodeId, IE_PDI, IE_PDR_Id, IE_Precedence, \
    IE_QueryURR, IE_RecoveryTimeStamp, IE_RedirectInformation, IE_ReportType, \
    IE_ReportingTriggers, IE_SDF_Filter, IE_SourceInterface, IE_StartTime, \
    IE_TimeQuota, IE_UE_IP_Address, IE_URR_Id, IE_UR_SEQN, IE_OuterHeaderRemoval,\
    IE_UsageReportTrigger, IE_VolumeMeasurement, IE_ApplicationId, PFCP,IE_FTEID, \
    PFCPAssociationSetupRequest, PFCPAssociationSetupResponse, \
    PFCPHeartbeatRequest, PFCPHeartbeatResponse, PFCPSessionDeletionRequest, \
    PFCPSessionDeletionResponse, PFCPSessionEstablishmentRequest, \
    PFCPSessionEstablishmentResponse, PFCPSessionModificationRequest, \
    PFCPSessionModificationResponse, PFCPSessionReportRequest, PFCPSessionReportResponse, \
    PFCPAssociationReleaseRequest, IE_CreateTrafficEndpoint, IE_TrafficEndpointId, \
    IE_RemoveTrafficEndpoint, IE_UpdateTrafficEndpoint, IE_QFI, PFCPPFDManagementRequest, \
    IE_ApplicationID_PFDs, IE_PFDContext, IE_PFDContents
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.all import send, sniff, sendp
import logging
import threading
import signal, os

# PFCP_CP_IP_V4 = "192.168.110.208"
# PFCP_UP_IP_V4 = "192.168.70.56"
# N3_IP_V4 = "192.168.100.56"
# N9_IP_V4 = "192.168.100.57"
# GNB_IP_V4 = "192.168.110.226"
# # IUPF_IP_V4 = "192.168.101.249"
# PSA1_UPF_N9_IP_V4 = "192.168.101.57"
# PSA2_UPF_N9_IP_V4 = '192.168.102.57'
# ULCL_IP_N9_V4 = '192.168.100.57'
# UE_IP_V4 = "192.168.130.55"

PFCP_CP_IP_V4 = "{{ ulcl_traffic_interface_ip }}"
PFCP_UP_IP_V4 = "{{ ulcl_n4_ip_v4 }}"
N3_IP_V4 = "{{ ulcl_n3_ip_v4 }}"
N9_IP_V4 = "{{ ulcl_n9_ip_v4 }}"
GNB_IP_V4 = "{{ gnb_traffic_interface_ip }}"
# IUPF_IP_V4 = "192.168.101.249"
PSA1_UPF_N9_IP_V4 = "{{ psa1_upf_n9_ip_v4 }}"
PSA2_UPF_N9_IP_V4 = "{{ psa2_upf_n9_ip_v4 }}"
ULCL_IP_N9_V4 = "{{ ulcl_n9_ip_v4 }}"
UE_IP_V4 = "{{ ulcl_ue_ip_v4 }}"


def seid():
    return uuid.uuid4().int & (1 << 64) - 1

class PfcpSkeleton(object):
    def __init__(self, pfcp_cp_ip,pfcp_up_ip):
        self.pfcp_cp_ip = pfcp_cp_ip
        self.pfcp_up_ip = pfcp_up_ip
        self.ue_ip = UE_IP_V4
        self.iface = "{{ ulcl_interface_name }}"
        self.ts = int((datetime.now() - datetime(1900, 1, 1)).total_seconds())
        self.seq = 1
        #self.nodeId = IE_NodeId(id_type=2, id="smf01")
        self.cur_seid = 0
        self.nodeId = IE_NodeId(id_type=0, ipv4=PFCP_CP_IP_V4)
        logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def ie_ue_ip_address(self, SD=0):
        return IE_UE_IP_Address(ipv4=self.ue_ip, V4=1, SD=SD)

    def ie_fseid(self):
        return IE_FSEID(ipv4=self.pfcp_cp_ip, v4=1, seid=self.cur_seid)

    def associate(self):
        self.chat(PFCPAssociationSetupRequest(IE_list=[
            IE_RecoveryTimeStamp(timestamp=self.ts),
            self.nodeId
            ]))

    def SniffStatusReq(self):
        pkt = sniff(iface=self.iface,filter="udp port 8805", count=1)
        resp = pkt[0][PFCP]
        self.logger.info("REQ: %r" % resp.message_type)
        if resp.message_type == 1:
            heartReq = resp[PFCPHeartbeatRequest]
            heartRep = PFCPHeartbeatResponse(IE_list=[
            IE_RecoveryTimeStamp(timestamp=self.ts)])
            self.chat(heartRep, resp.seq)
        elif resp.message_type == 51:
            #print('Received session establishment response: ' + resp.seid)
            self.cur_seid = resp.seid
        elif resp.message_type == 56:
            localtime = time.asctime( time.localtime(time.time()) )
            reportResp = PFCPSessionReportResponse(IE_list=[IE_Cause(cause=1)])
            print('Received SRR' + localtime)
            self.chat(reportResp, resp.seq)

    def heartbeat(self):
        resp = self.chat(PFCPHeartbeatRequest(IE_list=[
            IE_RecoveryTimeStamp(timestamp=self.ts)
        ]))

    def pfd_management(self):
        self.chat(PFCPPFDManagementRequest(IE_list=[
            IE_ApplicationID_PFDs(IE_list=[
                IE_ApplicationId(id="100"),
                IE_PFDContext(IE_list=[
                    IE_PFDContents(
                        FD=1,
                        flow_length=51,
                        flow="permit in ip from {{ ulcl_ue_ip_v4 }} to {{ local_dn_traffic_interface_ip }}"
                    )
                ])
            ]),
            self.nodeId
        ]))

    def establish_session_request(self):
        self.cur_seid += 1
        resp = self.chat(PFCPSessionEstablishmentRequest(IE_list=[
            #UPLINK FAR=1,PDR=1
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=1),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Core"),
                    IE_NetworkInstance(instance="N3"),
                    IE_OuterHeaderCreation(GTPUUDPIPV4=1,TEID=1118,ipv4=PSA1_UPF_N9_IP_V4)
                ])
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=1),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="N3"),
                    IE_SourceInterface(interface="Access"),
                    self.ie_ue_ip_address(SD=0),
                    IE_FTEID(V4=1,TEID=1111,ipv4=N3_IP_V4)
                ]),
                IE_PDR_Id(id=1),
                IE_Precedence(precedence=65600),
                IE_OuterHeaderRemoval(),
            ]),

            #DOWNLINK FAR=2,PDR=2
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=2),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(instance="N9"),
                    IE_OuterHeaderCreation(GTPUUDPIPV4=1,TEID=2222,ipv4=GNB_IP_V4)
                ])
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=2),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="N9"),
                    IE_SourceInterface(interface="Access"),
                    # self.ie_ue_ip_address(SD=1),
                    IE_FTEID(V4=1,TEID=2228,ipv4=ULCL_IP_N9_V4)
                ]),
                IE_PDR_Id(id=2),
                IE_Precedence(precedence=65600),
                IE_OuterHeaderRemoval(),
            ]),

            #UPLINK FAR=256,PDR=256
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=256),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Core"),
                    IE_NetworkInstance(instance="N3"),
                    IE_OuterHeaderCreation(GTPUUDPIPV4=1,TEID=1119,ipv4=PSA2_UPF_N9_IP_V4)
                ])
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=256),
                IE_PDI(IE_list=[
                    IE_SourceInterface(interface="Access"),
                    IE_TrafficEndpointId(id=1),
                    IE_ApplicationId(id="100")
                ]),
                IE_PDR_Id(id=256),
                IE_Precedence(precedence=200),
                IE_OuterHeaderRemoval()
            ]),
            IE_CreateTrafficEndpoint(IE_list=[
                IE_NetworkInstance(instance="N3"),
                IE_TrafficEndpointId(id=1),
                IE_FTEID(V4=1,TEID=1111,ipv4=N3_IP_V4)
            ]),

            #DOWNLINK FAR=257,PDR=257
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=257),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(instance="N9"),
                    IE_OuterHeaderCreation(GTPUUDPIPV4=1,TEID=2222,ipv4=GNB_IP_V4)
                ])
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=257),
                IE_PDI(IE_list=[
                    IE_SourceInterface(interface="Access"),
                    IE_TrafficEndpointId(id=2)
                ]),
                IE_PDR_Id(id=257),
                IE_Precedence(precedence=200),
                IE_OuterHeaderRemoval()
            ]),
            IE_CreateTrafficEndpoint(IE_list=[
                IE_TrafficEndpointId(id=2),
                IE_FTEID(V4=1,TEID=2229,ipv4=N9_IP_V4),
                IE_NetworkInstance(instance="N9")
            ]),
            self.ie_fseid(),
            self.nodeId,
        ]), seid=0)

    def chat(self, pkt, seq=None,seid=None):
        self.logger.info("REQ: %r" % pkt)
        sendp(
            Ether()/
            IP(src=self.pfcp_cp_ip, dst=self.pfcp_up_ip) /
            UDP(sport=8805, dport=8805) /
            PFCP(
                version=1,
                S=0 if seid is None else 1,
                seid=0 if seid is None else seid,
                seq=self.seq if seq is None else seq) /
                pkt, iface=self.iface)
        if seq is None:
            self.seq +=1

    def signal_fun(self,signum,frame):
        self.chat(PFCPAssociationReleaseRequest(IE_list=[
            self.nodeId
        ]))
        os._exit(0)

class ResponderThread(threading.Thread):
    def __init__(self, threadID, name, counter,ass):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.ass = ass

    def run(self):
        while self.counter:
            self.ass.SniffStatusReq()
            self.counter -= 1


if __name__ =="__main__":
    pfcp_client = PfcpSkeleton(PFCP_CP_IP_V4,PFCP_UP_IP_V4)
    hb = ResponderThread(1000, 'HB', 50, pfcp_client)
    hb.start()
    pfcp_client.associate()
    time.sleep(1)
    pfcp_client.pfd_management()
    time.sleep(1)
    pfcp_client.establish_session_request()
    hb.join()
