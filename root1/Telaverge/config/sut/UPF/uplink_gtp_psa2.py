#!/usr/bin/python3

# Send uplink packets to DN.

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sendp
from scapy.contrib.gtp import GTPHeader as GTPHeader
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time

# gNB_ADDR = "192.168.101.249"
# N3_ADDR = "192.168.101.57"
# UE_22_ADDR = '192.168.102.22'
# DN_ADDR = '192.168.102.251'

gNB_ADDR = "{{ gnb_traffic_interface_ip }}"
N3_ADDR = "{{ n3_ip_v4 }}"
UE_22_ADDR = "{{ ue_ip_v4 }}"
DN_ADDR = "{{ local_dn_traffic_interface_ip }}"

##### send GTP packet towards UPF
RATE = 1  # packets per second
GTP = GTPHeader(version=1, teid=1111,gtp_type=0xff)

print("Sending %d UDP packets per second to %s..." % (RATE, UE_22_ADDR))

PAYLOAD = 'It is uplink traffic: {}'.format(0)
print("Sending packet: {}".format(0))
reqpkt = Ether()/IP(src=gNB_ADDR,dst=N3_ADDR) / UDP(sport=2152, dport=2152) /GTP/IP(src=UE_22_ADDR,dst=DN_ADDR)/UDP(sport=10053,dport=10053)/PAYLOAD
sendp(reqpkt, iface="{{ gnb_interface }}",inter=1.0 / RATE, loop=False, verbose=True)
