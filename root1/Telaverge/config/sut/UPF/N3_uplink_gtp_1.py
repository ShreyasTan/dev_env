#!/usr/bin/python3

# Send uplink packets to DN.

#GnodeB script

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sendp
from scapy.contrib.gtp import GTPHeader as GTPHeader
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

# gNB_ADDR = "192.168.110.128" #Mangement ip of the gNode b
# #N3_ADDR = '192.168.100.237'
# N3_ADDR = '192.168.10.56' # Same as the upf node
# #N3_ADDR = '10.8.124.197'
# UE_ADDR = '192.168.130.55' # keep constan
# DN_ADDR = '192.168.110.244' #Mangement ip of the DN


gNB_ADDR = "{{ gnb_traffic_interface_ip }}" #ip of gnb
#N3_ADDR = '192.168.100.237'
N3_ADDR = "{{ n3_ip_v4 }}" #n3 in upf
#N3_ADDR = '10.8.124.197'
UE_ADDR = "{{ ue_ip_v4 }}" #ip of v4 UE this should be constant in testcase configuration
DN_ADDR = "{{ dn_traffic_interface_ip }}" #ip of dn 

RATE = 1  # packets per second
PAYLOAD = 'P4 is great!'
GTP = GTPHeader(version=1, teid=1111,gtp_type=0xff)
print("Sending %d UDP packets per second to %s..." % (RATE, UE_ADDR))
#pkt = IP(src=gNB_ADDR,dst=N3_ADDR) / UDP(sport=2152, dport=2152) /GTP/IP(src=UE_ADDR,dst=DN_ADDR)/UDP(sport=10053,dport=10053)/PAYLOAD
#pkt = Ether()/IP(src=gNB_ADDR,dst=N3_ADDR) / UDP(sport=2152, dport=2152) /GTP/IP(src=UE_ADDR,dst=DN_ADDR)/UDP(sport=10053,dport=10053)/DNS(rd=1, qd=DNSQR(qname="google.com"))
#pkt = Ether(src='78:2b:cb:76:44:82', dst='a0:36:9f:a1:22:e2') /IP(src=gNB_ADDR,dst=N3_ADDR) / UDP(sport=2152, dport=2152) /GTP/IP(src=UE_ADDR,dst=DN_ADDR)/UDP(sport=10053,dport=10053)/PAYLOAD
pkt = Ether()/IP(src=gNB_ADDR,dst=N3_ADDR) / UDP(sport=2152, dport=2152) /GTP/IP(src=UE_ADDR,dst=DN_ADDR)/UDP(sport=10053,dport=10053)/PAYLOAD
#pkt = Ether()/IP(src=DN_ADDR,dst=UE_ADDR) /UDP(sport=10053,dport=10053)/PAYLOAD
#sendp(pkt, iface='virbr0',inter=1.0 / RATE, loop=False, verbose=True)
#pkt=Ether(dst='52:54:00:d2:91:01')/DNS(rd=1, qd=DNSQR(qname="github.com"))
#Interface of the 110 subent series
# sendp(pkt, iface='enp7s0',inter=1 / RATE, loop=False, verbose=True)
sendp(pkt, iface="{{ gnb_interface }}",inter=1 / RATE, loop=False, verbose=True)
#sendp(pkt, iface='virbr2',inter=0,count=100000000)
#send(pkt, IP(dstenp7s0168.120.219'),inter=1.0 / RATE, loop=False, verbose=True)
