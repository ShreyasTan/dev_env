#!/usr/bin/python

# Send uplink packets to DN.

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sendp, sniff
from scapy.contrib.gtp import GTPHeader as GTPHeader
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
import logging
import threading
import signal,os

# gNB_ADDR = '192.168.110.1'
# N3_ADDR = '192.168.110.237'
# UE_ADDR = '192.168.190.65'
# DN_ADDR = '192.168.170.226' 

# gNB_ADDR = '192.168.110.1'
# N3_ADDR = '192.168.110.237'
UE_ADDR = "{{ psa2_ue_ip_v4 }}"
DN_ADDR = "{{ local_dn_traffic_interface_ip }}"

RATE = 1

class down(object):
    def fn1(packets):
        pkt = sniff(iface="{{ local_dn_interface }}",filter="udp port 10053", count=1)
        PAYLOAD = 'Downlink traffic'
        #pkt = Ether()/IP(src=DN_ADDR,dst=UE_ADDR) /UDP(sport=10053,dport=10053)/PAYLOAD
        #pkt1 = Ether(src=pkt[0][0].dst,dst=pkt[0][0].src)/IP(src=pkt[0][1].dst,dst=pkt[0][1].src) /UDP(sport=10053,dport=10053)/PAYLOAD
        pkt1 = Ether()/IP(src=DN_ADDR,dst=UE_ADDR) /UDP(sport=10053,dport=10053)/PAYLOAD
        sendp(pkt1, iface="{{ local_dn_interface }}",inter=1.0 / RATE, loop=False, verbose=True)


class pkttthread(threading.Thread):
    def __init__(self, threadID, name, counter,fn):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.fn = fn
    def run(self):
        while self.counter:
            self.fn.fn1()
            self.counter -= 1

if __name__ =="__main__":
    obj=down()
    obj1=pkttthread(1,"thread",1000,obj)
    obj1.start()
    obj1.join()
