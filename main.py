!#usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def snffr(interface):
    scapy.sniff(iface=interface, store=False, prn=pcktsnffSeq, filter="")

def pcktsnffrSeq(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet.show())

snffr("eth0")