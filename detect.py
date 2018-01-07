#! /usr/bin/python
from scapy.all import *

MAC_ADDRESS = 'b4:7c:9c:e5:47:c7' # Amazon Charmin Dash Button MAC Address

def detect_button(pkt):
    if pkt.haslayer(DHCP) and pkt[Ether].src == MAC_ADDRESS:
            print "Button Press Detected" 
            #Do stuff

sniff(prn=detect_button, filter="(udp and (port 67 or 68))", store=0)
