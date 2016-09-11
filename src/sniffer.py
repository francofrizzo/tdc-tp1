#! /usr/bin/env python2
import sys
from scapy.all import Ether, Dot11, sniff

BROADCAST_PHYSICAL_ADDRESS = 'ff:ff:ff:ff:ff:ff'

broadcast_packets = 0
sniff_count = 0
pcap_file = None

if len(sys.argv) > 1:
    # limit amount of packets to be sniffed
    sniff_count = int(sys.argv[1])
    if len(sys.argv) > 2:
        # use a pcap file as input
        pcap_file = sys.argv[2]

sniffed_packets = sniff(count=sniff_count, offline=pcap_file, store=1)

# count broadcast messages
broadcast_packets = len([1 for pkt in sniffed_packets \
    if (Ether in pkt and pkt.dst == BROADCAST_PHYSICAL_ADDRESS) or \
       (Dot11 in pkt and pkt.addr1 == BROADCAST_PHYSICAL_ADDRESS)])

print broadcast_packets * 1.0 / len(sniffed_packets)
