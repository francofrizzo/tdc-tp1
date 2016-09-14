#! /usr/bin/env python2
import sys
from math import log
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

broadcast_p = broadcast_packets * 1.0 / len(sniffed_packets)
not_broadcast_p = 1 - broadcast_p
broadcast_i = -log(broadcast_p, 2)
not_broadcast_i = -log(not_broadcast_p, 2)
s_entropy = broadcast_p*broadcast_i + not_broadcast_p*not_broadcast_i

print '\nFuente S'
print '--------'
print 'E = {Paquete con destino broadcast}'
print 'P(E) = ' + str(broadcast_p)
print 'P(!E) = ' + str(not_broadcast_p)
print 'I(E) = ' + str(broadcast_i) + ' bits'
print 'I(!E) = ' + str(not_broadcast_i) + ' bits'
print 'H(S) = ' + str(s_entropy) + ' bits'
