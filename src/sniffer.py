#! /usr/bin/env python2
import sys
import pprint
from math import log
from scapy.all import ARP, Ether, Dot11, sniff

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

# S
broadcast_p = broadcast_packets * 1.0 / len(sniffed_packets)
not_broadcast_p = 1 - broadcast_p
broadcast_i = -log(broadcast_p, 2)
not_broadcast_i = -log(not_broadcast_p, 2)
s_entropy = broadcast_p*broadcast_i + not_broadcast_p*not_broadcast_i

# S1
hosts = {}
total_packets = 0
for pkt in sniffed_packets:
    if ARP in pkt and pkt.op == ARP.who_has and pkt.psrc != pkt.pdst:
        total_packets += 2
        if pkt.pdst in hosts:
            hosts[pkt.pdst] += 1
        else:
            hosts[pkt.pdst] = 1
        if pkt.psrc in hosts:
            hosts[pkt.psrc] += 1
        else:
            hosts[pkt.psrc] = 1

host_probability = {h: (hosts[h] * 1.0 / total_packets) for h in hosts.keys()}
host_information = {h: -log(host_probability[h], 2) for h in hosts.keys()}
s1_entropy = 0
for h in hosts.keys():
   s1_entropy += host_probability[h] * host_information[h]

print '\nFuente S'
print '----------'
print 'E = {Paquete con destino broadcast}'
print 'P(E) = ' + str(broadcast_p)
print 'P(!E) = ' + str(not_broadcast_p)
print 'I(E) = ' + str(broadcast_i) + ' bits'
print 'I(!E) = ' + str(not_broadcast_i) + ' bits'
print 'H(S) = ' + str(s_entropy) + ' bits'

print '\nFuente S1'
print '-----------'
print 's_i = {Paquete ARP WHO_HAS con destino u origen host i}'
# debugging
#pprint.pprint(hosts)
#pprint.pprint(host_information)
print 'H(S) = ' + str(s1_entropy) + ' bits'
