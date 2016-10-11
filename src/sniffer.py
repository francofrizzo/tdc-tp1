#! /usr/bin/env python2
import argparse
import pprint
import operator
from math import log
from scapy.all import ARP, Ether, Dot11, sniff

BROADCAST_PHYSICAL_ADDRESS = 'ff:ff:ff:ff:ff:ff'

broadcast_packets = 0
sniff_count = 0
pcap_file = None

parser = argparse.ArgumentParser(description='Sniff network packets and generate stats.')

parser.add_argument('-f', dest='pcap_file', default=None, help='use pcap capture file')
parser.add_argument('-c', dest='sniff_count', default=0, type=int,
                    help='limit number of packets to sniff')
parser.add_argument('-o', dest='output_files_prefix', default=None,
                    help='output all information using OUTPUT_FILES_PREFIX as filename prefix')
parser.add_argument('--gack', dest='allow_gratuitous_arp', action='store_true',
                    help='include gratuitous ARP packets when generating stats')

args = parser.parse_args()

sniffed_packets = sniff(count=args.sniff_count, offline=args.pcap_file, store=1)

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
host_arp_network = set()
for pkt in sniffed_packets:
    if ARP in pkt and pkt.op == ARP.who_has \
                  and ((not args.allow_gratuitous_arp and pkt.psrc != pkt.pdst) \
                  or args.allow_gratuitous_arp):

        if args.allow_gratuitous_arp:
            total_packets += 1
            if pkt.pdst in hosts:
                hosts[pkt.pdst] += 1
            else:
                hosts[pkt.pdst] = 1
        else:
            arp_pair = (pkt.psrc, pkt.pdst)
            if arp_pair not in host_arp_network and reversed(arp_pair) not in host_arp_network:
                host_arp_network.add(arp_pair)
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

if args.output_files_prefix != None:
    # graph files
    f_nodes = open(args.output_files_prefix + '_nodes.csv', 'w')
    f_nodes.write('Id;Label;Weight\n')
    for h in hosts.keys():
        f_nodes.write(h + ';"' + h +'";' + str(host_probability[h]) + '\n')
    f_nodes.close()

    f_edges = open(args.output_files_prefix + '_edges.csv', 'w')
    f_edges.write('Source;Target;Type\n')
    for e in host_arp_network:
        f_edges.write(e[0] + ';' + e[1] + ';Undirected\n')
    f_edges.close()

    # entropy files
    file = open(args.output_files_prefix + '.s.entropy', 'w')
    file.write(str(s_entropy) + '\n')
    file.close()

    file = open(args.output_files_prefix + '.s1.entropy', 'w')
    file.write(str(s1_entropy) + '\n')
    file.close()

    # information files
    file = open(args.output_files_prefix + '.s.information', 'w')
    file.write('IsBroadcast Information\n')
    file.write('0 ' + str(not_broadcast_i) + '\n')
    file.write('1 ' + str(broadcast_i) + '\n')
    file.close()

    file = open(args.output_files_prefix + '.s1.information', 'w')
    file.write('X-Pos IP Information\n')
    idx = 0
    for h, i in sorted(host_information.iteritems(), key=operator.itemgetter(1)):
        file.write(str(idx) + ' ' + h + ' ' + str(i) + '\n')
        idx = idx + 1
    file.close()
