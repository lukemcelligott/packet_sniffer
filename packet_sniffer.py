"""
Authors: Douglas Maxwell and Luke McElligott
Reference Source: https://www.binarytides.com/python-packet-sniffer-code-linux/
                  https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf

Packet Sniffer for analyzing network traffic packets
Must run in Linux environment to use raw socket

"""

# TODO

import socket
import struct
import sys
from email.policy import HTTP

# function to parse the Ethernet Header. Returns destination MAC, source MAC, protocol, and data.


def ethernet_head(raw_data):
    # use .unpack to get 6 byte structures
    destination, source, prototype = struct.unpack('! 6s 6s H', raw_data[:14])  # format gathered is MAC, MAC, 2char
    dest_mac = destination.hex(":")
    src_mac = source.hex(":")
    proto = socket.htons(prototype)  # get protocol
    data = raw_data[14:]    # get remaining data
    return dest_mac, src_mac, proto, data


# function to parse the IP headers
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    def get_ip(addr):
        return '.'.join(map(str, addr))
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, data


def tcp_head( raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,
    flag_psh, flag_rst, flag_syn, flag_fin, data


# main
try:
    # create INET Raw socket. Parameter: (Family:INET, Type:RAW, Protocol:TCP)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

except Exception as E:
    print("Error occurred when creating the socket: 5", str(E))

# use infinite loop to gather data from socket
while True:
    raw_data, addr = s.recvfrom(65535)  # place data into string - raw_data
    eth = ethernet_head(raw_data)  # Use ethernet_head function to parse the ethernet header of the data

    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
    if eth[2] == 8:
        ipv4 = ipv4(eth[4])
        print('\t - ' + 'IPv4 Packet:')
        print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {}, '.format(ipv4[1], ipv4[2], ipv4[3]))
        print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[4], ipv4[5], ipv4[6]))
        if ipv4[4] == 6:
            tcp = tcp_head(ipv4[7])
            print('TCP Segment:')
            print('Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
            print('Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
            print('Flags:')
            print('URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
            print('RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
            if len(tcp[10]) > 0:
                # HTTP
                if tcp[0] == 80 or tcp[1] == 80:
                    print('HTTP Data:')
                try:
                    http = HTTP(tcp[10])
                    http_info = str(http[10]).split('\n')
                    for line in http_info:
                        print(str(line))
                except:
                    print(tcp[10])
                else:
                    print('TCP Data:')
                    print(tcp[10])
    print('\n')