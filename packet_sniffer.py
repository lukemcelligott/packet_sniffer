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


# main
try:
    # create INET Raw socket. Parameter: (Family:AF_Packet, Type:RAW, Protocol:ntohs)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

except Exception as E:
    print("Error occurred when creating the socket: ", str(E))

# use infinite loop to gather data from socket
while True:
    raw_data, addr = s.recvfrom(65535)  # place data into string - raw_data
    eth = ethernet_head(raw_data)  # Use ethernet_head function to parse the ethernet header of the data
    if eth[2] == 8:
        ipv4 = ipv4_head(eth[3])
        if ipv4[4] == '10.0.2.15' and ipv4[5] == '157.240.229.35':
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
            print('\t - ' + 'IPv4 Packet:')
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {}, '.format(ipv4[0], ipv4[1], ipv4[2]))
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
    print('\n')