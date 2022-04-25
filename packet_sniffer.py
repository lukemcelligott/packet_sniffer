"""
Authors: Douglas Maxwell and Luke McElligott
Reference Source: https://www.binarytides.com/python-packet-sniffer-code-linux/
                  https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf

Packet Sniffer for analyzing network traffic packets
Must run in Linux environment to use raw socket

"""

# TODO
# figure out get_mac_addr function
# Test ethernet_head function

import socket
import struct
import sys


# function to parse the Ethernet Header. Returns destination MAC, source MAC, protocol, and data.
def ethernet_head(raw_data):
    # use .unpack to get 6 byte structures
    destination, source, prototype = struct.unpack('! 6s 6s H', raw_data[:14])  # format gathered is MAC, MAC, 2char
    dest_mac = get_mac_addr(destination)
    src_mac = get_mac_addr(source)
    proto = socket.htons(prototype)  # get protocol
    data = raw_data[14:]    # get remaining data
    return dest_mac, src_mac, proto, data


# main
try:
    # create INET Raw socket. Parameter: (Family:INET, Type:RAW, Protocol:TCP)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

except Exception as E:
    print("Error occurred when creating the socket: 5", str(E))

# use infinite loop to gather data from socket
while True:
    print(s.recvfrom(65565))  # print receiving data
    raw_data, addr = s.recvfrom(65535)  # place data into string - raw_data
    eth = ethernet_head(raw_data)  # Use ethernet_head function to parse the ethernet header of the data

    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))