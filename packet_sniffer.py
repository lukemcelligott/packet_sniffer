"""
Authors: Douglas Maxwell and Luke McElligott
Reference Source: https://www.binarytides.com/python-packet-sniffer-code-linux/
                  https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf

Packet Sniffer for analyzing network traffic packets
Must run in Linux environment to use raw socket

"""

import socket
import struct


# function to parse the Ethernet Header. Returns destination MAC, source MAC, protocol, and data.
def ethernet_head(raw_data):
    # use .unpack to get 6 byte + 6 byte + 2 byte
    destination, source, prototype = struct.unpack('! 6s 6s H', raw_data[:14])  # format gathered is MAC, MAC, 2char
    # use hex() to decode with delimiter of ':'
    dest_mac = destination.hex(":")
    src_mac = source.hex(":")
    proto = socket.htons(prototype)  # get protocol
    data = raw_data[14:]    # get remaining data
    return dest_mac, src_mac, proto, data


# function to parse the IP headers. Returns ipv4 protocol, source IP, and target IP
def ipv4_head(raw_data):
    # use .unpack() to get [8 padding, int(1), int(1), 2 padding, char[4], char[4]]
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])

    # use function to get ip of extracted src and target data
    def get_ip(address):
        return '.'.join(map(str, address))
    src = get_ip(src)
    target = get_ip(target)

    return proto, src, target


# function to print parsed packet information
def print_packet_info(eth, ipv4):
    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
    print('\t - ' + 'IPv4 Packet:')
    print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[0], ipv4[1], ipv4[2]))


# main
print("PACKET SNIFFER")
# menu for program options
valid_menu = False
while not valid_menu:
    user_select = input("Options: \n1. Receive all packets\n2. Filter by source IP\n"
                        "3. Filter by destination IP\n4. Filter by source and destination IP's\n")
    if int(user_select) in (1, 2, 3, 4):
        valid_menu = True

if int(user_select) in (2, 4):
    user_source_ip = input("Enter source IP: ")
if int(user_select) in (3, 4):
    user_destination_ip = input("Enter destination IP: ")

try:
    # create INET Raw socket. Parameter: (Family:AF_Packet, Type:RAW, Protocol:ntohs)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

except Exception as E:
    print("Error occurred when creating the socket: ", str(E))

print("sniffing packets...")
# use infinite loop to gather data from socket
while True:
    raw_data, addr = s.recvfrom(65535)  # place data into string - raw_data
    eth = ethernet_head(raw_data)  # Use ethernet_head function to parse the ethernet header of the data

    # after receiving eth[] array, assign variables
    eth_dest = eth[0]
    eth_source = eth[1]
    eth_proto = eth[2]
    remaining_raw_data = eth[3]

    # if protocol is 8 (ipv4), process packet
    if eth_proto == 8:
        # use ipv4_head to parse remaining data and assign to corresponding variables
        ipv4 = ipv4_head(remaining_raw_data)
        ipv4_proto = ipv4[0]
        ipv4_source = ipv4[1]
        ipv4_dest = ipv4[2]

        # match for user input (src and dest)
        if user_select == '4' and ipv4_source == user_source_ip and ipv4_dest == user_destination_ip:
            print_packet_info(eth, ipv4)
        # match for user input (src)
        elif user_select == '2' and ipv4_source == user_source_ip:
            print_packet_info(eth, ipv4)
        # match for user input (dest)
        elif user_select == '3' and ipv4_dest == user_destination_ip:
            print_packet_info(eth, ipv4)
        # else, print all packets
        elif user_select == '1':
            print_packet_info(eth, ipv4)