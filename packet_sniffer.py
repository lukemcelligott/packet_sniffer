"""
Authors: Douglas Maxwell and Luke McElligott
Reference Source: https://www.binarytides.com/python-packet-sniffer-code-linux/
                  https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf

Packet Sniffer for analyzing network traffic packets
Must run in Linux environment to use raw socket

"""

import socket
import sys

# create INET Raw socket. Parameter: (Family:INET, Type:RAW, Protocol:TCP)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# use infinite loop to gather data from socket
while True:
    print(s.recvfrom(65565))