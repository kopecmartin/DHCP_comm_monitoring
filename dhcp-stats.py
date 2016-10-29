# !/usr/bin/python

# #######################
# Project: ISA - DHCP communication monitoring
# Description:
# Author: Martin Kopec (xkopec42)
# Date:
# #######################

import pcapy
import socket
from struct import *
import sys


def main(argv):
    # list all devices
    # devices = pcapy.findalldevs()

    dev = 'enp0s3'
    print "Sniffing device " + dev

    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live(dev, 65536, 1, 0)

    # start sniffing packets
    while(1):
        (header, packet) = cap.next()
        # print ('%s: captured %d bytes, truncated to %d bytes'
        #   %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet)


# function to parse a packet
def parse_packet(packet):

    # parse ethernet header
    ethLength = 14

    ethHeader = packet[:ethLength]
    eth = unpack('!6s6sH', ethHeader)
    eth_protocol = socket.ntohs(eth[2])

    # Parse IP packets, IP Protocol number == 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the IP header
        ipheader = packet[ethLength:20 + ethLength]

        # unpack IP header
        iph = unpack('!BBHHHBBH4s4s', ipheader)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF

        # length of IP header
        iphLength = ihl * 4

        # parse protocol
        protocol = iph[6]

        # UDP packets, number of UDP protocol == 17
        if protocol == 17:
            u = iphLength + ethLength
            udphLength = 8
            udpHeader = packet[u:u + 8]

            # unpack UDP header
            udph = unpack('!HHHH', udpHeader)

            srcPort = udph[0]
            destPort = udph[1]
            length = udph[2]
            checksum = udph[3]

            # print 'Source Port : ' + str(srcPort) + ' Dest Port : '
            #   + str(destPort) + ' Length : ' + str(length)
            #   + ' Checksum : ' + str(checksum)

            # DHCP protocol
            if srcPort == 67 or srcPort == 68:

                # sum legths of all the headers
                hSize = ethLength + iphLength + udphLength

                # get data from the packet
                # parse option 1 (section where DHCP type is stored)
                data = packet[hSize + 241:]
                reqType = unpack('!BBB', data[:3])[1]

                # DEBUG
                # print 'DHCP DATA:'
                # print 'Source Port: ' + str(srcPort)
                # print 'Dest Port: ' + str(destPort)
                # print 'Length: ' + str(length)
                # print 'Checksum: ' + str(checksum)

                # number of ACK == 5
                if reqType == 5:

                    # new IP of a device
                    yourIP = packet[hSize + 16:]
                    yourIP = yourIP[:4]
                    yourIP = unpack('!BBBB', yourIP)

                    IP = str(yourIP[0]) + '.' + str(yourIP[1]) + '.'
                    IP = IP + str(yourIP[2]) + '.' + str(yourIP[3])

                    # DEBUG
                    print "ACK"
                    print 'YourIP ' + IP

                # number of RELEASE == 7
                if reqType == 7:

                    # IP of the device, the IP whill be released
                    yourIP = packet[hSize + 12:]
                    yourIP = yourIP[:4]
                    yourIP = unpack('!BBBB', yourIP)

                    IP = str(yourIP[0]) + '.' + str(yourIP[1]) + '.'
                    IP = IP + str(yourIP[2]) + '.' + str(yourIP[3])

                    # DEBUG
                    print "RELEASE"
                    print 'YourIP ' + IP


if __name__ == "__main__":
    main(sys.argv)
