# !/usr/bin/python

# #######################
# Project: ISA - DHCP communication monitoring
# Description:
# Author: Martin Kopec (xkopec42)
# Date:
# #######################

import ipaddress
import pcapy
import socket
from struct import *
import sys


def main():
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


def parse_packet(packet):
    """Parses packet, obtains information from DHCP packets only"""

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


def errorOutput(msg):
    """Prints error message and ends with error code"""
    sys.stderr.write("\033[1;31mERROR: " + msg + "\033[0m\n")
    sys.stdout.write("\nDHCP communication monitoring script:\n")
    sys.stdout.write("Run as:\n./dhcp-stats.py <ip_addr/mask> ")
    sys.stdout.write("[ <ip_addr/mask> [...] ]\n\n")
    sys.exit(1)


def checkFormat(network):
    """
    Checks format of network address
    returns ip_network object
    """

    net = network.split("/")
    if len(net) != 2:
        errorOutput("Wrong format of IP address and mask")

    mask = net[1]
    net = net[0]

    if int(mask) > 32 or int(mask) < 0:
        errorOutput("Wrong network mask")

    check = net.split('.')
    if len(check) != 4:
        errorOutput("Wrong format of IP address")

    for n in check:
        if len(n) == 0 or int(n) < 0 or int(n) > 255:
            errorOutput("Wrong format of IP address")

    try:
        network = ipaddress.ip_network(unicode(network))
    except:
        errorOutput("Wrong IP for the mask given")

    return network


class NetPools:
    """
    NetPools contains monitored networks
    """

    def __init__(self):
        self.networks = []

    def addNetwork(self, net):
        """
        Adds a network to the IpPool
        Arguments:
         - net = network address in string
        """
        self.networks.append(Network(checkFormat(net)))

    def addIp2Range(self, ip):
        """
        Adds IP to the right range(s)
        Arguments:
        - ip = ip address in string
        """
        for net in self.networks:
            if net.isInRange(ip):
                net.increaseHosts()

    def removeIpFromRange(self, ip):
        """
        Remove IP from the range(s)
        Arguments:
        - ip = ip address in string
        """
        for net in self.networks:
            if net.isInRange(ip):
                net.decreaseHosts()


class Network:
    """
    Network gathers information about a network
    """

    def __init__(self, net):
        # ipaddress network object
        self.net = net
        # number of assigned IPs at the moment
        self.allocatedHosts = 0
        # maximum of allocated IPs till now
        self.maximum = 0

    def isInRange(self, ip):
        for i in self.net.hosts():
            if ip == str(i):
                return True
        return False

    def getMaxHosts(self):
        return self.net.num_addresses

    def increaseHosts(self):
        """Increases number of assigned IPs
        and changes the maximum if needed
        """
        self.allocatedHosts += 1
        if self.allocatedHosts > self.maximum:
            self.maximum = self.allocatedHosts

    def decreaseHosts(self):
        """Decreases number of assigned IPs"""
        self.allocatedHosts -= 1


if __name__ == "__main__":

    if len(sys.argv) < 2:
        errorOutput("Wrong arguments")

    Pool = NetPools()

    for net in sys.argv[1:]:
        Pool.addNetwork(net)
        print net

    print Pool.networks[0].isInRange(unicode('10.10.10.2'))

    # main()
