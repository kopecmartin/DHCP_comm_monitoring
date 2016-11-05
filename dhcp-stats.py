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
import curses
import time
import threading

verbose = False


def main():
    # list all devices
    # devices = pcapy.findalldevs()

    dev = 'wlp3s0'
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

            # DHCP protocol
            if srcPort == 67 or srcPort == 68:

                # sum legths of all the headers
                hSize = ethLength + iphLength + udphLength

                # get data from the packet
                # parse option 1 (section where DHCP type is stored)
                data = packet[hSize + 241:]
                reqType = unpack('!BBB', data[:3])[1]

                # number of ACK == 5
                if reqType == 5:

                    # new IP of a device
                    yourIP = packet[hSize + 16:]
                    yourIP = yourIP[:4]
                    yourIP = unpack('!BBBB', yourIP)

                    leaseTime = packet[hSize + 251:]
                    leaseTime = leaseTime[:4]
                    leaseTime = unpack('!i', leaseTime)[0]

                    IP = str(yourIP[0]) + '.' + str(yourIP[1]) + '.'
                    IP = IP + str(yourIP[2]) + '.' + str(yourIP[3])

                    # add ip to statistics
                    Pool.addIP2Range(IP, leaseTime)

                    # DEBUG
                    if verbose:
                        print "ACK"
                        print 'YourIP ' + IP
                        print "Release time:" + str(leaseTime)

                # number of RELEASE == 7
                if reqType == 7:

                    # IP of the device, the IP whill be released
                    yourIP = packet[hSize + 12:]
                    yourIP = yourIP[:4]
                    yourIP = unpack('!BBBB', yourIP)

                    IP = str(yourIP[0]) + '.' + str(yourIP[1]) + '.'
                    IP = IP + str(yourIP[2]) + '.' + str(yourIP[3])

                    # remove ip from statistics
                    Pool.removeIPFromRange(IP)

                    # DEBUG
                    if verbose:
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


class LeaseTimer:
    """
    LeaseTimer contains all set up timers to count down
    the lease time of IP address assigned by DHCP server
    """

    def __init__(self):
        self.timers = []

    def setTimer(self, ip, leaseTime):
        t = threading.Timer(leaseTime, self._timerFunc, [ip])
        self.timers.append([ip, t])
        t.start()

    def resetTimer(self, ip, leaseTime):
        self.stopTimer(ip)
        self.setTimer(ip, leaseTime)

    def _timerFunc(self, ip):
        pass
        if verbose:
            print "Lease time is up for: ", ip
        # do action when time's up

    def stopTimer(self, ip):
        for t in self.timers:
            if t[0] == ip:
                self.timers.remove(t)
                t[1].cancel()
                break


class NetPools:
    """
    NetPools contains monitored networks
    """

    def __init__(self):
        # list objects of monitored networks
        self.networks = []
        # list of assigned IP addresses
        self.ips = []
        # instance of LeaseTimer class
        self.timer = LeaseTimer()

    def addNetwork(self, net):
        """
        Adds a network to the pool
        Arguments:
         - net = network address in string
        """
        self.networks.append(Network(checkFormat(net)))

    def addIP2Range(self, ip, leaseTime):
        """
        Adds IP to the right range(s)
        Arguments:
        - ip = ip address in string
        """
        if ip in self.ips:
            # reset the timer
            self.timer.resetTimer(ip, leaseTime)
        else:
            self.ips.append(ip)
            self.timer.setTimer(ip, leaseTime)

            for net in self.networks:
                if net.isInRange(ip):
                    net.increaseHosts()
                    self.printStatistics()

    def removeIPFromRange(self, ip):
        """
        Remove IP from the range(s)
        Arguments:
        - ip = ip address in string
        """

        # check if ip was assigned before, if it was not
        # it may mean program started after ACK was sent -
        # in case like that just ignore it
        if ip in self.ips:
            self.ips.remove(ip)

            for net in self.networks:
                if net.isInRange(ip):
                    net.decreaseHosts()
                    self.printStatistics()

    def printStatistics(self):
        stdscr.clear()
        headers = ["IP Prefix", "Max hosts",
                   "Allocated addresses", "Utilization"]
        stdscr.addstr(headers[0] + "\t" + headers[1] + "\t" +
                      headers[2] + "\t" + headers[3] + "\n")

        for n in self.networks:
            A = str(n.net) + "\t"
            H = str(n.maxHosts) + (len(headers[1]) -
                                   len(str(n.maxHosts))) * " " + "\t"
            AH = str(n.allocatedHosts) + (len(headers[2]) -
                                          len(str(n.allocatedHosts))
                                          ) * " " + "\t"
            U = str("unknown\n")
            stdscr.addstr(A + H + AH + U)

        stdscr.refresh()


class Network:
    """
    Network gathers information about a network
    """

    def __init__(self, net):
        # ipaddress network object
        self.net = net
        # number of assigned IPs at the moment
        self.allocatedHosts = 0
        # number of addresses
        self.maxHosts = net.num_addresses

    def isInRange(self, ip):
        for i in self.net.hosts():
            if ip == str(i):
                return True
        return False

    def increaseHosts(self):
        """Increases number of assigned IPs"""
        self.allocatedHosts += 1

    def decreaseHosts(self):
        """Decreases number of assigned IPs"""
        self.allocatedHosts -= 1


if __name__ == "__main__":

    # verbose mode for debugging
    if "-v" in sys.argv:
        verbose = True

    if len(sys.argv) < 3 and "-v" in sys.argv:
        errorOutput("Wrong arguments")

    Pool = NetPools()

    for net in sys.argv[1:]:
        Pool.addNetwork(net)
        print net

    # print Pool.networks[0].isInRange(unicode('10.10.10.2'))

    # Pool.printStatistics()

    try:
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(1)
        main()
    finally:
        stdscr.erase()
        stdscr.refresh()
        stdscr.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()

