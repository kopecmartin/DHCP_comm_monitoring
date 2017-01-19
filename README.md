# DHCP communication monitoring tool


## About
The project was created as a school project. The aim of the tool is monitoring of DHCP communication in order
to create statistics about usage of network prefixes. For sniffing packets pcapy library is used. Every ACK or 
DHCPINFORM DHCP packet is parsed and according the information obtained is a number of used prefixes increased 
and on every RELEASE DHCP packet is the number decreased. All others packets are ignored.


## Run

    $ dhcp-stats.py [-h] [-f] [-i INTERFACE] [-c INT] IP-PREFIX [IP-PREFIX]...


## OPTIONS

- -h, --help => output a usage message and exit.
- -f => print all available interfaces and exit.
- -i INTERFACE => monitor only interface given by parameter INTERFACE. If not used, all available interfaces are monitored.
- -c INT => every INT seconds output statistics to a file. Format of output is CSV. Default name of the file is log.csv.


## EXAMPLES
Monitor DHCP communication on interface eth1 and create statistics about usage in 192.168.1.0/24 and 192.168.0.0/28 
network prefixes can be made by following command:

    $ dhcp-stats -i eth1 192.168.1.0/24 192.168.0.0/28

Monitor communication on any available interface, create statistics about usage in 192.168.1.0/24 network and every
60 seconds output statistics to a log.csv file:
       
    $ dhcp-stats -c 60 192.168.1.0/24
   
    
## Limitations
The tools uses for sniffing packets pcapy library. Usage without parameter -f make pcapy listen to all available
interfaces, which may not be reliable in case a lot of interfaces is available.
      