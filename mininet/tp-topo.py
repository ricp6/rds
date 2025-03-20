#!/usr/bin/env python3


from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import os
import sys
import argparse
from time import sleep

# If you look at this parser, it can identify 4 arguments
# --behavioral-exe, with the default value 'simple_switch'
## this indicates that the arch of our software switch is the 'simple_switch'
## and any p4 program made for this arch needs to be compiled against de 'v1model.p4'
# --thrift-port, with the default value of 9090, which is the default server port of
## a thrift server - the P4Switch instantiates a Thrift server that allows us
## to communicate our P4Switch (software switch) at runtime
# --num-hosts, with default value 2 indicates the number of hosts...
# --json, is the path to JSON config file - the output of your p4 program compilation
## this is the only argument that you will need to pass in orther to run the script
parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default='simple_switch')
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--jsonS1', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--jsonR1', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--jsonR4', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--jsonRX', help='Path to JSON config file',
                    type=str, action="store", required=True)

args = parser.parse_args()


sw_mac_base = "cc:00:00:00:01:%02x"
mac_base = "aa:00:00:00:%02x:%02x"

host_ip_base = "10.0.%d.%d/24"


class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, json_s1, json_r1, json_r4, json_rx, thrift_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        
        # Add switches/routers
        s1 = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_s1,
                                thrift_port = thrift_port)
        r1 = self.addSwitch('r1',
                                sw_path = sw_path,
                                json_path = json_r1,
                                thrift_port = thrift_port + 1)
        r2 = self.addSwitch('r2',
                                sw_path = sw_path,
                                json_path = json_rx,
                                thrift_port = thrift_port + 2)
        r3 = self.addSwitch('r3',
                                sw_path = sw_path,
                                json_path = json_rx,
                                thrift_port = thrift_port + 3)
        r4 = self.addSwitch('r4',
                                sw_path = sw_path,
                                json_path = json_r4,
                                thrift_port = thrift_port + 4)
        r5 = self.addSwitch('r5',
                                sw_path = sw_path,
                                json_path = json_rx,
                                thrift_port = thrift_port + 5)
        r6 = self.addSwitch('r6',
                                sw_path = sw_path,
                                json_path = json_rx,
                                thrift_port = thrift_port + 6)
        
        # Add hosts
        h1 = self.addHost('h1',
                    ip = host_ip_base % (1,1),
                    mac = mac_base % (0,1))
        h2 = self.addHost('h2',
                    ip = host_ip_base % (1,2),
                    mac = mac_base % (0,2))
        h3 = self.addHost('h3',
                    ip = host_ip_base % (1,3),
                    mac = mac_base % (0,3))
        h4 = self.addHost('h4',
                    ip = host_ip_base % (2,1),
                    mac = mac_base % (0,4))
        
        # Add links
        self.addLink(h1, s1, port2= 1, addr2= sw_mac_base % 1)
        self.addLink(h2, s1, port2= 2, addr2= sw_mac_base % 2)
        self.addLink(h3, s1, port2= 3, addr2= sw_mac_base % 3)
        
        self.addLink(s1, r1, port1= 4, port2= 1, addr1= sw_mac_base % 4, addr2= mac_base % (1,1))
        self.addLink(r1, r2, port1= 2, port2= 1, addr1= mac_base % (1,2), addr2= mac_base % (2,1))
        self.addLink(r1, r6, port1= 3, port2= 1, addr1= mac_base % (1,3), addr2= mac_base % (6,1))
        self.addLink(r2, r3, port1= 2, port2= 1, addr1= mac_base % (2,2), addr2= mac_base % (3,1))
        self.addLink(r3, r4, port1= 2, port2= 3, addr1= mac_base % (3,2), addr2= mac_base % (4,3))
        self.addLink(r4, r5, port1= 2, port2= 2, addr1= mac_base % (4,2), addr2= mac_base % (5,2))
        self.addLink(r5, r6, port1= 1, port2= 2, addr1= mac_base % (5,1), addr2= mac_base % (6,2))

        self.addLink(h4, r4, port2= 1, addr2= mac_base % (4,1))
        
def main():
    if not os.path.exists(args.jsonS1):
        print(f"The file {args.jsonS1} does not exist.")
        sys.exit()
    if not os.path.exists(args.jsonR1):
        print(f"The file {args.jsonR1} does not exist.")
        sys.exit()
    if not os.path.exists(args.jsonR4):
        print(f"The file {args.jsonR4} does not exist.")
        sys.exit()
    if not os.path.exists(args.jsonRX):
        print(f"The file {args.jsonRX} does not exist.")
        sys.exit()

    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.jsonS1,
                            args.jsonR1,
                            args.jsonR4,
                            args.jsonRX,
                            args.thrift_port)

    # the host class is the P4Host
    # the switch class is the P4Switch
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None)

    # Here, the mininet will use the constructor (__init__()) of the P4Switch class, 
    # with the arguments passed to the SingleSwitchTopo class in order to create 
    # our software switch.
    net.start()
    
    sleep(1)  # time for the host and switch confs to take effect

    # Configurar ARP tables dos hosts

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    h1.setARP("10.0.1.254", "aa:00:00:00:01:01")
    h2.setARP("10.0.1.254", "aa:00:00:00:01:01")
    h3.setARP("10.0.1.254", "aa:00:00:00:01:01")
    
    h1.setDefaultRoute("dev eth0 via 10.0.1.254")
    h2.setDefaultRoute("dev eth0 via 10.0.1.254")
    h3.setDefaultRoute("dev eth0 via 10.0.1.254")

    h4 = net.get('h4')
    h4.setARP("10.0.2.254", "aa:00:00:00:04:01")
    h4.setDefaultRoute("dev eth0 via 10.0.2.254")
    

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
