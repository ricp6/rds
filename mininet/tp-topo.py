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
parser.add_argument('--jsonR1', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--jsonR2', help='Path to JSON config file',
                    type=str, action="store", required=True)

args = parser.parse_args()



class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, json_r1, json_r2, thrift_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        
        # TODO: Add switches/routers
        #r1 = self.addSwitch('r1',
        #                        sw_path = sw_path,
        #                        json_path = json_r1,
        #                        thrift_port = thrift_port)
        
        # TODO: Add hosts
        #h1 = self.addHost('h1', ip="10.0.1.1/24", mac="00:04:00:00:00:01")
        
        # TODO: Add links
        #self.addLink(r1, r2, port1=2, port2=1, addr1="aa:00:00:00:01:02", addr2="aa:00:00:00:02:01")

def main():
    if not os.path.exists(args.jsonR1):
        print(f"The file {args.jsonR1} does not exist.")
        sys.exit()
    if not os.path.exists(args.jsonR2):
        print(f"The file {args.jsonR2} does not exist.")
        sys.exit()

    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.jsonR1,
                            args.jsonR2,
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

    # TODO: configurar ARP tables dos hosts

    #h1 = net.get('h1')
    #h1.setARP("10.0.1.254", "aa:00:00:00:01:01")
    #h1.setDefaultRoute("dev eth0 via 10.0.1.254")

    

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
