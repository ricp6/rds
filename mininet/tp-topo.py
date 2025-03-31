#!/usr/bin/env python3


from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Host
from p4runtime_switch import P4RuntimeSwitch

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

# Argument to specify the path to the behavioral executable (the P4 program executable)
# Use the default value
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default='simple_switch_grpc')
# Argument to specify the Thrift server port for table updates (default 9090)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
# Argument to specify the gRPC server port for controller communication (default 50051)
parser.add_argument('--grpc-port', help='gRPC server port for controller comm',
                        type=int, action="store", default=50051)

args = parser.parse_args()


sw_mac_base = "cc:00:00:00:01:%02x"
mac_base = "aa:00:00:00:%02x:%02x"

host_ip_base = "10.0.%d.%d/24"


class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, thrift_port, grpc_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Add switches/routers
        s1 = self.addSwitch('s1',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port,
                                grpc_port = grpc_port,
                                device_id = 1,
                                cpu_port = 510)
        
        r1 = self.addSwitch('r1',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 1,
                                grpc_port = grpc_port + 1,
                                device_id = 2,
                                cpu_port = 511)
        r2 = self.addSwitch('r2',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 2,
                                grpc_port = grpc_port + 2,
                                device_id = 3,
                                cpu_port = 512)
        r3 = self.addSwitch('r3',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 3,
                                grpc_port = grpc_port + 3,
                                device_id = 4,
                                cpu_port = 513)
        r4 = self.addSwitch('r4',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 4,
                                grpc_port = grpc_port + 4,
                                device_id = 5,
                                cpu_port = 514)
        r5 = self.addSwitch('r5',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 5,
                                grpc_port = grpc_port + 5,
                                device_id = 6,
                                cpu_port = 515)
        r6 = self.addSwitch('r6',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 6,
                                grpc_port = grpc_port + 6,
                                device_id = 7,
                                cpu_port = 516)
        
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

    # Initialize the custom topology with the provided arguments
    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.thrift_port,
                            args.grpc_port)

    # the host class is the P4Host
    net = Mininet(topo = topo,
                  host = P4Host,
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

    # Start the Mininet CLI, which allows interactive control of the network
    CLI( net )
    # Stop the network after exiting the CLI
    net.stop()

if __name__ == '__main__':
    # Set the log level for Mininet to display info-level messages
    setLogLevel( 'info' )
    main()
