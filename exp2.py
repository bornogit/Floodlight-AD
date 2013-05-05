#!/usr/bin/python

"""
Create a 1024-host network, and run the CLI on it.
If this fails because of kernel limits, you may have
to adjust them, e.g. by adding entries to /etc/sysctl.conf
and running sysctl -p. Check util/sysctl_addon.
"""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController
from mininet.topolib import TreeNet
from mininet.topo import Topo
from mininet.net import Mininet

class TreeTopo( Topo ):
    "Topology for a tree network with a given depth and fanout."

    def __init__( self, depth=1, fanout=2 ):
        super( TreeTopo, self ).__init__()
        # Numbering:  h1..N, s1..M
        self.hostNum = 1
        self.switchNum = 1
        # Build topology
        self.addTree( depth, fanout )

    def addTree( self, depth, fanout ):
        """Add a subtree starting with node n.
           returns: last node added"""
        isSwitch = depth > 0
        if isSwitch:
            node = self.addSwitch( 's%s' % self.switchNum )
            self.switchNum += 1
            for _ in range( fanout ):
                child = self.addTree( depth - 1, fanout )
                self.addLink( node, child )
        else:
	    node = self.addHost( 'h%s' % self.hostNum )
            self.hostNum += 1
        return node

if __name__ == '__main__':
    setLogLevel( 'info' )

    topo = TreeTopo (depth=3, fanout=2)

    network = Mininet(switch=OVSKernelSwitch,controller=RemoteController )
   
    c0 = network.addController( 'c0', controller=RemoteController, ip='192.168.56.101', port=6633 )

    network.buildFromTopo(topo)
    h1,h2,h3,h4,h5,h6,h7,h8 = network.getNodeByName('h1','h2','h3','h4','h5','h6','h7','h8')
    network.start()
    h1.cmd( 'iperf -s -u &' )
    h8.cmd( 'iperf -c 10.0.0.1 -u -t 100 -b 10M &' )
    h2.cmd( 'iperf -s -u &' )
    h7.cmd( 'iperf -u -c 10.0.0.2 -t 100 -b 10M &' )
    h3.cmd( 'iperf -s -u &' )
    h6.cmd( 'iperf -u -c 10.0.0.3 -t 100 -b 10M &' )
    h4.cmd( 'iperf -s -u &' )
    h5.cmd( 'iperf -u -c 10.0.0.4 -t 100 -b 40M &' )

    #network.run( CLI, network )
    CLI( network) 
