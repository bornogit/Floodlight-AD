#!/usr/bin/python

"""
This example creates a multi-controller network from
semi-scratch; note a topo object could also be used and
would be passed into the Mininet() constructor.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from threading import Thread

def addHost( net, N ):
    "Create host hN and add to net."
    name = 'h%d' % N
    ip = '10.0.0.%d' % N
    mac = '00:00:00:00:%d:00' % N
    return net.addHost( name, ip=ip, mac=mac )

net = Mininet( controller=RemoteController, switch=OVSKernelSwitch)
c1 = net.addController( 'c1', controller=RemoteController, ip='192.168.56.101', port=6633 )
s1 = net.addSwitch( 's1' )

host1 = addHost( net, 1)
host2 = addHost( net, 2)
host3 = addHost( net, 3)
host4 = addHost( net, 4)

s1.linkTo( host1 )
s1.linkTo( host2 )
s1.linkTo( host3 )
s1.linkTo( host4 )

net.build()
s1.start( [ c1 ] )

net.pingAll()

h1, h2 = net.getNodeByName('h1', 'h2')
h3, h4 = net.getNodeByName('h1', 'h2')
#net.iperf((h1,h2), 'UDP', '20M')
#net.iperf((h3,h4), 'TCP')

h1.cmd( 'iperf -s &' )
h2.cmd( 'iperf -c 10.0.0.1 -t 100 &')
h3.cmd( 'iperf -s -u &' )
h4.cmd( 'iperf -u -c 10.0.0.3 -t 100 -b 10M &' )
 
print "*** Running CLI"
CLI( net )

net.stop()
