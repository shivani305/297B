from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Controller, RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import irange
from mininet.link import TCLink

c0 = RemoteController('c0', ip='192.168.89.172')

class NetworkTopo(Topo):
    def build(self):
       h1 = self.addHost('h1', ip = '10.10.1.1/24', defaultRoute='via 10.10.1.254')
       h2 = self.addHost('h2', ip = '10.10.1.2/24', defaultRoute='via 10.10.1.254')
       h3 = self.addHost('h3', ip = '10.10.1.3/24', defaultRoute='via 10.10.1.254')
       h4 = self.addHost('h4', ip = '10.10.1.4/24', defaultRoute='via 10.10.1.254')
       h5 = self.addHost('h5', ip = '10.10.1.5/24', defaultRoute='via 10.10.1.254')
       h6 = self.addHost('h6', ip = '10.10.1.6/24', defaultRoute='via 10.10.1.254')
       h7 = self.addHost('h7', ip = '10.10.1.7/24', defaultRoute='via 10.10.1.254')
       h8 = self.addHost('h8', ip = '10.10.1.8/24', defaultRoute='via 10.10.1.254')  
       g1 = self.addHost('g1', ip = '10.10.1.254')

       s1 = self.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13')
       s2 = self.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13')
       s3 = self.addSwitch('s3', dpid='0000000000000003', protocols='OpenFlow13')
       s4 = self.addSwitch('s4', dpid='0000000000000004', protocols='OpenFlow13')
       s5 = self.addSwitch('s5', dpid='0000000000000005', protocols='OpenFlow13')
       s6 = self.addSwitch('s6', dpid='0000000000000006', protocols='OpenFlow13')
       s7 = self.addSwitch('s7', dpid='0000000000000007', protocols='OpenFlow13')
       s8 = self.addSwitch('s8', dpid='0000000000000008', protocols='OpenFlow13')

       self.addLink(s1,s2)
       self.addLink(s2,s3)
       self.addLink(s3,s4)
       self.addLink(s4,s5)
       self.addLink(s1,s6)
       self.addLink(s6,s4)
       self.addLink(s6,s7)
       self.addLink(s7,s5)
       self.addLink(s1,s8)
       self.addLink(s6,s8)
       self.addLink(s7,s8)
       self.addLink(s5,s8)
       self.addLink(s2,s8)
       self.addLink(s4,s8)
       
def run():
       topo = NetworkTopo()
       net = Mininet(topo=topo, controller=c0)
       net.start()

       CLI(net)
       net.stop()

setLogLevel('info')
run()




