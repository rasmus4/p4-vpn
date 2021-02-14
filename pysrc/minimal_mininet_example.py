from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI

if __name__ == "__main__":
    net = Mininet()

    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')

    s1 = net.addSwitch('s1', cls=OVSBridge)

    net.addLink(h1, s1)
    net.addLink(h2, s1)

    net.start()
    CLI(net)
    net.stop()