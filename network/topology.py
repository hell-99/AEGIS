from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def create_aegis_topology():
    net = Mininet(switch=OVSBridge, link=TCLink, controller=None)

    print("[AEGIS] Creating network topology...")

    # Switches (3 subnets)
    s1 = net.addSwitch('s1')  # Corporate subnet
    s2 = net.addSwitch('s2')  # Server subnet
    s3 = net.addSwitch('s3')  # DMZ subnet

    # Legitimate hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24')
    h2 = net.addHost('h2', ip='10.0.1.2/24')
    server1 = net.addHost('server1', ip='10.0.2.1/24')
    server2 = net.addHost('server2', ip='10.0.2.2/24')

    # Attacker node
    attacker = net.addHost('attacker', ip='10.0.3.1/24')

    # Links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(server1, s2)
    net.addLink(server2, s2)
    net.addLink(attacker, s3)
    net.addLink(s1, s2)
    net.addLink(s2, s3)

    net.start()
    h1.cmd('ip route add 10.0.2.0/24 via 10.0.1.1')
    h2.cmd('ip route add 10.0.2.0/24 via 10.0.1.1')
    server1.cmd('ip route add 10.0.1.0/24 via 10.0.2.1')
    server2.cmd('ip route add 10.0.1.0/24 via 10.0.2.1')
    attacker.cmd('ip route add 10.0.2.0/24 via 10.0.3.1')
    attacker.cmd('ip route add 10.0.1.0/24 via 10.0.3.1')
    print("[AEGIS] Network started!")
    print("[AEGIS] Hosts: h1, h2, server1, server2, attacker")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_aegis_topology()