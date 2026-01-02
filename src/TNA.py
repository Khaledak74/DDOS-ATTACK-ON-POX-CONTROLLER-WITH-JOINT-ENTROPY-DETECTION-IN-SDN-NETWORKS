from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import os

class CustomTopo(Topo):
    def build(self):
        # Create hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')

        # Create switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        # Add links between switches
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s1, s5)

        # Add links between hosts and switches
        self.addLink(h1, s2)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s3)
        self.addLink(h5, s4)
        self.addLink(h6, s4)
        self.addLink(h7, s5)
        self.addLink(h8, s5)

def run():
    os.system("mn -c")
    setLogLevel('info')

    topo = CustomTopo()
    net = Mininet(topo=topo,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
                  switch=OVSSwitch,
                  autoSetMacs=True,
                  autoStaticArp=True)

    net.start()

    c0 = net.get('c0')
    c0.cmd("wireshark &")
    info('*** Waiting 10 seconds for Wireshark setup...\n')
    time.sleep(10)

    info('*** Running pingAll...\n')
    net.pingAll()

    h1, h2, h3, h4, h5, h6, h7, h8 = [net.get(f'h{i}') for i in range(1, 9)]
    h8_ip = h8.IP()

    # Start HTTP server on h8
    info('*** Starting HTTP server on h8: http://%s:8080\n' % h8_ip)
    h8.cmd('python3 -m http.server 8080 &')
    time.sleep(5)

    # Normal traffic using fping (3 packets)
    info('*** Normal fping traffic to h8 from h2, h4, h6, h7...\n')
    for host in [h2, h4, h6, h7]:
        info(f'{host.name} fping:\n')
        print(host.cmd(f'fping -c 3 {h8_ip}'))

    time.sleep(5)

    # Start attack traffic (TCP, UDP, ICMP)
    info('*** Launching DDoS attack...\n')
    print("h1 is flooding with TCP SYN traffic")
    h1.cmd(f'hping3 -d 300 -S -w 64 -p 8080 --flood --rand-source {h8_ip} &')
    time.sleep(2)
    
    print("h3 is flooding with UDP traffic")
    h3.cmd(f'hping3 -d 300 -2 -w 64 -p 8080 --flood --rand-source {h8_ip} &')
    time.sleep(2)
    
    print("h5 is flooding with ICMP traffic")
    h5.cmd(f'hping3 -d 300 -1 -w 64 -p 8080 --flood --rand-source {h8_ip} &')
    

    info('*** Attacks running... waiting 60 seconds\n')
    time.sleep(60)

    # During the attack: fping 2 packets
    info('*** fping during attack (2 packets)...\n')
    for host in [h2, h4, h6, h7]:
        info(f'{host.name} fping during attack:\n')
        print(host.cmd(f'fping -c 2 {h8_ip}'))

    # Stop all hping3 processes
    info('*** Stopping DDoS attack...\n')
    for attacker in [h1, h3, h5]:
        attacker.cmd('pkill hping3')

    # Wait before checking connectivity again
    info('*** Waiting 20 seconds for recovery...\n')
    time.sleep(20)

    info('*** Running final pingAll after attack...\n')
    net.pingAll()

    info('*** Waiting 30 seconds to capture packets before shutting down...\n')
    time.sleep(30)
    info('*** Saving pcap file and shutting down the network...\n')

    net.stop()

if __name__ == '__main__':
    run()

