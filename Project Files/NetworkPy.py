import sys
from scapy.layers.inet import ICMP, IP, UDP, TCP
from scapy.sendrecv import sr1, sniff
import time
import ipaddress
from scapy.all import *
from threading import Thread, Event
from time import sleep

# Sends an ICMP packet to the given IP address, and returns the respone packet.
# The return will equal 'None' if there was no response (the host is down)
# Also returns a list of the packet times (ms)
def ping(dst_ip, count="3", timeout=3):
    # Creating an ICMP packet
    icmp_packet = IP(dst=dst_ip) / ICMP()

    # Sending the ICMP packets, and storing the packets in list
    packets = []
    latency_list = []
    for i in range(int(count)):
        start_time = time.time()
        response_packet = sr1(icmp_packet, timeout=timeout, verbose=0)
        latency = (time.time() - start_time) * 1000

        packets.append(response_packet)
        latency_list.append(latency)

    return packets, latency_list


# Sends an ICMP packet to all given IP addresses in subnet, and return the hosts up.
# The return will equal 'None' if there was no response (the host is down)
def ping_sweep(dst_ip, subnet_mask, count="3", timeout=3):
    # Calculating subnet address
    subnet, mask_bits = calculate_subnet(dst_ip, subnet_mask)
    address_list = [str(ip) for ip in ipaddress.IPv4Network(subnet + "/" + str(mask_bits))]

    print("PING SWEEP:", subnet, "/", mask_bits)
    for address in address_list:
        print("Scanning Address: " + address)
        packets, latency_list = ping(address, count=1, timeout=0.1)

        if all(packet is None for packet in packets):  # If No response from host
            print("Host is Down")
        else:
            print("Host is Up")


def calculate_subnet(ip, subnet_mask):
    subnet = ""
    mask_bits = 0
    dst_ip_bytes = ip.split(sep='.')  # Splits dst_ip into list of numbers. Split via '.'
    dst_ip_bytes = [bin(int(num))[2:] for num in dst_ip_bytes]  # Converts all deanery numbers to binary

    subnet_mask_bytes = subnet_mask.split(sep='.')  # Splits subnet_mask into list of numbers. Split via '.'
    subnet_mask_bytes = [bin(int(num))[2:] for num in subnet_mask_bytes]  # Converts all deanery numbers to binary

    for index, byte in enumerate(dst_ip_bytes):
        subnet += str(int(byte, 2) & int(subnet_mask_bytes[index], 2))
        mask_bits += subnet_mask_bytes[index].count("1")

        if index != 3:
            subnet += "."

    return subnet, mask_bits


def traceroute(dst_ip):
    reply_packets = []

    for ttl in range(1, 30):
        packet = IP(dst=dst_ip, ttl=ttl) / UDP(dport=33434)  # Port 33434 is used for traceroute

        reply_packet = sr1(packet, verbose=0, timeout=2)
        reply_packets.append(reply_packet)

        if reply_packet is None:
            print("*")
        elif reply_packet.type == 3:
            print("Done!",reply_packet.src)
            break
        else:
            print(f"Hop {ttl}: {reply_packet.src}")

    return reply_packets


class Sniffer(Thread):
    def  __init__(self):
        super().__init__()

        self.daemon = True
        self.socket = None
        self.stop_sniffer = Event()
        self.pkt = ''

    def run(self):
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            filter="ip"
        )

        sniff(
            opened_socket=self.socket,
            prn=self.print_packet,
            stop_filter=self.should_stop_sniffer,
            timeout = 10
        )

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        self.pkt = "[!] New Packet: {src} -> {dst}\n".format(src=ip_layer.src, dst=ip_layer.dst)