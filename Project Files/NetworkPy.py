import sys
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1
import time


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
        print(f"\nPing {i+1}")

        start_time = time.time()
        response_packet = sr1(icmp_packet, timeout=timeout)
        latency = (time.time() - start_time) * 1000

        packets.append(response_packet)
        latency_list.append(latency)

    return packets, latency_list


