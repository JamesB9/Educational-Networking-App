import sys
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1
import time
import ipaddress


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
        print(f"\nPing {i + 1}")

        start_time = time.time()
        response_packet = sr1(icmp_packet, timeout=timeout)
        latency = (time.time() - start_time) * 1000

        packets.append(response_packet)
        latency_list.append(latency)

    return packets, latency_list


# Sends an ICMP packet to all given IP addresses in subnet, and return the hosts up.
# The return will equal 'None' if there was no response (the host is down)
def ping_sweep(dst_ip, subnet_mask, count="3", timeout=3):
    # Calculating subnet address
    subnet, mask_bits = calculate_subnet(dst_ip, subnet_mask)
    address_list = [str(ip) for ip in ipaddress.IPv4Network(subnet+"/"+str(mask_bits))]

    print("PING SWEEP:", subnet, "/", mask_bits)
    for address in address_list:
        print("Scanning Address: "+address)
        packets , latency_list = ping(address, count=1, timeout=0.1)

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

