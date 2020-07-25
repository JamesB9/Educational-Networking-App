import logging
import time
import threading

import scapy.all as scapy

sniffPackets = True #global variable

def print_packet(packet):
    logging.info(packet.show())
    logging.info("\n________________________________________________________________\n")

def sniff():
    sniffer = scapy.sniff(filter="udp", prn=print_packet)

if sniffPackets:
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")

    logging.info("before thread started")
    thread1 = threading.Thread(target=sniff, args=(), daemon=True)
    thread1.start()
    logging.info("after thread started")
    time.sleep(3)
    logging.info("end of program")