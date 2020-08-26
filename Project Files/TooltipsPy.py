HOST_ADDRESS = str("<b>Host Address:</b><br>" +
                   "This is the IPv4 address of the recipient computer. If a domain name is provided, then a DNS lookup"
                   "will be used to replace the domain with its associated IPv4 address."
                   )

NUMBER_OF_REQUESTS = str("<b>Number of Requests:</b><br>" +
                         "This is the number of packets to send."
                         )

DURATION = str("<b>Duration:</b><br>" +
               "How long in seconds to sniff."
               )

# PACKET FIELDS

# Ethernet
MAC_ADDRESS_DST = str("")
MAC_ADDRESS_SRC = str("")
TYPE = str("")

# IP
VERSION = str("")
IHL = str("")
TOS = str("")
IP_LENGTH = str("")
ID = str("")
FLAGS = str("")
FRAG = str("")
TTL = str("")
PROTO = str("")
CHECKSUM = str("")
IP_ADDRESS_SRC = str("")
IP_ADDRESS_DST = str("")

# TCP / UDP
SOURCE_PORT = str("")
DESTINATION_PORT = str("")
SEQ = str("")
ACK = str("")
DATAOFS = str("")
RESERVED = str("")
WINDOW = str("")
URGPTR = str("")
OPTIONS = str("")

# ICMP
TYPE = str("")
CODE = str("")
ID = str("")

# PADDING
PADDING = str("")

# PAYLOAD
PAYLOAD = str("")
