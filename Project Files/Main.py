import sys

import PySide2
from PySide2 import QtCore, QtWidgets
from PySide2.QtGui import QPainter, QPen, QBrush
from PySide2.QtWidgets import *
from PySide2.QtQuick import QQuickView
from PySide2.QtCore import QUrl, Slot, Qt, SIGNAL
import time
from threading import Thread, Event

import NetworkPy  # NetworkPy is the custom python file I made
import TooltipsPy
import LearningPy

# The main window of the program
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Padding, Raw


class MainWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setWindowTitle("Multi-purpose, Educational Networking Tool")

        # Main Menu Bar
        self.init_menu_bar()
        # Status Bar
        self.init_status_bar()

        # SCREENS
        self.setCentralWidget(HomeScreen())

    def init_menu_bar(self):
        # MAIN MENU
        self.menu = self.menuBar()

        # FILE MENU BUTTON ---------------------
        self.file_menu = self.menu.addMenu("File")

        home_action = QAction("Home Screen", self)  # Home QAction
        home_action.setShortcut("Ctrl+H")
        home_action.triggered.connect(self.home_screen)
        self.file_menu.addAction(home_action)

        exit_action = QAction("Exit", self)  # Exit QAction
        exit_action.setShortcut("Ctrl+Q")
        self.file_menu.addAction(exit_action)
        exit_action.triggered.connect(quit)

        # TOOLS MENU BUTTON ---------------------
        self.tools_menu = self.menu.addMenu("Tools")

        sniffer_action = QAction("Packet Sniffer", self)  # Packet Sniffer QAction
        sniffer_action.setShortcut("Ctrl+Alt+S")
        sniffer_action.triggered.connect(self.sniffer_screen)
        self.tools_menu.addAction(sniffer_action)

        ping_action = QAction("Ping", self)  # Ping QAction
        ping_action.setShortcut("Ctrl+Alt+P")
        ping_action.triggered.connect(self.ping_screen)
        self.tools_menu.addAction(ping_action)

        traceroute_action = QAction("Traceroute", self)  # Trace Route QAction
        traceroute_action.setShortcut("Ctrl+Alt+T")
        traceroute_action.triggered.connect(self.traceroute_screen)
        self.tools_menu.addAction(traceroute_action)

        # HELP BUTTON ---------------------

        help_action = QAction("Help", self)  # Packet Sniffer QAction
        help_action.triggered.connect(self.help_screen)
        self.menu.addAction(help_action)

    def init_status_bar(self):
        # Creating Status Bar
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)

        # Adding progress bar
        progress_bar = CoolProgressBar()
        status_bar.addWidget(progress_bar)

    def ping_screen(self):
        self.setCentralWidget(PingScreen())
        print("Central Widget: %s", self.centralWidget())

    def sniffer_screen(self):
        self.setCentralWidget(PacketSniffer())
        print("Central Widget: %s", self.centralWidget())

    def traceroute_screen(self):
        self.setCentralWidget(TracerouteScreen())
        print("Central Widget: %s", self.centralWidget())

    def home_screen(self):
        self.setCentralWidget(HomeScreen())
        print("Central Widget: %s", self.centralWidget())

    def help_screen(self):
        self.setCentralWidget(HelpScreen())
        print("Central Widget: %s", self.centralWidget())


class PacketSniffer(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        layout = QGridLayout()

        input_form = self.init_form()

        # Console Output Box
        output_box_area = QScrollArea()
        output_box_area.setMinimumWidth(500)
        output_box_area.setObjectName("outputBox")

        self.output_box = QLabel()
        self.output_box.setText("This is where the output of your SNIFF will appear")

        output_box_area.setWidget(self.output_box)

        # Information Area
        info_area = QScrollArea()
        info_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        info_area.setFixedWidth(400)
        info_area.setObjectName("learningBox")

        # Label
        info_label = QLabel()
        info_label.setFixedWidth(360)
        info_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        info_label.setWordWrap(True)
        info_label.setText(LearningPy.LEARNING_SNIFF)
        info_area.setWidget(info_label)

        # Adding widgets to the ping page layout
        layout.addWidget(input_form, 0, 0)
        layout.addWidget(output_box_area, 0, 1, 2, 1)
        layout.addWidget(info_area, 1, 0)

        self.setLayout(layout)

    def init_form(self):
        input_form = QWidget()
        input_form.setMaximumWidth(400)
        input_form.setMaximumHeight(150)
        input_form.setObjectName("PingForm")

        duration = QLabel('Duration:')
        self.duration_edit = QLineEdit()
        duration.setToolTip(TooltipsPy.DURATION)
        self.duration_edit.setToolTip(TooltipsPy.DURATION)

        sniff_button = QPushButton("SNIFF")
        sniff_button.clicked.connect(self.sniff)

        layout = QFormLayout()
        layout.setLabelAlignment(Qt.AlignLeft)
        layout.setFormAlignment(Qt.AlignLeft)

        layout.addRow(duration, self.duration_edit)
        layout.addRow(sniff_button)

        input_form.setLayout(layout)

        return input_form

    def sniff(self):
        sniffer = NetworkPy.Sniffer()
        sniff_output = f"[*] Start sniffing...\n"

        sniffer.start()
        sniff_output += sniffer.pkt
        print(sniff_output)
        # self.output_box.setText(sniff_output)
        # self.output_box.adjustSize()

        # sniffer.join(2.0)
        # if sniffer.is_alive():
        #     sniffer.socket.close()

        sniff_output += "[*] Stop sniffing"
        # self.output_box.setText(sniff_output)
        # self.output_box.adjustSize()


class HomeScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        welcome_label = QLabel('Welcome to this Awesome Networking Tool!')

        layout = QVBoxLayout()
        layout.addWidget(welcome_label)

        self.setLayout(layout)


class CoolProgressBar(QProgressBar):
    def __init__(self, percentage=True):
        QProgressBar.__init__(self)

        if percentage:
            self.setRange(0, 100)
            self.setValue(25)

        self.setTextVisible(True)
        self.setAlignment(Qt.AlignCenter)


class HelpScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        welcome_label = QLabel('This is the help screen')

        layout = QVBoxLayout()
        layout.addWidget(welcome_label)

        self.setLayout(layout)


class TracerouteScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        layout = QGridLayout()

        input_form = self.init_form()

        # Console Output Box
        output_box_area = QScrollArea()
        output_box_area.setMinimumWidth(500)
        output_box_area.setObjectName("outputBox")

        self.output_box = AdvancedOutput()
        self.output_box.add_new_line("This is where the output of your Traceroute will appear")

        output_box_area.setWidget(self.output_box)

        # Information Area
        info_area = QScrollArea()
        info_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        info_area.setFixedWidth(400)
        info_area.setObjectName("learningBox")
        # Label
        info_label = QLabel()
        info_label.setFixedWidth(360)
        info_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        info_label.setWordWrap(True)
        info_label.setText(LearningPy.LEARNING_PING)
        info_area.setWidget(info_label)

        # Adding widgets to the ping page layout
        layout.addWidget(input_form, 0, 0)
        layout.addWidget(output_box_area, 0, 1, 2, 1)
        layout.addWidget(info_area, 1, 0)

        self.setLayout(layout)

    def init_form(self):
        input_form = QWidget()
        input_form.setMaximumWidth(400)
        input_form.setMaximumHeight(150)
        input_form.setObjectName("PingForm")

        # Host Address Label & Input Field
        ipv4_address_label = QLabel('Host Address:')
        self.ipv4_address_edit = QLineEdit()
        ipv4_address_label.setToolTip(TooltipsPy.HOST_ADDRESS)
        self.ipv4_address_edit.setToolTip(TooltipsPy.HOST_ADDRESS)

        ping_button = QPushButton("COMMENCE TRACEROUTE")
        ping_button.clicked.connect(self.traceroute)

        layout = QFormLayout()
        layout.setLabelAlignment(Qt.AlignLeft)
        layout.setFormAlignment(Qt.AlignLeft)

        layout.addRow(ipv4_address_label, self.ipv4_address_edit)
        layout.addRow(ping_button)

        input_form.setLayout(layout)

        return input_form

    def traceroute(self):
        print(f"TRACEROUTE: {self.ipv4_address_edit.text()}")
        response_packets = NetworkPy.traceroute(self.ipv4_address_edit.text())

        self.output_box.add_new_line(f"Traceroute to host ({self.ipv4_address_edit.text()}) :\n\n")
        for index, packet in enumerate(response_packets):
            if packet is None:
                self.output_box.add_new_line(f"{index + 1:>02} - *")
            else:
                self.output_box.add_new_line(f"{index + 1:>02} - {packet.src}\n", packet=packet)

        self.output_box.add_new_line(f"\nTraceroute Completed to {self.ipv4_address_edit.text()}")


class PacketScreen(QWidget):
    def __init__(self, packet):
        QWidget.__init__(self)

        layout = QGridLayout()
        self.setLayout(layout)

        # Information Area
        info_area = QScrollArea()
        info_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        info_area.setFixedWidth(400)
        info_area.setObjectName("learningBox")
        # Label
        info_label = QLabel()
        info_label.setFixedWidth(360)
        info_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        info_label.setWordWrap(True)
        info_label.setText(LearningPy.LEARNING_PACKET)
        info_area.setWidget(info_label)

        layout.addWidget(info_area, 0, 0)

        # PACKET DISPLAY AREA
        scroll_area = QScrollArea()
        scroll_area.setObjectName("packetScrollArea")

        scroll_area.setAlignment(Qt.AlignCenter)

        packet_area = PacketRenderArea(packet)
        scroll_area.setWidget(packet_area)
        layout.addWidget(scroll_area, 0, 1)


class PacketRenderArea(QWidget):

    def __init__(self, packet):
        QWidget.__init__(self)
        print(packet.show())
        self.setObjectName("PacketRenderArea")
        self.packet_layout = QVBoxLayout()
        self.packet_layout.setAlignment(Qt.AlignTop)
        self.setLayout(self.packet_layout)
        self.packet_layout.setSpacing(0)
        self.packet_layout.setContentsMargins(0, 0, 0, 0)

        # ETHERNET LAYER
        if Ether in packet:
            self.create_ethernet_layer(packet)
        # IP LAYER
        if IP in packet:
            self.create_ip_layer(packet)

        # ICMP LAYER
        if ICMP in packet:
            self.create_icmp_layer(packet)
        # TCP
        if TCP in packet:
            self.create_tcp_layer(packet)
        # UDP
        if UDP in packet:
            self.create_udp_layer(packet)
        # PADDING
        if Padding in packet:
            self.create_padding_layer(packet)
        # PAYLOAD
        if Raw in packet:
            self.create_payload_layer(packet)

    def create_ethernet_layer(self, packet):
        ether_layer = QWidget()
        ether_layer.setObjectName("etherLayer")
        ether_layer_layout = QGridLayout()
        ether_layer.setLayout(ether_layer_layout)
        # Title
        ether_layer_title = QLabel("Ethernet Layer")
        ether_layer_title.setObjectName("layerTitle")
        ether_layer_title.setAlignment(Qt.AlignCenter)

        src_mac_label = PacketField("Source MAC", packet.src, tooltip=TooltipsPy.MAC_ADDRESS_SRC)
        dest_mac_label = PacketField("Destination MAC", packet.dst, tooltip=TooltipsPy.MAC_ADDRESS_DST)

        ether_layer_layout.addWidget(ether_layer_title, 0, 0, 1, 2)
        ether_layer_layout.addWidget(dest_mac_label, 1, 1)
        ether_layer_layout.addWidget(src_mac_label, 1, 0)

        self.packet_layout.addWidget(ether_layer)

    def create_ip_layer(self, packet):
        # IP LAYER
        ip_layer = QWidget()
        ip_layer.setObjectName("ipLayer")
        ip_layer_layout = QGridLayout()
        ip_layer.setLayout(ip_layer_layout)
        # Title
        ip_layer_title = QLabel("Network Layer")
        ip_layer_title.setObjectName("layerTitle")
        ip_layer_title.setAlignment(Qt.AlignCenter)
        ip_layer_layout.addWidget(ip_layer_title, 0, 0)
        # Row 1
        row = PacketRow()
        row.add_field("Source IP", packet[IP].src)
        row.add_field("Destination IP", packet[IP].dst)
        ip_layer_layout.addWidget(row, 1, 0)
        # Row 2
        row2 = PacketRow()
        row2.add_field("Version", packet[IP].version)
        row2.add_field("IHL", packet[IP].ihl)
        row2.add_field("TOS", packet[IP].tos)
        row2.add_field("Length", packet[IP].len)
        row2.add_field("ID", packet[IP].id)
        ip_layer_layout.addWidget(row2, 2, 0)
        # Row 3
        row3 = PacketRow()
        row3.add_field("Checksum", packet[IP].chksum)
        row3.add_field("TTL", packet[IP].ttl)
        row3.add_field("Protocol", packet[IP].proto)
        row3.add_field("Offset", packet[IP].frag)
        ip_layer_layout.addWidget(row3, 3, 0)
        # Row 4
        row4 = PacketRow()
        row4.add_field("Flags", packet[IP].flags)
        ip_layer_layout.addWidget(row4, 4, 0)

        self.packet_layout.addWidget(ip_layer)

    def create_tcp_layer(self, packet):
        # TCP LAYER
        tcp_layer = QWidget()
        tcp_layer.setObjectName("tcpLayer")
        tcp_layer_layout = QGridLayout()
        tcp_layer.setLayout(tcp_layer_layout)
        # Title
        tcp_layer_title = QLabel("Transport Layer (TCP)")
        tcp_layer_title.setObjectName("layerTitle")
        tcp_layer_title.setAlignment(Qt.AlignCenter)
        tcp_layer_layout.addWidget(tcp_layer_title, 0, 0)
        # Row 1
        row = PacketRow()
        row.add_field("Source Port", packet[TCP].sport)
        row.add_field("Destination Port", packet[TCP].dport)
        tcp_layer_layout.addWidget(row, 1, 0)
        # Row 2
        row2 = PacketRow()
        row2.add_field("Sequence Number", packet[TCP].seq)
        row2.add_field("Acknowledgement Number", packet[TCP].ack)
        tcp_layer_layout.addWidget(row2, 2, 0)
        # Row 3
        row3 = PacketRow()
        row3.add_field("Data Ofs", packet[TCP].dataofs)
        row3.add_field("Reserved", packet[TCP].reserved)
        row3.add_field("Flags", packet[TCP].flags)
        row3.add_field("Window", packet[TCP].window)
        tcp_layer_layout.addWidget(row3, 3, 0)
        # Row 4
        row4 = PacketRow()
        row4.add_field("Checksum", packet[TCP].chksum)
        row4.add_field("Urgent Pointer", packet[TCP].urgptr)
        row4.add_field("Options", packet[TCP].options)
        tcp_layer_layout.addWidget(row4, 4, 0)

        self.packet_layout.addWidget(tcp_layer)

    def create_udp_layer(self, packet):
        # udp LAYER
        udp_layer = QWidget()
        udp_layer.setObjectName("udpLayer")
        udp_layer_layout = QGridLayout()
        udp_layer.setLayout(udp_layer_layout)
        # Title
        udp_layer_title = QLabel("Transport Layer (UDP)")
        udp_layer_title.setObjectName("layerTitle")
        udp_layer_title.setAlignment(Qt.AlignCenter)
        udp_layer_layout.addWidget(udp_layer_title, 0, 0)
        # Row 1
        row = PacketRow()
        row.add_field("Source Port", packet[UDP].sport)
        row.add_field("Destination Port", packet[UDP].dport)
        udp_layer_layout.addWidget(row, 1, 0)
        # Row 2
        row2 = PacketRow()
        row2.add_field("Length", packet[UDP].len)
        row2.add_field("Checksum", packet[UDP].chksum)
        udp_layer_layout.addWidget(row2, 2, 0)

        self.packet_layout.addWidget(udp_layer)

    def create_icmp_layer(self, packet):
        # ICMP LAYER
        icmp_layer = QWidget()
        icmp_layer.setObjectName("ipLayer")
        icmp_layer_layout = QGridLayout()
        icmp_layer.setLayout(icmp_layer_layout)
        # Title
        icmp_layer_title = QLabel("ICMP")
        icmp_layer_title.setObjectName("layerTitle")
        icmp_layer_title.setAlignment(Qt.AlignCenter)
        icmp_layer_layout.addWidget(icmp_layer_title, 0, 0)
        # Row 1
        row = PacketRow()
        row.add_field("Type", packet[ICMP].type)
        row.add_field("Code", packet[ICMP].code)
        icmp_layer_layout.addWidget(row, 1, 0)
        # Row 2
        row2 = PacketRow()
        row2.add_field("Checksum", packet[ICMP].chksum)
        row2.add_field("ID", packet[ICMP].id)
        row2.add_field("Sequence Number", packet[ICMP].seq)
        icmp_layer_layout.addWidget(row2, 2, 0)

        self.packet_layout.addWidget(icmp_layer)

    def create_padding_layer(self, packet):
        padding_layer = QWidget()
        padding_layer.setObjectName("ipLayer")
        padding_layer_layout = QVBoxLayout()
        padding_layer.setLayout(padding_layer_layout)
        # Title
        padding_layer_title = QLabel("Padding")
        padding_layer_title.setObjectName("layerTitle")
        padding_layer_title.setAlignment(Qt.AlignCenter)
        padding_layer_layout.addWidget(padding_layer_title)
        # Row 1
        padding_scroll = QScrollArea()
        padding_scroll.setObjectName("payloadScrollArea")
        padding_label = QLabel(str(packet[Padding].load))
        padding_label.setObjectName("payloadLabel")
        padding_label.setWordWrap(True)
        padding_scroll.setWidget(padding_label)
        padding_layer_layout.addWidget(padding_scroll)

        self.packet_layout.addWidget(padding_layer)

    def create_payload_layer(self, packet):
        payload_layer = QWidget()
        payload_layer.setObjectName("payloadLayer")
        payload_layer_layout = QVBoxLayout()
        payload_layer.setLayout(payload_layer_layout)
        # Title
        payload_layer_title = QLabel("Payload")
        payload_layer_title.setObjectName("layerTitle")
        payload_layer_title.setAlignment(Qt.AlignCenter)
        payload_layer_layout.addWidget(payload_layer_title)
        # Row 1
        payload_scroll = QScrollArea()
        payload_scroll.setObjectName("payloadScrollArea")
        payload_label = QLabel(str(packet[Raw].load))
        payload_label.setObjectName("payloadLabel")
        payload_label.setWordWrap(True)
        payload_scroll.setWidget(payload_label)
        payload_layer_layout.addWidget(payload_scroll)

        self.packet_layout.addWidget(payload_layer)


class PacketField(QLabel):
    def __init__(self, string, value, tooltip=""):
        QLabel.__init__(self)
        self.setObjectName("PacketField")
        self.setText(f"{string} : {value}")
        self.setFixedHeight(35)
        self.setToolTip(tooltip)


class PacketRow(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.setLayout(QGridLayout())
        self.layout().setContentsMargins(0, 2, 0, 2)
        self.count = 0

    def add_field(self, name, data, tooltip=""):
        self.layout().addWidget(PacketField(name, data, tooltip=tooltip), 0, self.count)
        self.count += 1


class AdvancedOutput(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignTop)
        self.setLayout(self.layout)
        self.setObjectName("AdvancedOutput")
        self.setMinimumHeight(5000)
        self.layout.expandingDirections()
        # self.packet_layout.setSpacing(0)
        # self.packet_layout.setContentsMargins(0, 0, 0, 0)

    def add_new_line(self, string, packet=""):
        new_line = QLabel(string)
        new_line.setObjectName("AdvancedLine")
        if packet != "":
            global window
            new_line.mousePressEvent = lambda a: window.setCentralWidget(PacketScreen(packet))
        print("New Line:", string)
        self.layout.addWidget(new_line)


class PingScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        layout = QGridLayout()

        input_form = self.init_form()

        # Console Output Box
        output_box_area = QScrollArea()
        output_box_area.setMinimumWidth(500)
        output_box_area.setObjectName("outputBox")

        self.output_box = AdvancedOutput()
        self.output_box.add_new_line("This is where the output of your PING will appear")

        output_box_area.setWidget(self.output_box)

        # Information Area
        info_area = QScrollArea()
        info_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        info_area.setFixedWidth(400)
        info_area.setObjectName("learningBox")
        # Label
        info_label = QLabel()
        info_label.setFixedWidth(360)
        info_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        info_label.setWordWrap(True)
        info_label.setText(LearningPy.LEARNING_PING)
        info_area.setWidget(info_label)

        # Adding widgets to the ping page layout
        layout.addWidget(input_form, 0, 0)
        layout.addWidget(output_box_area, 0, 1, 2, 1)
        layout.addWidget(info_area, 1, 0)

        self.setLayout(layout)

    def init_form(self):
        input_form = QWidget()
        input_form.setMaximumWidth(400)
        input_form.setMaximumHeight(150)
        input_form.setObjectName("PingForm")

        # Host Address Label & Input Field
        ipv4_address_label = QLabel('Host Address:')
        self.ipv4_address_edit = QLineEdit()
        ipv4_address_label.setToolTip(TooltipsPy.HOST_ADDRESS)
        self.ipv4_address_edit.setToolTip(TooltipsPy.HOST_ADDRESS)

        # Number of requests Label & Input Field
        count_label = QLabel('No. of Requests:')
        self.count_edit = QLineEdit()
        count_label.setToolTip(TooltipsPy.NUMBER_OF_REQUESTS)
        self.count_edit.setToolTip(TooltipsPy.NUMBER_OF_REQUESTS)

        ping_button = QPushButton("COMMENCE PING")
        ping_button.clicked.connect(self.ping)

        layout = QFormLayout()
        layout.setLabelAlignment(Qt.AlignLeft)
        layout.setFormAlignment(Qt.AlignLeft)

        layout.addRow(ipv4_address_label, self.ipv4_address_edit)
        layout.addRow(count_label, self.count_edit)
        layout.addRow(ping_button)

        input_form.setLayout(layout)

        return input_form

    def ping(self):
        print(f"PINGING {self.ipv4_address_edit.text()}")

        if self.count_edit.text() != '':
            response_packets, latency_list = NetworkPy.ping(self.ipv4_address_edit.text(), timeout=1,
                                                            count=self.count_edit.text())
        else:
            response_packets, latency_list = NetworkPy.ping(self.ipv4_address_edit.text(), timeout=1)

        if all(packet is None for packet in response_packets):  # If all packets are None
            ping_output = f"The Host ({self.ipv4_address_edit.text()}) is Down"
            self.output_box.add_new_line(ping_output)
        else:  # If at least one packet is returned
            ping_output = f"The Host ({self.ipv4_address_edit.text()}) is UP\n"
            for index, latency in enumerate(latency_list):
                self.output_box.add_new_line(f"Packet {index + 1} : {latency:.1f} ms", packet=response_packets[index])

            # Calculating average, min and max ping
            average_ping = sum(latency_list) / len(latency_list)
            max_ping = max(latency_list)
            min_ping = min(latency_list)
            ping_output = f"Average: {average_ping:.1f} ms, Min: {min_ping:.1f} ms, Max: {max_ping:.1f} ms"
            self.output_box.add_new_line(ping_output)


if __name__ == "__main__":
    # Qt Application
    app = QApplication(sys.argv)
    app.setStyleSheet(open("style.css").read())

    # Creating the Main Window
    global window
    window = MainWindow()
    packets, latency = NetworkPy.ping("192.168.1.254")
    packet = Ether() / IP() / UDP() / TCP() / ICMP() / "HELLO WORLD!"

    window.setCentralWidget(PacketScreen(packet))
    window.resize(1280, 720)
    window.show()

    # Execute application
    sys.exit(app.exec_())
