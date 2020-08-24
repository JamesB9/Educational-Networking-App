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
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether


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


class PingScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        layout = QGridLayout()

        input_form = self.init_form()

        # Console Output Box
        output_box_area = QScrollArea()
        output_box_area.setMinimumWidth(500)
        output_box_area.setObjectName("outputBox")

        self.output_box = QLabel()
        self.output_box.setText("This is where the output of your PING will appear")

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
            self.output_box.setText(ping_output)
            self.output_box.adjustSize()
        else:  # If at least one packet is returned
            ping_output = f"The Host ({self.ipv4_address_edit.text()}) is UP\n"
            for index, latency in enumerate(latency_list):
                ping_output += f"Packet {index + 1} : {latency:.1f} ms\n"

            # Calculating average, min and max ping
            average_ping = sum(latency_list) / len(latency_list)
            max_ping = max(latency_list)
            min_ping = min(latency_list)
            ping_output += f"Average: {average_ping:.1f} ms, Min: {min_ping:.1f} ms, Max: {max_ping:.1f} ms"
            print(ping_output)
            self.output_box.setText(ping_output)
            self.output_box.adjustSize()


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

        self.output_box = QLabel()
        self.output_box.setText("This is where the output of your Traceroute will appear")

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

        output_text = f"Traceroute to host ({self.ipv4_address_edit.text()}) :\n\n"
        for index, packet in enumerate(response_packets):
            if packet is None:
                output_text += f"{index + 1:>02} - *\n"
            else:
                output_text += f"{index + 1:>02} - {packet.src}\n"

        output_text += f"\nTraceroute Completed to {self.ipv4_address_edit.text()}"

        self.output_box.setText(output_text)
        self.output_box.adjustSize()


class PacketScreen(QWidget):
    def __init__(self, packet):
        QWidget.__init__(self)

        layout = QGridLayout()

        # Console Output Box
        scrollArea = QScrollArea()
        packet_area = PacketRenderArea(packet)
        packet_area.setMinimumWidth(500)
        scrollArea.setWidget(packet_area)

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

        # Adding widgets to the ping page layout
        layout.addWidget(info_area, 0, 0)
        layout.addWidget(packet_area, 0, 1, 2, 1)

        self.setLayout(layout)


class PacketRenderArea(QWidget):

    def __init__(self, packet):
        QWidget.__init__(self)
        print(packet.show())
        packet_layout = QVBoxLayout()
        packet_layout.setAlignment(Qt.AlignTop)
        self.setLayout(packet_layout)
        packet_layout.setSpacing(0)
        packet_layout.setContentsMargins(0,0,0,0)

        # ETHERNET LAYER
        ether_layer = QWidget()
        ether_layer.setObjectName("etherLayer")
        ether_layer_layout = QGridLayout()
        ether_layer.setLayout(ether_layer_layout)

      

        dest_mac_label = PacketField("Dst MAC", "")
        src_mac_label = PacketField("Src MAC", "")

        ether_layer_layout.addWidget(dest_mac_label, 1, 0)
        ether_layer_layout.addWidget(src_mac_label, 1, 1)

        # IP LAYER
        ip_layer = QWidget()
        ip_layer.setObjectName("ipLayer")
        ip_layer_layout = QGridLayout()
        ip_layer.setLayout(ip_layer_layout)

        dest_ip_label = PacketField("Dst IP", packet[IP].dst)
        src_ip_label = PacketField("Src IP", packet[IP].src)

        ip_layer_layout.addWidget(dest_ip_label, 1, 0)
        ip_layer_layout.addWidget(src_ip_label, 1, 1)

        packet_layout.addWidget(ether_layer)
        packet_layout.addWidget(ip_layer)

    # def __init__(self, packet):
    # QWidget.__init__(self)
    # self.setStyleSheet("QWidget{background-color:white;}")
    # layout = QGridLayout()
    # self.setLayout(layout)
    # packet.show(dump=True)

    # ether_field_names = [field.name for field in Ether.fields_desc]
    # ip_field_names = [field.name for field in IP.fields_desc]
    # icmp_field_names = [field.name for field in ICMP.fields_desc]
    # fields = {field_name: getattr(packet, field_name) for field_name in ether_field_names}
    # fields2 = {field_name: getattr(packet, field_name) for field_name in ip_field_names}
    # fields3 = {field_name: getattr(packet, field_name) for field_name in icmp_field_names}

    # fields = {**fields, **fields2, **fields3}

    # row = 0
    # column = 0
    # for field in fields:
    #    widget = QLabel(f"{field}: {str(fields.get(field))}")
    #    widget.setObjectName("PacketField")

    #    row+=1
    #    layout.addWidget(widget, row, column)


class PacketField(QLabel):
    def __init__(self, string, value):
        QLabel.__init__(self)
        self.setObjectName("PacketField")
        self.setText(f"{string} : {value}")
        self.setFixedHeight(35)

"""
class PacketRenderArea(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.display = self.packet_top_level
        self.layout = QVBoxLayout()

        self.header_button = QPushButton("View HEADER Data")
        self.header_button.setObjectName("packetButton_header")
        self.header_button.clicked.connect(self.render_packet_header)

        self.payload_button = QPushButton("View PAYLOAD Data")
        self.payload_button.setObjectName("packetButton_payload")
        self.payload_button.clicked.connect(lambda a: print("Payload Clicked"))

        self.footer_button = QPushButton("View FOOTER Data")
        self.footer_button.setObjectName("packetButton_footer")
        self.footer_button.clicked.connect(lambda a: print("Footer Clicked"))

        self.layout.addWidget(self.header_button)
        self.layout.addWidget(self.payload_button)
        self.layout.addWidget(self.footer_button)
        self.setLayout(self.layout)

    def render_packet_header(self):
        self.display = self.packet_header
        self.payload_button.hide()
        self.footer_button.hide()
        self.setLayout(self.layout)

    def packet_top_level(self):
        area_width = self.width()
        area_height = self.height()
        area_center_x = area_width / 2
        area_center_y = area_height / 2

        packet_width = self.width() * (2 / 3)
        packet_height = self.height() * (7 / 8)

        header_fract = 4 / 10
        payload_fract = 4 / 10
        footer_fract = 2 / 10

        draw_y = (area_height - packet_height) / 2

        # Packet Header
        self.header_button.setGeometry(area_center_x - (packet_width / 2),
                                       draw_y,
                                       packet_width,
                                       packet_height * header_fract)
        draw_y += packet_height * header_fract

        # Packet Payload
        self.payload_button.setGeometry(area_center_x - (packet_width / 2),
                                        draw_y,
                                        packet_width,
                                        packet_height * payload_fract)
        draw_y += packet_height * payload_fract

        # Packet Footer
        self.footer_button.setGeometry(area_center_x - (packet_width / 2),
                                       draw_y,
                                       packet_width,
                                       packet_height * footer_fract)

    def packet_header(self):
        area_width = self.width()
        area_height = self.height()
        area_center_x = area_width / 2
        area_center_y = area_height / 2

        packet_width = self.width() * (2 / 3)
        packet_height = self.height() * (7 / 8)

        header_fract = 4 / 10
        payload_fract = 4 / 10
        footer_fract = 2 / 10

        draw_y = (area_height - packet_height) / 2
        # Packet Header
        self.header_button.setGeometry(area_center_x - (packet_width / 2),
                                       draw_y,
                                       packet_width,
                                       packet_height)

    def paintEvent(self, event):
        self.display()
"""

if __name__ == "__main__":
    # Qt Application
    app = QApplication(sys.argv)
    app.setStyleSheet(open("style.css").read())

    # Creating the Main Window
    window = MainWindow()
    packets, latency = NetworkPy.ping("192.168.1.254")
    window.setCentralWidget(PacketScreen(packets[0]))
    window.resize(1280, 720)
    window.show()

    # Execute application
    sys.exit(app.exec_())
