import sys

import PySide2
from PySide2 import QtCore
from PySide2.QtWidgets import *
from PySide2.QtQuick import QQuickView
from PySide2.QtCore import QUrl, Slot, Qt, SIGNAL

import NetworkPy # NetworkPy is the custom python file I made


# The main window of the program
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

    def home_screen(self):
        self.setCentralWidget(HomeScreen())
        print("Central Widget: %s", self.centralWidget())


class PingScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        self.ipv4_address_edit = ""
        self.port_edit = ""

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        input_form = self.init_form()
        layout.addWidget(input_form)

        self.output_box = self.init_text_output()
        layout.addWidget(self.output_box)

        self.setLayout(layout)

    def init_form(self):
        input_form = QWidget()
        input_form.setMaximumWidth(400)

        input_form.setObjectName("PingForm")

        ipv4_address_label = QLabel('Host Address:')
        self.ipv4_address_edit = QLineEdit()

        count_label = QLabel('No. of Requests:')
        self.count_edit = QLineEdit()

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

    def init_text_output(self):
        output_box = QLabel()
        output_box.setObjectName("outputBox")
        output_box.setText("Hello")
        return output_box

    def ping(self):
        print(f"PINGING {self.ipv4_address_edit.text()}")

        if self.count_edit.text() != '':
            response_packets, latency_list = NetworkPy.ping(self.ipv4_address_edit.text(), timeout=1, count=self.count_edit.text())
        else:
            response_packets, latency_list = NetworkPy.ping(self.ipv4_address_edit.text(), timeout=1)

        if all(packet is None for packet in response_packets): # If all packets are None
            ping_output = f"The Host ({self.ipv4_address_edit.text()}) is Down"
            self.output_box.setText(ping_output)
        else:  # If at least one packet is returned
            ping_output = f"The Host ({self.ipv4_address_edit.text()}) is UP\n"
            for index, latency in enumerate(latency_list):
                ping_output += f"Packet {index+1} : {latency:.1f} ms\n"

            # Calculating average, min and max ping
            average_ping = sum(latency_list) / len(latency_list)
            max_ping = max(latency_list)
            min_ping = min(latency_list)
            ping_output += f"Average: {average_ping:.1f} ms, Min: {min_ping:.1f} ms, Max: {max_ping:.1f} ms"

            self.output_box.setText(ping_output)


class PacketSniffer(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        welcome_label = QLabel('This is the Packet Sniffer Screen')

        layout = QVBoxLayout()
        layout.addWidget(welcome_label)

        self.setLayout(layout)


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


if __name__ == "__main__":
    # Qt Application
    app = QApplication(sys.argv)
    app.setStyleSheet(open("style.css").read())

    # Creating the Main Window
    window = MainWindow()
    window.resize(800, 600)
    window.show()

    # Execute application
    sys.exit(app.exec_())
