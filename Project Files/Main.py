import sys

import PySide2
from PySide2 import QtCore
from PySide2.QtWidgets import *
from PySide2.QtQuick import QQuickView
from PySide2.QtCore import QUrl, Slot, Qt, SIGNAL


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
        self.setMaximumWidth(200)

        ipv4_address_label = QLabel('IPv4 Address:')
        self.ipv4_address_edit = QLineEdit()

        port_label = QLabel('Port Number:')
        self.port_edit = QLineEdit()

        ping_button = QPushButton("COMMENCE PING")
        ping_button.clicked.connect(self.ping)

        layout = QFormLayout()
        layout.setLabelAlignment(Qt.AlignLeft)
        layout.setFormAlignment(Qt.AlignLeft)

        layout.addRow(ipv4_address_label, self.ipv4_address_edit)
        layout.addRow(port_label, self.port_edit)
        layout.addRow(ping_button)

        self.setLayout(layout)

    def ping(self):
        print(f"PINGING {self.ipv4_address_edit.text()}:{self.port_edit.text()}")


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
