import sys
from PySide2.QtWidgets import QApplication, QPushButton, QMainWindow, QAction
from PySide2.QtQuick import QQuickView
from PySide2.QtCore import QUrl, Slot

# The main window of the program
class MainWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setWindowTitle("Multi-purpose, Educational Networking Tool")

        # MAIN MENU
        self.menu = self.menuBar()
        self.file_menu = self.menu.addMenu("File")
        self.tools_menu = self.menu.addMenu("Tools")

        # Exit QAction
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")

        # Packet Sniffer QAction
        sniffer_action = QAction("Packet Sniffer", self)
        sniffer_action.setShortcut("Ctrl+Alt+S")
        # Ping QAction
        ping_action = QAction("Ping", self)
        ping_action.setShortcut("Ctrl+Alt+P")

        self.file_menu.addAction(exit_action)
        self.tools_menu.addAction(sniffer_action)
        self.tools_menu.addAction(ping_action)


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



# Begin program
sys.exit(app.exec_())