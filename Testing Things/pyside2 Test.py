import sys
import random
from PySide2 import QtCore, QtWidgets, QtGui

class MyWidget(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        self.hello = ["Hello 139", "This is the", "start of", "our project"]

        # CREATING CHILD WIDGETS
        self.button = QtWidgets.QPushButton("Click me!") # Button with label
        self.text = QtWidgets.QLabel("Hello World") # Text Label
        self.text.setAlignment(QtCore.Qt.AlignCenter)

        # LAYING OUT THE CHILD WIDGETS
        self.layout = QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.text)
        self.layout.addWidget(self.button)
        self.setLayout(self.layout)

        # SETS THE FUNCTION TO BE RAN WHEN THE BUTTON IS CLICKED
        self.button.clicked.connect(self.magic)


    def magic(self):
        self.text.setText(random.choice(self.hello))

if __name__ == "__main__":
    app = QtWidgets.QApplication([]) # INITIALISES THE QT PROGRAM READY FOR WIDGETS,GUI,ACTIONS etc

    widget = MyWidget() # CREATES AN INSTANCE OF THE 'MyWidget' class
    widget.resize(800, 600) # SETS SIZE OF WINDOW (xPixels, yPixels)
    widget.show()# SHOWS THE WIDGET ON SCREEN

    sys.exit(app.exec_())