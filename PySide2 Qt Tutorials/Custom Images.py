import sys
from PySide2.QtGui import QIcon, QMovie
from PySide2.QtWidgets import QApplication, QPushButton, QLabel
from PySide2.QtCore import Slot, QSize

@Slot()
def say_hello():
 print("You have clicked PICARD")

# Create the Qt Application
app = QApplication(sys.argv)

# A BUTTON WITH IMAGE ON
button = QPushButton("")
button.setWindowTitle("Image button test")
button.setIcon(QIcon('assets/picard.jpg'))
button.setIconSize(QSize(800,450))
button.clicked.connect(say_hello)
button.show()

# A GIF
label = QLabel()
label.setWindowTitle("Spiral GIF test")
movie = QMovie("assets/spiral.gif")
label.setMovie(movie)
movie.start()
label.show()

# Run the main Qt loop
app.exec_()