class OutputLine(QWidget):
    def __init__(self, line_string, line_tooltip="", widget_list=[]):
        QWidget.__init__(self)
        self.setMinimumHeight(50)
        layout = QHBoxLayout()

        line_text = QLabel(line_string)

        if line_tooltip != "":
            self.setToolTip(line_tooltip)

        layout.addWidget(line_text)
        for widget in widget_list:
            layout.addWidget(widget)

        self.setLayout(layout)


class AdvancedOutputBox(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        # SCROLLABLE AREA
        output_box_area = QScrollArea()

        self.list_of_lines_widget = QWidget()  # CREATING LIST
        output_box_area.setWidget(self.list_of_lines_widget)
        self.list_layout = QVBoxLayout()  # LIST LAYOUT
        self.list_of_lines_widget.setLayout(self.list_layout)

        self.list_layout.addWidget(OutputLine("HELLO"))

        self.list_of_lines = []

        self.show()

    #def add_line(self, line_string, line_tooltip="", widget_list=[]):
        #new_line = OutputLine(line_string, line_tooltip=line_tooltip, widget_list=widget_list)
        #self.list_of_lines.append(new_line)
        #self.list_of_lines_widget.layout().addWidget(new_line)


class AdvancedOutputTestScreen(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        layout = QGridLayout()

        # Console Output Box
        self.output_box_area = AdvancedOutputBox()
        self.output_box_area.setMinimumWidth(500)
        self.output_box_area.setObjectName("advancedOutputBox")

        input_form = self.init_form()

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
        layout.addWidget(self.output_box_area, 0, 1, 2, 1)
        layout.addWidget(info_area, 1, 0)

        self.setLayout(layout)

    def init_form(self):
        input_form = QWidget()
        input_form.setMaximumWidth(400)
        input_form.setMaximumHeight(150)
        input_form.setObjectName("PingForm")

        # Host Address Label & Input Field
        input_label = QLabel('Host Address:')
        self.input_edit = QLineEdit()

        ping_button = QPushButton("Add Line")
        #ping_button.clicked.connect(self.output_box_area.add_line(self.input_edit))

        layout = QFormLayout()
        layout.setLabelAlignment(Qt.AlignLeft)
        layout.setFormAlignment(Qt.AlignLeft)

        layout.addRow(input_label, self.input_edit)
        layout.addRow(ping_button)

        input_form.setLayout(layout)

        return input_form
