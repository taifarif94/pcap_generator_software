import sys
import os
import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSizePolicy, QHeaderView
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget,
                               QVBoxLayout, QHBoxLayout, QPushButton,
                               QTreeWidget, QTreeWidgetItem, QTableWidget,
                               QTableWidgetItem, QLabel, QHeaderView,
                               QTreeWidgetItemIterator)

from PySide6.QtWidgets import QDialog, QLineEdit, QFormLayout, QDialogButtonBox
from PySide6.QtWidgets import (QRadioButton, QCheckBox, QGridLayout, QSpinBox, QDialogButtonBox)


class AddFieldDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Add Field')

        self.layout = QFormLayout(self)

        # Field name input
        self.field_name = QLineEdit(self)
        self.layout.addRow('Field Name (optional)', self.field_name)

        # Options for data type
        self.hex_radio = QRadioButton('Hex')
        self.ascii_radio = QRadioButton('ASCII')
        self.bits_radio = QRadioButton('Bits')
        self.layout.addRow(self.hex_radio)
        self.layout.addRow(self.ascii_radio)
        self.layout.addRow(self.bits_radio)

        # Value input
        self.value_input = QLineEdit(self)
        self.layout.addRow('Value', self.value_input)

        # Number of bits (only enabled if Bits is selected)
        self.num_bits = QSpinBox(self)
        self.num_bits.setRange(1, 32)  # Assuming 32 bits maximum
        self.num_bits.setValue(8)  # Default byte size
        self.num_bits_label = QLabel('Number of Bits')
        self.layout.addRow(self.num_bits_label, self.num_bits)

        # Disable bit options by default
        self.num_bits_label.setDisabled(True)
        self.num_bits.setDisabled(True)
        self.num_bits.setVisible(False)
        self.num_bits_label.setVisible(False)

        # Checkboxes for bits (only enabled and shown if Bits is selected)
        self.bits_checkboxes = {f'Bit {i}': QCheckBox(f'Bit {i}', self) for i in range(32)}
        self.bits_checkbox_layout = QGridLayout()
        for i, (label, checkbox) in enumerate(self.bits_checkboxes.items()):
            self.bits_checkbox_layout.addWidget(checkbox, i // 8, i % 8)
            checkbox.setDisabled(True)  # Disable by default

        self.layout.addRow(self.bits_checkbox_layout)

        # Update the UI based on selected radio button
        self.hex_radio.toggled.connect(self.on_format_toggled)
        self.ascii_radio.toggled.connect(self.on_format_toggled)
        self.bits_radio.toggled.connect(self.on_format_toggled)
        # Connect the spinbox's valueChanged signal
        self.num_bits.valueChanged.connect(self.on_num_bits_changed)

        # Standard buttons (OK/Cancel)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addRow(self.buttons)

        self.hex_radio.setChecked(True)  # Set Hex as the default selected option

        # Hide bits checkboxes initially
        for _, checkbox in self.bits_checkboxes.items():
            checkbox.hide()

        # Set placeholder text for the value input
        self.value_input.setPlaceholderText("Value (Hex)")

    def on_format_toggled(self, checked):
        # Enable or disable the value input based on selected format
        is_bits = self.bits_radio.isChecked()
        self.value_input.setDisabled(is_bits)

        # Toggle the visibility and enabled state of checkboxes directly based on the radio button selection
        for checkbox in self.bits_checkboxes.values():
            checkbox.setDisabled(not is_bits)
            checkbox.setVisible(is_bits)  # Show checkboxes if Bits is selected

        # Set placeholder text for the value input or hide it, depending on the format selected
        if self.hex_radio.isChecked():
            self.value_input.setPlaceholderText("Value (Hex)")
            self.value_input.setVisible(True)
            self.num_bits.setVisible(False)
            self.num_bits.setEnabled(False)
            self.num_bits_label.setVisible(False)
        elif self.ascii_radio.isChecked():
            self.value_input.setPlaceholderText("Value (ASCII)")
            self.value_input.setVisible(True)
            self.num_bits.setVisible(False)
            self.num_bits.setEnabled(False)
            self.num_bits_label.setVisible(False)
        elif self.bits_radio.isChecked():
            self.value_input.setVisible(False)
            self.num_bits.setVisible(True)
            self.num_bits.setEnabled(True)
            self.num_bits_label.setVisible(True)
            # The following code adjusts the visibility of the num_bits spinbox based on the selected format
            show_bits_options = self.bits_radio.isChecked()
            self.num_bits.setVisible(show_bits_options)
            self.num_bits_label.setVisible(show_bits_options)
            # Call the method to update checkboxes immediately when the radio button changes
            if show_bits_options:
                self.on_num_bits_changed(self.num_bits.value())

    def on_num_bits_changed(self, value):
        # Show or hide checkboxes based on the value from the spinbox
        for i, checkbox in enumerate(self.bits_checkboxes.values()):
            checkbox.setVisible(i < value)
            checkbox.setChecked(False)  # Reset the checkbox state

    def get_field_data(self):
        # Get the data from the dialog
        field_name = self.field_name.text()
        value = self.value_input.text()
        if self.hex_radio.isChecked():
            data_type = 'Hex'
        elif self.ascii_radio.isChecked():
            data_type = 'ASCII'
            # Convert ASCII to hex, assuming each character's byte value in hex format
            value = ''.join(f"{ord(c):02x}" for c in value)
        elif self.bits_radio.isChecked():
            # Get the number of bits from the spinbox
            num_bits = self.num_bits.value()
            # Create a binary string from the checked state of checkboxes up to the num_bits
            bits_str = ''.join('1' if self.bits_checkboxes[f'Bit {i}'].isChecked() else '0' for i in range(num_bits))
            # Convert the binary string to a hexadecimal string, filling with 0's to complete the byte if necessary
            data_type = 'Bits'
            value = f"{int(bits_str, 2):0{num_bits // 4}X}"
        return field_name, data_type, value


class AddBlockDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Add Block')

        # Create layout and form fields
        self.layout = QFormLayout(self)
        self.block_name_field = QLineEdit(self)
        self.block_type_field = QLineEdit(self)
        self.block_length_field = QLineEdit(self)
        self.block_version_high_field = QLineEdit(self)
        self.block_version_low_field = QLineEdit(self)

        # Add form fields to the layout
        self.layout.addRow('Block Name', self.block_name_field)
        self.layout.addRow('Block Type', self.block_type_field)
        self.layout.addRow('Block Length', self.block_length_field)
        self.layout.addRow('Block Version High', self.block_version_high_field)
        self.layout.addRow('Block Version Low', self.block_version_low_field)

        # Add standard buttons (OK/Cancel) and connect them
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addRow(self.buttons)

    def get_values(self):
        return {
            'name': self.block_name_field.text(),
            'type': self.block_type_field.text(),
            'length': self.block_length_field.text(),
            'version_high': self.block_version_high_field.text(),
            'version_low': self.block_version_low_field.text()
        }


class PcapGenerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Pcap Generator')
        self.setGeometry(100, 100, 1280, 1024)  # x, y, width, height
        self.protocol_structure = {
            "Ethernet II": {
                "fields": {
                    "Destination": {"hex_values": ['0xa0', '0x36', '0x9f', '0x31', '0xa7', '0x2e']},
                    "Source": {"hex_values": ['0x00', '0xa0', '0x45', '0xd5', '0x37', '0xca']},
                    "Type": {"hex_values": ['0x08', '0x00']}
                }
            },
            "Internet Protocol": {
                "fields": {
                    "Version + Header Length": {"hex_values": ['0x45']},
                    "Differentiated Services Field": {"hex_values": ['0x00']},
                    "Total Length": {"hex_values": ['0x00', '0x00']},
                    "Identification": {"hex_values": ['0x17', '0x5b']},
                    "Flags + Fragment Offset": {"hex_values": ['0x40']},
                    "Fragment Offset": {"hex_values": ['0x00']},
                    "Time to Live": {"hex_values": ['0x40']},
                    "Protocol": {"hex_values": ['0x11']},
                    "Header Checksum": {"hex_values": ['0x00', '0x00']},
                    "Source Address": {"hex_values": ['0xc0', '0xa8', '0x00', '0x32']},
                    "Destination Address": {"hex_values": ['0xc0', '0xa8', '0x00', '0x19']}
                }
            },
            "User Datagram Protocol": {
                "fields": {
                    "Source Port": {"hex_values": ['0xeb', '0xb0']},
                    "Destination Port": {"hex_values": ['0xc0', '0x15']},
                    "Length": {"hex_values": ['0x00', '0x00']},
                    "Checksum": {"hex_values": ['0x00', '0x00']}
                }
            },
            "Distributed Computing Environment / Remote Procedure Call": {
                "fields": {
                    "Version": {"hex_values": ['0x04']},
                    "Packet Type": {"hex_values": ['0x02']},
                    "Flags 1": {"hex_values": ['0x20']},
                    "Flags 2": {"hex_values": ['0x00']},
                    "Data Representation": {"hex_values": ['0x00', '0x00', '0x00']},
                    "Serial High": {"hex_values": ['0x00']},
                    "Object UUID": {
                        "hex_values": ['0xde', '0xa0', '0x00', '0x00', '0x6c', '0x97', '0x11', '0xd1', '0x82', '0x71',
                                       '0x00', '0x01', '0x00', '0x01', '0x01', '0x74']},
                    "Interface UUID": {
                        "hex_values": ['0xde', '0xa0', '0x00', '0x01', '0x6c', '0x97', '0x11', '0xd1', '0x82', '0x71',
                                       '0x00', '0xa0', '0x24', '0x42', '0xdf', '0x7d']},
                    "Activity UUID": {
                        "hex_values": ['0xfa', '0x60', '0x15', '0x15', '0x32', '0x29', '0x46', '0xf3', '0xb6', '0xe0',
                                       '0xa6', '0x38', '0x0a', '0x58', '0x38', '0x07']},
                    "Server Boot Time": {"hex_values": ['0x5d', '0x61', '0x78', '0x39']},
                    "Interface Version": {"hex_values": ['0x00', '0x00', '0x00', '0x01']},
                    "Sequence Number": {"hex_values": ['0x00', '0x00', '0x00', '0x06']},
                    "Opnum": {"hex_values": ['0x00', '0x02']},
                    "Interface Hint": {"hex_values": ['0xff', '0xff']},
                    "Activity Hint": {"hex_values": ['0xff', '0xff']},
                    "Fragment Length": {"hex_values": ['0x00', '0x00']},
                    "Fragment Number": {"hex_values": ['0x00', '0x00']},
                    "Auth Protocol": {"hex_values": ['0x00']},
                    "Serial Low": {"hex_values": ['0x00']},
                }
            },
            "Profinet IO": {
                "fields": {
                    "Status": {"hex_values": ['0x00', '0x00', '0x00', '0x00']},
                    "ArgsLength": {"hex_values": ['0x00', '0x00', '0x00', '0x68']},
                    "Array: Max, Offset, Size": {
                        "hex_values": ['0x00', '0x01', '0x03', '0x6c', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
                                       '0x00', '0x68']},
                    "IODReadResHeader": {
                        "fields": {
                            "BlockType": {"hex_values": ['0x80', '0x09']},
                            "BlockLength": {"hex_values": ['0x00', '0x3c']},
                            "BlockVersionHigh": {"hex_values": ['0x01']},
                            "BlockVersionLow": {"hex_values": ['0x00']},
                            "SeqNumber": {"hex_values": ['0x00', '0x04']},
                            # Continuing with ARUUID and the rest as an example
                            "ARUUID": {
                                "hex_values": ['0xe3', '0xf0', '0x22', '0xb4', '0x5a', '0xcc', '0x41', '0xa1', '0xbe',
                                               '0x98', '0x40', '0xe3', '0x00', '0xb9', '0xc0', '0x71']},
                            "API": {"hex_values": ['0x00', '0x00', '0x00', '0x00']},
                            "SlotNumber": {"hex_values": ['0x00', '0x00']},
                            "SubslotNumber": {"hex_values": ['0x80', '0x00']},
                            "Padding": {"hex_values": ['0x00', '0x00']},
                            "Index": {"hex_values": ['0xc0', '0x01']},
                            "RecordDataLength": {"hex_values": ['0x00', '0x00', '0x00', '0x28']},
                            "AdditionalValue1": {"hex_values": ['0x00', '0x00']},
                            "AdditionalValue2": {"hex_values": ['0x00', '0x00']},
                            "Another Padding": {
                                "hex_values": ['0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
                                               '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
                                               '0x00', '0x00']}},
                    }

                }
            },

        }

        self.header_byte_ranges = {
            "Ethernet II": (1, 14),  #
            "Destination": (1, 6),  #
            "Source": (7, 12),  #
            "Type": (13, 14),  #
            "Internet Protocol": (15, 34),  #
            "IP Version": (15, 15),  #
            "Header Length": (15, 15),  #
            "Differentiated Services Field": (16, 16),  #
            "Total Length": (17, 18),  #
            "Identification": (19, 20),  #
            "Flags": (21, 21),
            "Fragment Offset": (21, 22),
            "Time to Live": (23, 23),
            "Protocol": (24, 24),
            "Header Checksum": (25, 26),
            "Source Address": (27, 30),
            "Destination Address": (31, 34),
            "User Datagram Protocol": (35, 42),
            "Source Port": (35, 36),
            "Destination Port": (37, 38),
            "Length": (39, 40),
            "Checksum": (41, 42),
            "Distributed Computing Environment / Remote Procedure Call": (43, 62),
            "Version": (43, 43),
            "Packet Type": (44, 44),
            "Flags 1": (45, 45),
            "Flags 2": (46, 46),
            "Data Representation": (47, 49),
            "Serial High": (50, 50),
            "Object UUID": (51, 66),
            "Interface UUID": (67, 82),
            "Activity UUID": (83, 98),
            "Server Boot Time": (99, 102),
            "Interface Version": (103, 106),
            "Sequence Number": (107, 110),
            "Opnum": (111, 112),
            "Interface Hint": (113, 114),
            "Activity Hint": (115, 116),
            "Fragment Length": (117, 118),
            "Fragment Number": (119, 120),
            "Auth Protocol": (121, 121),
            "Serial Low": (122, 122),
            "Profinet IO": (123, 142),
            "Status": (123, 126),
            "ArgsLength": (127, 130),
            "Array: Max, Offset, Size": (131, 142),
        }

        self.profinet_data = [
            # Ethernet II
            '0xa0', '0x36', '0x9f', '0x31', '0xa7', '0x2e',  # Destination
            '0x00', '0xa0', '0x45', '0xd5', '0x37', '0xca',  # Source
            '0x08', '0x00',  # Type

            # Internet Protocol
            '0x45',  # Version + Header Length
            '0x00',  # Differentiated Services Field
            '0x00', '0x00',  # Total Length
            '0x17', '0x5b',  # Identification
            '0x40',  # Flags + Fragment Offset
            '0x00',  # Fragment Offset
            '0x40',  # Time to Live
            '0x11',  # Protocol: UDP
            '0x00', '0x00',  # Header Checksum
            '0xc0', '0xa8', '0x00', '0x32',  # Source Address
            '0xc0', '0xa8', '0x00', '0x19',  # Destination Address

            # User Datagram Protocol
            '0xeb', '0xb0',  # Source Port
            '0xc0', '0x15',  # Destination Port
            '0x00', '0x00',  # Length
            '0x00', '0x00',  # Checksum

            # Distributed Computing Environment / Remote Procedure Call
            '0x04',  # Version
            '0x02',  # Packet Type: Response
            '0x20',  # Flags 1
            '0x00',  # Flags 2
            '0x00', '0x00', '0x00',  # Data Representation
            '0x00',  # Serial High
            # Object UUID
            '0xde', '0xa0', '0x00', '0x00', '0x6c', '0x97', '0x11', '0xd1', '0x82', '0x71', '0x00', '0x01', '0x00',
            '0x01', '0x01', '0x74',
            # Interface UUID
            '0xde', '0xa0', '0x00', '0x01', '0x6c', '0x97', '0x11', '0xd1', '0x82', '0x71', '0x00', '0xa0', '0x24',
            '0x42', '0xdf', '0x7d',
            # Activity UUID
            '0xfa', '0x60', '0x15', '0x15', '0x32', '0x29', '0x46', '0xf3', '0xb6', '0xe0', '0xa6', '0x38', '0x0a',
            '0x58', '0x38', '0x07',
            '0x5d', '0x61', '0x78', '0x39',  # Server Boot time
            '0x00', '0x00', '0x00', '0x01',  # Interface Ver: 1
            '0x00', '0x00', '0x00', '0x06',  # Sequence Number: 6
            '0x00', '0x02',  # Opnum: 2
            '0xff', '0xff',  # Interface Hint
            '0xff', '0xff',  # Activity Hint
            '0x00', '0x00',  # Fragment len
            '0x00', '0x00',  # Fragment num
            '0x00',  # Auth proto
            '0x00',  # Serial Low

            # Profinet IO
            '0x00', '0x00', '0x00', '0x00',  # Status: OK
            '0x00', '0x00', '0x00', '0x68',  # ArgsLength: 104
            '0x00', '0x01', '0x03', '0x6c',  # MaximumCount: 66412
            '0x00', '0x00', '0x00', '0x00',  # Offset: 0
            '0x00', '0x00', '0x00', '0x68',  # ActualCount: 104
            '0x80', '0x09',  # BlockType: IODReadResHeader
            '0x00', '0x3c',  # BlockLength: 60
            '0x01', '0x00',  # BlockVersionHigh: 1, BlockVersionLow: 0
            '0x00', '0x04',  # SeqNumber: 4
            # ARUUID
            '0xe3', '0xf0', '0x22', '0xb4', '0x5a', '0xcc', '0x41', '0xa1', '0xbe', '0x98', '0x40', '0xe3', '0x00',
            '0xb9', '0xc0', '0x71',
            '0x00', '0x00', '0x00', '0x00',  # API: 0x00000000
            '0x00', '0x00',  # SlotNumber: 0x0000
            '0x80', '0x00',  # SubslotNumber: 0x8000
            '0x00', '0x00',  # Padding
            '0xc0', '0x01',  # Index: RealIdentificationData for one slot
            '0x00', '0x00', '0x00', '0x28',  # RecordDataLength: 40
            '0x00', '0x00',  # AdditionalValue1: 0
            '0x00', '0x00',  # AdditionalValue2: 0
            # Another Padding here
            '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
            '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
        ]

        self.initUI()

    def setup_buttons(self):
        # Connect the generate button's clicked signal to the generate_file method
        self.generate_button.clicked.connect(self.generate_file)
        # Connect the save button's clicked signal to the highlight_hardcoded_range method
        self.save_button.clicked.connect(self.highlight_hardcoded_range)
        self.add_block_button.clicked.connect(self.add_block)
        self.add_field_button.clicked.connect(self.add_field)

    def generate_file(self):
        # Get the data from the table and format it
        data_lines = []
        for row in range(self.hex_table.rowCount()):
            line_data = []
            for col in range(1, 9):  # Get the first 8 octets
                item = self.hex_table.item(row, col)
                if item is not None and item.text() != '':
                    line_data.append(f"0x{item.text()}")
                else:
                    line_data.append("0x00")  # Default value if no data is entered

            # The gap is at column 9, so we start the second half from column 10
            for col in range(10, 18):  # Get the second 8 octets
                item = self.hex_table.item(row, col)
                if item is not None and item.text() != '':
                    line_data.append(f"0x{item.text()}")
                else:
                    line_data.append("0x00")  # Default value if no data is entered

            # Split the line_data into two halves and join them separately
            first_half = ', '.join(line_data[:8]) + ","
            second_half = ', '.join(line_data[8:]) + ","
            data_lines.append(first_half)
            data_lines.append(second_half)

        # Combine all lines into the final data string, with a newline at the end of every 8 octets
        final_data = '\n'.join(data_lines)

        # Write the data to a text file
        filename = "output.txt"
        with open(filename, 'w') as file:
            file.write(final_data)

        # Show a message to the user that the file was generated
        print(f"File generated: {os.path.abspath(filename)}")

    def initUI(self):
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main Layout
        main_layout = QVBoxLayout(central_widget)

        # Tree Widget for packet structure
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(['Packet Structure'])
        self.populate_tree(self.protocol_structure)
        main_layout.addWidget(self.tree_widget)

        # Hexadecimal Data Display with offsets
        self.hex_table = QTableWidget()
        self.hex_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tree_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.hex_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.hex_table.setColumnCount(2)  # Set two columns
        self.hex_table.setHorizontalHeaderLabels(['Offset', 'Data'])
        self.hex_table.verticalHeader().setVisible(False)  # Hide vertical header
        self.populate_hex_table()
        main_layout.addWidget(self.hex_table)

        self.tree_widget.itemClicked.connect(self.on_tree_item_clicked)
        self.hex_table.cellClicked.connect(self.on_table_cell_clicked)

        # Buttons Layout
        buttons_layout = QHBoxLayout()

        # Buttons
        self.save_button = QPushButton('Save')
        self.load_button = QPushButton('Load')
        self.generate_button = QPushButton('Generate')
        self.add_block_button = QPushButton('Add Block')
        self.add_field_button = QPushButton('Add Field')
        self.delete_button = QPushButton('Delete')
        self.refresh_button = QPushButton('Refresh')

        # Add buttons to the buttons layout
        buttons_layout.addWidget(self.save_button)
        buttons_layout.addWidget(self.load_button)
        buttons_layout.addWidget(self.generate_button)
        buttons_layout.addWidget(self.add_block_button)
        buttons_layout.addWidget(self.add_field_button)
        buttons_layout.addWidget(self.delete_button)
        buttons_layout.addWidget(self.refresh_button)

        # Add buttons layout to main layout
        main_layout.addLayout(buttons_layout)

        # Assuming the first 8 data columns are labeled from 01 to 08
        # and the next 8 data columns are labeled from 0A to 11 (skipping 09 for the gap):

        column_labels = ['Offset'] + [f'{i:02X}' for i in range(1, 9)] + [''] + [f'{i:02X}' for i in range(10, 18)]
        self.hex_table.setHorizontalHeaderLabels(column_labels)

    def on_tree_item_clicked(self, item, column):
        # Clear any previous highlights
        self.unhighlight_all_cells()
        # Highlight the bytes related to the clicked tree item
        field_name = item.text(0)
        if field_name in self.header_byte_ranges:
            self.highlight_bytes(self.header_byte_ranges[field_name])
            print(self.header_byte_ranges[field_name])

    def highlight_hardcoded_range(self):
        # Clear any previous highlights
        print(len(self.header_byte_ranges))
        self.unhighlight_all_cells()
        # Hardcoded byte range defined here
        hardcoded_byte_range = (43, 62)
        start_byte, end_byte = hardcoded_byte_range
        print(end_byte)
        total_bytes_per_row = 16  # 16 data bytes per row
        # Highlight the hardcoded range
        self.highlight_bytes(hardcoded_byte_range)
        for byte_position in range(start_byte, end_byte + 1):
            # Calculate row and column for this byte position
            row = (byte_position - 1) // total_bytes_per_row
            col_in_row = (byte_position - 1) % total_bytes_per_row
            # Determine the actual column in the table, accounting for the offset column
            if col_in_row < 8:
                col = col_in_row + 1  # +1 for the offset column
            else:
                col = col_in_row + 2  # +2 for the offset and gap columns

            print(row, col)

    def highlight_bytes(self, byte_range):
        self.header_byte_ranges['Distributed Computing Environment / Remote Procedure Call'] = (
            43, len(self.profinet_data))
        start_byte, end_byte = byte_range
        total_bytes_per_row = 16  # 16 data bytes per row

        # Loop over each byte in the byte range
        for byte_position in range(start_byte, end_byte + 1):
            # Calculate row and column for this byte position
            row = (byte_position - 1) // total_bytes_per_row
            col_in_row = (byte_position - 1) % total_bytes_per_row

            # Determine the actual column in the table, accounting for the offset column
            if col_in_row < 8:
                col = col_in_row + 1  # +1 for the offset column
            else:
                col = col_in_row + 2  # +2 for the offset and gap columns

            # Get the item at the calculated row and column
            item = self.hex_table.item(row, col)
            if item:
                # Highlight the item
                item.setBackground(Qt.yellow)

    def unhighlight_all_cells(self):
        # Loop over all rows and columns
        for row in range(self.hex_table.rowCount()):
            for col in range(1, self.hex_table.columnCount()):  # Assuming column 0 is the 'Offset' column
                item = self.hex_table.item(row, col)
                if item:
                    # Reset the background to white to remove highlighting
                    item.setBackground(Qt.white)

    def on_table_cell_clicked(self, row, column):
        # Clear any previous highlights
        self.unhighlight_all_cells()

        # Highlight the clicked cell
        clicked_item = self.hex_table.item(row, column)
        if clicked_item:
            clicked_item.setBackground(Qt.yellow)

        # Find and highlight the corresponding tree item
        for header_name, byte_range in self.header_byte_ranges.items():
            # Check if the clicked column is within the byte range for this header field
            if byte_range[0] <= column <= byte_range[1]:
                self.highlight_tree_item(header_name)
                break

    def highlight_tree_item(self, header_name):
        # Iterate over all tree items to find the one that matches the header_name
        iterator = QTreeWidgetItemIterator(self.tree_widget)
        while iterator.value():
            item = iterator.value()
            if item.text(0) == header_name:
                # Select the found tree item
                self.tree_widget.setCurrentItem(item)
                # Highlight the associated bytes
                byte_range = self.header_byte_ranges.get(header_name)
                if byte_range:
                    self.highlight_bytes(byte_range)
                break
            iterator += 1

    def populate_tree(self, structure):
        self.tree_widget.clear()  # Clear existing items
        self.populate_tree_recursive(structure, None)

    def populate_tree_recursive(self, structure, parent_item):
        for protocol_name, protocol_info in structure.items():
            # Create a new tree item for the protocol or field
            if parent_item is None:  # Top-level protocol
                protocol_item = QTreeWidgetItem(self.tree_widget, [protocol_name])
            else:  # Nested field
                protocol_item = QTreeWidgetItem(parent_item, [protocol_name])

            # Recursively add fields as children, if any
            fields = protocol_info.get("fields", {})
            if fields:
                self.populate_tree_recursive(fields, protocol_item)
            else:  # If no further nested fields, set the item's data to include hex values
                hex_values = protocol_info.get("hex_values", [])
                protocol_item.setData(0, Qt.UserRole, hex_values)

    def populate_hex_table(self):
        def hex_to_item(hex_value):
            item = QTableWidgetItem(hex_value)
            item.setTextAlignment(Qt.AlignCenter)
            return item

        self.hex_table.clear()
        self.hex_table.setRowCount(50)  # Initial row count
        self.hex_table.setColumnCount(18)  # Including the gap

        column_labels = ['Offset'] + [f'{i:02X}' for i in range(1, 9)] + [''] + [f'{i:02X}' for i in range(10, 18)]
        self.hex_table.setHorizontalHeaderLabels(column_labels)

        def add_fields_to_table(protocol_structure, row, col, depth=0):
            for key, value in protocol_structure.items():
                if isinstance(value, dict):
                    # This is a nested dictionary; recurse into it
                    if 'fields' in value:  # Handle protocol or nested layer with fields
                        row, col = add_fields_to_table(value['fields'], row, col, depth + 1)
                    elif 'hex_values' in value:  # Direct field with hex values
                        for hex_value in value['hex_values']:
                            if col == 9:  # Skip the gap column
                                col += 1
                            if col > 17:  # Move to next row after 16th data column
                                row += 1
                                col = 1
                                if row >= self.hex_table.rowCount():  # Ensure enough rows
                                    self.hex_table.insertRow(row)
                            self.hex_table.setItem(row, col, hex_to_item(hex_value))
                            col += 1
                            if col == 9:  # Skip the gap if next column is 9
                                col += 1
                    else:  # Recurse into any other dictionary
                        row, col = add_fields_to_table(value, row, col, depth + 1)
            return row, col  # Return the updated row and column

        current_row, current_col = 0, 1
        self.hex_table.insertRow(current_row)  # Ensure at least one row

        # Starting point for recursion
        current_row, current_col = add_fields_to_table(self.protocol_structure, current_row, current_col)

        # Remove any excess empty rows
        while self.hex_table.rowCount() > current_row + 1:
            self.hex_table.removeRow(self.hex_table.rowCount() - 1)

        # Set the offset values for each row
        for i in range(self.hex_table.rowCount()):
            offset_item = hex_to_item(f'{i * 16:04X}')
            self.hex_table.setItem(i, 0, offset_item)

        self.hex_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.hex_table.verticalHeader().setVisible(False)

    def add_block(self):
        dialog = AddBlockDialog(self)
        if dialog.exec():
            values = dialog.get_values()
            block_name = values['name']
            block_type = values['type']
            block_length = int(values['length'])
            version_high = values['version_high']
            version_low = values['version_low']

            # Find the last byte range to place the new block after it
            last_byte = max(
                range_pair[1] for range_pair in self.header_byte_ranges.values()) if self.header_byte_ranges else 0
            new_block_range = (last_byte + 1, last_byte + block_length)

            # Add the new block to the tree and header byte ranges
            new_block_item = QTreeWidgetItem([block_name])
            self.tree_widget.addTopLevelItem(new_block_item)
            self.header_byte_ranges[block_name] = new_block_range

            # Add the new block details as child items in the tree widget
            new_block_item.addChild(QTreeWidgetItem([f"Block Type: {block_type}"]))
            new_block_item.addChild(QTreeWidgetItem([f"Block Length: {block_length}"]))
            new_block_item.addChild(QTreeWidgetItem([f"Block Version High: {version_high}"]))
            new_block_item.addChild(QTreeWidgetItem([f"Block Version Low: {version_low}"]))

            # Update the hex table with the new block details
            self.add_block_to_table(block_name, block_type, block_length, version_high, version_low, last_byte)

            # Expand the new block item to show its children
            new_block_item.setExpanded(True)

    def add_block_to_table(self, block_name, block_type, block_length, version_high, version_low, last_byte):
        # Assuming the block_type, version_high, version_low are hex strings and need to be displayed as such
        data_to_add = [block_type, str(block_length), version_high, version_low]

        # Calculate where to start adding new data (find the row and column)
        total_bytes_per_row = 16  # 16 data bytes per row
        start_row = last_byte // total_bytes_per_row
        start_col = (last_byte % total_bytes_per_row) + 1  # +1 to account for the offset column

        # Populate the table
        for data in data_to_add:
            # Check if we need to start a new row
            if start_col >= self.hex_table.columnCount():
                start_row += 1
                start_col = 1  # Reset to first column after offset
                self.hex_table.insertRow(self.hex_table.rowCount())  # Insert a new row at the end

            # Convert the data to a QTableWidgetItem and add to table
            item = QTableWidgetItem(data)
            self.hex_table.setItem(start_row, start_col, item)
            start_col += 1

            # Set the offset for the new row if it's the first column after offset
            if start_col == 1:
                offset_item = QTableWidgetItem(f'{start_row * total_bytes_per_row:04X}')
                self.hex_table.setItem(start_row, 0, offset_item)  # Column 0 is for offsets

        # Update the table to refresh the view
        self.hex_table.update()

    def save_structure_to_file(self, file_path):
        try:
            # Open the file in write mode ('w') and serialize the structure into JSON format.
            # Using 'indent=4' for pretty-printing the output for better readability.
            with open(file_path, 'w') as file:
                json.dump(self.protocol_structure, file, indent=4)
            print(f"Structure successfully saved to {file_path}.")
        except IOError as e:
            # Handle potential I/O errors (e.g., permission issues, disk full, etc.)
            print(f"Failed to save the structure to {file_path}. Error: {e}")

    def add_field(self):
        dialog = AddFieldDialog(self)
        if dialog.exec():
            field_name, data_type, value = dialog.get_field_data()

            # Assume the selected item provides a way to determine the path in the structure
            selected_item = self.tree_widget.currentItem()
            if selected_item:
                # Convert the user input value to hex values. This may need to be adjusted based on the actual data type and format.
                hex_values = [f"{int(value[i:i + 2], 16):#04x}" for i in range(0, len(value), 2)]

                # Find the path in the protocol structure that corresponds to the selected item.
                path = self.get_path_from_selection(selected_item)

                # Insert the new field into the protocol structure at the correct location.
                self.insert_field_in_structure(path, field_name, {"hex_values": hex_values})

                # Refresh the hex table to reflect the new field.
                self.populate_hex_table()
                self.populate_tree(self.protocol_structure)
                self.save_structure_to_file("mail.json")

    def get_path_from_selection(self, selected_item):
        # This function needs to return a list of keys that represent the path from the root of `protocol_structure`
        # to the selected item.
        path = []
        while selected_item:
            path.insert(0, selected_item.text(0))  # Assuming the item's text correlates to keys in the structure
            selected_item = selected_item.parent()
        print(path)
        return path

    def insert_field_in_structure(self, path, field_name, field_data):
        # Navigate the protocol_structure to find the right place based on the path.
        current_level = self.protocol_structure
        for key in path[:-1]:  # Navigate to the parent of the target location.
            current_level = current_level.setdefault(key, {}).setdefault("fields", {})

        # At this point, current_level is the dictionary where we need to insert the new field.
        # We will reconstruct this dictionary and insert the new field after the selected key.
        parent_key = path[-1]
        new_fields_order = []  # To hold our new fields in order
        inserted = False

        for k, v in current_level.items():
            new_fields_order.append((k, v))  # Append the existing field
            if k == parent_key:  # Check if it's the field after which we want to insert the new one
                new_fields_order.append((field_name, field_data))  # Insert the new field
                inserted = True

        if not inserted:  # If the field wasn't found and inserted, add it to the end.
            new_fields_order.append((field_name, field_data))

        # Now, we replace the old order with the new order
        new_current_level = dict(new_fields_order)
        current_level.clear()
        current_level.update(new_current_level)

    def add_value_to_tree(self, field_name, value):
        # Default field name if not provided
        if not field_name.strip():
            field_name = "Unnamed Field"

        # Convert value to the hex representation for display
        field_value = f"Value (Hex): {value.upper()}"

        # Find the last selected item or the last top-level item if none is selected
        current_item = self.tree_widget.currentItem()
        if current_item is None:
            current_item = self.tree_widget.topLevelItem(self.tree_widget.topLevelItemCount() - 1)

        # Create a new tree item with the field name and value
        new_field_item = QTreeWidgetItem([field_name])
        current_item.addChild(new_field_item)
        new_field_item.addChild(QTreeWidgetItem([field_value]))

        # Expand the current item to show the newly added child
        current_item.setExpanded(True)


# Find the last item in the tree and add a new child with the field name and value


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PcapGenerator()
    window.setup_buttons()
    window.show()
    sys.exit(app.exec())
