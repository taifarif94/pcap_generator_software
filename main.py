import sys
import os
import json
import struct
import socket
import pandas as pd
from collections import defaultdict


from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSizePolicy, QHeaderView
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget,
                               QVBoxLayout, QHBoxLayout, QPushButton,
                               QTreeWidget, QTreeWidgetItem, QTableWidget,
                               QTableWidgetItem, QLabel, QHeaderView,
                               QTreeWidgetItemIterator,
                               QPushButton, QMessageBox)

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

        # Help button
        self.help_button = QPushButton('Help', self)
        self.help_button.clicked.connect(self.show_help)
        self.layout.addRow(self.help_button)

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

    def show_help(self):
        # Display the help message
        QMessageBox.information(self, 'Help',
                                'To enter hex octets, select the "Hex" option. For ASCII values, choose the "ASCII" option; these will be automatically converted into hex values. To input bit information, select "Bits" and specify the number of bits. Use the checkboxes to set the bits: a checked box represents "1" and an unchecked box represents "0". All bit information will be automatically converted to hex and displayed in the table.')

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
        self.item_to_table_map = {}  # Initialize the mapping dictionary
        self.setWindowTitle('Pcap Generator')
        self.setGeometry(100, 100, 1280, 1024)  # x, y, width, height
        # AdjustDomainBoundarywithBlockVersionLow
        self.protocol_structure = {
            "Ethernet II": {
                "fields": {
                    "Destination": {"hex_values": ['0xa0', '0x36', '0x9f', '0x31', '0xa7', '0x2e'], "selected": 0},
                    "Source": {"hex_values": ['0x00', '0xa0', '0x45', '0xd5', '0x37', '0xca'], "selected": 0},
                    "Type": {"hex_values": ['0x08', '0x00'], "selected": 0}
                },
                "selected": 0
            },
            "Internet Protocol": {
                "fields": {
                    "Version + Header Length": {"hex_values": ['0x45'], "selected": 0},
                    "Differentiated Services Field": {"hex_values": ['0x00'], "selected": 0},
                    "Total Length": {"hex_values": ['0x00', '0x00'], "selected": 0},
                    "Identification": {"hex_values": ['0x17', '0x5b'], "selected": 0},
                    "Flags + Fragment Offset": {"hex_values": ['0x40', '0x00'], "selected": 0},
                    "Time to Live": {"hex_values": ['0x40'], "selected": 0},
                    "Protocol": {"hex_values": ['0x11'], "selected": 0},
                    "Header Checksum": {"hex_values": ['0x00', '0x00'], "selected": 0},
                    "Source Address": {"hex_values": ['0xc0', '0xa8', '0x00', '0x32'], "selected": 0},
                    "Destination Address": {"hex_values": ['0xc0', '0xa8', '0x00', '0x19'], "selected": 0}
                },
                "selected": 0
            },
            "User Datagram Protocol": {
                "fields": {
                    "Source Port": {"hex_values": ['0xeb', '0xb0'], "selected": 0},
                    "Destination Port": {"hex_values": ['0xc0', '0x15'], "selected": 0},
                    "Length": {"hex_values": ['0x00', '0x00'], "selected": 0},
                    "Checksum": {"hex_values": ['0x00', '0x00'], "selected": 0}
                },
                "selected": 0
            },
            "Distributed Computing Environment / Remote Procedure Call": {
                "fields": {
                    "Version": {"hex_values": ['0x04'], "selected": 0},
                    "Packet Type": {"hex_values": ['0x02'], "selected": 0},
                    "Flags 1": {"hex_values": ['0x20'], "selected": 0},
                    "Flags 2": {"hex_values": ['0x00'], "selected": 0},
                    "Data Representation": {"hex_values": ['0x00', '0x00', '0x00'], "selected": 0},
                    "Serial High": {"hex_values": ['0x00'], "selected": 0},
                    "Object UUID": {"hex_values": [
                        '0xde', '0xa0', '0x00', '0x00', '0x6c', '0x97', '0x11', '0xd1',
                        '0x82', '0x71', '0x00', '0x01', '0x00', '0x01', '0x01', '0x74'
                    ], "selected": 0},
                    "Interface UUID": {"hex_values": [
                        '0xde', '0xa0', '0x00', '0x01', '0x6c', '0x97', '0x11', '0xd1',
                        '0x82', '0x71', '0x00', '0xa0', '0x24', '0x42', '0xdf', '0x7d'
                    ], "selected": 0},
                    "Activity UUID": {"hex_values": [
                        '0xfa', '0x60', '0x15', '0x15', '0x32', '0x29', '0x46', '0xf3',
                        '0xb6', '0xe0', '0xa6', '0x38', '0x0a', '0x58', '0x38', '0x07'
                    ], "selected": 0},
                    "Server Boot Time": {"hex_values": ['0x5d', '0x61', '0x78', '0x39'], "selected": 0},
                    "Interface Version": {"hex_values": ['0x00', '0x00', '0x00', '0x01'], "selected": 0},
                    "Sequence Number": {"hex_values": ['0x00', '0x00', '0x00', '0x06'], "selected": 0},
                    "Opnum": {"hex_values": ['0x00', '0x02'], "selected": 0},
                    "Interface Hint": {"hex_values": ['0xff', '0xff'], "selected": 0},
                    "Activity Hint": {"hex_values": ['0xff', '0xff'], "selected": 0},
                    "Fragment Length": {"hex_values": ['0x00', '0x00'], "selected": 0},
                    "Fragment Number": {"hex_values": ['0x00', '0x00'], "selected": 0},
                    "Auth Protocol": {"hex_values": ['0x00'], "selected": 0},
                    "Serial Low": {"hex_values": ['0x00'], "selected": 0}
                },
                "selected": 0
            },
            "Profinet IO": {
                "fields": {
                    "Status": {"hex_values": ['0x00', '0x00', '0x00', '0x00'], "selected": 0},
                    "ArgsLength": {"hex_values": ['0x00', '0x00', '0x00', '0x00'], "selected": 0},
                    "MaximumCount": {"hex_values": ['0x00', '0x01', '0x03', '0x6c'], "selected": 0},
                    "Offset": {"hex_values": ['0x00', '0x00', '0x00', '0x54'], "selected": 0},
                    "ActualCount": {"hex_values": ['0x00', '0x00', '0x00', '0x00'], "selected": 0},
                    "IODReadResHeader": {
                        "fields": {
                            "BlockType": {"hex_values": ['0x80', '0x09'], "selected": 0},
                            "BlockLength": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "BlockVersionHigh": {"hex_values": ['0x01'], "selected": 0},
                            "BlockVersionLow": {"hex_values": ['0x00'], "selected": 0},
                            "SeqNumber": {"hex_values": ['0x00', '0x04'], "selected": 0},
                            "ARUUID": {"hex_values": [
                                '0xe3', '0xf0', '0x22', '0xb4', '0x5a', '0xcc', '0x41', '0xa1', '0xbe',
                                '0x98', '0x40', '0xe3', '0x00', '0xb9', '0xc0', '0x71'
                            ], "selected": 0},
                            "API": {"hex_values": ['0x00', '0x00', '0x00', '0x00'], "selected": 0},
                            "SlotNumber": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "SubslotNumber": {"hex_values": ['0x80', '0x00'], "selected": 0},
                            "Padding": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "Index": {"hex_values": ['0xc0', '0x01'], "selected": 0},
                            "RecordDataLength": {"hex_values": ['0x00', '0x00', '0x00', '0x14'], "selected": 0},
                            "AdditionalValue1": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "AdditionalValue2": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "Another Padding": {"hex_values": [
                                '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
                                '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
                                '0x00', '0x00'
                            ], "selected": 0}
                        },
                        "selected": 0
                    },

                    "AdjustDomainBoundary": {
                        "fields": {
                            "BlockType": {"hex_values": ['0x02', '0x09'], "selected": 0},
                            "BlockLength": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "BlockVersionHigh": {"hex_values": ['0x01'], "selected": 0},
                            "BlockVersionLow": {"hex_values": ['0x01'], "selected": 0},
                            "Padding": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "DomainBoundaryIngress": {"hex_values": ['0x00', '0x00', '0x00', '0x00'], "selected": 0},
                            "DomainBoundaryEgress": {"hex_values": ['0x00', '0x00', '0x00', '0x00'], "selected": 0},
                            "AdjustProperties": {"hex_values": ['0x00', '0x00'], "selected": 0},
                            "Padding2": {"hex_values": ['0x00', '0x00'], "selected": 0},

                        },
                        "selected": 0
                    }
                },
                "selected": 0
            }
        }

        self.initUI()

    def save_dict_to_file(self, data, filename):
        """Save a dictionary to a file in JSON format.

        Args:
            data (dict): The dictionary to save.
            filename (str): The filename for the saved file.
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            print(f"Data successfully saved to {filename}")
        except Exception as e:
            print(f"Failed to save data to {filename}: {e}")

    def setup_buttons(self):
        # Connect the generate button's clicked signal to the generate_file method
        self.generate_button.clicked.connect(self.generate_file)
        self.add_block_button.clicked.connect(self.add_block)
        self.add_field_button.clicked.connect(self.add_field)
        self.load_button.clicked.connect(self.print_structure_info)
        self.refresh_button.clicked.connect(self.count_hex_values_and_update_length)
        self.delete_button.clicked.connect(self.delete_selected)

    def generate_file(self):
        # Get the data from the table and format it
        data_lines = []
        for row in range(self.hex_table.rowCount()):
            line_data = []
            for col in range(1, 9):  # Get the first 8 octets
                item = self.hex_table.item(row, col)
                if item is not None and item.text() != '':
                    line_data.append(f"{item.text()}")
                else:
                    line_data.append("0x00")  # Default value if no data is entered

            # The gap is at column 9, so we start the second half from column 10
            for col in range(10, 18):  # Get the second 8 octets
                item = self.hex_table.item(row, col)
                if item is not None and item.text() != '':
                    line_data.append(f"{item.text()}")
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
        self.tree_widget.itemSelectionChanged.connect(self.on_item_selection_changed)  # Connect the signal
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
        from PySide6.QtGui import QBrush, QColor

        def hex_to_item(hex_value):
            item = QTableWidgetItem(hex_value)
            item.setTextAlignment(Qt.AlignCenter)
            return item

        self.hex_table.clear()
        self.hex_table.setRowCount(50)  # Initial row count
        self.hex_table.setColumnCount(18)  # Including the gap

        column_labels = ['Offset'] + [f'{i:02X}' for i in range(1, 9)] + [''] + [f'{i:02X}' for i in range(10, 18)]
        self.hex_table.setHorizontalHeaderLabels(column_labels)

        def add_fields_to_table(protocol_structure, row, col, depth=0, propagated_selected=0):
            for key, value in protocol_structure.items():
                if isinstance(value, dict):
                    # Check if the current level or any parent is selected
                    current_selected = value.get('selected', 0) or propagated_selected

                    # This is a nested dictionary; recurse into it
                    if 'fields' in value:
                        row, col = add_fields_to_table(value['fields'], row, col, depth + 1, current_selected)
                    elif 'hex_values' in value:
                        for hex_value in value['hex_values']:
                            if col == 9:  # Skip the gap column
                                col += 1
                            if col > 17:  # Move to next row after 16th data column
                                row += 1
                                col = 1
                                if row >= self.hex_table.rowCount():
                                    self.hex_table.insertRow(row)
                            item = hex_to_item(hex_value)
                            self.hex_table.setItem(row, col, item)
                            # Apply blue background if current or any parent level is selected
                            if current_selected:
                                item.setBackground(QBrush(QColor(0, 0, 255)))  # Blue background
                            col += 1
                            if col == 9:  # Skip the gap if next column is 9
                                col += 1
                    else:
                        row, col = add_fields_to_table(value, row, col, depth + 1, current_selected)
            return row, col

        current_row, current_col = 0, 1
        self.hex_table.insertRow(current_row)

        # Start the recursive process
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

    def hex_pair(self, value):
        # Ensure the value has an even length by padding with a leading zero if necessary
        value = value.zfill(len(value) + len(value) % 2)
        # Split the value into two-character chunks and format each as hex
        return [f"0x{value[i:i + 2]}" for i in range(0, len(value), 2)]

    def add_block(self):
        dialog = AddBlockDialog(self)
        if dialog.exec():
            values = dialog.get_values()
            block_name = values['name']
            # Initialize block properties with 'selected' set to 0
            block_properties = {
                'Type': {'hex_values': self.hex_pair(values['type']), 'selected': 0},
                'BlockLength': {'hex_values': self.hex_pair(values['length']), 'selected': 0},
                'Version High': {'hex_values': self.hex_pair(values['version_high']), 'selected': 0},
                'Version Low': {'hex_values': self.hex_pair(values['version_low']), 'selected': 0},
            }

            # Get the currently selected item to determine where to add the new block
            selected_item = self.tree_widget.currentItem()
            if not selected_item:
                QMessageBox.information(self, "Selection Required", "Please select a block to add a sibling block.")
                return

            # Find the path in the protocol_structure to insert the new block
            path = self.get_path_from_selection(selected_item)
            if not path:
                QMessageBox.critical(self, "Error", "Failed to determine the location in the structure.")
                return

            # Navigate to the correct location in the protocol_structure
            current_level = self.protocol_structure
            for key in path[:-1]:  # Navigate to the parent of the selected block
                current_level = current_level[key]['fields']

            # Insert the new block right after the selected item
            parent_key = path[-1]
            new_order = {}
            inserted = False
            for key, value in current_level.items():
                new_order[key] = value
                if key == parent_key:
                    new_order[block_name] = {'fields': block_properties, 'selected': 0}
                    inserted = True
            if not inserted:
                new_order[block_name] = {'fields': block_properties, 'selected': 0}

            # Update the current level with the new order
            current_level.clear()
            current_level.update(new_order)

            # Refresh the tree and possibly the table view
            self.populate_tree(self.protocol_structure)
            self.populate_hex_table()  # If applicable

            # Optionally save the updated structure to a file
            self.save_structure_to_file("updated_protocol_structure.json")

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
                hex_values = [f"{int(value[i:i + 2], 16):#04x}" for i in range(0, len(value), 2)]

                # Find the path in the protocol structure that corresponds to the selected item.
                path = self.get_path_from_selection(selected_item)

                self.print_structure_info()

                # Insert the new field into the protocol structure at the correct location.
                # Now also including 'selected' set to 0 by default
                self.insert_field_in_structure(path, field_name, {"hex_values": hex_values, "selected": 0})

                # Refresh the hex table and tree to reflect the new field.
                self.populate_hex_table()
                self.populate_tree(self.protocol_structure)
                self.save_structure_to_file("updated_protocol_structure.json")

    def get_path_from_selection(self, selected_item):
        # This function needs to return a list of keys that represent the path from the root of `protocol_structure`
        # to the selected item.
        path = []
        while selected_item:
            path.insert(0, selected_item.text(0))  # Assuming the item's text correlates to keys in the structure
            selected_item = selected_item.parent()
        print(path)
        return path

    def print_structure_info(self):
        # Initialize at the root of the protocol structure
        current_level = self.protocol_structure

        # Recursive function to calculate and print the field and block names with hex entry counts
        def recurse_structure(current_level, depth=0):
            indent = "    " * depth  # Indentation for readability
            total_hex_entries = 0  # Initialize total hex entries counter for current block

            if isinstance(current_level, dict):
                for key, value in current_level.items():
                    if isinstance(value, dict):
                        # Check if it's a block or just a regular field dictionary
                        if 'fields' in value:
                            # Recursively calculate the number of hex entries for sub-blocks
                            sub_block_hex_entries = recurse_structure(value['fields'], depth + 1)
                            print(f"{indent}{key} - Block, Length: {sub_block_hex_entries}")
                            total_hex_entries += sub_block_hex_entries  # Add sub-block hex entries to total
                        else:
                            # Calculate the number of hex entries for this field
                            hex_entries = len(value.get('hex_values', []))
                            print(f"{indent}{key} - Field, Length: {hex_entries}")
                            total_hex_entries += hex_entries  # Add this field's hex entries to total

                return total_hex_entries  # Return the total hex entries of the current block or field

            return 0  # Return zero if current level is not a dictionary (safety fallback)

        # Start the recursion from the root
        total_entries = recurse_structure(current_level)
        print(f"Total hex entries in structure: {total_entries}")

    def insert_field_in_structure(self, path, field_name, field_data):
        current_level = self.protocol_structure
        for key in path[:-1]:  # Navigate to the parent of the target location.
            current_level = current_level.setdefault(key, {}).setdefault("fields", {})

        # Insert the new field right after the parent field if specified
        parent_field = path[-1]
        if parent_field in current_level:
            new_order = {}
            for k, v in current_level.items():
                new_order[k] = v
                if k == parent_field:
                    new_order[field_name] = field_data  # Insert the new field after the parent field
            current_level.clear()
            current_level.update(new_order)
        else:
            # If the parent field is not found, just add the new field at the end
            current_level[field_name] = field_data

        self.populate_tree(self.protocol_structure)
        self.populate_hex_table()
        self.save_dict_to_file(self.protocol_structure, 'protocol_structure.txt')

    def set_selected_in_nested_dict(self, data_dict, key_list):
        # Start navigating through the nested dictionary
        current = data_dict
        for key in key_list:
            # Navigate deeper if the key exists
            if key in current:
                current = current[key]
            else:
                # If the key path is broken, print an error and exit
                print(f"Error: Key '{key}' not found in the current level of dictionary.")
                return False

        # Once the path is correctly navigated, set 'selected' at the current level
        if 'selected' in current:
            current['selected'] = 1
            return True
        else:
            # If 'selected' key is missing where it's expected, indicate an error
            print("Error: 'selected' key not found at the target location.")
            return False

    # Integration within the selection changed handler
    def on_item_selection_changed(self):
        selected_item = self.tree_widget.currentItem()
        if selected_item:
            # Reset all 'selected' values to 0 before setting a new one
            self.reset_selection(self.protocol_structure)

            # Get the path of keys to the selected item, automatically handling nested 'fields'
            search_key = self.get_path_from_selection(selected_item)

            # Dynamically insert 'fields' into the path for correct dictionary navigation
            full_path = []
            for part in search_key:
                if full_path:  # Always skip the first component as it's the top-level key
                    full_path.append('fields')
                full_path.append(part)

            print(f"Setting 'selected' for path: {full_path}")

            # Attempt to set 'selected' to 1 using the modified path
            if self.set_selected_in_nested_dict(self.protocol_structure, full_path):
                print("Selection updated successfully.")
            else:
                print("Failed to update selection.")

            # Refresh the UI or other components as needed
            self.populate_hex_table()
            self.save_dict_to_file(self.protocol_structure, 'protocol_structure.txt')
        else:
            print("No item selected")

    def reset_selection(self, structure):
        if isinstance(structure, dict):
            for key, value in structure.items():
                if isinstance(value, dict):
                    if 'selected' in value:
                        value['selected'] = 0
                    self.reset_selection(value)

    # def refresh(self):
    # self.protocol_structure["Internet Protocol"]["fields"]["Total Length"]["hex_values"] = 0x00

    def update_protocol_structure_with_block_lengths(self):
        def update_block_lengths(fields, path=""):
            total_hex_count = 0
            for field_name, field_data in fields.items():
                current_path = f"{path} > {field_name}" if path else field_name
                if 'fields' in field_data:  # This is a nested block
                    # Recurse into nested fields
                    block_hex_count = update_block_lengths(field_data['fields'], current_path)
                    # Now we check if 'BlockLength' is a direct child of 'fields'
                    if 'BlockLength' in field_data['fields']:  # Corrected path to check inside 'fields'
                        # Subtract the header size and calculate the adjusted block length as an integer
                        adjusted_block_length = max(0, block_hex_count - 4)  # Subtract 4 hex values for the header
                        field_data['fields']['BlockLength']['hex_values'] = [
            '0x' + (hex(adjusted_block_length)[2:].zfill(4))[:2], '0x' + (hex(adjusted_block_length)[2:].zfill(4))[2:]]
                        print(f"Updated BlockLength at {current_path}: {adjusted_block_length}")
                    else:
                        print(f"No BlockLength field found at {current_path}")
                    total_hex_count += block_hex_count
                elif 'hex_values' in field_data:  # Regular field with hex values
                    total_hex_count += len(field_data['hex_values'])

            return total_hex_count

        for block_name, block_data in self.protocol_structure.items():
            if 'fields' in block_data:
                update_block_lengths(block_data['fields'], block_name)

    def count_hex_values_and_update_length(self):
        total_count = 0
        block_lengths = {}

        def count_recursive(field_dict, path):
            nonlocal total_count
            hex_count = 0
            for key, value in field_dict.items():
                if 'hex_values' in value:
                    current_count = len(value['hex_values'])
                    hex_count += current_count
                    total_count += current_count
                    block_lengths[' > '.join(path + [key])] = current_count
                elif 'fields' in value:
                    sub_count, _ = count_recursive(value['fields'], path + [key])
                    hex_count += sub_count

            if path:
                block_lengths[' > '.join(path)] = hex_count
            return hex_count, block_lengths

        total_hex_count, all_block_lengths = count_recursive(self.protocol_structure, [])

        # Subtract Ethernet II count from total and update Internet Protocol > Total Length
        ethernet_count = block_lengths['Ethernet II']
        ip_count = block_lengths['Internet Protocol']
        new_ip_total_length = total_hex_count - ethernet_count
        # Calculate new UDP Length
        new_udp_length = new_ip_total_length - ip_count

        self.protocol_structure['Internet Protocol']['fields']['Total Length']['hex_values'] = [
            '0x' + (hex(new_ip_total_length)[2:].zfill(4))[:2], '0x' + (hex(new_ip_total_length)[2:].zfill(4))[2:]]

        self.protocol_structure['User Datagram Protocol']['fields']['Length']['hex_values'] = \
            ['0x' + (hex(new_udp_length)[2:].zfill(4))[:2], '0x' + (hex(new_udp_length)[2:].zfill(4))[2:]]

        # Calculate and update the IP checksum
        ip_header_fields = self.protocol_structure['Internet Protocol']['fields']
        header_values = []
        for key, value in ip_header_fields.items():
            header_values.extend(value['hex_values'])
        # Calculate checksum
        ip_checksum = self.calculate_IP_checksum(header_values)
        if 'Header Checksum' in ip_header_fields:
            ip_header_fields['Header Checksum']['hex_values'] = ip_checksum
        else:
            print("No Header Checksum field found.")

        # print("Total Hex Count:", total_hex_count)
        # print("Block Lengths:")
        # for block, length in all_block_lengths.items():
            # print(f"{block}: {length}")

        fragment_length = len(self.extract_hex_values_fragment())
        self.protocol_structure['Distributed Computing Environment / Remote Procedure Call']['fields']['Fragment Length']['hex_values'] = [
            '0x' + format(fragment_length, '04x')[0:2],
            '0x' + format(fragment_length, '04x')[2:]]



        source_address_ip_hex = self.protocol_structure['Internet Protocol']['fields']['Source Address']['hex_values']
        source_address_ip = ".".join(str(int(x, 16)) for x in source_address_ip_hex)

        dest_address_ip_hex = self.protocol_structure['Internet Protocol']['fields']['Destination Address']['hex_values']
        dest_address_ip = ".".join(str(int(x, 16)) for x in dest_address_ip_hex)

        source_address_ip = socket.inet_aton(source_address_ip)
        dest_address_ip = socket.inet_aton(dest_address_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        # construct the pseudo header
        psh = struct.pack('!4s4sBBH', source_address_ip, dest_address_ip, placeholder, protocol, new_udp_length)

        DCE_RPC = self.extract_hex_values()

        udp_header_without_checksum = (
                self.protocol_structure['User Datagram Protocol']['fields']['Source Port']['hex_values'] +
                self.protocol_structure['User Datagram Protocol']['fields']['Destination Port']['hex_values'] +
                self.protocol_structure['User Datagram Protocol']['fields']['Length']['hex_values']
        )

        udp_header_without_checksum = "".join(x[2:] for x in udp_header_without_checksum)
        udp_header_without_checksum = bytes.fromhex(udp_header_without_checksum)

        DCE_RPC_hex = "".join(x[2:] for x in DCE_RPC)
        DCE_RPC_hex = bytes.fromhex(DCE_RPC_hex)

        # pad the data if necessary
        if len(DCE_RPC_hex) % 2 != 0:
            DCE_RPC_hex += b'\0'
        # concatenate the pseudo-header, the udp header without checksum, zeros for checksum and the data
        packet = psh + udp_header_without_checksum + b'\x00\x00' + DCE_RPC_hex
        # compute the checksum
        calculated_checksum = self.calculate_checksum_UDP(packet)
        calculated_checksum = socket.htons(calculated_checksum)  # convert to network byte order
        # insert the calculated checksum into profinet_data
        self.protocol_structure['User Datagram Protocol']['fields']['Checksum']['hex_values'] = ['0x' + format(calculated_checksum, '04x')[0:2],
                             '0x' + format(calculated_checksum, '04x')[2:]]

        ActualCount = len(self.extract_hex_values_Arg_ActualCount())
        self.protocol_structure['Profinet IO']['fields']['ArgsLength']['hex_values'] = [
            '0x' + format(ActualCount, '08x')[0:2],
            '0x' + format(ActualCount, '08x')[2:4],
            '0x' + format(ActualCount, '08x')[4:6],
            '0x' + format(ActualCount, '08x')[6:]]

        self.protocol_structure['Profinet IO']['fields']['ActualCount']['hex_values'] = [
            '0x' + format(ActualCount, '08x')[0:2],
            '0x' + format(ActualCount, '08x')[2:4],
            '0x' + format(ActualCount, '08x')[4:6],
            '0x' + format(ActualCount, '08x')[6:]]

        self.update_protocol_structure_with_block_lengths()
        self.populate_hex_table()
        return total_hex_count, all_block_lengths

    def calculate_IP_checksum(self, header):
        # concatenate adjacent bytes in header to form words, skip checksum bytes
        words = [header[i] + header[i + 1][2:] for i in range(0, len(header), 2) if i not in [10, 11]]

        # convert hexadecimal words to decimal and calculate sum
        total = sum(int(word, 16) for word in words)

        # calculate carries
        while total > 0xffff:
            total = (total & 0xffff) + (total >> 16)

        # one's complement
        checksum = total ^ 0xffff
        checksumList = []
        checksumList.extend([('0x' + (hex(checksum)[2:].zfill(4))[:2]), ('0x' + (hex(checksum)[2:].zfill(4))[2:])])

        return checksumList

        # return '0x' + format(checksum, '04x')  # return checksum as hexadecimal

    def delete_selected(self):
        selected_item = self.tree_widget.currentItem()
        if selected_item is None:
            QMessageBox.warning(self, "Selection Required", "Please select a block to delete.")
            return

        reply = QMessageBox.question(self, 'Confirm Delete',
                                     'Are you sure you want to delete the selected block?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            # Get the path to the selected item
            path = self.get_path_from_selection(selected_item)
            if not path:
                QMessageBox.critical(self, "Error", "Failed to determine the location in the structure for deletion.")
                return

            # Navigate to the parent in the protocol_structure
            current_level = self.protocol_structure
            for key in path[:-1]:  # Navigate to the parent of the selected block
                current_level = current_level[key]['fields']

            # Remove the selected block
            block_to_remove = path[-1]
            if block_to_remove in current_level:
                del current_level[block_to_remove]

            # Refresh the tree and possibly the hex table
            self.populate_tree(self.protocol_structure)
            self.populate_hex_table()  # If applicable

    def calculate_checksum_UDP(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i + 1] << 8)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

    def extract_hex_values(self):
        excluded_blocks = ["Ethernet II", "Internet Protocol", "User Datagram Protocol"]
        hex_values = []

        def extract_from_fields(fields):
            for field_name, field_data in fields.items():
                if isinstance(field_data, dict):
                    # If this field itself contains fields, recurse
                    if "fields" in field_data:
                        extract_from_fields(field_data["fields"])
                    # Otherwise, it's a field with hex values
                    elif "hex_values" in field_data:
                        hex_values.extend(field_data["hex_values"])

        for block_name, block_data in self.protocol_structure.items():
            if block_name not in excluded_blocks:
                if "fields" in block_data:
                    extract_from_fields(block_data["fields"])

        return hex_values

    def extract_hex_values_fragment(self):
        excluded_blocks = ["Ethernet II", "Internet Protocol", "User Datagram Protocol", "Distributed Computing Environment / Remote Procedure Call"]
        hex_values = []

        def extract_from_fields(fields):
            for field_name, field_data in fields.items():
                if isinstance(field_data, dict):
                    # If this field itself contains fields, recurse
                    if "fields" in field_data:
                        extract_from_fields(field_data["fields"])
                    # Otherwise, it's a field with hex values
                    elif "hex_values" in field_data:
                        hex_values.extend(field_data["hex_values"])

        for block_name, block_data in self.protocol_structure.items():
            if block_name not in excluded_blocks:
                if "fields" in block_data:
                    extract_from_fields(block_data["fields"])

        return hex_values

    def extract_hex_values_Arg_ActualCount(self):
        excluded_blocks = [
            "Ethernet II",
            "Internet Protocol",
            "User Datagram Protocol",
            "Distributed Computing Environment / Remote Procedure Call"
        ]
        excluded_fields_profinet_io = ["Status", "ArgsLength", "MaximumCount", "Offset", "ActualCount"]
        hex_values = []

        def extract_from_fields(fields, block_name):
            for field_name, field_data in fields.items():
                if isinstance(field_data, dict):
                    # If this field itself contains fields, recurse
                    if "fields" in field_data:
                        extract_from_fields(field_data["fields"], block_name)
                    # Otherwise, it's a field with hex values
                    elif "hex_values" in field_data:
                        # Skip the field if it's in the excluded fields for Profinet IO block
                        if block_name == "Profinet IO" and field_name in excluded_fields_profinet_io:
                            continue
                        hex_values.extend(field_data["hex_values"])

        for block_name, block_data in self.protocol_structure.items():
            if block_name not in excluded_blocks:
                if "fields" in block_data:
                    extract_from_fields(block_data["fields"], block_name)

        return hex_values


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PcapGenerator()
    window.setup_buttons()
    window.show()
    sys.exit(app.exec())
