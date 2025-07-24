import os
import sys
import threading
import sqlite3
from datetime import datetime
import traceback
import time

# Tambahkan parent folder ke path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# PySide6 Core
from PySide6.QtCore import (
    Qt, QEvent, Signal, QObject, QMetaObject, Q_ARG
)

# PySide6 Widgets
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFrame, QTableWidget,
    QTableWidgetItem, QScrollArea, QTextEdit, QStackedWidget,
    QMessageBox,QFileDialog,QInputDialog,QSizePolicy

)

# PySide6 GUI
from PySide6.QtGui import QColor

# Ekstensi
from wifiget import get_network_name

# Core modules (local imports)
from core.sniffer import Sniffer
from core.network_scanner import NetworkScanner
from core.dos_flodder import DoSFlooder
from core.mqtt_enum import MQTTEnumerator
from core.fuzzer import Fuzzer
from core.qos_delay import QoSTester
from core.report import ReportGenerator
from core.acl_checker import AclCheck 


def safe_set_label_text(label, text):
    QMetaObject.invokeMethod(label, "setText", Qt.QueuedConnection, Q_ARG(str, text))

def safe_append_text(textedit, text):
    def append():
        textedit.append(text)
        textedit.verticalScrollBar().setValue(textedit.verticalScrollBar().maximum())
    QMetaObject.invokeMethod(textedit, "append", Qt.QueuedConnection, Q_ARG(str, text))

class PenMQTT(QMainWindow):
    def __init__(self):
        super().__init__()
        # Active Worker Threads
        self._active_threads = []
        self._active_workers = []

        self.dos_max_delay = 2.0  # default value
        self.qos_value = 0
        self.brute_value = 0
        self.fuzzing_value = 0
        self.dos_value = 0
        self.waiting_for_manual_input = False
        self.setWindowTitle("PenMQTT")
        self.resize(1920, 1080)  # Set window size to 1920x1080
        self.setStyleSheet("""
            QMainWindow {
                background-color: #a0a0a0;
            }
            QLabel {
                font-size: 14px;
                color: black;
            }
            QPushButton {
                background-color: white;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
                color: black;
            }
            QPushButton#scanButton {
                background-color: #ffff70;
                font-weight: bold;
                color: black;
            }
            QPushButton#enterButton {
                background-color: #90ee90;
                color: black;
            }
            QPushButton#browseButton {
                background-color: #f5e198;
                color: black;
            }
            QPushButton#reportButton {
                background-color: #87CEFA;
                border-radius: 5px;
                color: black;
            }
            QLineEdit {
                border: 1px solid gray;
                border-radius: 5px;
                padding: 2px;
                color: black;
            }
            QFrame#section {
                background-color: white;
                border-radius: 10px;
                padding: 10px;
            }
            QFrame#statusSection {
                background-color: #e74c3c;
                border-radius: 10px;
                padding: 10px;
            }
            QTableWidget {
                background-color: white;
                gridline-color: gray;
                color: black;
            }
            QTableWidget::item:selected {
                background-color: #87CEFA;
            }
            QScrollArea {
                border: none;
            }
            QTextEdit {
                color: black;
            }
        """)
        
        # Initialize NetworkScanner
        self.network_scanner = NetworkScanner()
        # Initialize device tracking
        self.device_buttons = []
        self.current_device = None

        # Central widget
        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)
        
        # Left side (Section 1)
        left_layout = QVBoxLayout()
        
        # === Logo section container ===
        logo_layout = QHBoxLayout()

        logo_frame = QFrame()
        logo_frame.setObjectName("logoFrame")
        logo_frame.setStyleSheet("""
            QFrame#logoFrame {
                background-color: #e0e0e0;
                border-radius: 20px;
                padding: 10px;
            }
        """)
        logo_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        logo_text = QLabel("PenMQTT", logo_frame)
        logo_text.setStyleSheet("font-size: 24px; font-weight: bold; color: black;")
        logo_text.setAlignment(Qt.AlignCenter)

        logo_inner_layout = QHBoxLayout(logo_frame)
        logo_inner_layout.setContentsMargins(5, 0, 5, 0)
        logo_inner_layout.addWidget(logo_text)

        # === Button
        dos_config_button = QPushButton("⚙️")
        dos_config_button.setFixedSize(32, 32)
        dos_config_button.setStyleSheet("""
            QPushButton {
                background-color: #d9f7be;
                color: black;
                border-radius: 8px;
                font-size: 16px;
            }
        """)
        dos_config_button.clicked.connect(self.configure_dos_delay)

        # === Assemble layout
        logo_layout.addWidget(logo_frame)
        logo_layout.addWidget(dos_config_button)

        left_layout.addLayout(logo_layout)
        
        # Section 1: Network scanning section
        section1 = QFrame()
        section1.setObjectName("section")
        section1_layout = QVBoxLayout(section1)
        
        # Network selection
        network_layout = QHBoxLayout()
        network_label = QLabel("Network :")
        self.network_value = QLabel(get_network_name())
        self.network_value.setStyleSheet("border: 1px solid black; border-radius: 10px; padding: 5px; color: black;")
        network_layout.addWidget(network_label)
        network_layout.addWidget(self.network_value)
        section1_layout.addLayout(network_layout)
        
        # Scan button
        scan_button = QPushButton("Scan")
        scan_button.setObjectName("scanButton")
        scan_button.setMinimumHeight(50)
        section1_layout.addWidget(scan_button)
        
        # Devices label
        devices_label = QLabel("Devices :")
        section1_layout.addWidget(devices_label)
        
        # Devices list container
        self.devices_frame = QFrame()
        self.devices_frame.setFrameShape(QFrame.StyledPanel)
        self.devices_frame.setStyleSheet("background-color: white;")
        self.devices_layout = QVBoxLayout(self.devices_frame)
        
        # Add a scroll area for devices
        devices_scroll = QScrollArea()
        devices_scroll.setWidgetResizable(True)
        devices_scroll.setWidget(self.devices_frame)
        section1_layout.addWidget(devices_scroll)
        
        # Credential info section
        cred_frame = QFrame()
        cred_frame.setFrameShape(QFrame.StyledPanel)
        cred_layout = QVBoxLayout(cred_frame)
        
        cred_title = QLabel("Credential Info")
        cred_title.setStyleSheet("color: black;")
        cred_layout.addWidget(cred_title)
        
        id_layout = QHBoxLayout()
        id_label = QLabel("ID / Username :")
        id_label.setStyleSheet("color: black;")
        id_layout.addWidget(id_label)
        cred_layout.addLayout(id_layout)
        
        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("Enter ID")
        self.id_input.setStyleSheet("color: white;")
        cred_layout.addWidget(self.id_input)
        
        pass_label = QLabel("Password :")
        pass_label.setStyleSheet("color: black;")
        cred_layout.addWidget(pass_label)
        
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Enter Password")
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setStyleSheet("color: white;")
        cred_layout.addWidget(self.pass_input)
        
        enter_layout = QHBoxLayout()
        enter_layout.addStretch()
        enter_button = QPushButton("Enter")
        enter_button.setObjectName("enterButton")
        enter_layout.addWidget(enter_button)
        cred_layout.addLayout(enter_layout)
        
        section1_layout.addWidget(cred_frame)
        
        left_layout.addWidget(section1)
        main_layout.addLayout(left_layout, 1)
        
        # Right side (Sections 2, 3, and 4)
        right_layout = QVBoxLayout()
        
        # Section 2: Status bar
        section2 = QFrame()
        section2.setObjectName("statusSection")
        section2_layout = QVBoxLayout(section2)

        status_title_label = QLabel("Status")
        status_title_label.setAlignment(Qt.AlignCenter)
        status_title_label.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        section2_layout.addWidget(status_title_label)

        # Status indicators in a row
        status_indicators_layout = QHBoxLayout()
        self.status_types = ["BruteForce", "Fuzzing", "QoS", "DoS"]
        self.status_indicators = {}

        for status_type in self.status_types: 
            # Create a frame for each status indicator
            indicator_frame = QFrame()
            indicator_frame.setStyleSheet("""
                QFrame {
                    background-color: white;
                    border-radius: 8px;
                    border: none;
                }
            """)
            
            # Create a layout for the indicator
            indicator_layout = QVBoxLayout(indicator_frame)
            indicator_layout.setContentsMargins(5, 5, 5, 5)
            
            # Create status label
            status_label = QLabel(status_type)
            status_label.setStyleSheet("color: black; font-size: 16px;")
            status_label.setAlignment(Qt.AlignCenter)
            indicator_layout.addWidget(status_label)
            
            
            # Store the indicator frame reference
            self.status_indicators[status_type] = indicator_frame
            
            # Add to layout
            status_indicators_layout.addWidget(indicator_frame)

        section2_layout.addLayout(status_indicators_layout)

        right_layout.addWidget(section2)

        
        # Section 3: Report view
        section3 = QFrame()
        section3.setObjectName("section")
        section3_layout = QVBoxLayout(section3)
        
        self.report_stack = QStackedWidget()
        
        # Empty state
        empty_widget = QWidget()
        empty_layout = QVBoxLayout(empty_widget)
        empty_label = QLabel("Select a device to view details")
        empty_label.setAlignment(Qt.AlignCenter)
        empty_layout.addWidget(empty_label)
        self.report_stack.addWidget(empty_widget)
        
        # Report content state
        self.report_widget = QWidget()
        report_content_layout = QVBoxLayout(self.report_widget)
        
        report_header_layout = QHBoxLayout()
        self.device_info_label = QLabel("No device selected")
        self.device_info_label.setStyleSheet("color: black;")
        report_header_layout.addWidget(self.device_info_label)
        report_header_layout.addStretch()
        
        self.status_info = QLabel("")
        self.status_info.setStyleSheet("color: black;")
        report_header_layout.addWidget(self.status_info)
        
        # generate_report = QPushButton("Generate Report")
        # generate_report.setObjectName("reportButton")
        # generate_report.clicked.connect(self.generate_report)
        # report_header_layout.addWidget(generate_report)

        # auto_test_button = QPushButton("Run Full Pentest")
        # auto_test_button.setObjectName("testReportButton")
        # # auto_test_button.clicked.connect(self.run_full_pentest_ui)
        # report_header_layout.addWidget(auto_test_button)

        report_content_layout.addLayout(report_header_layout)
        
        self.attack_type_label = QLabel("")
        self.attack_type_label.setStyleSheet("color: black;")
        report_content_layout.addWidget(self.attack_type_label)
        
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setStyleSheet("color: black;")
        self.report_text.setStyleSheet("color: black;background-color: white;")
        report_content_layout.addWidget(self.report_text)
        
        self.report_stack.addWidget(self.report_widget)
        self.report_stack.setCurrentIndex(0)  # Start with empty state
        
        section3_layout.addWidget(self.report_stack)
        right_layout.addWidget(section3, 4)
        
        # Section 4: Audit log
        section4 = QFrame()
        section4.setObjectName("section")
        section4_layout = QVBoxLayout(section4)

        
        self.log_table = QTableWidget(0, 5)  # Start with 0 rows, 5 columns
        self.log_table.setHorizontalHeaderLabels(["Device Name", "TimeStamp", "Subject", "Description", "Status"])
        self.log_table.horizontalHeader().setStyleSheet("color: white;")

        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)  # Disable editing
        
        # Set column widths
        self.log_table.setColumnWidth(0, 150)  # Increased width
        self.log_table.setColumnWidth(1, 200)  # Increased width
        self.log_table.setColumnWidth(2, 150)  # Increased width
        self.log_table.setColumnWidth(3, 400)  # Increased width
        self.log_table.setColumnWidth(4, 100)  # Increased width

        # Connect a row click event to a handler
        self.log_table.cellClicked.connect(self.handle_log_selection) # Tambahan 22.53

        # Make the table take more space
        section4_layout.addWidget(self.log_table)
        right_layout.addWidget(section4, 3)  # Increased stretch factor to 3
        
        main_layout.addLayout(right_layout, 3)
        
        self.setCentralWidget(central_widget)
        
        # Connect signals
        scan_button.clicked.connect(self.scan_network)
        enter_button.clicked.connect(self.prompt_manual_credentials)
        self.pentest_running = False

    def handle_log_selection(self, row, column):  # def ini  juga Tambahan baru
        device_name = self.log_table.item(row, 0).text()
        timestamp = self.log_table.item(row, 1).text()
        subject = self.log_table.item(row, 2).text()
        description = self.log_table.item(row, 3).text()
        status = self.log_table.item(row, 4).text()

        # You can update Section 3 widgets based on this info
        self.device_info_label.setText(f"{device_name} @ {timestamp}")
        self.status_info.setText(status)
        self.attack_type_label.setText(subject)
        self.report_text.setText(f"Log Detail:\n\n{description}")
        self.report_stack.setCurrentIndex(1)

    def scan_network(self):
        """Start a network scan"""
        # Update network info
        # self.network_value.setText("Scanning...")
        
        # Clear existing device buttons
        self.clear_devices_list()
        
        # Show scanning message with a specific object name so we can find it later
        scanning_label = QLabel("Scanning network...")
        scanning_label.setObjectName("scanningLabel")
        scanning_label.setStyleSheet("color: black;")
        self.devices_layout.addWidget(scanning_label)
        QApplication.processEvents()  # Force UI update
        
        # Start network scan in a separate thread to keep UI responsive
        thread = threading.Thread(target=self._run_scan, daemon=True)
        thread.start()

    def _run_scan(self):
        """Run network scan in background thread"""
        try:
            # Perform the scan
            success = self.network_scanner.scan_network()
            if not success:
                # Use signal or other thread-safe method to show error
                print("A scan is already in progress.")
            else:
                # After successful scan, make sure to force update the devices list
                # by getting any cached devices from the network_scanner
                if hasattr(self.network_scanner, 'found_devices'):
                    # Update UI on the main thread 
                    QApplication.instance().postEvent(self, QEvent(QEvent.Type.User))
        except Exception as e:
            print(f"Error in network scan: {e}")

    def event(self, event):
        """Handle custom events"""
        if event.type() == QEvent.Type.User:
            # Update devices list from any cached devices
            if hasattr(self.network_scanner, 'found_devices'):
                self.update_devices_list(self.network_scanner.found_devices)
            return True
        return super().event(event)
            
    def clear_devices_list(self):
        """Clear the devices list"""
        # Remove the scanning label if it exists
        scanning_label = self.findChild(QLabel, "scanningLabel")
        if scanning_label:
            scanning_label.deleteLater()
        
        # Remove all device buttons
        if hasattr(self, 'device_buttons'):
            for button in self.device_buttons:
                button.deleteLater()
            self.device_buttons = []
        
        # Clear any other widgets in the devices layout
        while self.devices_layout.count():
            item = self.devices_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def update_devices_list(self, devices):
        """Update the devices list with scan results"""
        # This is called by the network scanner when scan completes
        self.clear_devices_list()
        
        # Update network name
        try:
            network_name = get_network_name()
            self.network_value.setText(network_name if network_name else "Unknown Network")
        except Exception as e:
            print(f"Error updating network name: {e}")
            self.network_value.setText("Unknown Network")
        
        if not devices:
            no_devices = QLabel("No devices found")
            no_devices.setStyleSheet("color: black;")
            self.devices_layout.addWidget(no_devices)
            return
        
        # Add device buttons with proper connection to handle selection
        for device in devices:
            device_text = f"{device['vendor']} ({device['ip']})"
            device_button = QPushButton(device_text)
            device_button.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    color: black;
                    padding: 8px;
                    border: 1px solid #d0d0d0;
                    border-radius: 4px;
                    margin: 2px;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                }
            """)
            
            # Use a lambda with default argument to avoid late binding issues
            device_button.clicked.connect(lambda checked, d=device: self.select_device(d))
            
            self.devices_layout.addWidget(device_button)
            self.device_buttons.append(device_button)
        
        # Add stretch to push buttons to top
        self.devices_layout.addStretch()
        
        # Add log entry
        self.add_log_entry("N/A", "Information", f"Network scan completed. Found {len(devices)} devices.", "Succeed")
        
        # Force UI update
        QApplication.processEvents()
        

    def append_to_report_text(self, message):
        safe_append_text(self.report_text, str(message))
        self.report_text.verticalScrollBar().setValue(
            self.report_text.verticalScrollBar().maximum()
        )
        QApplication.processEvents()
    
    def update_device_details(self, details):
        if not details:
            self.report_text.setText("Error fetching device details.")
            safe_set_label_text(self.status_info, "Failed")
            return
        
        # Format and display device details
        text = f"""
        Device IP: {details['ip']}
        MAC Address: {details['mac']}
        Vendor: {details['vendor']}
        Operating System: {details['os']}

        Open Ports:
        """
        
        if details['ports']:
            for port in details['ports']:
                text += f"• {port['number']}/{port['protocol']} - {port['state']} - {port['service']}"
                if port['product']:
                    text += f" ({port['product']}"
                    if port['version']:
                        text += f" {port['version']}"
                    text += ")"
                text += "\n"
        else:
            text += "No open ports detected."
        
        self.report_text.setText(text)
        safe_set_label_text(self.status_info, "Succeed")
        
        # Add log entry
        self.add_log_entry(self.current_device['name'], "Device Info", f"Scanned {details['ip']}", "Succeed")
    
    def refresh_status_bar(self):
        status_map = {
            "QoS": self.qos_value,
            "BruteForce": self.brute_value,
            "Fuzzing": self.fuzzing_value,
            "DoS": self.dos_value
        }

        for status_type in self.status_types:
            frame = self.status_indicators[status_type]
            if status_map.get(status_type, 0):
                frame.setStyleSheet("""
                    QFrame {
                        background-color: #ffff70;
                        border-radius: 8px;
                    }
                """)
            else:
                frame.setStyleSheet("""
                    QFrame {
                        background-color: white;
                        border-radius: 8px;
                    }
                """)

    def handle_status_update(self, name, value):
        if name == "QoS":
            self.qos_value = value
        elif name == "BruteForce":
            self.brute_value = value
        elif name == "Fuzzing":
            self.fuzzing_value = value
        elif name == "DoS":
            self.dos_value = value
        self.refresh_status_bar()

        
    def _update_attack_report(self, message):
        """Update the attack report with a new message"""
        safe_append_text(self.report_text, message)
        # Scroll to the bottom
        self.report_text.verticalScrollBar().setValue(
            self.report_text.verticalScrollBar().maximum()
        )
        # Process events to update UI
        QApplication.processEvents()

    def on_need_manual_credentials(self, broker_ip, enum, port):
        self.id_input.clear()
        self.pass_input.clear()
        self.waiting_for_manual_input = True
        self.prompt_manual_credentials(broker_ip, enum, port)

    def prompt_manual_credentials(self, broker_ip=None, enum=None, port=None, require_prompt=True):
        if not hasattr(self, 'current_device') or self.current_device is None:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("No Device Selected")
            msg.setText("Please select a device first.")
            msg.setStyleSheet("""
    QMessageBox QLabel {
        color: black;
    }
    QMessageBox {
        background-color: white;
    }
    QPushButton {
        color: black;
    }
""")
            msg.exec()
            return

        if require_prompt:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Question)
            msg.setWindowTitle("Input Manual Dibutuhkan")
            msg.setText("Brute force gagal.\nApakah Anda ingin melanjutkan dengan kredensial manual dari input form?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setStyleSheet("""
    QMessageBox QLabel {
        color: white;
    }
    QMessageBox {
        background-color: black;
    }
    QPushButton {
        color: white;
        background-color: black;
    }
""")
            result = msg.exec()
            if result != QMessageBox.Yes:
                self._update_attack_report("[!] Pengguna membatalkan pentest.\n")
                self.stop_automated_status_cycle()
                return

        username = self.id_input.text().strip()
        password = self.pass_input.text().strip()

        if username and password:
            self.manual_credentials = (username, password)
            self._update_attack_report(f"[✓] Menggunakan input manual: {username}:{password}\n")
            
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Credentials Entered")
            msg.setText(f"Credentials entered for {self.current_device['name']}:\nUsername: {username}")
            msg.setStyleSheet("""
    QMessageBox QLabel {
        color: white;
    }
    QMessageBox {
        background-color: black;
    }
    QPushButton {
        color: white;
        background-color: black;
    }
""")
            msg.exec()

            if hasattr(self, 'pentest_worker'):
                self.pentest_worker.manual_credentials = (username, password)

                # Hanya lanjutkan kalau memang sedang menunggu input
                if self.waiting_for_manual_input:
                    self.pentest_worker.continue_signal.emit()
                    self.waiting_for_manual_input = False

            self.add_log_entry(
                self.current_device['name'],
                "Credentials",
                f"Entered credentials for {self.current_device['ip']}",
                "Succeed"
            )
        else:
            self._update_attack_report("[!] Input manual belum diisi. Batalkan pentest.\n")
            self.id_input.clear()
            self.pass_input.clear()
            self.stop_automated_status_cycle()


    
    def add_log_entry(self, device, subject, description, status):
        from datetime import datetime
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%m/%d/%Y %H:%M:%S.")

        # Add new row to log table
        row_position = self.log_table.rowCount()
        self.log_table.insertRow(row_position)
        
        # Set table items
        device_item = QTableWidgetItem(device)
        device_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 0, device_item)
        
        timestamp_item = QTableWidgetItem(timestamp)
        timestamp_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 1, timestamp_item)
        
        subject_item = QTableWidgetItem(subject)
        subject_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 2, subject_item)
        
        desc_item = QTableWidgetItem(description)
        desc_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 3, desc_item)
        
        status_item = QTableWidgetItem(status)
        if status == "Succeed":
            status_item.setForeground(QColor("#FF6347"))  # Red text for "Succeed"
        else:
            status_item.setForeground(QColor("black"))
        self.log_table.setItem(row_position, 4, status_item)
        
        # Scroll to the newest entry
        self.log_table.scrollToBottom()
        
    def stop_automated_status_cycle(self):
        pass


    def select_device(self, device):
        if self.pentest_running:
            QMessageBox.warning(self, "Proses Sedang Berjalan", "Pentest masih berlangsung.")
            return

        self.pentest_running = True
        self.current_device = device
        self.device_info_label.setText(f"{device['name']} ({device['ip']}) - {device['mac']}")
        safe_set_label_text(self.status_info, "Scanning...")
        self.attack_type_label.setText("Device Information")
        self.report_text.setText("Gathering detailed information about this device...")
        self.report_stack.setCurrentIndex(1)

        self.network_scanner.get_device_details(device['ip'], callback=self.update_device_details)
        self.add_log_entry(device['name'], "Information", f"Device selected: {device['ip']}", "Succeed")

        from PySide6.QtCore import QThread
        self.pentest_thread = QThread()
        self.pentest_worker = PentestWorker(device['ip'], device['name'])
        self.pentest_worker.status_update.connect(self.handle_status_update)
        self.pentest_worker.moveToThread(self.pentest_thread)

        # Hubungkan signals ke UI
        self.pentest_worker.log.connect(self.append_to_report_text)
        self.pentest_worker.status.connect(lambda s: safe_set_label_text(self.status_info, s))
        self.pentest_worker.done.connect(self._on_pentest_finished)
        self.pentest_worker.need_manual_credentials.connect(self.on_need_manual_credentials)
        self.pentest_worker.log_entry.connect(self.add_log_entry) # Tambahan baru 22.19

        self.pentest_thread.started.connect(self.pentest_worker.run)
        self.pentest_worker.finished.connect(self.pentest_thread.quit)
        self.pentest_worker.finished.connect(self.pentest_worker.deleteLater)
        self.pentest_thread.finished.connect(self.pentest_thread.deleteLater)

        self.pentest_thread.start()

    def _on_pentest_finished(self, ip, device_name, status):
        self.add_log_entry(device_name, "Pentest", f"Pentest selesai untuk {ip}", status)
        self.stop_automated_status_cycle()
        self.pentest_running = False

    def configure_dos_delay(self):
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton

        dialog = QDialog(self)
        dialog.setWindowTitle("Konfigurasi DoS Delay")
        dialog.setStyleSheet("""
            QDialog {
                background-color: black;
            }
            QLabel {
                color: white;
            }
            QLineEdit {
                background-color: white;
                color: black;
                border: 1px solid gray;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: white;
                color: black;
                padding: 6px;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(dialog)
        label = QLabel("Berapa lama delay yang diinginkan? (maks: 5 detik):")
        input_field = QLineEdit()
        input_field.setPlaceholderText("Contoh: 1.5")

        button_ok = QPushButton("OK")
        button_cancel = QPushButton("Batal")

        layout.addWidget(label)
        layout.addWidget(input_field)
        layout.addWidget(button_ok)
        layout.addWidget(button_cancel)

        def validate_input():
            try:
                value = float(input_field.text())
                if 0 < value <= 5:
                    self.dos_max_delay = value
                    msg = QMessageBox(self)
                    msg.setIcon(QMessageBox.Information)
                    msg.setWindowTitle("Berhasil")
                    msg.setText(f"Delay DoS diatur ke {value} detik.")
                    msg.setStyleSheet("""
                        QMessageBox {
                            background-color: black;
                        }
                        QLabel {
                            color: white;
                        }
                        QPushButton {
                            color: white;
                            background-color: black;
                        }
                    """)
                    msg.exec()
                else:
                    raise ValueError
            except ValueError:
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Warning)
                msg.setWindowTitle("Input Tidak Valid")
                msg.setText("Masukkan angka antara 0.1 sampai 5.0 detik.")
                msg.setStyleSheet("""
                    QMessageBox {
                        background-color: black;
                    }
                    QLabel {
                        color: white;
                    }
                    QPushButton {
                        color: white;
                        background-color: black;
                    }
                """)
                msg.exec()

        button_ok.clicked.connect(validate_input)
        button_cancel.clicked.connect(dialog.reject)

        dialog.exec()




class ReportDatabase:
    DB_FILE = "pentest_reports.db"

    @staticmethod
    def init_db():
        conn = sqlite3.connect(ReportDatabase.DB_FILE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS report_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                pdf_data BLOB
            )
        ''')
        conn.commit()
        conn.close()

    @staticmethod
    def save_report(target_ip, pdf_path):
        with open(pdf_path, 'rb') as f:
            pdf_blob = f.read()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(ReportDatabase.DB_FILE)
        c = conn.cursor()
        c.execute('''
            INSERT INTO report_logs (timestamp, target, pdf_data)
            VALUES (?, ?, ?)
        ''', (timestamp, target_ip, pdf_blob))
        conn.commit()
        conn.close()

    @staticmethod
    def export_report(report_id, save_path):
        conn = sqlite3.connect(ReportDatabase.DB_FILE)
        c = conn.cursor()
        c.execute("SELECT pdf_data FROM report_logs WHERE id = ?", (report_id,))
        row = c.fetchone()
        conn.close()
        if row:
            with open(save_path, 'wb') as f:
                f.write(row[0])
            return True
        return False

class PentestWorker(QObject):
    log = Signal(str)
    status = Signal(str)
    status_update = Signal(str, int)  # nama status dan nilai 1 atau 0 
    finished = Signal()
    done = Signal(str, str, str)  # ip, device_name, status
    need_manual_credentials = Signal(str, object, int)
    continue_signal = Signal()
    log_entry = Signal(str, str, str, str)  # Tambahan baru 22.18

    def __init__(self, ip, device_name):
        super().__init__()
        self.ip = ip
        self.device_name = device_name
        self.manual_credentials = None
        self.continue_signal.connect(self.run)
        ReportDatabase.init_db()

    def get_ui_dos_delay(self):
        app = QApplication.instance()
        window = app.activeWindow()
        return getattr(window, "dos_max_delay", 2.0)


    def run(self):
        try:
            self.log.emit("Menjalankan pentest bertahap...\n")
            self.status.emit("Running...")
            acl_summary = "Pengecekan ACL tidak dilakukan."
            self.status_update.emit("BruteForce", 1)
            # Cek apakah enum sebelumnya sudah pernah sukses
            if hasattr(self, "cached_topics") and self.cached_topics:
                self.log.emit("[~] Topik sebelumnya sudah ditemukan. Gunakan cached.\n")
                topics = self.cached_topics
                credentials = self.manual_credentials
                goto_enum = False
            elif getattr(self, "waiting_for_manual", False):
                self.waiting_for_manual = False
                username, password = self.manual_credentials
                broker_ip, port = self.broker_info
                enum = self.enum
                self.log.emit(f"[✓] Melanjutkan dengan input manual: {username}:{password}\n")

                # Tambahan patch: retry enum hingga 3 kali jika gagal
                topics = None
                for attempt in range(3):
                    try:
                        topics = enum.enum(broker_ip, username, password, port)
                        if topics:
                            self.cached_topics = topics  # Simpan agar tidak enum ulang
                            break
                        self.log.emit(f"[!] Tidak ada topik ditemukan (percobaan ke-{attempt+1})\n")
                        time.sleep(1)
                    except Exception as e:
                        self.log.emit(f"[!] Gagal enum (percobaan ke-{attempt+1}): {str(e)}\n")
                        time.sleep(1)

                if not topics:
                    self.log.emit("[!] Gagal enum setelah 3 kali percobaan. Meminta ulang input manual.\n")
                    self.waiting_for_manual = True
                    self.need_manual_credentials.emit(broker_ip, enum, port)
                    return

                credentials = (username, password)
            
            else:
                scanner = NetworkScanner()
                interface = scanner.interface
                sniffer = Sniffer(interface)
                broker_list = sniffer.sniff_broker_from_iot(self.ip)
                if not broker_list:
                    self.log.emit("[!] Broker MQTT tidak ditemukan.\n")
                    self.done.emit(self.ip, self.device_name, "Failed")
                    self.finished.emit()
                    return

                broker_ip, port = broker_list[0]
                self.log.emit(f"[✓] Broker ditemukan: {broker_ip}:{port}\n")

                enum = MQTTEnumerator(logger=lambda msg: self.log.emit(msg))
                topics = enum.enum(broker_ip, port=port)

                

                if hasattr(enum, "valid_credentials") and enum.valid_credentials:
                    self.status_update.emit("BruteForce", 1)
                    credentials = enum.valid_credentials
                    self.log.emit(f"[✓] Menggunakan kredensial enum: {credentials[0]}:{credentials[1]}\n")
                    self.log_entry.emit(self.device_name, "BruteForce", f"Kredensial: {credentials[0]}:{credentials[1]}", "Succeed")
                    self.status_update.emit("BruteForce", 0)
                elif topics:
                    credentials = (None, None)
                else:
                    self.status_update.emit("BruteForce", 1)
                    self.log.emit("[!] Gagal enum. Menunggu input manual...\n")
                    self.enum = enum
                    self.broker_info = (broker_ip, port)
                    self.waiting_for_manual = True
                    self.need_manual_credentials.emit(broker_ip, enum, port)
                    self.log_entry.emit(self.device_name, "BruteForce", f"Device selected: {self.ip}", "Failed")
                    self.status_update.emit("BruteForce", 0)
                    return

                
                self.cached_topics = topics
            self.status_update.emit("BruteForce", 0)
            self.log.emit("➤ Menjalankan Pengecekan ACL...\n")
            acl_checker = AclCheck(client=enum.last_successful_client, logger=lambda msg: self.log.emit(msg))
            acl_summary_text, acl_is_strict = acl_checker.run()
            self.log.emit(acl_summary_text + "\n\n")
            self.log_entry.emit(self.device_name, "ACL Check", f"Pengecekan pada {broker_ip}", "Succeed")

            self.status_update.emit("Fuzzing", 1)
            self.log.emit("➤ Jalankan Fuzzing...\n")
            fuzzer = Fuzzer(broker_ip, port, *credentials, logger=lambda msg: self.log.emit(msg))
            fuzzer.run(self.cached_topics)
            self.log_entry.emit(self.device_name, "Fuzzing", f"Device selected: {self.ip}", "Succeed")
            self.status_update.emit("Fuzzing", 0)

            if not acl_is_strict:
                use_tls = (port == 8883)
                self.status_update.emit("QoS", 1)
                self.log.emit("➤ Uji Delay QoS...\n")
                qos = QoSTester(broker_ip, port, *credentials, logger=lambda msg: self.log.emit(msg))
                qos_summary = qos.run()
                self.log_entry.emit(self.device_name, "QoS", f"Device selected: {self.ip}", "Succeed")
                self.status_update.emit("QoS", 0)

                self.status_update.emit("DoS", 1)
                self.log.emit("➤ Jalankan Subscribe Flood (DoS)...\n")
                # Ambil delay dari UI
                max_delay = self.get_ui_dos_delay()
                if max_delay is None:
                    self.log.emit("[!] DoS Flood dibatalkan oleh pengguna.\n")
                    flood_info = {"total_topics": 0, "total_messages": 0, "payload_size_kb": 0, "reason": "dibatalkan"}
                else:
                    dos = DoSFlooder(broker_ip, port, *credentials, logger=lambda msg: self.log.emit(msg))
                    flood_result = dos.run(max_delay=self.get_ui_dos_delay())
                    flood_info = {
                        "total_topics": flood_result["total_topics"],
                        "total_messages": flood_result["total_messages"],
                        "payload_size_kb": flood_result["payload_size_kb"],
                        "reason": flood_result["reason"]
    }

                flood_info = {
                    "total_topics": flood_result["total_topics"],
                    "total_messages": flood_result["total_messages"],
                    "payload_size_kb": flood_result["payload_size_kb"],
                    "reason": flood_result["reason"]
                }
                self.status_update.emit("DoS", 0)
            else:
                self.log.emit("[!] ACL aktif — QoS Delay dan DoS mungkin diblokir oleh broker.\n")
                qos_summary = {"0": -1, "1": -1, "2": -1}
                flood_info = {"topic_count": 0, "messages_per_topic": 0}
                self.status_update.emit("DoS", 0)

            self.log.emit("➤ Membuat laporan...\n")
            report_path = f"report_{broker_ip.replace('.', '_')}.pdf"
            report = ReportGenerator(report_path)
            report.generate(
                broker_ip=broker_ip,
                username=credentials[0],
                password=credentials[1],
                topics=self.cached_topics,
                fuzz_count=20,
                flood_info=flood_info,
                qos_delay_summary=qos_summary,
                use_tls=(port == 8883),
                acl_summary=acl_summary_text
            )

            ReportDatabase.save_report(broker_ip, report_path)

            self.status.emit("Succeed")
            self.log.emit("[✓] Pentest selesai. Laporan telah dibuat.\n")
            self.done.emit(self.ip, self.device_name, "Succeed")
            self.log_entry.emit(self.device_name, "Report Generated", f"Report Saved at {report_path}", "Succeed")

            enum.cleanup()

        except Exception as e:
            self.log.emit(f"[ERROR] {str(e)}")
            self.done.emit(self.ip, self.device_name, "Failed")

        self.finished.emit()




def main():
    def excepthook(exc_type, exc_value, exc_tb):
        print("".join(traceback.format_exception(exc_type, exc_value, exc_tb)))

    sys.excepthook = excepthook
    app = QApplication(sys.argv)
    window = PenMQTT()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()