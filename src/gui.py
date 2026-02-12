from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, 
                            QTableWidget, QTableWidgetItem, QLabel, QComboBox, QFileDialog, QTextEdit, QDialog, 
                            QDateTimeEdit, QFormLayout, QInputDialog, QTabWidget, QColorDialog, QHeaderView, QCheckBox)
from PyQt6.QtCore import Qt, QTimer, QDateTime
from PyQt6.QtGui import QPainter, QPen, QColor, QFont
from network_monitor import NetworkMonitorCore
import logging
import time
import psutil
import binascii
from datetime import datetime

try:
    from scapy.layers.tls.all import *
    TLS_AVAILABLE = True
except ImportError:
    try:
        from scapy.all import load_layer
        load_layer("tls")
        from scapy.layers.tls.all import *
        TLS_AVAILABLE = True
    except ImportError:
        TLS_AVAILABLE = False
        logging.warning("Scapy TLS module not available. HTTPS parsing will be limited.")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class PacketDetailsDialog(QDialog):
    def __init__(self, packet_data, raw_packet, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.setGeometry(200, 200, 600, 400)
        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setText(self.format_packet_details(packet_data, raw_packet))
        layout.addWidget(self.text_edit)
        self.setLayout(layout)

    def format_packet_details(self, packet_data, raw_packet):
        try:
            timestamp, src, dst, protocol, sport, dport, flags, header_info, payload, correlation_id, length, ttl, seq, ack = packet_data
            # Format timestamp from float to human-readable string with milliseconds
            formatted_time = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]
            details = [
                f"Time: {formatted_time}",
                f"Source: {src}",
                f"Destination: {dst}",
                f"Protocol: {protocol}",
                f"Source Port: {sport}",
                f"Destination Port: {dport}",
                f"TCP Flags: {flags}",
                f"Header Info: {header_info if header_info else 'N/A'}",
                f"Payload Summary: {payload}",
                f"Packet Length: {length} bytes",
                f"IP TTL: {ttl if ttl else 'N/A'}",
                f"TCP Sequence Number: {seq if seq else 'N/A'}",
                f"TCP Acknowledgment Number: {ack if ack else 'N/A'}",
                f"Correlation ID: {correlation_id if correlation_id else 'N/A'}",
            ]
            if raw_packet and 'Raw' in raw_packet:
                payload = raw_packet['Raw'].load
                hex_dump = binascii.hexlify(payload).decode('utf-8')
                hex_formatted = ' '.join(hex_dump[i:i+2] for i in range(0, len(hex_dump), 2))
                details.append(f"Payload Hex Dump: {hex_formatted[:200]}{'...' if len(hex_formatted) > 200 else ''}")
                try:
                    full_payload = payload.decode('utf-8', errors='ignore')
                    details.append(f"Full Payload: {full_payload[:1000]}{'...' if len(full_payload) > 1000 else ''}")
                except:
                    details.append("Full Payload: Non-text (binary)")
            logging.debug(f"Packet details formatted: {timestamp}, {protocol}")
            return "\n".join(details)
        except Exception as e:
            logging.error(f"Error in format_packet_details: {e}")
            return "Error formatting packet details"

class AlertRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Alert Rules")
        self.setGeometry(300, 300, 400, 300)
        layout = QVBoxLayout()
        self.form_layout = QFormLayout()
        self.type_combo = QComboBox()
        self.type_combo.addItems(["HTTP", "TCP", "Payload", "HTTPS", "SSH", "FTP"])
        self.form_layout.addRow("Alert Type:", self.type_combo)
        self.condition_input = QLineEdit()
        self.condition_input.setPlaceholderText("e.g., Status_Code >= 400 or Flags == FA or TLS Version == 1.2")
        self.form_layout.addRow("Condition:", self.condition_input)
        self.color_button = QPushButton("Select Color")
        self.color_button.clicked.connect(self.select_color)
        self.color = QColor(255, 100, 100)
        self.color_button.setStyleSheet(f"background-color: {self.color.name()}")
        self.form_layout.addRow("Highlight Color:", self.color_button)
        layout.addLayout(self.form_layout)
        self.add_button = QPushButton("Add Rule")
        self.add_button.clicked.connect(self.add_rule)
        layout.addWidget(self.add_button)
        self.rules_list = QTextEdit()
        self.rules_list.setReadOnly(True)
        layout.addWidget(self.rules_list)
        # Display existing rules
        for rule in self.parent().core.alert_rules:
            self.rules_list.append(f"Type: {rule['type']}, Condition: {rule['condition']}, Color: {rule['color'].name()}")
        self.setLayout(layout)

    def select_color(self):
        color = QColorDialog.getColor(self.color, self)
        if color.isValid():
            self.color = color
            self.color_button.setStyleSheet(f"background-color: {color.name()}")

    def add_rule(self):
        rule = {"type": self.type_combo.currentText(), "condition": self.condition_input.text(), "color": self.color}
        self.parent().core.alert_rules.append(rule)
        self.rules_list.append(f"Type: {rule['type']}, Condition: {rule['condition']}, Color: {rule['color'].name()}")
        self.condition_input.clear()
        logging.info(f"Added alert rule: {rule}")
        self.parent().filter_table() # Re-apply rules to existing packets

class FilterPresetDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Filter Presets")
        self.setGeometry(300, 300, 400, 300)
        layout = QVBoxLayout()
        self.form_layout = QFormLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Preset Name")
        self.form_layout.addRow("Preset Name:", self.name_input)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP (e.g., 192.168.0.1)")
        self.form_layout.addRow("IP Filter:", self.ip_input)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g., 80)")
        self.form_layout.addRow("Port:", self.port_input)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "TCP", "UDP", "HTTP", "HTTPS", "FTP", "DNS", "ICMP", "SSH"])
        self.form_layout.addRow("Protocol:", self.protocol_combo)
        layout.addLayout(self.form_layout)
        self.add_button = QPushButton("Add Preset")
        self.add_button.clicked.connect(self.add_preset)
        layout.addWidget(self.add_button)
        self.presets_list = QTextEdit()
        self.presets_list.setReadOnly(True)
        layout.addWidget(self.presets_list)
        # Display existing presets
        for name, preset in self.parent().core.filter_presets.items():
            self.presets_list.append(f"Name: {name}, IP: {preset['ip']}, Port: {preset['port']}, Protocol: {preset['protocol']}")
        self.setLayout(layout)

    def add_preset(self):
        preset = {
            "name": self.name_input.text(),
            "ip": self.ip_input.text(),
            "port": self.port_input.text(),
            "protocol": self.protocol_combo.currentText()
        }
        if not preset["name"]:
            return # Don't save presets without a name
        self.parent().core.filter_presets[preset["name"]] = preset
        self.presets_list.append(f"Name: {preset['name']}, IP: {preset['ip']}, Port: {preset['port']}, Protocol: {preset['protocol']}")
        self.parent().core.save_filter_preset(preset["name"], preset["ip"], preset["port"], preset["protocol"])
        self.name_input.clear()
        self.ip_input.clear()
        self.port_input.clear()
        logging.info(f"Added filter preset: {preset}")

class ControlPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout()
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g., 80)")
        layout.addWidget(QLabel("Port:"))
        layout.addWidget(self.port_input)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP (e.g., 192.168.0.1)")
        layout.addWidget(QLabel("IP Filter:"))
        layout.addWidget(self.ip_input)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "TCP", "UDP", "HTTP", "HTTPS", "FTP", "DNS", "ICMP", "SSH"])
        layout.addWidget(QLabel("Protocol:"))
        layout.addWidget(self.protocol_combo)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search packets...")
        layout.addWidget(QLabel("Search:"))
        layout.addWidget(self.search_input)
        self.start_time = QDateTimeEdit(QDateTime.currentDateTime().addDays(-1))
        self.end_time = QDateTimeEdit(QDateTime.currentDateTime())
        layout.addWidget(QLabel("Time Filter:"))
        layout.addWidget(self.start_time)
        layout.addWidget(self.end_time)
        self.auto_scroll_check = QCheckBox("Auto Scroll")
        self.auto_scroll_check.setChecked(True)
        layout.addWidget(self.auto_scroll_check)
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.parent().start_monitoring)
        layout.addWidget(self.start_button)
        self.pause_button = QPushButton("Pause Monitoring")
        self.pause_button.clicked.connect(self.parent().toggle_pause)
        layout.addWidget(self.pause_button)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.parent().clear_table)
        layout.addWidget(self.clear_button)
        self.export_csv_button = QPushButton("Export to CSV")
        self.export_csv_button.clicked.connect(self.parent().export_to_csv)
        layout.addWidget(self.export_csv_button)
        self.export_pcap_button = QPushButton("Export to PCAP")
        self.export_pcap_button.clicked.connect(self.parent().export_to_pcap)
        layout.addWidget(self.export_pcap_button)
        self.summary_button = QPushButton("Generate Summary")
        self.summary_button.clicked.connect(self.parent().generate_summary)
        layout.addWidget(self.summary_button)
        self.replay_button = QPushButton("Replay Packets")
        self.replay_button.clicked.connect(self.parent().replay_packets)
        layout.addWidget(self.replay_button)
        self.alert_button = QPushButton("Manage Alert Rules")
        self.alert_button.clicked.connect(self.parent().open_alert_dialog)
        layout.addWidget(self.alert_button)
        self.preset_button = QPushButton("Manage Filter Presets")
        self.preset_button.clicked.connect(self.parent().open_preset_dialog)
        layout.addWidget(self.preset_button)
        self.status_label = QLabel("Status: Idle")
        layout.addWidget(self.status_label)
        self.setLayout(layout)

# --- Visualization Widgets (Unchanged) ---
class FlowGraphWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes = {}
        self.edges = {}
        self.setMinimumSize(400, 300)

    def update_flows(self, flows):
        self.nodes = {}
        self.edges = flows
        logging.debug(f"Updating flow graph with {len(flows)} flows")
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(0, 0, 0), 2)
        painter.setPen(pen)
        width, height = self.width(), self.height()
        if not self.edges:
            painter.drawText(width // 2 - 50, height // 2, "No data")
            return
        node_positions = {}
        for i, (src, dst, _, _, _) in enumerate(self.edges.keys()):
            if src not in node_positions:
                node_positions[src] = (50 + (i % 5) * 100, 50 + (i // 5) * 100)
            if dst not in node_positions:
                node_positions[dst] = (50 + ((i + 1) % 5) * 100, 50 + ((i + 1) // 5) * 100)
        self.nodes = node_positions
        for (src, dst, _, _, _), count in self.edges.items():
            if src not in self.nodes or dst not in self.nodes: continue
            src_pos = self.nodes[src]
            dst_pos = self.nodes[dst]
            pen.setWidth(min(count, 5))
            painter.setPen(pen)
            painter.drawLine(src_pos[0], src_pos[1], dst_pos[0], dst_pos[1])
        for node, pos in self.nodes.items():
            painter.setBrush(QColor(100, 150, 255))
            painter.drawEllipse(pos[0] - 20, pos[1] - 20, 40, 40)
            painter.drawText(pos[0] - 50, pos[1] + 30, node)

class SizeHistogramWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.sizes = []
        self.setMinimumSize(400, 300)

    def update_sizes(self, sizes):
        self.sizes = sizes
        logging.debug(f"Updating size histogram with {len(sizes)} sizes")
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width, height = self.width(), self.height()
        if not self.sizes:
            painter.drawText(width // 2 - 50, height // 2, "No data")
            return
        max_size = max(self.sizes, default=1500)
        bins = [0] * 10
        bin_width_size = max_size / 10
        if bin_width_size == 0: return
        for size in self.sizes:
            bin_index = min(int(size / bin_width_size), 9)
            bins[bin_index] += 1
        max_count = max(bins, default=1)
        bar_width = width // 10
        for i, count in enumerate(bins):
            bar_height = int((count / max_count) * (height - 50))
            painter.setBrush(QColor(100, 150, 255))
            painter.drawRect(i * bar_width, height - bar_height, bar_width - 5, bar_height)
            painter.drawText(i * bar_width, height - bar_height - 20, f"{count}")

class RatePlotWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rates = []
        self.times = []
        self.setMinimumSize(400, 300)

    def update_rates(self, rates, times):
        self.rates = rates
        self.times = times
        logging.debug(f"Updating rate plot with {len(rates)} rates")
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width, height = self.width(), self.height()
        if not self.rates or len(self.rates) < 2:
            painter.drawText(width // 2 - 50, height // 2, "No data")
            return
        max_rate = max(self.rates, default=1)
        min_time = min(self.times, default=time.time())
        max_time = max(self.times, default=time.time())
        time_span = max_time - min_time or 1
        pen = QPen(QColor(100, 150, 255), 2)
        painter.setPen(pen)
        for i in range(1, len(self.rates)):
            x1 = int(((self.times[i-1] - min_time) / time_span) * width)
            y1 = int(height - (self.rates[i-1] / max_rate) * (height - 50))
            x2 = int(((self.times[i] - min_time) / time_span) * width)
            y2 = int(height - (self.rates[i] / max_rate) * (height - 50))
            painter.drawLine(x1, y1, x2, y2)
        painter.drawText(10, 20, f"Max Rate: {max_rate:.1f} packets/s")

class ProtocolChartWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.protocol_counts = {}
        self.setMinimumSize(400, 300)

    def update_protocols(self, protocol_counts):
        self.protocol_counts = protocol_counts
        logging.debug(f"Updating protocol chart with {len(protocol_counts)} protocols")
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width, height = self.width(), self.height()
        if not self.protocol_counts:
            painter.drawText(width // 2 - 50, height // 2, "No data")
            return
        
        protocols = list(self.protocol_counts.keys())
        counts = list(self.protocol_counts.values())
        if not protocols: return

        max_count = max(counts, default=1)
        bar_width = width // len(protocols)
        colors = [
            QColor(76, 175, 80), QColor(33, 150, 243), QColor(255, 152, 0),
            QColor(244, 67, 54), QColor(156, 39, 176), QColor(63, 81, 181),
            QColor(255, 235, 59), QColor(121, 85, 72), QColor(96, 125, 139)
        ]
        for i, (protocol, count) in enumerate(self.protocol_counts.items()):
            bar_height = int((count / max_count) * (height - 50))
            painter.setBrush(colors[i % len(colors)])
            painter.drawRect(i * bar_width, height - bar_height, bar_width - 5, bar_height)
            painter.drawText(i * bar_width + 5, height - bar_height - 20, f"{count}")
            painter.drawText(i * bar_width + 5, height - 10, protocol)
        painter.drawText(10, 20, f"Total Packets: {sum(counts)}")

# --- Main Application Window ---
class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PortSniffer")
        self.setGeometry(100, 100, 1200, 800)
        self.packet_list = []
        self.raw_packets = []
        try:
            self.core = NetworkMonitorCore()
            if not self.core.select_interface(self):
                # Allow app to start even if no interface is selected initially
                logging.warning("No network interface selected on startup.")
        except Exception as e:
            logging.error(f"Error initializing NetworkMonitorCore: {e}")
            self.core = None
        
        self.setup_ui()

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        self.control_panel = ControlPanel(self)
        layout.addWidget(self.control_panel)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        # Packet Tab
        self.packet_tab = QWidget()
        self.tabs.addTab(self.packet_tab, "Packets")
        packet_layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(14)
        self.table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", 
            "TCP Flags", "Header Info", "Payload", "Corr ID", "Length", "TTL", "Seq", "Ack"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.cellDoubleClicked.connect(self.show_packet_details)
        packet_layout.addWidget(self.table)
        self.packet_tab.setLayout(packet_layout)
        # Visualizations Tab
        self.viz_tab = QWidget()
        self.tabs.addTab(self.viz_tab, "Visualizations")
        viz_layout = QHBoxLayout()
        self.flow_graph = FlowGraphWidget(self)
        viz_layout.addWidget(self.flow_graph)
        self.size_histogram = SizeHistogramWidget(self)
        viz_layout.addWidget(self.size_histogram)
        self.rate_plot = RatePlotWidget(self)
        viz_layout.addWidget(self.rate_plot)
        self.viz_tab.setLayout(viz_layout)
        # Protocol Tab
        self.protocol_tab = QWidget()
        self.tabs.addTab(self.protocol_tab, "Protocols")
        protocol_layout = QHBoxLayout() # Use QHBoxLayout for side-by-side view
        self.protocol_chart = ProtocolChartWidget(self)
        protocol_layout.addWidget(self.protocol_chart)
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count", "Percentage"])
        self.protocol_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        protocol_layout.addWidget(self.protocol_table)
        self.protocol_tab.setLayout(protocol_layout)
        main_widget.setLayout(layout)
        # Timer for processing packet queue
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_queue)
        self.timer.start(200) # Process queue every 200ms
        # Connect filter controls
        self.control_panel.search_input.textChanged.connect(self.filter_table)
        self.control_panel.start_time.dateTimeChanged.connect(self.filter_table)
        self.control_panel.end_time.dateTimeChanged.connect(self.filter_table)

    def start_monitoring(self):
        if not self.core or not self.core.iface:
            logging.error("Cannot start: NetworkMonitorCore not initialized or no interface selected.")
            self.control_panel.status_label.setText("Status: No interface")
            # Prompt to select an interface if none is chosen
            if self.core and not self.core.select_interface(self):
                return
        
        self.clear_table() # Clear previous session
        port = self.control_panel.port_input.text()
        ip_filter = self.control_panel.ip_input.text()
        protocol = self.control_panel.protocol_combo.currentText()
        try:
            port_num = int(port) if port else 0
            self.core.start_monitoring(port_num, ip_filter, protocol)
            self.control_panel.status_label.setText("Status: Monitoring")
            self.control_panel.start_button.setText("Stop Monitoring")
            self.control_panel.start_button.clicked.disconnect()
            self.control_panel.start_button.clicked.connect(self.stop_monitoring)
        except ValueError:
            logging.error("Invalid port number")
            self.control_panel.status_label.setText("Status: Invalid port")
        except Exception as e:
            logging.error(f"Error starting monitoring: {e}")
            self.control_panel.status_label.setText("Status: Error")

    def stop_monitoring(self):
        if self.core:
            self.core.stop_monitoring()
            self.control_panel.status_label.setText("Status: Idle")
            self.control_panel.start_button.setText("Start Monitoring")
            self.control_panel.start_button.clicked.disconnect()
            self.control_panel.start_button.clicked.connect(self.start_monitoring)

    def toggle_pause(self):
        if self.core and self.core.is_monitoring:
            self.core.toggle_pause()
            self.control_panel.status_label.setText(f"Status: {'Paused' if self.core.is_paused else 'Monitoring'}")

    def clear_table(self):
        self.table.setRowCount(0)
        self.packet_list = []
        self.raw_packets = []
        if self.core:
            self.core.flows.clear()
            self.core.packet_sizes.clear()
            self.core.packet_rates.clear()
            self.core.rate_times.clear()
            self.core.protocol_counts.clear()
            self.core.packet_count = 0
            self.core.correlation_id = 0
            # Update UI
            self.flow_graph.update_flows({})
            self.size_histogram.update_sizes([])
            self.rate_plot.update_rates([], [])
            self.protocol_chart.update_protocols({})
            self.update_protocol_table({})
            self.control_panel.status_label.setText("Status: Cleared")
            logging.info("Cleared table and reset data structures")

    def export_to_csv(self):
        if self.core and self.packet_list:
            file_path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "", "CSV Files (*.csv)")
            if file_path:
                self.core.export_to_csv(file_path, self.packet_list)

    def export_to_pcap(self):
        if self.core and self.raw_packets:
            file_path, _ = QFileDialog.getSaveFileName(self, "Export to PCAP", "", "PCAP Files (*.pcap)")
            if file_path:
                self.core.export_to_pcap(file_path, self.raw_packets)

    def generate_summary(self):
        if self.core and self.packet_list:
            file_path, _ = QFileDialog.getSaveFileName(self, "Generate Summary", "", "Text Files (*.txt)")
            if file_path:
                self.core.generate_summary(file_path, self.packet_list)

    def replay_packets(self):
        if self.core and self.raw_packets:
            iface, ok = QInputDialog.getText(self, "Replay Packets", "Enter network interface (e.g., eth0):")
            if ok and iface:
                self.core.replay_packets(self.raw_packets, iface)

    def open_alert_dialog(self):
        dialog = AlertRuleDialog(self)
        dialog.exec()

    def open_preset_dialog(self):
        dialog = FilterPresetDialog(self)
        dialog.exec()

    def show_packet_details(self, row, column):
        try:
            if row < len(self.packet_list):
                dialog = PacketDetailsDialog(self.packet_list[row], self.raw_packets[row], self)
                dialog.exec()
        except Exception as e:
            logging.error(f"Error showing packet details: {e}")

    def _apply_alert_rule(self, row_index):
        """Helper function to apply alert rules to a specific row."""
        try:
            packet_data = self.packet_list[row_index]
            raw_packet = self.raw_packets[row_index]
            timestamp, src, dst, protocol, sport, dport, flags, header_info, payload, _, _, _, _, _ = packet_data
            
            # Default background color
            default_color = QColor(Qt.GlobalColor.white)

            for rule in self.core.alert_rules:
                color = rule.get("color", default_color)
                condition_met = False
                try:
                    if rule["type"] == "HTTP" and raw_packet.haslayer('HTTPResponse'):
                        status_code = int(raw_packet['HTTPResponse'].Status_Code.decode('utf-8', errors='ignore'))
                        if eval(f"{status_code} {rule['condition'].split(' ')[1]} {rule['condition'].split(' ')[2]}"):
                            condition_met = True
                    elif rule["type"] == "TCP" and raw_packet.haslayer('TCP'):
                        flags_str = str(flags)
                        if f"'{flags_str}'" in rule['condition']:
                            condition_met = True
                    elif rule["type"] == "Payload" and raw_packet.haslayer('Raw'):
                        if rule["condition"].lower() in payload.lower():
                            condition_met = True
                    elif rule["type"] == "HTTPS" and (sport == "443" or dport == "443") and TLS_AVAILABLE and raw_packet.haslayer(TLS):
                        # Simple example: check for a specific TLS version
                        if "Version" in rule["condition"] and str(raw_packet[TLS].version) in rule["condition"]:
                            condition_met = True
                    # Add similar logic for FTP, SSH etc.
                    
                    if condition_met:
                        for col in range(self.table.columnCount()):
                            self.table.item(row_index, col).setBackground(color)
                        return # Apply first matching rule and exit
                except Exception as e:
                    logging.warning(f"Could not evaluate rule {rule}: {e}")
            
            # If no rule matched, set back to default
            for col in range(self.table.columnCount()):
                self.table.item(row_index, col).setBackground(default_color)

        except Exception as e:
            logging.error(f"Error applying alert rule: {e}")
            
    def filter_table(self):
        """Efficiently hide or show rows based on current filter criteria.
        This function is called ONLY when the user changes a filter control."""
        search_text = self.control_panel.search_input.text().lower()
        start_ts = self.control_panel.start_time.dateTime().toSecsSinceEpoch()
        end_ts = self.control_panel.end_time.dateTime().toSecsSinceEpoch()

        for i in range(len(self.packet_list)):
            packet_data = self.packet_list[i]
            timestamp = packet_data[0]
            
            # Time check
            time_match = start_ts <= timestamp <= end_ts
            
            # Search text check
            text_match = not search_text or any(search_text in str(field).lower() for field in packet_data)
            
            if time_match and text_match:
                self.table.setRowHidden(i, False)
            else:
                self.table.setRowHidden(i, True)
            
            # Re-apply coloring rules
            self._apply_alert_rule(i)

    def _add_packet_to_table(self, packet_data, raw_packet):
        """Adds a single packet to the table and applies alert rules."""
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        
        # Populate cells
        for col, value in enumerate(packet_data):
            # Format timestamp for display
            if col == 0:
                value = datetime.fromtimestamp(value).strftime('%H:%M:%S.%f')[:-3]
            item = QTableWidgetItem(str(value) if value is not None else "N/A")
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_position, col, item)
        
        # Apply alert rules to the new row
        self._apply_alert_rule(row_position)
        
        # *** FIX: New rows are now visible by default. The main filter_table() function
        # will handle hiding them if the user changes the filter controls. ***
        self.table.setRowHidden(row_position, False)


    def process_queue(self):
        try:
            if not self.core or self.core.is_paused:
                return

            new_packets = self.core.process_queue()
            if not new_packets:
                self.core.update_packet_rate() # Still update rate even if no new packets
                return

            for packet_data, raw_packet in new_packets:
                # Update core data models (now safely on the main thread)
                self.core.packet_count += 1
                self.core.correlation_id += 1
                
                # Unpack data for processing
                timestamp, src, dst, protocol, sport, dport, _, _, _, _, length, _, _, _ = packet_data
                
                # Re-create the tuple with the correct correlation ID
                packet_data = (timestamp, src, dst, protocol, sport, dport, packet_data[6], packet_data[7], packet_data[8], self.core.correlation_id, length, packet_data[11], packet_data[12], packet_data[13])

                self.core.protocol_counts[protocol] += 1
                self.core.packet_sizes.append(length)
                self.core.packet_times.append(timestamp)
                flow_key = (src, dst, sport, dport, protocol)
                self.core.flows[flow_key] = self.core.flows.get(flow_key, 0) + 1
                
                # Add to internal lists
                self.packet_list.append(packet_data)
                self.raw_packets.append(raw_packet)

                # Add to UI table
                self._add_packet_to_table(packet_data, raw_packet)

            # Trim old packets if list exceeds max size
            if len(self.packet_list) > self.core.max_packets:
                remove_count = len(self.packet_list) - self.core.max_packets
                self.packet_list = self.packet_list[remove_count:]
                self.raw_packets = self.raw_packets[remove_count:]
                for _ in range(remove_count):
                    self.table.removeRow(0)

            # Scroll to bottom if enabled
            if self.control_panel.auto_scroll_check.isChecked():
                self.table.scrollToBottom()

            # Update visualizations and stats
            self.flow_graph.update_flows(self.core.flows)
            self.size_histogram.update_sizes(self.core.packet_sizes)
            self.core.update_packet_rate()
            self.rate_plot.update_rates(self.core.packet_rates, self.core.rate_times)
            self.protocol_chart.update_protocols(self.core.protocol_counts)
            self.update_protocol_table(self.core.protocol_counts)

        except Exception as e:
            logging.error(f"Error in process_queue: {e}")
            self.control_panel.status_label.setText("Status: Error")

    def update_protocol_table(self, protocol_counts):
        try:
            self.protocol_table.setRowCount(len(protocol_counts))
            total = sum(protocol_counts.values()) or 1
            for i, (protocol, count) in enumerate(protocol_counts.items()):
                percentage = (count / total) * 100
                self.protocol_table.setItem(i, 0, QTableWidgetItem(protocol))
                self.protocol_table.setItem(i, 1, QTableWidgetItem(str(count)))
                self.protocol_table.setItem(i, 2, QTableWidgetItem(f"{percentage:.1f}%"))
        except Exception as e:
            logging.error(f"Error updating protocol table: {e}")