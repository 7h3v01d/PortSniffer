import threading
import time
import queue
import csv
import logging
import os
import json
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, wrpcap, sendp, get_if_list, get_if_addr, AsyncSniffer
from utils import analyze_headers, get_payload_summary
from PyQt6.QtWidgets import QFileDialog, QInputDialog
from PyQt6.QtGui import QColor

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

try:
    from scapy.all import load_layer
    load_layer("http")
    from scapy.layers.http import HTTPRequest
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False
    logging.warning("Scapy HTTP module not available. HTTP parsing will be limited.")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class NetworkMonitorCore:
    def __init__(self, max_packets=1000): # Increased default capacity
        self.is_monitoring = False
        self.is_paused = False
        self.packet_queue = queue.Queue(maxsize=max_packets)
        self.max_packets = max_packets
        self.packet_count = 0
        self.start_time = None
        self.packet_times = []
        self.packet_sizes = []
        self.packet_rates = []
        self.rate_times = []
        self.protocol_counts = defaultdict(int) # Use defaultdict for simplicity
        self.flows = {}
        self.ip_packet_counts = defaultdict(list)
        self.ip_suggestions = set()
        self.port_suggestions = set()
        self.ip_history = []
        self.port_history = []
        self.protocol_history = []
        self.max_history = 5
        self.filter_file = "filter_history.json"
        self.preset_file = "filter_presets.json"
        self.filter_presets = {}
        self.correlation_map = {}
        self.correlation_id = 0
        # Default alert rule for HTTP errors
        self.alert_rules = [{"type": "HTTP", "condition": "Status_Code >= 400", "color": QColor(255, 100, 100)}]
        self.load_filter_history()
        self.load_filter_presets()
        self.iface = None
        self.sniffer = None
        logging.info("Initialized NetworkMonitorCore")

    def select_interface(self, parent=None):
        try:
            interfaces = get_if_list()
            if not interfaces:
                logging.error("No network interfaces available")
                return False
            iface_items = []
            for iface in interfaces:
                try:
                    ip = get_if_addr(iface)
                    iface_items.append(f"{iface} (IP: {ip})")
                except:
                    iface_items.append(f"{iface} (No IP)")
            iface, ok = QInputDialog.getItem(parent, "Select Network Interface", "Choose an interface:", iface_items, 0, False)
            if ok and iface:
                self.iface = iface.split(" (")[0]
                logging.info(f"Selected interface: {self.iface}")
                return True
            logging.info("Interface selection cancelled")
            return False
        except Exception as e:
            logging.error(f"Error selecting interface: {e}")
            return False

    def load_filter_history(self):
        try:
            if os.path.exists(self.filter_file):
                with open(self.filter_file, 'r') as f:
                    data = json.load(f)
                    self.ip_history = data.get("ip_history", [])[:self.max_history]
                    self.port_history = data.get("port_history", [])[:self.max_history]
                    self.protocol_history = data.get("protocol_history", [])[:self.max_history]
                logging.info("Loaded filter history")
        except Exception as e:
            logging.error(f"Error loading filter history: {e}")

    def save_filter_history(self, ip_filter, port, protocol):
        try:
            self.ip_history = [ip_filter] + [x for x in self.ip_history if x != ip_filter][:self.max_history-1]
            self.port_history = [port] + [x for x in self.port_history if x != port][:self.max_history-1]
            self.protocol_history = [protocol] + [x for x in self.protocol_history if x != protocol][:self.max_history-1]
            with open(self.filter_file, 'w') as f:
                json.dump({
                    "ip_history": self.ip_history,
                    "port_history": self.port_history,
                    "protocol_history": self.protocol_history
                }, f)
            logging.info("Saved filter history")
        except Exception as e:
            logging.error(f"Error saving filter history: {e}")

    def load_filter_presets(self):
        try:
            if os.path.exists(self.preset_file):
                with open(self.preset_file, 'r') as f:
                    self.filter_presets = json.load(f)
                logging.info("Loaded filter presets")
        except Exception as e:
            logging.error(f"Error loading filter presets: {e}")

    def save_filter_preset(self, name, ip_filter, port, protocol):
        try:
            self.filter_presets[name] = {"ip": ip_filter, "port": port, "protocol": protocol}
            with open(self.preset_file, 'w') as f:
                json.dump(self.filter_presets, f)
            logging.info(f"Saved filter preset: {name}")
        except Exception as e:
            logging.error(f"Error saving filter preset: {e}")

    def packet_callback(self, packet):
        try:
            if not self.is_monitoring or self.is_paused:
                return
            
            # Using epoch float for precise time filtering
            timestamp = packet.time
            src = packet[IP].src if packet.haslayer(IP) else "N/A"
            dst = packet[IP].dst if packet.haslayer(IP) else "N/A"
            protocol = "Other"
            sport = "N/A"
            dport = "N/A"
            flags = "N/A"
            seq = "N/A"
            ack = "N/A"
            length = len(packet)
            ttl = packet[IP].ttl if packet.haslayer(IP) else "N/A"

            if packet.haslayer(TCP):
                sport = str(packet[TCP].sport)
                dport = str(packet[TCP].dport)
                flags = packet[TCP].flags
                seq = packet[TCP].seq
                ack = packet[TCP].ack
                if HTTP_AVAILABLE and packet.haslayer(HTTPRequest):
                    protocol = "HTTP"
                elif TLS_AVAILABLE and packet.haslayer(TLS) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    protocol = "HTTPS"
                elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    protocol = "FTP"
                elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    protocol = "SSH"
                else:
                    protocol = "TCP"
            elif packet.haslayer(UDP):
                sport = str(packet[UDP].sport)
                dport = str(packet[UDP].dport)
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    protocol = "DNS"
                else:
                    protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            header_info = analyze_headers(packet)
            payload = get_payload_summary(packet)
            
            # This ID will be managed by the main thread
            correlation_id = -1 

            packet_data = (timestamp, src, dst, protocol, sport, dport, flags, header_info, payload, correlation_id, length, ttl, seq, ack)

            # Securely pass both formatted data and the raw Scapy packet to the GUI thread
            self.packet_queue.put((packet_data, packet), block=False)
            
        except queue.Full:
            # This is not an error, just means the GUI is busy. Packets are dropped gracefully.
            pass 
        except Exception as e:
            logging.error(f"Error in packet_callback: {e}")

    def process_queue(self):
        """Processes packets from the queue and returns data for GUI updates."""
        packets_to_process = []
        try:
            while not self.packet_queue.empty():
                packets_to_process.append(self.packet_queue.get(block=False))
        except queue.Empty:
            pass
        return packets_to_process

    def update_packet_rate(self):
        try:
            current_time = time.time()
            if self.packet_times:
                # Calculate rate over the last 1 second
                one_second_ago = current_time - 1
                recent_packet_count = sum(1 for t in self.packet_times if t > one_second_ago)
                
                self.packet_rates.append(recent_packet_count)
                self.rate_times.append(current_time)
                
                # Keep the rate history to a manageable size (e.g., last 100 seconds)
                if len(self.packet_rates) > 100:
                    self.packet_rates.pop(0)
                    self.rate_times.pop(0)
                # Prune old packet times to avoid unbounded growth
                self.packet_times = [t for t in self.packet_times if t > one_second_ago]

        except Exception as e:
            logging.error(f"Error updating packet rate: {e}")

    def start_monitoring(self, port=0, ip_filter="", protocol="All"):
        try:
            if not self.iface:
                logging.error("No interface selected")
                return
            if self.is_monitoring:
                self.stop_monitoring()

            self.filter_expr = ""
            if port:
                self.filter_expr += f"port {port}"
            if ip_filter:
                self.filter_expr += (" and " if self.filter_expr else "") + f"host {ip_filter}"
            if protocol == "HTTP":
                self.filter_expr += (" and " if self.filter_expr else "") + "tcp port 80"
            elif protocol in ["TCP", "UDP", "ICMP", "DNS", "HTTPS", "FTP", "SSH"]:
                 if protocol == "HTTPS": self.filter_expr += (" and " if self.filter_expr else "") + "tcp port 443"
                 elif protocol == "FTP": self.filter_expr += (" and " if self.filter_expr else "") + "tcp port 21"
                 elif protocol == "SSH": self.filter_expr += (" and " if self.filter_expr else "") + "tcp port 22"
                 else: self.filter_expr += (" and " if self.filter_expr else "") + protocol.lower()
            
            self.is_monitoring = True # Set flag before starting sniffer
            self.start_time = time.time()

            self.sniffer = AsyncSniffer(
                iface=self.iface,
                filter=self.filter_expr,
                prn=self.packet_callback,
                store=0
            )
            self.sniffer.start()
            logging.info(f"Started monitoring with filter: '{self.filter_expr if self.filter_expr else 'None'}'")
            
        except Exception as e:
            logging.error(f"Error starting monitoring: {e}")
            self.is_monitoring = False

    def stop_monitoring(self):
        self.is_monitoring = False
        self.is_paused = False
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
                self.sniffer.join() # Wait for the thread to terminate
                logging.info("Stopped monitoring")
            except Exception as e:
                logging.error(f"Error stopping sniffer: {e}")
    
    def toggle_pause(self):
        if self.is_monitoring:
            self.is_paused = not self.is_paused

    def export_to_csv(self, file_path, packets_to_export):
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Source IP", "Dest IP", "Protocol", "Src Port", "Dst Port", 
                               "TCP Flags", "Header Info", "Payload", "Corr ID", "Length", "TTL", "Seq", "Ack"])
                for packet in packets_to_export:
                    # Format timestamp from float to readable string for export
                    packet_to_write = list(packet)
                    packet_to_write[0] = time.strftime("%H:%M:%S", time.localtime(packet[0]))
                    writer.writerow(packet_to_write)
            logging.info(f"Exported {len(packets_to_export)} packets to {file_path}")
        except Exception as e:
            logging.error(f"Error exporting to CSV: {e}")

    def export_to_pcap(self, file_path, raw_packets_to_export):
        try:
            wrpcap(file_path, raw_packets_to_export)
            logging.info(f"Exported {len(raw_packets_to_export)} packets to {file_path}")
        except Exception as e:
            logging.error(f"Error exporting to PCAP: {e}")

    def generate_summary(self, file_path, packets_to_export):
        try:
            ip_counts = defaultdict(int)
            port_counts = defaultdict(int)
            for packet in packets_to_export:
                src, dst, sport, dport = packet[1], packet[2], packet[4], packet[5]
                ip_counts[src] += 1
                ip_counts[dst] += 1
                if sport != "N/A":
                    port_counts[sport] += 1
                if dport != "N/A":
                    port_counts[dport] += 1
            
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"Traffic Summary (Generated: {time.strftime('%Y-%m-%d %H:%M:%S')})\n")
                f.write(f"Total Packets Captured: {self.packet_count}\n")
                f.write(f"Capture Duration: {int(time.time() - self.start_time) if self.start_time else 0}s\n")
                f.write("\nTop 5 IPs by Packet Count:\n")
                for ip, count in top_ips:
                    f.write(f"{ip}: {count} packets\n")
                f.write("\nTop 5 Ports by Packet Count:\n")
                for port, count in top_ports:
                    f.write(f"{port}: {count} packets\n")
                f.write("\nProtocol Breakdown:\n")
                total = sum(self.protocol_counts.values()) or 1
                for protocol, count in self.protocol_counts.items():
                    f.write(f"{protocol}: {count} packets ({(count/total)*100:.1f}%)\n")
            logging.info(f"Traffic summary saved to {file_path}")
        except Exception as e:
            logging.error(f"Error in generate_summary: {e}")

    def replay_packets(self, raw_packets, iface):
        try:
            if not iface:
                logging.warning("Replay cancelled, no interface provided.")
                return
            sendp(raw_packets, iface=iface, verbose=False)
            logging.info(f"Replayed {len(raw_packets)} packets on {iface}")
        except Exception as e:
            logging.error(f"Error in replay_packets: {e}")