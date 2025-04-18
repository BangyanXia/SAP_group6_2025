#!/usr/bin/env python3
"""
Smart Home Network Detection & Management System (SHNDMS)
For deployment on Laptop2 to protect Smart TV from attacks and enable file transfers
"""

import os
import sys
import time
import logging
import argparse
import threading
import subprocess
import ipaddress
import signal
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import json
import socket
# import pyshark
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import Ether, ARP
# import netifaces as ni
import colorama
from colorama import Fore, Style
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import shutil
import requests
from queue import Queue
# from file_encryptor import FileEncryptor
# from gui_encryption_integration import integrate_encryption_with_shndms, integrate_encryption_with_file_transfer
# Initialize colorama for color output
colorama.init()
alert_log = []

# Global configuration
CONFIG = {
    "smart_tv_ip": "192.168.1.69",
    "defender_ip": "192.168.1.132",  # Laptop2
    "attacker_ip": "192.168.1.219",  # Laptop1
    "router_ip": "192.168.1.254",
    "web_interface_port": 8080,
    "monitor_interval": 1,  # seconds
    "log_dir": "logs",
    "file_transfer_dir": "transfers",
    "alert_threshold": {
        "syn_packets": 20,  # per second
        "icmp_packets": 10,  # per second
        "arp_packets": 5,  # per second
        "connections": 15  # concurrent
    },
    "snort_config_path": "/etc/snort/snort.conf",
    "snort_rules_path": "/etc/snort/rules/local.rules",
    "interface": "eth0"
}

# Setup logging
if not os.path.exists(CONFIG["log_dir"]):
    os.makedirs(CONFIG["log_dir"])

if not os.path.exists(CONFIG["file_transfer_dir"]):
    os.makedirs(CONFIG["file_transfer_dir"])

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{CONFIG['log_dir']}/shndms_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SHNDMS")

# Attack detection counters
packet_stats = {
    "syn_packets": 0,
    "icmp_packets": 0,
    "arp_packets": 0,
    "connections": 0,
    "last_reset": time.time()
}

# Attack detection flags
attack_detected = {
    "syn_flood": False,
    "icmp_flood": False,
    "arp_spoofing": False,
    "slowloris": False
}

# Thread control
stop_threads = threading.Event()
alert_queue = Queue()


class PacketProcessor:
    """Process and analyze network packets"""

    @staticmethod
    def process_packet(packet):
        """Process a single packet and update stats"""
        try:
            # Reset counters if interval has passed
            current_time = time.time()
            if current_time - packet_stats["last_reset"] >= CONFIG["monitor_interval"]:
                PacketProcessor.reset_packet_stats()

            # Process packet based on protocol
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Check TCP packets for SYN flood
                if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag
                    if dst_ip == CONFIG["smart_tv_ip"]:
                        packet_stats["syn_packets"] += 1
                        if packet_stats["syn_packets"] > CONFIG["alert_threshold"]["syn_packets"]:
                            if not attack_detected["syn_flood"]:
                                alert_queue.put({
                                    "type": "syn_flood",
                                    "source": src_ip,
                                    "count": packet_stats["syn_packets"]
                                })
                                attack_detected["syn_flood"] = True

                # Check for ICMP flood
                if ICMP in packet:
                    if dst_ip == CONFIG["smart_tv_ip"]:
                        packet_stats["icmp_packets"] += 1
                        if packet_stats["icmp_packets"] > CONFIG["alert_threshold"]["icmp_packets"]:
                            if not attack_detected["icmp_flood"]:
                                alert_queue.put({
                                    "type": "icmp_flood",
                                    "source": src_ip,
                                    "count": packet_stats["icmp_packets"]
                                })
                                attack_detected["icmp_flood"] = True

            # Check for ARP spoofing
            if ARP in packet:
                packet_stats["arp_packets"] += 1
                if packet_stats["arp_packets"] > CONFIG["alert_threshold"]["arp_packets"]:
                    if not attack_detected["arp_spoofing"]:
                        alert_queue.put({
                            "type": "arp_spoofing",
                            "source": packet[ARP].hwsrc,
                            "count": packet_stats["arp_packets"]
                        })
                        attack_detected["arp_spoofing"] = True

            # Detect potential Slowloris attacks by monitoring half-open connections
            if TCP in packet and dst_ip == CONFIG["smart_tv_ip"] and packet[TCP].dport == 80:
                if packet[TCP].flags & 0x02:  # SYN flag
                    packet_stats["connections"] += 1
                    if packet_stats["connections"] > CONFIG["alert_threshold"]["connections"]:
                        if not attack_detected["slowloris"]:
                            alert_queue.put({
                                "type": "slowloris",
                                "source": src_ip,
                                "count": packet_stats["connections"]
                            })
                            attack_detected["slowloris"] = True

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    @staticmethod
    def reset_packet_stats():
        """Reset packet statistics counters"""
        packet_stats["syn_packets"] = 0
        packet_stats["icmp_packets"] = 0
        packet_stats["arp_packets"] = 0
        packet_stats["connections"] = 0
        packet_stats["last_reset"] = time.time()

        # Reset attack detection flags
        for key in attack_detected:
            attack_detected[key] = False


class Defender:
    """Implements defensive countermeasures"""

    @staticmethod
    def block_ip(ip_address, duration=300):
        """Block an IP using iptables for a specified duration (seconds)"""
        try:
            # Check if IP is already blocked
            check_cmd = f"sudo iptables -C OUTPUT -s {ip_address} -j DROP"
            if subprocess.call(check_cmd, shell=True, stderr=subprocess.DEVNULL) != 0:
                # IP is not blocked, add the rule
                block_cmd = f"sudo iptables -I OUTPUT -s {ip_address} -j DROP"
                subprocess.call(block_cmd, shell=True)
                logger.info(f"Blocked IP {ip_address} for {duration} seconds")

                # Schedule unblock after duration
                threading.Timer(duration, Defender.unblock_ip, args=[ip_address]).start()
                return True
            return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False

    @staticmethod
    def unblock_ip(ip_address):
        """Remove IP block from iptables"""
        try:
            unblock_cmd = f"sudo iptables -D OUTPUT -s {ip_address} -j DROP"
            subprocess.call(unblock_cmd, shell=True)
            logger.info(f"Unblocked IP {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False

    @staticmethod
    def enable_syn_cookies():
        """Enable SYN cookies to mitigate SYN flood attacks"""
        try:
            cmd = "sudo sysctl -w net.ipv4.tcp_syncookies=1"
            subprocess.call(cmd, shell=True)
            logger.info("Enabled SYN cookies")
            return True
        except Exception as e:
            logger.error(f"Error enabling SYN cookies: {e}")
            return False

    @staticmethod
    def limit_connections(ip_address, max_conn=10):
        """Limit the number of connections from an IP"""
        try:
            cmd = f"sudo iptables -I INPUT -s {ip_address} -p tcp --syn -m connlimit --connlimit-above {max_conn} -j DROP"
            subprocess.call(cmd, shell=True)
            logger.info(f"Limited connections from {ip_address} to {max_conn}")
            return True
        except Exception as e:
            logger.error(f"Error limiting connections: {e}")
            return False

    @staticmethod
    def detect_arp_spoofing():
        """Check for ARP spoofing attacks"""
        try:
            # Get the current ARP table
            cmd = "arp -n"
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')

            # Parse the output
            lines = output.strip().split('\n')[1:]  # Skip the header
            arp_table = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[2]
                    if mac in arp_table and arp_table[mac] != ip:
                        logger.warning(f"Possible ARP spoofing detected: MAC {mac} associated with multiple IPs")
                        return True
                    arp_table[mac] = ip
            return False
        except Exception as e:
            logger.error(f"Error detecting ARP spoofing: {e}")
            return False


class MonitorThread(threading.Thread):
    """Thread for continuous network monitoring"""

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.name = "MonitorThread"

    def run(self):
        logger.info(f"Starting network monitoring on interface {CONFIG['interface']}")

        try:
            # Start capturing packets
            sniff_filter = f"host {CONFIG['smart_tv_ip']}"
            scapy.sniff(filter=sniff_filter, prn=PacketProcessor.process_packet,
                        store=0, iface=CONFIG['interface'], stop_filter=lambda x: stop_threads.is_set())
        except Exception as e:
            logger.error(f"Error in monitoring thread: {e}")


class AlertThread(threading.Thread):
    """Thread for processing and responding to alerts"""

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.name = "AlertThread"

    def run(self):
        logger.info("Starting alert monitoring thread")

        while not stop_threads.is_set():
            try:
                if not alert_queue.empty():
                    alert = alert_queue.get()
                    self.process_alert(alert)
                    alert_queue.task_done()
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in alert thread: {e}")

    def process_alert(self, alert):
        """Process and respond to an alert"""
        alert_type = alert["type"]
        source = alert["source"]
        count = alert["count"]

        logger.warning(
            f"{Fore.RED}ALERT: {alert_type.upper()} attack detected from {source} ({count} packets){Style.RESET_ALL}")
        alert_log.append({
            "type": alert_type,
            "source": source,
            "time": datetime.now().strftime("%H:%M:%S")
        })
        # Take defensive action based on alert type
        if alert_type == "syn_flood":
            Defender.enable_syn_cookies()
            Defender.block_ip(source)
        elif alert_type == "icmp_flood":
            Defender.block_ip(source)
        elif alert_type == "arp_spoofing":
            # Log the ARP spoofing attempt, but handle differently
            logger.critical(f"ARP spoofing detected! MAC: {source}")
            # Restart monitoring to refresh ARP tables
        elif alert_type == "slowloris":
            Defender.limit_connections(source, 5)

        # Send alert to web interface
        self.send_alert_to_ui(alert)

    def send_alert_to_ui(self, alert):
        """Send alert to web interface if it's running"""
        try:
            url = f"http://localhost:{CONFIG['web_interface_port']}/api/alerts"
            requests.post(url, json=alert, timeout=1)
        except:
            # Web UI might not be running, just continue
            pass


class FileTransferHandler(BaseHTTPRequestHandler):
    """HTTP handler for file transfer functionality"""

    def _set_headers(self, content_type="text/html"):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def _set_error_headers(self, error_code=400):
        self.send_response(error_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/":
            # Serve main dashboard
            self._set_headers()
            with open("dashboard.html", "r") as f:
                self.wfile.write(f.read().encode())

        elif self.path == "/api/status":
            # Return system status
            self._set_headers("application/json")
            status = {
                "smart_tv_ip": CONFIG["smart_tv_ip"],
                "defender_ip": CONFIG["defender_ip"],
                "is_running": True,
                "uptime": int(time.time() - start_time),
                "attacks_detected": sum(1 for k, v in attack_detected.items() if v)
            }
            self.wfile.write(json.dumps(status).encode())

        elif self.path.startswith("/api/files"):
            # List available files
            self._set_headers("application/json")
            files = []
            for filename in os.listdir(CONFIG["file_transfer_dir"]):
                file_path = os.path.join(CONFIG["file_transfer_dir"], filename)
                if os.path.isfile(file_path):
                    files.append({
                        "name": filename,
                        "size": os.path.getsize(file_path),
                        "modified": os.path.getmtime(file_path)
                    })
            self.wfile.write(json.dumps(files).encode())

        else:
            self._set_error_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def do_POST(self):
        """Handle POST requests"""
        if self.path == "/api/transfer":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())

            if "filename" not in data or "target_ip" not in data:
                self._set_error_headers()
                self.wfile.write(json.dumps({"error": "Missing filename or target IP"}).encode())
                return

            filename = data["filename"]
            target_ip = data["target_ip"]
            file_path = os.path.join(CONFIG["file_transfer_dir"], filename)

            if not os.path.exists(file_path):
                self._set_error_headers(404)
                self.wfile.write(json.dumps({"error": "File not found"}).encode())
                return

            # Transfer file to target (Smart TV)
            success = self.transfer_file(file_path, target_ip)

            self._set_headers("application/json")
            if success:
                self.wfile.write(json.dumps({"status": "success"}).encode())
                logger.info(f"File {filename} transferred to {target_ip}")
            else:
                self.wfile.write(json.dumps({"status": "failed"}).encode())

        elif self.path == "/api/alerts":
            # Endpoint for receiving alerts from other components
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            # Just acknowledge receipt
            self._set_headers("application/json")
            self.wfile.write(json.dumps({"status": "received"}).encode())

        else:
            self._set_error_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def transfer_file(self, file_path, target_ip, port=8000):
        """Transfer a file to the target device using a simple HTTP server"""
        try:
            # Use scp for file transfer (requires SSH setup on target device)
            # For demo purposes, we're just simulating the transfer
            logger.info(f"Transferring {file_path} to {target_ip}")

            # In a real implementation, use something like:
            # cmd = f"scp {file_path} user@{target_ip}:/destination/"
            # subprocess.call(cmd, shell=True)

            # Or use an HTTP POST to a receiving endpoint on the target

            time.sleep(1)  # Simulate transfer time
            return True
        except Exception as e:
            logger.error(f"Error transferring file: {e}")
            return False


class WebInterfaceThread(threading.Thread):
    """Thread for web interface server"""

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.name = "WebInterfaceThread"
        self.server = None

    def run(self):
        try:
            port = CONFIG["web_interface_port"]
            server_address = ('', port)

            # Create a basic HTML dashboard if it doesn't exist
            if not os.path.exists("dashboard.html"):
                self.create_dashboard_html()

            self.server = HTTPServer(server_address, FileTransferHandler)
            logger.info(f"Starting web interface on port {port}")
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"Error in web interface thread: {e}")

    def stop(self):
        if self.server:
            self.server.shutdown()

    def create_dashboard_html(self):
        """Create a simple dashboard HTML file"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Smart Home Network Detection & Management System</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                h1 { color: #333; }
                .container { display: flex; flex-wrap: wrap; }
                .panel { background: #f5f5f5; border-radius: 5px; padding: 15px; margin: 10px; flex: 1; min-width: 300px; }
                button { background: #4CAF50; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 3px; }
                button:hover { background: #45a049; }
                table { width: 100%; border-collapse: collapse; }
                th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
                .alert { background-color: #f8d7da; color: #721c24; padding: 10px; margin: 10px 0; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>Smart Home Network Detection & Management System</h1>

            <div class="container">
                <div class="panel">
                    <h2>System Status</h2>
                    <div id="status-panel"></div>
                </div>

                <div class="panel">
                    <h2>File Transfer</h2>
                    <table id="file-table">
                        <tr>
                            <th>Filename</th>
                            <th>Size</th>
                            <th>Action</th>
                        </tr>
                    </table>
                    <p>
                        <button onclick="uploadFile()">Upload New File</button>
                    </p>
                </div>
            </div>

            <div class="panel">
                <h2>Attack Alerts</h2>
                <div id="alerts-panel"></div>
            </div>

            <script>
                // JavaScript for the dashboard functionality
                function updateStatus() {
                    fetch('/api/status')
                        .then(response => response.json())
                        .then(data => {
                            let html = `
                                <p>Smart TV IP: ${data.smart_tv_ip}</p>
                                <p>Defender IP: ${data.defender_ip}</p>
                                <p>Uptime: ${Math.floor(data.uptime / 60)} minutes</p>
                                <p>Attacks Detected: ${data.attacks_detected}</p>
                            `;
                            document.getElementById('status-panel').innerHTML = html;
                        });
                }

                function updateFiles() {
                    fetch('/api/files')
                        .then(response => response.json())
                        .then(files => {
                            let tableHtml = `
                                <tr>
                                    <th>Filename</th>
                                    <th>Size</th>
                                    <th>Action</th>
                                </tr>
                            `;

                            files.forEach(file => {
                                const size = Math.round(file.size / 1024) + ' KB';
                                tableHtml += `
                                    <tr>
                                        <td>${file.name}</td>
                                        <td>${size}</td>
                                        <td>
                                            <button onclick="transferFile('${file.name}')">Transfer to TV</button>
                                        </td>
                                    </tr>
                                `;
                            });

                            document.getElementById('file-table').innerHTML = tableHtml;
                        });
                }

                function transferFile(filename) {
                    fetch('/api/transfer', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            filename: filename,
                            target_ip: '192.168.1.100'  // Smart TV IP
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            alert('File transferred successfully');
                        } else {
                            alert('File transfer failed');
                        }
                    });
                }

                function uploadFile() {
                    alert('File upload functionality would go here');
                    // In a real implementation, this would open a file dialog
                }

                // Initialize
                updateStatus();
                updateFiles();

                // Refresh data periodically
                setInterval(updateStatus, 5000);
                setInterval(updateFiles, 10000);
            </script>
        </body>
        </html>
        """

        with open("dashboard.html", "w") as f:
            f.write(html)


class SnortManager:
    """Manage Snort IDS functionality"""

    @staticmethod
    def create_snort_rules():
        """Create Snort rules for attack detection"""
        rules = [
            # SYN flood detection
            'alert tcp any any -> $HOME_NET any (msg:"SYN flood attack detected"; flow:stateless; flags:S; threshold:type threshold, track by_dst, count 50, seconds 1; classtype:attempted-dos; sid:1000001; rev:1;)',

            # ICMP flood detection
            'alert icmp any any -> $HOME_NET any (msg:"ICMP flood attack detected"; threshold:type threshold, track by_dst, count 20, seconds 1; classtype:attempted-dos; sid:1000002; rev:1;)',

            # ARP spoofing detection
            'alert arp any any -> any any (msg:"ARP spoofing detected"; threshold:type threshold, track by_src, count 5, seconds 10; sid:1000003; rev:1;)',

            # Slowloris detection
            'alert tcp any any -> $HOME_NET 80 (msg:"Possible Slowloris attack"; flow:stateless; flags:S; threshold:type both, track by_src, count 20, seconds 30; classtype:attempted-dos; sid:1000004; rev:1;)'
        ]

        try:
            # Check if Snort is installed
            if subprocess.call("which snort", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                logger.warning("Snort is not installed. Skipping rule creation.")
                return False

            # Create rules file
            with open(CONFIG["snort_rules_path"], "w") as f:
                for rule in rules:
                    f.write(rule + "\n")

            logger.info(f"Created Snort rules at {CONFIG['snort_rules_path']}")
            return True
        except Exception as e:
            logger.error(f"Error creating Snort rules: {e}")
            return False

    @staticmethod
    def start_snort():
        """Start Snort IDS in background"""
        try:
            if subprocess.call("which snort", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                logger.warning("Snort is not installed. Skipping Snort start.")
                return False

            # Start Snort in background
            cmd = f"sudo snort -A console -q -c {CONFIG['snort_config_path']} -i {CONFIG['interface']} &"
            subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            logger.info("Started Snort IDS")
            return True
        except Exception as e:
            logger.error(f"Error starting Snort: {e}")
            return False


class GUIApp:
    """GUI Application for the system"""

    def __init__(self, root):
        self.root = root
        self.root.title("Smart Home Network Detection & Management System")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)

        self.create_gui()
        self.update_status()

    def create_gui(self):
        """Create the GUI elements"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title and status
        ttk.Label(main_frame, text="Smart Home Network Protection System", font=("Arial", 16)).pack(pady=10)

        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="System Status")
        status_frame.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(status_frame, text="Initializing...", padding=10)
        self.status_label.pack(fill=tk.X)

        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # File Transfer Tab
        transfer_frame = ttk.Frame(notebook, padding=10)
        notebook.add(transfer_frame, text="File Transfer")

        ttk.Label(transfer_frame, text="Files Available for Transfer:").pack(anchor=tk.W, pady=5)

        # File list
        file_frame = ttk.Frame(transfer_frame)
        file_frame.pack(fill=tk.BOTH, expand=True)

        self.file_list = ttk.Treeview(file_frame, columns=("size", "modified"), show="headings")
        self.file_list.heading("size", text="Size (KB)")
        self.file_list.heading("modified", text="Last Modified")
        self.file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar for file list
        scrollbar = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.file_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_list.configure(yscrollcommand=scrollbar.set)

        # Buttons for file operations
        btn_frame = ttk.Frame(transfer_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Upload File", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Transfer to TV", command=self.transfer_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh Files", command=self.refresh_files).pack(side=tk.LEFT, padx=5)

        # Network Monitoring Tab
        monitor_frame = ttk.Frame(notebook, padding=10)
        notebook.add(monitor_frame, text="Network Monitoring")

        ttk.Label(monitor_frame, text="Attack Detection:").pack(anchor=tk.W, pady=5)

        # Alert list
        self.alert_list = ttk.Treeview(monitor_frame, columns=("type", "source", "time"), show="headings")
        self.alert_list.heading("type", text="Attack Type")
        self.alert_list.heading("source", text="Source")
        self.alert_list.heading("time", text="Time")
        self.alert_list.pack(fill=tk.BOTH, expand=True, pady=5)

        # Alert scrollbar
        alert_scrollbar = ttk.Scrollbar(monitor_frame, orient=tk.VERTICAL, command=self.alert_list.yview)
        alert_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alert_list.configure(yscrollcommand=alert_scrollbar.set)

        # Control buttons for network monitoring
        net_btn_frame = ttk.Frame(monitor_frame)
        net_btn_frame.pack(fill=tk.X, pady=10)

        self.block_btn = ttk.Button(net_btn_frame, text="Block Selected IP", command=self.block_selected_ip)
        self.block_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(net_btn_frame, text="Clear Alerts", command=self.clear_alerts).pack(side=tk.LEFT, padx=5)

        # Configuration Tab
        config_frame = ttk.Frame(notebook, padding=10)
        notebook.add(config_frame, text="Configuration")

        # IP Configuration
        ttk.Label(config_frame, text="Network Configuration:").pack(anchor=tk.W, pady=5)

        ip_frame = ttk.Frame(config_frame)
        ip_frame.pack(fill=tk.X, pady=5)

        ttk.Label(ip_frame, text="Smart TV IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.tv_ip_var = tk.StringVar(value=CONFIG["smart_tv_ip"])
        ttk.Entry(ip_frame, textvariable=self.tv_ip_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(ip_frame, text="Network Interface:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.interface_var = tk.StringVar(value=CONFIG["interface"])
        interface_combo = ttk.Combobox(ip_frame, textvariable=self.interface_var)
        interface_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        interface_combo['values'] = self.get_network_interfaces()

        # Threshold configuration
        ttk.Label(config_frame, text="Attack Detection Thresholds:").pack(anchor=tk.W, pady=10)

        threshold_frame = ttk.Frame(config_frame)
        threshold_frame.pack(fill=tk.X, pady=5)

        ttk.Label(threshold_frame, text="SYN packets/sec:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.syn_threshold_var = tk.IntVar(value=CONFIG["alert_threshold"]["syn_packets"])
        ttk.Spinbox(threshold_frame, from_=5, to=100, textvariable=self.syn_threshold_var).grid(row=0, column=1,
                                                                                                sticky=tk.W, padx=5,
                                                                                                pady=5)

        ttk.Label(threshold_frame, text="ICMP packets/sec:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.icmp_threshold_var = tk.IntVar(value=CONFIG["alert_threshold"]["icmp_packets"])
        ttk.Spinbox(threshold_frame, from_=5, to=50, textvariable=self.icmp_threshold_var).grid(row=1, column=1,
                                                                                                sticky=tk.W, padx=5,
                                                                                                pady=5)

        ttk.Label(threshold_frame, text="ARP packets/sec:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.arp_threshold_var = tk.IntVar(value=CONFIG["alert_threshold"]["arp_packets"])
        ttk.Spinbox(threshold_frame, from_=2, to=20, textvariable=self.arp_threshold_var).grid(row=2, column=1,
                                                                                               sticky=tk.W, padx=5,
                                                                                               pady=5)

        # Save button
        ttk.Button(config_frame, text="Save Configuration", command=self.save_config).pack(anchor=tk.W, pady=10)

        # Status bar at bottom
        self.status_bar = ttk.Label(self.root, text="System ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self):
        """Update status information"""
        uptime = int(time.time() - start_time)
        minutes, seconds = divmod(uptime, 60)
        hours, minutes = divmod(minutes, 60)

        status_text = f"System running | Uptime: {hours:02d}:{minutes:02d}:{seconds:02d} | "
        status_text += f"Smart TV: {CONFIG['smart_tv_ip']} | Defender: {CONFIG['defender_ip']}"

        self.status_label.config(text=status_text)

        # Add any detected attacks to alert list
        
        if hasattr(self, 'last_alert_index'):
            start_idx = self.last_alert_index
        else:
            start_idx = 0

        for alert in alert_log[start_idx:]:
            self.alert_list.insert("", 0, values=(alert["type"], alert["source"], alert["time"]))

        self.last_alert_index = len(alert_log)

        # Schedule next update
        self.root.after(1000, self.update_status)

    def refresh_files(self):
        """Refresh the file list"""
        # Clear existing items
        for item in self.file_list.get_children():
            self.file_list.delete(item)

        # Add files from the transfer directory
        for filename in os.listdir(CONFIG["file_transfer_dir"]):
            file_path = os.path.join(CONFIG["file_transfer_dir"], filename)
            if os.path.isfile(file_path):
                size_kb = f"{os.path.getsize(file_path) / 1024:.1f}"
                modified = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M")
                self.file_list.insert("", "end", values=(size_kb, modified), text=filename)

    def upload_file(self):
        """Upload a file to the transfer directory"""
        filetypes = [("All files", "*.*")]
        filename = filedialog.askopenfilename(title="Select file to upload", filetypes=filetypes)

        if filename:
            dest = os.path.join(CONFIG["file_transfer_dir"], os.path.basename(filename))
            try:
                shutil.copy2(filename, dest)
                messagebox.showinfo("Upload Successful", f"File uploaded: {os.path.basename(filename)}")
                self.refresh_files()
            except Exception as e:
                messagebox.showerror("Upload Failed", f"Error: {e}")

    def transfer_file(self):
        """Transfer selected file to Smart TV"""
        selected = self.file_list.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a file to transfer")
            return

        filename = self.file_list.item(selected[0], "text")
        file_path = os.path.join(CONFIG["file_transfer_dir"], filename)

        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"File {filename} not found")
            return

        # Transfer file to Smart TV
        try:
            # In a real implementation, use a proper file transfer method
            # For demo, we'll just show a message
            self.status_bar.config(text=f"Transferring {filename} to {CONFIG['smart_tv_ip']}...")
            time.sleep(1)  # Simulate transfer time

            messagebox.showinfo("Transfer Complete", f"File {filename} transferred to Smart TV")
            self.status_bar.config(text="File transfer complete")
        except Exception as e:
            messagebox.showerror("Transfer Failed", f"Error: {e}")

    def block_selected_ip(self):
        """Block the IP of the selected alert"""
        selected = self.alert_list.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an alert to block the source IP")
            return

        source_ip = self.alert_list.item(selected[0], "values")[1]
        if source_ip == "Unknown":
            messagebox.showwarning("Unknown Source", "Source IP is unknown")
            return

        # Block the IP
        if Defender.block_ip(source_ip):
            messagebox.showinfo("IP Blocked", f"IP {source_ip} has been blocked")
            self.status_bar.config(text=f"Blocked IP: {source_ip}")
        else:
            messagebox.showerror("Block Failed", f"Failed to block IP {source_ip}")

    def clear_alerts(self):
        """Clear all alerts from the list"""
        for item in self.alert_list.get_children():
            self.alert_list.delete(item)

    def save_config(self):
        """Save configuration changes"""
        # Update CONFIG dictionary
        CONFIG["smart_tv_ip"] = self.tv_ip_var.get()
        CONFIG["interface"] = self.interface_var.get()
        CONFIG["alert_threshold"]["syn_packets"] = self.syn_threshold_var.get()
        CONFIG["alert_threshold"]["icmp_packets"] = self.icmp_threshold_var.get()
        CONFIG["alert_threshold"]["arp_packets"] = self.arp_threshold_var.get()

        # In a real app, save to config file
        messagebox.showinfo("Configuration Saved", "Configuration has been updated")
        self.status_bar.config(text="Configuration saved")

    def get_network_interfaces(self):
        """Get list of network interfaces"""
        try:
            # interfaces = ni.interfaces()
            return ["wlan0", "eth0"]

        except:
            return ["wlan0", "eth0"]  # Fallback


def main():
    """Main application entry point"""
    global start_time
    start_time = time.time()

    parser = argparse.ArgumentParser(description="Smart Home Network Detection & Management System")
    parser.add_argument("--nogui", action="store_true", help="Run without GUI")
    parser.add_argument("--config", help="Path to configuration file")
    args = parser.parse_args()

    # Load configuration if provided
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
                # Update global CONFIG
                for key, value in config_data.items():
                    if key in CONFIG:
                        CONFIG[key] = value
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")

    # Create required directories
    os.makedirs(CONFIG["log_dir"], exist_ok=True)
    os.makedirs(CONFIG["file_transfer_dir"], exist_ok=True)

    try:
        # Create Snort rules
        SnortManager.create_snort_rules()

        # Start Snort if available
        SnortManager.start_snort()

        # Start monitoring thread
        monitor_thread = MonitorThread()
        monitor_thread.start()
        logger.info("Started network monitoring thread")

        # Start alert processing thread
        alert_thread = AlertThread()
        alert_thread.start()
        logger.info("Started alert processing thread")

        # Start web interface
        web_thread = WebInterfaceThread()
        web_thread.start()
        logger.info(f"Started web interface on port {CONFIG['web_interface_port']}")

        # Enable defenses
        Defender.enable_syn_cookies()

        if args.nogui:
            # Run in console mode
            logger.info("Running in console mode. Press Ctrl+C to exit.")
            signal.signal(signal.SIGINT, signal_handler)

            # Keep main thread alive
            while True:
                time.sleep(1)
        else:
            # Start GUI
            root = tk.Tk()
            app = GUIApp(root)
            root.protocol("WM_DELETE_WINDOW", lambda: signal_handler(None, None))
            root.mainloop()

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Exiting...")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
    finally:
        # Clean up
        stop_threads.set()
        logger.info("Stopping threads...")
        time.sleep(1)
        logger.info("Exiting Smart Home Network Detection & Management System")


def signal_handler(sig, frame):
    """Handle signals to allow clean shutdown"""
    logger.info("Shutdown signal received")
    stop_threads.set()
    time.sleep(1)
    sys.exit(0)


if __name__ == "__main__":
    main()