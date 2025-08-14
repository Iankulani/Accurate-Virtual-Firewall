import os
import sys
import time
import socket
import threading
import subprocess
import platform
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd
import requests
from scapy.all import sniff, IP, TCP, UDP
import psutil
from collections import defaultdict

class VirtualFirewall:
    def __init__(self):
        self.monitored_ips = set()
        self.traffic_data = defaultdict(lambda: {'in': 0, 'out': 0, 'total': 0})
        self.running = True
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.alerts = []
        self.log_file = "firewall_log.txt"
        self.config_file = "firewall_config.cfg"
        self.load_config()
        self.initialize_logging()
        
    def initialize_logging(self):
        with open(self.log_file, 'a') as f:
            f.write(f"\n\n=== New Session - {datetime.now()} ===\n")

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                for line in f:
                    if line.startswith("TELEGRAM_TOKEN="):
                        self.telegram_token = line.split('=')[1].strip()
                    elif line.startswith("TELEGRAM_CHAT_ID="):
                        self.telegram_chat_id = line.split('=')[1].strip()
                    elif line.startswith("MONITORED_IPS="):
                        ips = line.split('=')[1].strip().split(',')
                        if ips[0]:  # Check if not empty
                            self.monitored_ips.update(ips)

    def save_config(self):
        with open(self.config_file, 'w') as f:
            f.write(f"TELEGRAM_TOKEN={self.telegram_token or ''}\n")
            f.write(f"TELEGRAM_CHAT_ID={self.telegram_chat_id or ''}\n")
            f.write(f"MONITORED_IPS={','.join(self.monitored_ips)}\n")

    def log_event(self, event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}\n"
        print(log_entry, end='')
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
            
        if self.telegram_token and self.telegram_chat_id:
            self.send_telegram_alert(log_entry)

    def send_telegram_alert(self, message):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload)
            return response.json()
        except Exception as e:
            self.log_event(f"Telegram alert failed: {str(e)}")

    def start_monitoring(self):
        if self.monitoring_active:
            self.log_event("Monitoring is already active")
            return
            
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=self.monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        self.log_event("Started network traffic monitoring")

    def stop_monitoring(self):
        self.monitoring_active = False
        self.log_event("Stopped network traffic monitoring")

    def monitor_traffic(self):
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if src_ip in self.monitored_ips or dst_ip in self.monitored_ips:
                    size = len(packet)
                    
                    if src_ip in self.monitored_ips:
                        self.traffic_data[src_ip]['out'] += size
                        self.traffic_data[src_ip]['total'] += size
                        
                    if dst_ip in self.monitored_ips:
                        self.traffic_data[dst_ip]['in'] += size
                        self.traffic_data[dst_ip]['total'] += size

        while self.monitoring_active:
            sniff(prn=packet_callback, store=0, timeout=5)

    def ping_ip(self, ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.log_event(f"Ping results for {ip}:\n{output}")
            return True
        except subprocess.CalledProcessError as e:
            self.log_event(f"Ping failed for {ip}: {e.output}")
            return False

    def traceroute(self, ip):
        try:
            param = '-d' if platform.system().lower() == 'windows' else ''
            command = ['tracert', param, ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.log_event(f"Traceroute results for {ip}:\n{output}")
            return True
        except subprocess.CalledProcessError as e:
            self.log_event(f"Traceroute failed for {ip}: {e.output}")
            return False

    def add_ip(self, ip):
        if self.validate_ip(ip):
            self.monitored_ips.add(ip)
            self.log_event(f"Added IP to monitoring: {ip}")
            self.save_config()
            return True
        else:
            self.log_event(f"Invalid IP address: {ip}")
            return False

    def remove_ip(self, ip):
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.log_event(f"Removed IP from monitoring: {ip}")
            self.save_config()
            return True
        else:
            self.log_event(f"IP not in monitoring list: {ip}")
            return False

    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def view_traffic(self):
        if not self.traffic_data:
            self.log_event("No traffic data available")
            return

        df = pd.DataFrame.from_dict(self.traffic_data, orient='index')
        self.log_event("Traffic Data:\n" + df.to_string())

        # Generate charts
        self.generate_charts(df)

    def generate_charts(self, df):
        try:
            # Bar chart for total traffic
            df['total'].plot(kind='bar', title='Total Traffic by IP', color='red')
            plt.ylabel('Bytes')
            plt.tight_layout()
            plt.savefig('total_traffic.png')
            plt.close()

            # Pie chart for in/out distribution
            if len(df) == 1:
                ip = df.index[0]
                sizes = [df.loc[ip, 'in'], df.loc[ip, 'out']]
                labels = ['Inbound', 'Outbound']
                plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['lightcoral', 'indianred'])
                plt.title(f'Traffic Distribution for {ip}')
                plt.tight_layout()
                plt.savefig('traffic_distribution.png')
                plt.close()

            self.log_event("Charts generated: total_traffic.png, traffic_distribution.png")
        except Exception as e:
            self.log_event(f"Chart generation failed: {str(e)}")

    def view_status(self):
        status = {
            'Monitoring Active': self.monitoring_active,
            'Monitored IPs': ', '.join(self.monitored_ips) if self.monitored_ips else 'None',
            'Telegram Alerts Configured': bool(self.telegram_token and self.telegram_chat_id),
            'System': platform.system(),
            'Python Version': platform.python_version()
        }
        
        self.log_event("Firewall Status:")
        for key, value in status.items():
            self.log_event(f"{key}: {value}")

    def config_telegram(self, token, chat_id):
        self.telegram_token = token
        self.telegram_chat_id = chat_id
        self.save_config()
        self.log_event("Telegram configuration updated")

    def clear_data(self):
        self.traffic_data.clear()
        self.log_event("Traffic data cleared")

    def show_dashboard(self):
        # This would be a more sophisticated GUI in a real implementation
        self.log_event("\n=== DASHBOARD ===")
        self.log_event("1. File")
        self.log_event("2. Tools")
        self.log_event("3. View")
        self.log_event("4. Help")
        self.log_event("5. About")
        self.log_event("6. Settings")
        self.log_event("=================")

    def run(self):
        self.log_event("Virtual Cyber Firewall initialized - Type 'help' for commands")
        
        while self.running:
            try:
                command = input("firewall> ").strip().lower()
                
                if command == 'help':
                    self.show_help()
                elif command.startswith('ping'):
                    parts = command.split()
                    if len(parts) == 2:
                        self.ping_ip(parts[1])
                    else:
                        self.log_event("Usage: ping <ip_address>")
                elif command == 'start monitoring':
                    self.start_monitoring()
                elif command == 'stop':
                    self.stop_monitoring()
                elif command == 'exit':
                    self.running = False
                elif command == 'clear':
                    self.clear_data()
                elif command == 'view':
                    self.view_traffic()
                elif command == 'status':
                    self.view_status()
                elif command.startswith('traceroute'):
                    parts = command.split()
                    if len(parts) == 2:
                        self.traceroute(parts[1])
                    else:
                        self.log_event("Usage: traceroute <ip_address>")
                elif command.startswith('add ip'):
                    parts = command.split()
                    if len(parts) == 3:
                        self.add_ip(parts[2])
                    else:
                        self.log_event("Usage: add ip <ip_address>")
                elif command.startswith('remove ip'):
                    parts = command.split()
                    if len(parts) == 3:
                        self.remove_ip(parts[2])
                    else:
                        self.log_event("Usage: remove ip <ip_address>")
                elif command.startswith('config telegram token'):
                    parts = command.split(maxsplit=4)
                    if len(parts) == 5:
                        self.config_telegram(parts[4], self.telegram_chat_id)
                    else:
                        self.log_event("Usage: config telegram token <your_token>")
                elif command.startswith('config telegram chat_id'):
                    parts = command.split(maxsplit=4)
                    if len(parts) == 5:
                        self.config_telegram(self.telegram_token, parts[4])
                    else:
                        self.log_event("Usage: config telegram chat_id <your_chat_id>")
                elif command == 'dashboard':
                    self.show_dashboard()
                else:
                    self.log_event(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                self.log_event("Received interrupt signal")
                self.running = False
            except Exception as e:
                self.log_event(f"Error: {str(e)}")

        self.log_event("Virtual Cyber Firewall shutting down")

    def show_help(self):
        help_text = """
        Available Commands:
        help - Show this help message
        ping <ip> - Ping an IP address
        start monitoring - Start monitoring network traffic
        stop - Stop monitoring network traffic
        exit - Exit the firewall
        clear - Clear traffic data
        view - View traffic data and generate charts
        status - Show firewall status
        traceroute <ip> - Perform a traceroute to an IP
        add ip <ip> - Add an IP to monitoring list
        remove ip <ip> - Remove an IP from monitoring list
        config telegram token <token> - Set Telegram bot token
        config telegram chat_id <id> - Set Telegram chat ID
        dashboard - Show dashboard menu
        """
        self.log_event(help_text)

def main():
    # Set matplotlib style to have a red theme
    plt.style.use('ggplot')
    plt.rcParams['axes.prop_cycle'] = plt.cycler(color=['red', 'darkred', 'firebrick', 'indianred', 'lightcoral'])
    
    firewall = VirtualFirewall()
    firewall.run()

if __name__ == "__main__":
    main()