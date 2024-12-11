import scapy.all as scapy
import threading
import queue
import time
import socket
import ipaddress
from colorama import init, Fore, Style
import logging
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama for colored output
init(autoreset=True)

class NetworkIDS:
    def __init__(self):
        # Threat signatures and patterns
        self.threat_signatures = {
            'port_scan': {
                'description': 'Potential Port Scanning',
                'threshold': 50,
                'severity': 'HIGH'
            },
            'syn_flood': {
                'description': 'SYN Flood Attack Detected',
                'threshold': 100,
                'severity': 'CRITICAL'
            },
            'unusual_traffic': {
                'description': 'Unusual Network Traffic Pattern',
                'threshold': 30,
                'severity': 'MEDIUM'
            }
        }
        
        # Traffic tracking
        self.traffic_log = {}
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Logging setup
        logging.basicConfig(
            filename='network_ids.log', 
            level=logging.INFO, 
            format='%(asctime)s - %(message)s'
        )
        
    def packet_handler(self, packet):
        """
        Analyze each captured packet
        """
        try:
            # Put packet in queue for processing
            self.packet_queue.put(packet)
        except Exception as e:
            logging.error(f"Packet processing error: {e}")
    
    def threat_detection_thread(self):
        """
        Continuous threat detection thread
        """
        while not self.stop_event.is_set():
            try:
                # Process packets from queue
                packet = self.packet_queue.get(timeout=1)
                
                # Analyze source and destination IP
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    
                    # Track packet counts for potential threats
                    self.track_traffic(src_ip, dst_ip)
                    
                    # Perform threat detection
                    threats = self.detect_threats(src_ip)
                    
                    # Display threats
                    if threats:
                        for threat, details in threats.items():
                            self.display_threat(threat, details)
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Threat detection error: {e}")
    
    def track_traffic(self, src_ip, dst_ip):
        """
        Track network traffic patterns
        """
        # Initialize traffic log for IPs if not exists
        if src_ip not in self.traffic_log:
            self.traffic_log[src_ip] = {
                'packet_count': 0,
                'dst_ips': set(),
                'timestamp': time.time()
            }
        
        # Update traffic log
        log_entry = self.traffic_log[src_ip]
        log_entry['packet_count'] += 1
        log_entry['dst_ips'].add(dst_ip)
    
    def detect_threats(self, src_ip):
        """
        Detect potential network threats
        """
        threats = {}
        log_entry = self.traffic_log.get(src_ip, {})
        
        # Port Scanning Detection
        if log_entry.get('packet_count', 0) > self.threat_signatures['port_scan']['threshold']:
            threats['port_scan'] = {
                'source_ip': src_ip,
                'packet_count': log_entry['packet_count'],
                'severity': 'HIGH'
            }
        
        # Unusual Traffic Detection
        if len(log_entry.get('dst_ips', set())) > self.threat_signatures['unusual_traffic']['threshold']:
            threats['unusual_traffic'] = {
                'source_ip': src_ip,
                'unique_destinations': len(log_entry['dst_ips']),
                'severity': 'MEDIUM'
            }
        
        return threats
    
    def display_threat(self, threat_type, threat_details):
        """
        Display threat with color-coded severity
        """
        if threat_details['severity'] == 'CRITICAL':
            color = Fore.RED
            symbol = '🔴'
        elif threat_details['severity'] == 'HIGH':
            color = Fore.RED
            symbol = '🔴'
        else:
            color = Fore.YELLOW
            symbol = '🟡'
        
        # Threat message
        threat_msg = (
            f"{color}{symbol} THREAT DETECTED: {threat_type.upper()} "
            f"from {threat_details['source_ip']}"
        )
        
        # Print and log threat
        print(threat_msg)
        logging.warning(f"Threat: {threat_type} - {threat_details}")
    
    def start_ids(self):
        """
        Start Intrusion Detection System
        """
        print(Fore.GREEN + "🟢 Network IDS Started. Monitoring network traffic...")
        
        # Start packet capture thread
        capture_thread = threading.Thread(
            target=scapy.sniff, 
            kwargs={
                'prn': self.packet_handler, 
                'store': 0
            }
        )
        capture_thread.start()
        
        # Start threat detection thread
        detection_thread = threading.Thread(target=self.threat_detection_thread)
        detection_thread.start()
        
        try:
            # Keep main thread running
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n🟡 Stopping Network IDS...")
            self.stop_event.set()
        
        # Wait for threads to finish
        capture_thread.join()
        detection_thread.join()

def main():
    # Require root/admin privileges for packet capture
    try:
        ids = NetworkIDS()
        ids.start_ids()
    except PermissionError:
        print(Fore.RED + "🔴 Error: This script requires root/administrator privileges.")
        print("Run the script with:")
        print("- On Windows: Run Command Prompt as Administrator")
        print("- On Linux/Mac: Use 'sudo python3 script.py'")
    except Exception as e:
        print(Fore.RED + f"🔴 An error occurred: {e}")

if __name__ == "__main__":
    main()