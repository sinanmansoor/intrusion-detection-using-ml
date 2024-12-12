import scapy.all as scapy
import threading
import queue
import time
import numpy as np
import logging
import sys
import subprocess
import platform
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Suppress TensorFlow logging
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Dependency Management
def check_and_install_dependencies():
    required_packages = [
        'scapy', 'numpy', 'scikit-learn', 'tensorflow', 'colorama'
    ]
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

# Perform dependency check
check_and_install_dependencies()

# Machine Learning and Deep Learning Imports
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense

class ColoredNetworkIDS:
    def __init__(self, interface=None):
        # Logging Configuration with Color
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('network_ids.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Threat Classification Thresholds
        self.threat_levels = {
            'NORMAL': {
                'color': Fore.GREEN,
                'symbol': '🟢',
                'threshold': 0.7  # Confidence of normal behavior
            },
            'SUSPICIOUS': {
                'color': Fore.YELLOW,
                'symbol': '🟡',
                'threshold': 0.4  # Moderate anomaly confidence
            },
            'MALWARE': {
                'color': Fore.RED,
                'symbol': '🔴',
                'threshold': 0.1  # High anomaly confidence
            }
        }
        
        # Network Interface
        self.interface = interface
        
        # Machine Learning Components
        self.anomaly_detector = None
        self.feature_scaler = StandardScaler()
        
        # Training data for initial model fitting
        self.training_data = []
        
        # Packet Processing Queue
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self):
        """
        Initialize machine learning models with placeholder training
        """
        # Generate synthetic training data with varied characteristics
        np.random.seed(42)
        
        # Simulate different network behavior patterns
        normal_traffic = np.random.normal(loc=0, scale=1, size=(50, 5))
        suspicious_traffic = np.random.normal(loc=2, scale=2, size=(30, 5))
        malware_traffic = np.random.normal(loc=5, scale=3, size=(20, 5))
        
        # Combine and scale data
        combined_data = np.vstack([normal_traffic, suspicious_traffic, malware_traffic])
        scaled_data = self.feature_scaler.fit_transform(combined_data)
        
        # Fit Isolation Forest
        self.anomaly_detector = IsolationForest(
            contamination=0.2,  # Expect 20% anomalous traffic 
            random_state=42
        )
        self.anomaly_detector.fit(scaled_data)
    
    def classify_threat_level(self, anomaly_score):
        """
        Classify threat level based on anomaly score
        """
        # Normalize anomaly score to 0-1 range
        normalized_score = (anomaly_score + 1) / 2
        
        if normalized_score >= self.threat_levels['NORMAL']['threshold']:
            return 'NORMAL'
        elif normalized_score >= self.threat_levels['SUSPICIOUS']['threshold']:
            return 'SUSPICIOUS'
        else:
            return 'MALWARE'
    
    def display_threat(self, threat_level, features):
        """
        Display threat with color-coded output
        """
        threat_info = self.threat_levels[threat_level]
        
        # Construct threat message
        threat_msg = (
            f"{threat_info['color']}{threat_info['symbol']} "
            f"{threat_level} THREAT DETECTED\n"
            f"Features: {features}"
        )
        
        # Print colored threat message
        print(threat_msg)
        
        # Log the threat
        logging.info(f"{threat_level} Threat Detected: {features}")
    
    def packet_handler(self, packet):
        """
        Process captured packets
        """
        try:
            if packet.haslayer(scapy.IP):
                self.packet_queue.put(packet)
        except Exception as e:
            logging.error(f"Packet handling error: {e}")
    
    def extract_network_features(self, packet):
        """
        Extract comprehensive network behavior features
        """
        try:
            features = [
                packet.len if hasattr(packet, 'len') else 0,
                packet.time if hasattr(packet, 'time') else time.time(),
                int(packet.haslayer(scapy.TCP)),
                int(packet.haslayer(scapy.UDP)),
                self._calculate_entropy(packet)
            ]
            return features
        except Exception as e:
            logging.error(f"Feature extraction error: {e}")
            return [0, 0, 0, 0, 0]
    
    def _calculate_entropy(self, packet):
        """
        Calculate payload entropy
        """
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                probabilities = [payload.count(byte)/len(payload) for byte in set(payload)]
                return -sum(p * np.log2(p) for p in probabilities if p > 0)
            return 0
        except Exception:
            return 0
    
    def threat_detection_thread(self):
        """
        Continuous threat detection with color-coded classification
        """
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=1)
                features = self.extract_network_features(packet)
                
                # Anomaly Detection
                scaled_features = self.feature_scaler.transform([features])
                anomaly_score = self.anomaly_detector.score_samples(scaled_features)[0]
                
                # Classify Threat Level
                threat_level = self.classify_threat_level(anomaly_score)
                
                # Display Threat if not Normal
                if threat_level != 'NORMAL':
                    self.display_threat(threat_level, features)
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Threat detection error: {e}")
    
    def start_ids(self):
        """
        Start Intrusion Detection System with colored output
        """
        try:
            print(Fore.GREEN + "Network IDS Started. Monitoring network traffic...")
            
            # Packet Capture Thread
            capture_thread = threading.Thread(
                target=scapy.sniff, 
                kwargs={
                    'prn': self.packet_handler, 
                    'store': 0,
                    'iface': self.interface
                }
            )
            capture_thread.start()
            
            # Threat Detection Thread
            detection_thread = threading.Thread(target=self.threat_detection_thread)
            detection_thread.start()
            
            # Keep main thread running
            while not self.stop_event.is_set():
                time.sleep(1)
        
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nStopping Network IDS...")
            self.stop_event.set()
        except Exception as e:
            print(Fore.RED + f"IDS Start Error: {e}")
        finally:
            self.stop_event.set()

def main():
    try:
        # Initialize IDS
        ids = ColoredNetworkIDS()
        ids.start_ids()
    
    except PermissionError:
        print(Fore.RED + "Administrator privileges required. Run as Administrator.")
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}")

if __name__ == "__main__":
    main()