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
        'scapy', 'numpy', 'scikit-learn', 'tensorflow', 'colorama', 'scipy'
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
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from scipy.stats import zscore
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam

class EnhancedNetworkIDS:
    def __init__(self, interface=None, learning_rate=0.001):
        # Advanced Logging Configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('network_ids_enhanced.log', encoding='utf-8', mode='a'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Enhanced Threat Classification Thresholds
        self.threat_levels = {
            'NORMAL': {
                'color': Fore.GREEN,
                'symbol': '🟢',
                'confidence_range': (0.7, 1.0)
            },
            'SUSPICIOUS': {
                'color': Fore.YELLOW,
                'symbol': '🟡',
                'confidence_range': (0.3, 0.7)
            },
            'MALICIOUS': {
                'color': Fore.RED,
                'symbol': '🔴',
                'confidence_range': (0.0, 0.3)
            }
        }
        
        # Network Configuration
        self.interface = interface
        
        # Enhanced Machine Learning Components
        self.anomaly_detector = None
        self.feature_scaler = StandardScaler()
        self.feature_min_max_scaler = MinMaxScaler()
        
        # Dynamic Learning Parameters
        self.learning_rate = learning_rate
        self.dynamic_threshold = 0.5  # Initial dynamic threshold
        
        # Advanced Training Data Management
        self.training_data = []
        self.packet_history = []
        
        # Enhanced Processing Queue
        self.packet_queue = queue.Queue(maxsize=1000)
        self.stop_event = threading.Event()
        
        # Additional Statistics
        self.total_packets = 0
        self.detected_threats = {
            'NORMAL': 0,
            'SUSPICIOUS': 0,
            'MALICIOUS': 0
        }
        
        # Initialize advanced models
        self._initialize_advanced_models()
    
    def _initialize_advanced_models(self):
        """
        Initialize sophisticated machine learning models
        with more comprehensive training data
        """
        np.random.seed(42)
        
        # Generate multi-dimensional synthetic network traffic
        normal_traffic = np.random.normal(loc=0, scale=1, size=(100, 8))
        suspicious_traffic = np.random.normal(loc=2, scale=2, size=(50, 8))
        malicious_traffic = np.random.normal(loc=5, scale=3, size=(30, 8))
        
        combined_data = np.vstack([normal_traffic, suspicious_traffic, malicious_traffic])
        scaled_data = self.feature_scaler.fit_transform(combined_data)
        
        # Enhanced Isolation Forest with more parameters
        self.anomaly_detector = IsolationForest(
            contamination=0.15,  # Slightly adjust expected anomaly rate
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_estimators=200  # More trees for better precision
        )
        self.anomaly_detector.fit(scaled_data)
    
    def _extract_comprehensive_features(self, packet):
        """
        Extract multi-dimensional network features with more context
        """
        features = []
        try:
            # Packet Size Features
            features.extend([
                packet.len if hasattr(packet, 'len') else 0,
                packet.time if hasattr(packet, 'time') else time.time()
            ])
            
            # Protocol Flags
            features.extend([
                int(packet.haslayer(scapy.TCP)),
                int(packet.haslayer(scapy.UDP)),
                int(packet.haslayer(scapy.ICMP))
            ])
            
            # Advanced Entropy and Payload Analysis
            features.append(self._calculate_entropy(packet))
            features.append(self._calculate_payload_diversity(packet))
            
            # Temporal Context
            features.append(self._compute_temporal_features(packet))
            
            return features
        except Exception as e:
            logging.error(f"Advanced feature extraction error: {e}")
            return [0] * 8
    
    def _calculate_entropy(self, packet):
        """Enhanced entropy calculation with more robust method"""
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                probabilities = [payload.count(byte)/len(payload) for byte in set(payload)]
                return -sum(p * np.log2(p) for p in probabilities if p > 0)
            return 0
        except Exception:
            return 0
    
    def _calculate_payload_diversity(self, packet):
        """Calculate payload byte distribution diversity"""
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                unique_bytes = len(set(payload))
                return unique_bytes / len(payload) if payload else 0
            return 0
        except Exception:
            return 0
    
    def _compute_temporal_features(self, packet):
        """Compute temporal context and inter-packet characteristics"""
        current_time = time.time()
        if self.packet_history:
            last_packet_time = self.packet_history[-1]
            time_diff = current_time - last_packet_time
            self.packet_history.append(current_time)
            return time_diff
        self.packet_history.append(current_time)
        return 0
    
    def _adaptive_threat_classification(self, anomaly_scores):
        """
        Adaptive threat classification with dynamic thresholding
        """
        # Compute z-scores for anomaly scores
        z_scores = zscore(anomaly_scores)
        
        # Dynamic threshold adjustment
        self.dynamic_threshold = np.median(anomaly_scores)
        
        classifications = []
        for score, z_score in zip(anomaly_scores, z_scores):
            if z_score <= -1:  # More normal
                classification = 'NORMAL'
            elif -1 < z_score <= 1:  # Transitional/suspicious
                classification = 'SUSPICIOUS'
            else:  # High anomaly
                classification = 'MALICIOUS'
            
            classifications.append(classification)
        
        return classifications
    
    def _display_threat_summary(self):
        """Generate periodic threat detection summary"""
        total_processed = sum(self.detected_threats.values())
        print(Fore.CYAN + "\n--- Threat Detection Summary ---")
        print(f"Total Packets Analyzed: {total_processed}")
        for threat_level, count in self.detected_threats.items():
            percentage = (count / total_processed * 100) if total_processed > 0 else 0
            print(f"{threat_level}: {count} ({percentage:.2f}%)")
        print("-" * 40)
    
    def packet_processing_thread(self):
        """Enhanced packet processing with advanced analysis"""
        while not self.stop_event.is_set():
            try:
                packets = [self.packet_queue.get(timeout=1) for _ in range(self.packet_queue.qsize())]
                
                if not packets:
                    continue
                
                # Extract comprehensive features for all packets
                features = [self._extract_comprehensive_features(packet) for packet in packets]
                scaled_features = self.feature_scaler.transform(features)
                
                # Compute anomaly scores
                anomaly_scores = self.anomaly_detector.score_samples(scaled_features)
                
                # Adaptive classification
                threat_classifications = self._adaptive_threat_classification(anomaly_scores)
                
                # Process and display threats
                for packet, classification, score in zip(packets, threat_classifications, anomaly_scores):
                    if classification != 'NORMAL':
                        self._display_threat(classification, packet, score)
                    
                    # Update threat detection statistics
                    self.detected_threats[classification] += 1
                
                # Periodic summary
                if self.total_packets % 100 == 0:
                    self._display_threat_summary()
                
                self.total_packets += len(packets)
                
            except queue.Empty:
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Advanced packet processing error: {e}")
    
    def _display_threat(self, threat_level, packet, score):
        """Enhanced threat display with more context"""
        threat_info = self.threat_levels[threat_level]
        features = self._extract_comprehensive_features(packet)
        
        threat_msg = (
            f"{threat_info['color']}{threat_info['symbol']} "
            f"{threat_level} THREAT DETECTED\n"
            f"Anomaly Score: {score:.4f}\n"
            f"Packet Info: {features}"
        )
        
        print(threat_msg)
        logging.warning(threat_msg)
    
    def start_ids(self):
        """Start Enhanced Intrusion Detection System"""
        try:
            print(Fore.GREEN + "Enhanced Network IDS Started. Monitoring Network...")
            
            # Packet Capture Thread
            capture_thread = threading.Thread(
                target=scapy.sniff, 
                kwargs={
                    'prn': lambda packet: self.packet_queue.put(packet), 
                    'store': 0,
                    'iface': self.interface
                }
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            # Enhanced Packet Processing Thread
            processing_thread = threading.Thread(target=self.packet_processing_thread)
            processing_thread.daemon = True
            processing_thread.start()
            
            # Keep main thread running
            while not self.stop_event.is_set():
                time.sleep(1)
        
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nStopping Enhanced Network IDS...")
            self._display_threat_summary()
        except Exception as e:
            print(Fore.RED + f"IDS Start Error: {e}")
        finally:
            self.stop_event.set()

def main():
    try:
        # Initialize Enhanced IDS
        ids = EnhancedNetworkIDS()
        ids.start_ids()
    
    except PermissionError:
        print(Fore.RED + "Administrator privileges required. Run as Administrator.")
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}")

if __name__ == "__main__":
    main()