import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import random
import time
import socket
import ipaddress
from datetime import datetime
import colorsys

class AdvancedNetworkIDSDemo:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Network Intrusion Detection System")
        master.geometry("1200x800")
        master.configure(bg='#2C3E50')  # Dark background

        # Modern threat types with more details
        self.threat_types = {
            'Port Scan': {
                'description': 'Systematic scanning of network ports to identify vulnerabilities',
                'severity': 'High',
                'color': '#E74C3C',  # Vibrant red
                'mitigation': 'Block source IP, update firewall rules'
            },
            'Malware Connection': {
                'description': 'Detected potential command and control communication',
                'severity': 'Critical',
                'color': '#C0392B',  # Dark red
                'mitigation': 'Isolate network, run comprehensive malware scan'
            },
            'Suspicious Login': {
                'description': 'Multiple failed authentication attempts detected',
                'severity': 'High',
                'color': '#F39C12',  # Orange
                'mitigation': 'Temporary account lock, multi-factor authentication'
            },
            'DDoS Attempt': {
                'description': 'Distributed Denial of Service traffic pattern identified',
                'severity': 'Critical',
                'color': '#D35400',  # Burnt orange
                'mitigation': 'Activate traffic filtering, contact ISP'
            },
            'Anomalous Data Transfer': {
                'description': 'Unusual data volume or pattern detected',
                'severity': 'Medium',
                'color': '#3498DB',  # Blue
                'mitigation': 'Analyze transfer, check data exfiltration'
            },
            'Normal Traffic': {
                'description': 'Standard network communication',
                'severity': 'Low',
                'color': '#2ECC71',  # Green
                'mitigation': 'No action required'
            }
        }
        
        self.create_advanced_ui()
        
        # Simulation Thread
        self.simulation_running = False
        self.simulation_thread = None
    
    def create_advanced_ui(self):
        # Main Container with Grid Layout
        main_container = tk.Frame(self.master, bg='#2C3E50')
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Top Section - Network Topology
        network_frame = tk.Frame(main_container, bg='#34495E', relief=tk.RAISED, borderwidth=2)
        network_frame.pack(fill=tk.X, pady=(0, 10))

        topology_label = tk.Label(network_frame, text="Network Topology & Real-time Threat Visualization", 
                                  font=("Segoe UI", 16, "bold"), bg='#34495E', fg='white')
        topology_label.pack(pady=10)

        # Enhanced Network Canvas
        self.network_canvas = tk.Canvas(network_frame, 
                                        width=1150, height=250, 
                                        bg='#2C3E50', 
                                        highlightthickness=0)
        self.network_canvas.pack(padx=10, pady=10)
        
        # Draw advanced network topology
        self.draw_network_topology()

        # Middle Section - Threat Log and Statistics
        mid_frame = tk.Frame(main_container, bg='#2C3E50')
        mid_frame.pack(fill=tk.BOTH, expand=True)

        # Left Side - Detailed Threat Log
        log_frame = tk.Frame(mid_frame, bg='#34495E', relief=tk.RAISED, borderwidth=2)
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        log_title = tk.Label(log_frame, text="Threat Detection Log", 
                             font=("Segoe UI", 14, "bold"), 
                             bg='#34495E', fg='white')
        log_title.pack(pady=10)

        self.log_text = scrolledtext.ScrolledText(log_frame, 
                                                  height=20, 
                                                  width=70,
                                                  font=("Consolas", 10),
                                                  bg='#2C3E50', 
                                                  fg='white',
                                                  insertbackground='white')
        self.log_text.pack(padx=10, pady=10)

        # Right Side - Threat Statistics
        stats_frame = tk.Frame(mid_frame, bg='#34495E', relief=tk.RAISED, borderwidth=2)
        stats_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        stats_title = tk.Label(stats_frame, text="Threat Statistics", 
                               font=("Segoe UI", 14, "bold"), 
                               bg='#34495E', fg='white')
        stats_title.pack(pady=10)

        # Threat Type Statistics
        self.stats_text = tk.Text(stats_frame, 
                                  height=20, 
                                  width=40,
                                  font=("Consolas", 10),
                                  bg='#2C3E50', 
                                  fg='white',
                                  insertbackground='white')
        self.stats_text.pack(padx=10, pady=10)
        self.stats_text.config(state=tk.DISABLED)

        # Bottom Section - Control Buttons
        control_frame = tk.Frame(main_container, bg='#34495E', relief=tk.RAISED, borderwidth=2)
        control_frame.pack(fill=tk.X, pady=(10, 0))

        # Stylish Buttons
        style = ttk.Style()
        style.configure('Green.TButton', foreground='white', background='#2ECC71')
        style.configure('Red.TButton', foreground='white', background='#E74C3C')

        start_btn = ttk.Button(control_frame, text="Start IDS Simulation", 
                               command=self.start_simulation, 
                               style='Green.TButton')
        start_btn.pack(side=tk.LEFT, padx=20, pady=10)
        
        stop_btn = ttk.Button(control_frame, text="Stop Simulation", 
                              command=self.stop_simulation, 
                              style='Red.TButton')
        stop_btn.pack(side=tk.RIGHT, padx=20, pady=10)

        # Initialize threat counters
        self.threat_counts = {threat: 0 for threat in self.threat_types.keys()}

    def draw_network_topology(self):
        # More sophisticated network topology
        devices = [
            {'x': 200, 'y': 125, 'type': 'Secure Server', 'icon': '🖥️'},
            {'x': 400, 'y': 75, 'type': 'Firewall', 'icon': '🛡️'},
            {'x': 600, 'y': 125, 'type': 'Router', 'icon': '📡'},
            {'x': 800, 'y': 75, 'type': 'Client Network', 'icon': '💻'}
        ]
        
        for device in devices:
            # Create gradient circle
            self.create_gradient_circle(device['x'], device['y'], device['icon'])
            
            # Add device label
            self.network_canvas.create_text(
                device['x'], device['y']+50, 
                text=device['type'],
                fill='white',
                font=("Segoe UI", 10, "bold")
            )

    def create_gradient_circle(self, x, y, icon):
        # Create a gradient-filled circle
        for i in range(30, 0, -1):
            r = i
            # Create gradient from darker to lighter blue
            color = self.interpolate_color('#2C3E50', '#34495E', i/30)
            self.network_canvas.create_oval(
                x-r, y-r, x+r, y+r, 
                fill=color, 
                outline=''
            )
        
        # Add icon text
        self.network_canvas.create_text(
            x, y, 
            text=icon, 
            font=("Arial", 20),
            fill='white'
        )

    def interpolate_color(self, color1, color2, t):
        # Convert hex to RGB
        def hex_to_rgb(hex_color):
            return tuple(int(hex_color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
        
        # Interpolate between two colors
        rgb1 = hex_to_rgb(color1)
        rgb2 = hex_to_rgb(color2)
        
        interpolated = [
            int(rgb1[i] + (rgb2[i] - rgb1[i]) * t) 
            for i in range(3)
        ]
        
        return f'#{interpolated[0]:02x}{interpolated[1]:02x}{interpolated[2]:02x}'

    def simulate_network_threats(self):
        while self.simulation_running:
            # Randomly generate threats with weighted probability
            threat_weights = {
                'Port Scan': 0.15,
                'Malware Connection': 0.1,
                'Suspicious Login': 0.2,
                'DDoS Attempt': 0.05,
                'Anomalous Data Transfer': 0.25,
                'Normal Traffic': 0.25
            }
            
            threat = random.choices(list(threat_weights.keys()), 
                                    weights=list(threat_weights.values()))[0]
            
            threat_info = self.threat_types[threat]
            
            # Generate random IP
            src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            dst_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            # Log threat
            log_entry = (
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"🚨 {threat} Detected\n"
                f"Source IP: {src_ip}\n"
                f"Destination IP: {dst_ip}\n"
                f"Severity: {threat_info['severity']}\n"
                f"Description: {threat_info['description']}\n"
                f"Mitigation: {threat_info['mitigation']}\n\n"
            )
            
            # Update UI
            self.update_log(log_entry, threat_info['color'])
            
            # Update threat counts
            self.threat_counts[threat] += 1
            
            # Update statistics
            self.update_statistics()
            
            # Visualize threat on network
            self.visualize_threat()
            
            # Wait before next threat
            time.sleep(random.uniform(1, 3))
    
    def update_log(self, log_entry, color):
        # Thread-safe log update
        self.master.after(0, self._update_log, log_entry, color)
    
    def _update_log(self, log_entry, color):
        # Insert log with color
        self.log_text.tag_config(color, foreground=color)
        self.log_text.insert(tk.END, log_entry, color)
        self.log_text.see(tk.END)
    
    def update_statistics(self):
        # Thread-safe statistics update
        self.master.after(0, self._update_statistics)
    
    def _update_statistics(self):
        # Enable text widget for editing
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete('1.0', tk.END)
        
        # Create statistics display
        stats_content = "🔍 Threat Detection Summary\n\n"
        total_threats = sum(self.threat_counts.values())
        
        for threat, count in sorted(self.threat_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_threats * 100) if total_threats > 0 else 0
            color = self.threat_types[threat]['color']
            
            stats_line = f"{threat}: {count} ({percentage:.2f}%)\n"
            
            # Add color tags
            self.stats_text.tag_config(threat, foreground=color)
            self.stats_text.insert(tk.END, stats_line, threat)
        
        # Disable editing
        self.stats_text.config(state=tk.DISABLED)
    
    def visualize_threat(self):
        # Simulate threat on network topology
        canvas = self.network_canvas
        
        # Create a moving threat visualization
        threat_dot = canvas.create_oval(
            50, 50, 70, 70, 
            fill='red', outline='red'
        )
        
        def animate_threat():
            # Threat movement simulation
            coords = canvas.coords(threat_dot)
            if coords[0] < 1000:
                canvas.move(threat_dot, 15, random.choice([-5, 0, 5]))
                self.master.after(100, animate_threat)
            else:
                canvas.delete(threat_dot)
        
        animate_threat()
    
    def start_simulation(self):
        if not self.simulation_running:
            self.simulation_running = True
            self.simulation_thread = threading.Thread(
                target=self.simulate_network_threats
            )
            self.simulation_thread.start()
            messagebox.showinfo("IDS Simulation", "Advanced Intrusion Detection Simulation Started!")
    
    def stop_simulation(self):
        if self.simulation_running:
            self.simulation_running = False
            if self.simulation_thread:
                self.simulation_thread.join()
            messagebox.showinfo("IDS Simulation", "Intrusion Detection Simulation Stopped!")

def main():
    root = tk.Tk()
    ids_demo = AdvancedNetworkIDSDemo(root)
    root.mainloop()

if __name__ == "__main__":
    main()