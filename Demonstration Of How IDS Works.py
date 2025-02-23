import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import random
import time
import socket
import ipaddress
from datetime import datetime

class NetworkIDSDemo:
    def __init__(self, master):
        self.master = master
        master.title("Network Intrusion Detection System (IDS) Demonstration")
        master.geometry("800x600")
        
        # Threat Types
        self.threat_types = {
            'Port Scan': {
                'description': 'Attempt to discover open ports on a network',
                'severity': 'High',
                'color': 'red'
            },
            'Malware Connection': {
                'description': 'Potential malware communication',
                'severity': 'Critical',
                'color': 'dark red'
            },
            'Suspicious Login': {
                'description': 'Multiple failed login attempts',
                'severity': 'Medium',
                'color': 'orange'
            },
            'DDoS Attempt': {
                'description': 'Distributed Denial of Service preparation',
                'severity': 'High',
                'color': 'red'
            },
            'Normal Traffic': {
                'description': 'Regular network communication',
                'severity': 'Low',
                'color': 'green'
            }
        }
        
        # Create UI Components
        self.create_ui()
        
        # Simulation Thread
        self.simulation_running = False
        self.simulation_thread = None
    
    def create_ui(self):
        # Network Map Frame
        network_frame = tk.Frame(self.master, relief=tk.RAISED, borderwidth=1)
        network_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Network Title
        tk.Label(network_frame, text="Network Topology Simulation", 
                 font=("Arial", 14, "bold")).pack(pady=5)
        
        # Network Canvas
        self.network_canvas = tk.Canvas(network_frame, 
                                        width=700, height=200, 
                                        bg='light gray')
        self.network_canvas.pack(padx=10, pady=10)
        
        # Draw initial network topology
        self.draw_network_topology()
        
        # Threat Log Frame
        log_frame = tk.Frame(self.master)
        log_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Threat Log Title
        tk.Label(log_frame, text="Threat Detection Log", 
                 font=("Arial", 12, "bold")).pack(pady=5)
        
        # Scrolled Text for Logs
        self.log_text = scrolledtext.ScrolledText(log_frame, 
                                                  height=10, 
                                                  width=90)
        self.log_text.pack(padx=10, pady=10)
        
        # Control Buttons
        button_frame = tk.Frame(self.master)
        button_frame.pack(pady=10)
        
        start_btn = tk.Button(button_frame, text="Start IDS Simulation", 
                               command=self.start_simulation, 
                               bg='green', fg='white')
        start_btn.pack(side=tk.LEFT, padx=10)
        
        stop_btn = tk.Button(button_frame, text="Stop Simulation", 
                             command=self.stop_simulation, 
                             bg='red', fg='white')
        stop_btn.pack(side=tk.LEFT, padx=10)
    
    def draw_network_topology(self):
        # Draw network devices
        devices = [
            {'x': 100, 'y': 100, 'type': 'Server'},
            {'x': 300, 'y': 50, 'type': 'Firewall'},
            {'x': 500, 'y': 100, 'type': 'Router'},
            {'x': 700, 'y': 50, 'type': 'Client'}
        ]
        
        for device in devices:
            self.network_canvas.create_oval(
                device['x']-30, device['y']-30, 
                device['x']+30, device['y']+30, 
                fill='blue', outline='black'
            )
            self.network_canvas.create_text(
                device['x'], device['y']+50, 
                text=device['type']
            )
    
    def simulate_network_threats(self):
        while self.simulation_running:
            # Randomly generate threats
            threat = random.choice(list(self.threat_types.keys()))
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
                f"Description: {threat_info['description']}\n\n"
            )
            
            # Update UI
            self.update_log(log_entry, threat_info['color'])
            
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
            if coords[0] < 700:
                canvas.move(threat_dot, 10, 0)
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
            messagebox.showinfo("IDS Simulation", "Intrusion Detection Simulation Started!")
    
    def stop_simulation(self):
        if self.simulation_running:
            self.simulation_running = False
            if self.simulation_thread:
                self.simulation_thread.join()
            messagebox.showinfo("IDS Simulation", "Intrusion Detection Simulation Stopped!")

def main():
    root = tk.Tk()
    ids_demo = NetworkIDSDemo(root)
    root.mainloop()

if __name__ == "__main__":
    main()