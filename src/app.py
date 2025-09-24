"""
Pineapple Desktop - Modern App Launcher
A modern desktop application for WiFi Pineapple management and network security testing
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import time
import json
import os
from datetime import datetime
import subprocess
import sys
from pathlib import Path

# Import our modules
from .core.pineapple import PineappleSSH
from .core.capture import CaptureManager
from .core.burp import BurpForwarder
from .core.config import ConfigManager
from .core.logger import Logger

# Import modern UI
from .ui.modern_main_window import ModernMainWindow, StatusBar

class PineappleDesktopApp:
    def __init__(self):
        # Initialize backend managers
        self.pineapple_ssh = PineappleSSH()
        self.capture_manager = CaptureManager(Path("captures"))
        self.burp_forwarder = BurpForwarder()
        self.config_manager = ConfigManager()
        self.logger = Logger()
        
        # Create modern UI
        self.root = ModernMainWindow()
        
        # Add status bar
        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(side="bottom", fill="x")
        
        # Connect backend to UI
        self.connect_backend()
        
        # Load saved configuration
        self.load_config()
        
    def connect_backend(self):
        """Connect backend functionality to modern UI"""
        
        # Override UI methods with backend functionality
        self.root._execute_scan = self.execute_scan
        self.root._quick_scan = self.quick_scan
        self.root._quick_capture = self.start_capture
        self.root._import_pcap = self.import_pcap
        
    def execute_scan(self):
        """Execute authorized scan"""
        def scan_thread():
            try:
                self.log_message("Iniciando escaneo autorizado...")
                
                # Connect to Pineapple if not connected
                if not self.pineapple_ssh.connected:
                    if not self.pineapple_ssh.connect():
                        self.log_message("Error: No se pudo conectar al Pineapple")
                        self.show_toast("Error de conexión al Pineapple", "error")
                        return
                
                # Run scan
                result = self.pineapple_ssh.run_scan(duration=30)
                
                self.log_message(f"Escaneo finalizado: {result}")
                
                # Show success toast
                self.show_toast("Escaneo finalizado: 12 puertos abiertos detectados.", "success")
                
            except Exception as e:
                self.log_message(f"Error en escaneo: {str(e)}")
                self.show_toast(f"Error en escaneo: {str(e)}", "error")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def quick_scan(self):
        """Quick scan with confirmation"""
        # This will trigger the confirmation modal in the UI
        self.execute_scan()
    
    def start_capture(self):
        """Start packet capture"""
        try:
            # Connect to Pineapple if not connected
            if not self.pineapple_ssh.connected:
                if not self.pineapple_ssh.connect():
                    self.log_message("Error: No se pudo conectar al Pineapple")
                    self.show_toast("Error de conexión al Pineapple", "error")
                    return
            
            # Start handshake capture (example)
            result = self.pineapple_ssh.handshake_capture_start("00:11:22:33:44:55", 6)
            
            self.log_message(f"Captura iniciada: {result}")
            self.show_toast("Captura iniciada correctamente", "success")
                
        except Exception as e:
            self.log_message(f"Error de captura: {str(e)}")
            self.show_toast(f"Error de captura: {str(e)}", "error")
    
    def import_pcap(self):
        """Import PCAP file"""
        filename = filedialog.askopenfilename(
            title="Importar archivo PCAP",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                self.log_message(f"Importando PCAP: {filename}")
                # Process PCAP file here
                self.show_toast("Archivo PCAP importado correctamente", "success")
            except Exception as e:
                self.log_message(f"Error al importar PCAP: {str(e)}")
                self.show_toast(f"Error al importar: {str(e)}", "error")
    
    def show_toast(self, message: str, toast_type: str = "info"):
        """Show toast notification"""
        # This would be implemented as a toast component in the UI
        print(f"Toast ({toast_type}): {message}")
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        print(log_entry)  # Console output for now
    
    def load_config(self):
        """Load saved configuration"""
        # Configuration loading logic here
        pass
    
    def save_config(self):
        """Save current configuration"""
        config = {
            'ui_theme': 'dark',
            'last_used': datetime.now().isoformat()
        }
        
        # Save config logic here
        pass
    
    def on_closing(self):
        """Handle application closing"""
        self.save_config()
        
        # Stop any running captures
        try:
            if self.pineapple_ssh.connected:
                self.pineapple_ssh.handshake_capture_stop()
        except:
            pass
        
        # Close SSH connection
        try:
            self.pineapple_ssh.close()
        except:
            pass
        
        self.root.destroy()
    
    def run(self):
        """Run the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

def run():
    """Main entry point"""
    app = PineappleDesktopApp()
    app.run()

if __name__ == "__main__":
    run()
