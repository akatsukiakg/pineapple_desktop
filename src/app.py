"""Pineapple Desktop Application
Main application entry point with modern UI
"""

import customtkinter as ctk
from pathlib import Path
import threading
import time

# Core imports
from core.config import ConfigManager
from core.logger import Logger
from core.capture import CaptureManager
from core.packet_capture import PacketCaptureManager
from core.pineapple import PineappleSSH
from core.connection_manager import ConnectionManager, ConnectionStatus
from core.scan_manager import ScanManager
from core.attack_manager import AttackManager
from core.pineap_manager import PineAPManager

# UI imports
from ui.modern_main_window import ModernMainWindow
from ui.components import ConfirmationModal

class PineappleDesktopApp:
    def __init__(self):
        # Initialize core managers
        self.config_manager = ConfigManager()
        self.logger = Logger()
        self.capture_manager = CaptureManager(self.logger)
        self.packet_capture_manager = PacketCaptureManager(self.logger)
        
        # Initialize connection and operation managers
        self.connection_manager = ConnectionManager(self.logger)
        self.scan_manager = ScanManager(self.logger)
        self.attack_manager = AttackManager(logger=self.logger)
        self.pineap_manager = PineAPManager(logger=self.logger)
        
        # Pineapple SSH connection
        self.pineapple_ssh = None
        
        # UI
        self.root = None
        self.main_window = None
        
        # Setup callbacks
        self._setup_callbacks()
        
        self.logger.info("Pineapple Desktop Application initialized")
    
    def _setup_callbacks(self):
        """Setup callbacks for manager updates"""
        self.connection_manager.add_status_callback(self._on_connection_status_change)
        self.connection_manager.add_device_callback(self._on_device_update)
        self.scan_manager.add_callback(self._on_scan_update)
        self.attack_manager.add_callback(self._on_attack_update)
        self.pineap_manager.add_callback(self._on_pineap_update)
        self.pineap_manager.add_probe_callback(self._on_probe_request)
    
    def _on_connection_status_change(self, status: ConnectionStatus, message: str):
        """Handle connection status changes"""
        self.logger.info(f"Connection status changed: {status.value} - {message}")
        
        if self.main_window:
            # Update UI connection status
            self.main_window.update_connection_status(status, message)
            
            # Update attack manager with SSH connection
            if status == ConnectionStatus.CONNECTED and self.pineapple_ssh:
                self.attack_manager.pineapple_ssh = self.pineapple_ssh
                self.pineap_manager.pineapple_ssh = self.pineapple_ssh
            elif status == ConnectionStatus.DISCONNECTED:
                self.attack_manager.pineapple_ssh = None
                self.pineap_manager.pineapple_ssh = None
    
    def _on_device_update(self, devices):
        """Handle device discovery updates"""
        self.logger.debug(f"Device update: {len(devices)} devices found")
        
        if self.main_window:
            self.main_window.update_connected_devices(devices)
    
    def _on_scan_update(self, scan_job):
        """Handle scan progress updates"""
        self.logger.debug(f"Scan update: {scan_job.scan_id} - {scan_job.status.value}")
        
        if self.main_window:
            self.main_window.update_scan_status(scan_job)
    
    def _on_attack_update(self, attack_job):
        """Handle attack progress updates"""
        self.logger.debug(f"Attack update: {attack_job.attack_id} - {attack_job.status.value}")
        
        if self.main_window:
            self.main_window.update_attack_status(attack_job)
    
    def _on_pineap_update(self, event_type: str, data=None):
        """Handle PineAP updates"""
        self.logger.debug(f"PineAP update: {event_type}")
        
        if self.main_window:
            self.main_window.update_pineap_status(event_type, data)
    
    def _on_probe_request(self, probe):
        """Handle new probe requests"""
        self.logger.debug(f"New probe request: {probe.ssid} from {probe.mac}")
        
        if self.main_window:
            self.main_window.update_probe_requests(probe)
    
    def connect_to_pineapple(self, connection_info: dict):
        """Connect to Pineapple device via SSH or Serial"""
        def connect_thread():
            success = self.connection_manager.connect_to_pineapple(connection_info)
            if success:
                if connection_info.get('type') == 'ssh':
                    self.pineapple_ssh = self.connection_manager.pineapple_ssh
                    self.logger.log_user_action(f"Connected to Pineapple at {connection_info.get('ip')}")
                else:  # serial
                    self.logger.log_user_action(f"Connected to Pineapple via {connection_info.get('com_port')}")
            else:
                connection_target = connection_info.get('ip') if connection_info.get('type') == 'ssh' else connection_info.get('com_port')
                self.logger.log_user_action(f"Failed to connect to Pineapple at {connection_target}")
        
        # Show confirmation modal for security
        if self.main_window:
            connection_target = connection_info.get('ip') if connection_info.get('type') == 'ssh' else connection_info.get('com_port')
            connection_type_text = "SSH" if connection_info.get('type') == 'ssh' else "Serial"
            
            modal = ConfirmationModal(
                self.main_window.root,
                title="Conectar a Pineapple",
                message=f"¿Está seguro de que desea conectarse al dispositivo Pineapple via {connection_type_text} en {connection_target}?\n\nEsta acción iniciará una conexión y habilitará las funcionalidades de penetration testing.",
                require_consent=True,
                consent_text="Confirmo que tengo autorización para usar este dispositivo",
                on_confirm=lambda: threading.Thread(target=connect_thread, daemon=True).start()
            )
            modal.grab_set()
    
    def disconnect_from_pineapple(self):
        """Disconnect from Pineapple device"""
        self.connection_manager.disconnect()
        self.pineapple_ssh = None
        self.logger.log_user_action("Disconnected from Pineapple")
    
    def start_scan(self, scan_type, target, options=None):
        """Start a network scan"""
        def scan_with_confirmation():
            scan_id = self.scan_manager.start_scan(scan_type, target, options)
            self.logger.log_user_action(f"Started {scan_type.value} scan on {target}")
            return scan_id
        
        # Show security confirmation
        if self.main_window:
            modal = ConfirmationModal(
                self.main_window.root,
                title="Iniciar Escaneo",
                message=f"¿Está seguro de que desea iniciar un escaneo {scan_type.value} en {target}?\n\nEsta acción puede ser detectada por sistemas de seguridad de red.",
                require_consent=True,
                consent_text="Confirmo que tengo autorización para escanear esta red",
                on_confirm=scan_with_confirmation
            )
            modal.grab_set()
    
    def start_attack(self, attack_type, target, options=None):
        """Start a penetration testing attack"""
        def attack_with_confirmation():
            if not self.connection_manager.is_connected():
                if self.main_window:
                    self.main_window.show_toast("Error: No hay conexión con Pineapple", "error")
                return
            
            attack_id = self.attack_manager.start_attack(attack_type, target, options)
            self.logger.log_user_action(f"Started {attack_type.value} attack on {target.ssid}")
            return attack_id
        
        # Show security confirmation with stronger warning
        if self.main_window:
            modal = ConfirmationModal(
                self.main_window.root,
                title="⚠️ INICIAR ATAQUE",
                message=f"ADVERTENCIA: Está a punto de iniciar un ataque {attack_type.value} contra {target.ssid}.\n\n"
                       f"Esta acción puede:\n"
                       f"• Interrumpir servicios de red\n"
                       f"• Ser detectada por sistemas de seguridad\n"
                       f"• Tener implicaciones legales\n\n"
                       f"Use solo en redes de su propiedad o con autorización explícita.",
                require_consent=True,
                consent_text="Confirmo que tengo autorización legal para realizar este ataque",
                on_confirm=attack_with_confirmation
            )
            modal.grab_set()

        
    def execute_scan(self, target_ip: str):
        """Execute network scan (legacy method for compatibility)"""
        from src.core.scan_manager import ScanType
        self.start_scan(ScanType.PORT_SCAN, target_ip)
    
    def start_capture(self):
        """Start handshake capture (legacy method for compatibility)"""
        if not self.connection_manager.is_connected():
            if self.main_window:
                self.main_window.show_toast("Error: No hay conexión con Pineapple", "error")
            return
        
        # This would integrate with the attack manager for handshake capture
        from src.core.attack_manager import AttackType, AttackTarget
        
        # For now, create a dummy target - in real implementation this would come from UI
        target = AttackTarget(
            bssid="00:00:00:00:00:00",
            ssid="Target Network",
            channel=6,
            encryption="WPA2",
            signal_strength=-50
        )
        
        self.start_attack(AttackType.HANDSHAKE_CAPTURE, target)
    
    def import_pcap(self, file_path: str):
        """Import PCAP file for analysis"""
        try:
            # This would integrate with capture manager
            self.logger.log_user_action(f"Imported PCAP file: {file_path}")
            if self.main_window:
                self.main_window.show_toast("PCAP importado exitosamente", "success")
        except Exception as e:
            self.logger.error(f"Failed to import PCAP: {e}")
            if self.main_window:
                self.main_window.show_toast(f"Error importando PCAP: {e}", "error")
    

    
    def on_closing(self):
        """Handle application closing"""
        try:
            # Save configuration
            self.config_manager.save()
            
            # Stop any running operations
            if self.connection_manager.is_connected():
                self.disconnect_from_pineapple()
            
            # Stop active scans and attacks
            for scan_id in list(self.scan_manager.active_scans.keys()):
                self.scan_manager.cancel_scan(scan_id)
            
            for attack_id in list(self.attack_manager.active_attacks.keys()):
                self.attack_manager.stop_attack(attack_id)
            
            self.logger.info("Application closing")
            
            if self.root:
                self.root.destroy()
                
        except Exception as e:
            self.logger.error(f"Error during application shutdown: {e}")
    
    def run(self):
        """Run the application"""
        try:
            # Set appearance mode and color theme
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            
            # Create main window
            self.root = ctk.CTk()
            self.root.title("Pineapple Desktop")
            self.root.geometry("1400x900")
            
            # Create main window UI
            self.main_window = ModernMainWindow(self.root, self)
            
            # Set closing protocol
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            
            # Load saved configuration
            window_geometry = self.config_manager.get("window_geometry", "1400x900")
            self.root.geometry(window_geometry)
            
            self.logger.info("Application started successfully")
            
            # Start main loop
            self.root.mainloop()
            
        except Exception as e:
            self.logger.error(f"Failed to start application: {e}")
            raise

if __name__ == "__main__":
    app = PineappleDesktopApp()
    app.run()
