"""
Connection Manager for Pineapple Device
Handles connection status, device discovery, and communication
"""

import asyncio
import threading
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import subprocess
import json
import socket

class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"

@dataclass
class DeviceInfo:
    hostname: str
    ip: str
    mac: str
    device_type: str
    vendor: str
    status: str
    last_seen: float
    ports: List[int] = None

class ConnectionManager:
    """Manages Pineapple device connections and network discovery"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.status = ConnectionStatus.DISCONNECTED
        self.pineapple_ip = None
        self.pineapple_ssh = None
        self.connected_devices: Dict[str, DeviceInfo] = {}
        self.status_callbacks: List[Callable] = []
        self.device_callbacks: List[Callable] = []
        self._discovery_thread = None
        self._monitoring_thread = None
        self._running = False
        
    def add_status_callback(self, callback: Callable):
        """Add callback for connection status changes"""
        self.status_callbacks.append(callback)
        
    def add_device_callback(self, callback: Callable):
        """Add callback for device discovery updates"""
        self.device_callbacks.append(callback)
        
    def _notify_status_change(self, status: ConnectionStatus, message: str = ""):
        """Notify all status callbacks of connection changes"""
        self.status = status
        for callback in self.status_callbacks:
            try:
                callback(status, message)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in status callback: {e}")
                    
    def _notify_device_update(self, devices: Dict[str, DeviceInfo]):
        """Notify all device callbacks of device updates"""
        for callback in self.device_callbacks:
            try:
                callback(devices)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in device callback: {e}")
    
    def connect_to_pineapple(self, ip: str, username: str = "root", password: str = "pineapplesareyummy") -> bool:
        """Connect to Pineapple device"""
        try:
            self._notify_status_change(ConnectionStatus.CONNECTING, f"Conectando a {ip}...")
            
            # Test SSH connection
            from .pineapple import PineappleSSH
            self.pineapple_ssh = PineappleSSH(ip, username, password)
            
            # Test connection with a simple command
            result = self.pineapple_ssh.run_command("echo 'test'")
            if result and "test" in result:
                self.pineapple_ip = ip
                self._notify_status_change(ConnectionStatus.CONNECTED, f"Conectado a Pineapple en {ip}")
                
                # Start monitoring
                self._start_monitoring()
                
                if self.logger:
                    self.logger.info(f"Successfully connected to Pineapple at {ip}")
                return True
            else:
                raise Exception("Failed to execute test command")
                
        except Exception as e:
            error_msg = f"Error conectando a Pineapple: {str(e)}"
            self._notify_status_change(ConnectionStatus.ERROR, error_msg)
            if self.logger:
                self.logger.error(error_msg)
            return False
    
    def disconnect(self):
        """Disconnect from Pineapple device"""
        self._running = False
        
        if self.pineapple_ssh:
            try:
                self.pineapple_ssh.close()
            except:
                pass
            self.pineapple_ssh = None
            
        self.pineapple_ip = None
        self.connected_devices.clear()
        self._notify_status_change(ConnectionStatus.DISCONNECTED, "Desconectado")
        
        if self.logger:
            self.logger.info("Disconnected from Pineapple")
    
    def _start_monitoring(self):
        """Start monitoring threads for device discovery and status"""
        self._running = True
        
        # Start device discovery thread
        self._discovery_thread = threading.Thread(target=self._device_discovery_loop, daemon=True)
        self._discovery_thread.start()
        
        # Start connection monitoring thread
        self._monitoring_thread = threading.Thread(target=self._connection_monitoring_loop, daemon=True)
        self._monitoring_thread.start()
    
    def _device_discovery_loop(self):
        """Continuous device discovery loop"""
        while self._running:
            try:
                self._discover_devices()
                time.sleep(10)  # Scan every 10 seconds
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in device discovery: {e}")
                time.sleep(5)
    
    def _connection_monitoring_loop(self):
        """Monitor Pineapple connection status"""
        while self._running:
            try:
                if self.pineapple_ssh:
                    # Test connection with ping
                    result = self.pineapple_ssh.run_command("echo 'alive'")
                    if not result or "alive" not in result:
                        self._notify_status_change(ConnectionStatus.ERROR, "Conexión perdida")
                        break
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Connection monitoring error: {e}")
                self._notify_status_change(ConnectionStatus.ERROR, "Error de conexión")
                break
    
    def _discover_devices(self):
        """Discover devices on the network"""
        if not self.pineapple_ssh:
            return
            
        try:
            # Get connected clients from Pineapple
            result = self.pineapple_ssh.run_command("cat /proc/net/arp")
            if result:
                devices = self._parse_arp_table(result)
                
                # Update device list
                current_time = time.time()
                for device in devices:
                    device.last_seen = current_time
                    self.connected_devices[device.mac] = device
                
                # Remove old devices (not seen in 5 minutes)
                cutoff_time = current_time - 300
                self.connected_devices = {
                    mac: device for mac, device in self.connected_devices.items()
                    if device.last_seen > cutoff_time
                }
                
                # Notify callbacks
                self._notify_device_update(self.connected_devices)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Device discovery error: {e}")
    
    def _parse_arp_table(self, arp_output: str) -> List[DeviceInfo]:
        """Parse ARP table output to extract device information"""
        devices = []
        lines = arp_output.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[3]
                interface = parts[5]
                
                # Skip invalid entries
                if mac == "00:00:00:00:00:00" or ip == "0.0.0.0":
                    continue
                
                # Try to get hostname
                hostname = self._get_hostname(ip)
                
                # Determine device type based on MAC vendor
                vendor = self._get_vendor_from_mac(mac)
                device_type = self._guess_device_type(vendor, hostname)
                
                device = DeviceInfo(
                    hostname=hostname or ip,
                    ip=ip,
                    mac=mac,
                    device_type=device_type,
                    vendor=vendor,
                    status="connected",
                    last_seen=time.time()
                )
                devices.append(device)
        
        return devices
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Try to resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor information from MAC address (simplified)"""
        # This is a simplified version - in production you'd use a proper OUI database
        mac_prefixes = {
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "00:0C:29": "VMware",
            "00:1B:21": "Intel",
            "00:23:24": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
        }
        
        prefix = mac[:8].upper()
        return mac_prefixes.get(prefix, "Unknown")
    
    def _guess_device_type(self, vendor: str, hostname: str) -> str:
        """Guess device type based on vendor and hostname"""
        hostname_lower = (hostname or "").lower()
        vendor_lower = vendor.lower()
        
        if "raspberry" in vendor_lower or "pi" in hostname_lower:
            return "Single Board Computer"
        elif "apple" in vendor_lower or "iphone" in hostname_lower or "ipad" in hostname_lower:
            return "Mobile Device"
        elif "android" in hostname_lower:
            return "Mobile Device"
        elif "laptop" in hostname_lower or "pc" in hostname_lower:
            return "Computer"
        elif "router" in hostname_lower or "gateway" in hostname_lower:
            return "Network Device"
        else:
            return "Unknown Device"
    
    def get_device_count(self) -> int:
        """Get number of connected devices"""
        return len(self.connected_devices)
    
    def get_devices(self) -> Dict[str, DeviceInfo]:
        """Get all connected devices"""
        return self.connected_devices.copy()
    
    def is_connected(self) -> bool:
        """Check if connected to Pineapple"""
        return self.status == ConnectionStatus.CONNECTED
    
    def get_pineapple_ip(self) -> Optional[str]:
        """Get Pineapple IP address"""
        return self.pineapple_ip