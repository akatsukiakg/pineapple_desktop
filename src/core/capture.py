"""
Capture Manager for WiFi Handshake Capture
Integrates with aircrack-ng suite and provides capture capabilities
"""

import subprocess
import threading
import time
import os
import signal
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import psutil

class CaptureStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class CaptureInfo:
    interface: str
    filename: str
    start_time: float
    process: Optional[subprocess.Popen]
    status: CaptureStatus

class CaptureManager:
    """Manages WiFi handshake capture operations"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.active_captures: Dict[str, CaptureInfo] = {}
        self.callbacks: List[Callable] = []
        self._tshark_available = self._check_tshark_availability()
        self._aircrack_available = self._check_aircrack_availability()
        
        if not self._tshark_available and self.logger:
            self.logger.warning("tshark not available, limited capture functionality")
        
        if not self._aircrack_available and self.logger:
            self.logger.warning("aircrack-ng suite not available, using alternative methods")

    def _check_tshark_availability(self) -> bool:
        """Check if tshark is available"""
        try:
            result = subprocess.run(["tshark", "--version"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_aircrack_availability(self) -> bool:
        """Check if aircrack-ng suite is available"""
        try:
            result = subprocess.run(["airodump-ng", "--help"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def add_callback(self, callback: Callable):
        """Add callback for capture updates"""
        self.callbacks.append(callback)
        
    def _notify_callbacks(self, capture_id: str, status: CaptureStatus):
        """Notify all callbacks of capture updates"""
        for callback in self.callbacks:
            try:
                callback(capture_id, status)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in capture callback: {e}")

    def list_interfaces(self) -> List[Dict[str, str]]:
        """List available network interfaces"""
        interfaces = []
        
        if self._tshark_available:
            try:
                result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            # Parse tshark interface format
                            parts = line.split('.', 1)
                            if len(parts) == 2:
                                interface_info = parts[1].strip()
                                name = interface_info.split()[0]
                                description = interface_info
                                interfaces.append({
                                    'name': name,
                                    'description': description
                                })
                else:
                    if self.logger:
                        self.logger.error(f"tshark -D failed: {result.stderr}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to list interfaces: {e}")
        
        # Fallback to system network interfaces
        if not interfaces:
            try:
                # Use psutil to get network interfaces
                net_interfaces = psutil.net_if_addrs()
                for name, addrs in net_interfaces.items():
                    # Get IP address if available
                    ip_addr = "No IP"
                    for addr in addrs:
                        if addr.family == 2:  # AF_INET (IPv4)
                            ip_addr = addr.address
                            break
                    
                    interfaces.append({
                        'name': name,
                        'description': f"{name} ({ip_addr})"
                    })
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to get network interfaces: {e}")
                # Ultimate fallback
                interfaces = [{'name': 'any', 'description': 'Any available interface'}]
        
        return interfaces

    def start_capture(self, interface: str, output_dir: str = "captures") -> str:
        """Start handshake capture on specified interface"""
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = int(time.time())
        filename = f"handshake_{interface}_{timestamp}"
        filepath = os.path.join(output_dir, filename)
        
        capture_id = f"{interface}_{timestamp}"
        
        try:
            if self._aircrack_available:
                # Use airodump-ng for WiFi handshake capture
                process = self._start_airodump_capture(interface, filepath)
            elif self._tshark_available:
                # Use tshark as fallback
                process = self._start_tshark_capture(interface, filepath)
            else:
                # Use basic fallback method
                process = self._start_fallback_capture(interface, filepath)
            
            capture_info = CaptureInfo(
                interface=interface,
                filename=filepath,
                start_time=time.time(),
                process=process,
                status=CaptureStatus.RUNNING
            )
            
            self.active_captures[capture_id] = capture_info
            self._notify_callbacks(capture_id, CaptureStatus.RUNNING)
            
            if self.logger:
                self.logger.info(f"Started capture on {interface}, output: {filepath}")
            
            return capture_id
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to start capture: {e}")
            raise

    def _start_airodump_capture(self, interface: str, filepath: str) -> subprocess.Popen:
        """Start capture using airodump-ng"""
        cmd = [
            "airodump-ng",
            "--write", filepath,
            "--output-format", "pcap",
            interface
        ]
        
        if self.logger:
            self.logger.debug(f"Starting airodump-ng: {' '.join(cmd)}")
        
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _start_tshark_capture(self, interface: str, filepath: str) -> subprocess.Popen:
        """Start capture using tshark"""
        cmd = [
            "tshark",
            "-i", interface,
            "-w", f"{filepath}.pcap",
            "-f", "type mgt subtype auth or type mgt subtype assoc-req or type mgt subtype assoc-resp or type mgt subtype reassoc-req or type mgt subtype reassoc-resp or type mgt subtype disassoc or type mgt subtype deauth"
        ]
        
        if self.logger:
            self.logger.debug(f"Starting tshark: {' '.join(cmd)}")
        
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _start_fallback_capture(self, interface: str, filepath: str) -> subprocess.Popen:
        """Start basic capture using system tools"""
        # Create a dummy process for consistency
        # In a real implementation, this would use raw sockets or other methods
        cmd = ["ping", "127.0.0.1"]  # Placeholder command
        
        if self.logger:
            self.logger.warning(f"Using fallback capture method for {interface}")
        
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stop_capture(self, capture_id: str) -> bool:
        """Stop active capture"""
        if capture_id not in self.active_captures:
            return False
        
        capture_info = self.active_captures[capture_id]
        
        try:
            if capture_info.process and capture_info.process.poll() is None:
                # Terminate the process
                if os.name == 'nt':  # Windows
                    capture_info.process.terminate()
                else:  # Unix-like
                    capture_info.process.send_signal(signal.SIGTERM)
                
                # Wait for process to terminate
                try:
                    capture_info.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture_info.process.kill()
            
            capture_info.status = CaptureStatus.COMPLETED
            self._notify_callbacks(capture_id, CaptureStatus.COMPLETED)
            
            if self.logger:
                self.logger.info(f"Stopped capture {capture_id}")
            
            return True
            
        except Exception as e:
            capture_info.status = CaptureStatus.ERROR
            self._notify_callbacks(capture_id, CaptureStatus.ERROR)
            
            if self.logger:
                self.logger.error(f"Error stopping capture {capture_id}: {e}")
            
            return False

    def get_capture_status(self, capture_id: str) -> Optional[CaptureStatus]:
        """Get status of a capture"""
        if capture_id in self.active_captures:
            capture_info = self.active_captures[capture_id]
            
            # Check if process is still running
            if capture_info.process and capture_info.process.poll() is not None:
                # Process has terminated
                if capture_info.status == CaptureStatus.RUNNING:
                    capture_info.status = CaptureStatus.COMPLETED
                    self._notify_callbacks(capture_id, CaptureStatus.COMPLETED)
            
            return capture_info.status
        
        return None

    def get_active_captures(self) -> Dict[str, CaptureInfo]:
        """Get all active captures"""
        return self.active_captures.copy()

    def get_active_capture_count(self) -> int:
        """Get count of active captures"""
        active_count = 0
        for capture_info in self.active_captures.values():
            if capture_info.status == CaptureStatus.RUNNING:
                # Check if process is still actually running
                if capture_info.process and capture_info.process.poll() is None:
                    active_count += 1
                else:
                    # Update status if process has terminated
                    capture_info.status = CaptureStatus.COMPLETED
        
        return active_count

    def cleanup_completed_captures(self):
        """Remove completed captures from active list"""
        completed_captures = []
        
        for capture_id, capture_info in self.active_captures.items():
            if capture_info.status in [CaptureStatus.COMPLETED, CaptureStatus.ERROR]:
                completed_captures.append(capture_id)
        
        for capture_id in completed_captures:
            del self.active_captures[capture_id]

    def is_tshark_available(self) -> bool:
        """Check if tshark is available"""
        return self._tshark_available

    def is_aircrack_available(self) -> bool:
        """Check if aircrack-ng suite is available"""
        return self._aircrack_available
