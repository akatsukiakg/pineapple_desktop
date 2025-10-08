"""PineAP Manager for WiFi Pineapple CLI Integration"""
from __future__ import annotations
import threading
import time
import json
from typing import Optional, List, Dict, Callable, Any
from enum import Enum
from dataclasses import dataclass
from .pineapple import PineappleSSH

class PineAPStatus(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    SCANNING = "scanning"
    ERROR = "error"

class ScanFrequency(Enum):
    FREQ_2GHZ = 0
    FREQ_5GHZ = 1
    FREQ_BOTH = 2

class BeaconInterval(Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    AGGRESSIVE = "AGGRESSIVE"

class FilterType(Enum):
    BLACK = "black"
    WHITE = "white"

@dataclass
class ProbeRequest:
    ssid: str
    mac: str
    timestamp: str
    signal_strength: Optional[int] = None

@dataclass
class PineAPConfig:
    karma_enabled: bool = False
    logging_enabled: bool = False
    capture_ssids: bool = False
    connect_notifications: bool = False
    disconnect_notifications: bool = False
    beacon_responses: bool = False
    broadcast_pool: bool = False
    ssid_filter: FilterType = FilterType.BLACK
    mac_filter: FilterType = FilterType.BLACK
    beacon_interval: BeaconInterval = BeaconInterval.NORMAL
    beacon_response_interval: BeaconInterval = BeaconInterval.NORMAL
    ap_channel: int = 6

class PineAPManager:
    def __init__(self, pineapple_ssh: Optional[PineappleSSH] = None, logger=None):
        self.pineapple_ssh = pineapple_ssh
        self.logger = logger
        self.status = PineAPStatus.STOPPED
        self.config = PineAPConfig()
        self.callbacks: List[Callable] = []
        self.probe_callbacks: List[Callable] = []
        self.scan_callbacks: List[Callable] = []
        
        # Monitoring threads
        self._monitoring = False
        self._probe_thread: Optional[threading.Thread] = None
        self._scan_thread: Optional[threading.Thread] = None
        
        # Data storage
        self.probe_requests: List[ProbeRequest] = []
        self.ssid_pool: List[str] = []
        self.scan_results: Dict[str, Any] = {}
        
    def add_callback(self, callback: Callable):
        """Add status callback"""
        self.callbacks.append(callback)
        
    def add_probe_callback(self, callback: Callable):
        """Add probe request callback"""
        self.probe_callbacks.append(callback)
        
    def add_scan_callback(self, callback: Callable):
        """Add scan results callback"""
        self.scan_callbacks.append(callback)
        
    def _notify_callbacks(self, event_type: str, data: Any = None):
        """Notify all callbacks of status changes"""
        for callback in self.callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in PineAP callback: {e}")
                    
    def _notify_probe_callbacks(self, probe: ProbeRequest):
        """Notify probe callbacks"""
        for callback in self.probe_callbacks:
            try:
                callback(probe)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in probe callback: {e}")
                    
    def _notify_scan_callbacks(self, results: Dict[str, Any]):
        """Notify scan callbacks"""
        for callback in self.scan_callbacks:
            try:
                callback(results)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in scan callback: {e}")

    def _execute_pineap_command(self, command: str) -> Optional[str]:
        """Execute PineAP CLI command"""
        if not self.pineapple_ssh or not self.pineapple_ssh.connected:
            if self.logger:
                self.logger.error("PineAP: SSH not connected")
            return None
            
        try:
            full_command = f"/usr/bin/pineap /tmp/pineap.conf {command}"
            result = self.pineapple_ssh.run_command(full_command)
            return result
        except Exception as e:
            if self.logger:
                self.logger.error(f"PineAP command error: {e}")
            return None

    def start_pineap(self) -> bool:
        """Start PineAP daemon"""
        try:
            self.status = PineAPStatus.STARTING
            self._notify_callbacks("status_change", self.status)
            
            # Start PineAP daemon
            result = self.pineapple_ssh.run_command("/etc/init.d/pineapd start")
            if result and "OK" in result or "already running" in result.lower():
                self.status = PineAPStatus.RUNNING
                self._notify_callbacks("pineap_started")
                if self.logger:
                    self.logger.info("PineAP started successfully")
                return True
            else:
                self.status = PineAPStatus.ERROR
                self._notify_callbacks("pineap_error", "Failed to start PineAP")
                return False
                
        except Exception as e:
            self.status = PineAPStatus.ERROR
            self._notify_callbacks("pineap_error", str(e))
            if self.logger:
                self.logger.error(f"Error starting PineAP: {e}")
            return False

    def stop_pineap(self) -> bool:
        """Stop PineAP daemon"""
        try:
            self._monitoring = False
            result = self.pineapple_ssh.run_command("/etc/init.d/pineapd stop")
            self.status = PineAPStatus.STOPPED
            self._notify_callbacks("pineap_stopped")
            if self.logger:
                self.logger.info("PineAP stopped")
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error stopping PineAP: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get PineAP status"""
        result = self._execute_pineap_command("get_status")
        if result:
            try:
                # Parse status output
                status_data = {
                    "daemon_running": "running" in result.lower(),
                    "scanning": "scanning" in result.lower(),
                    "karma_enabled": self.config.karma_enabled,
                    "logging_enabled": self.config.logging_enabled
                }
                return status_data
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error parsing status: {e}")
        return {}

    def enable_logging(self) -> bool:
        """Enable PineAP logging"""
        result = self._execute_pineap_command("logging on")
        if result:
            self.config.logging_enabled = True
            self._notify_callbacks("logging_enabled")
            return True
        return False

    def disable_logging(self) -> bool:
        """Disable PineAP logging"""
        result = self._execute_pineap_command("logging off")
        if result:
            self.config.logging_enabled = False
            self._notify_callbacks("logging_disabled")
            return True
        return False

    def enable_karma(self) -> bool:
        """Enable Karma attack"""
        result = self._execute_pineap_command("karma on")
        if result:
            self.config.karma_enabled = True
            self._notify_callbacks("karma_enabled")
            return True
        return False

    def disable_karma(self) -> bool:
        """Disable Karma attack"""
        result = self._execute_pineap_command("karma off")
        if result:
            self.config.karma_enabled = False
            self._notify_callbacks("karma_disabled")
            return True
        return False

    def start_scan(self, duration: int = 0, frequency: ScanFrequency = ScanFrequency.FREQ_BOTH) -> bool:
        """Start WiFi scan"""
        try:
            command = f"run_scan {duration} {frequency.value}"
            result = self._execute_pineap_command(command)
            if result:
                self.status = PineAPStatus.SCANNING
                self._notify_callbacks("scan_started", {"duration": duration, "frequency": frequency})
                if self.logger:
                    self.logger.info(f"Started scan: duration={duration}, frequency={frequency.name}")
                return True
            return False
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error starting scan: {e}")
            return False

    def stop_scan(self) -> bool:
        """Stop WiFi scan"""
        result = self._execute_pineap_command("stop_scan")
        if result:
            self.status = PineAPStatus.RUNNING
            self._notify_callbacks("scan_stopped")
            return True
        return False

    def pause_scan(self) -> bool:
        """Pause WiFi scan"""
        result = self._execute_pineap_command("pause_scan")
        if result:
            self._notify_callbacks("scan_paused")
            return True
        return False

    def unpause_scan(self) -> bool:
        """Unpause WiFi scan"""
        result = self._execute_pineap_command("unpause_scan")
        if result:
            self._notify_callbacks("scan_resumed")
            return True
        return False

    def get_probe_requests(self) -> List[ProbeRequest]:
        """Get current probe requests"""
        result = self._execute_pineap_command("list_probes")
        probes = []
        
        if result:
            try:
                # Parse probe request output
                lines = result.strip().split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        # Parse probe format: SSID MAC TIMESTAMP
                        parts = line.split()
                        if len(parts) >= 3:
                            probe = ProbeRequest(
                                ssid=parts[0],
                                mac=parts[1],
                                timestamp=parts[2]
                            )
                            probes.append(probe)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error parsing probes: {e}")
                    
        return probes

    def add_ssid(self, ssid: str) -> bool:
        """Add SSID to pool"""
        result = self._execute_pineap_command(f"add_ssid {ssid}")
        if result:
            if ssid not in self.ssid_pool:
                self.ssid_pool.append(ssid)
            self._notify_callbacks("ssid_added", ssid)
            return True
        return False

    def remove_ssid(self, ssid: str) -> bool:
        """Remove SSID from pool"""
        result = self._execute_pineap_command(f"del_ssid {ssid}")
        if result:
            if ssid in self.ssid_pool:
                self.ssid_pool.remove(ssid)
            self._notify_callbacks("ssid_removed", ssid)
            return True
        return False

    def get_ssid_list(self) -> List[str]:
        """Get current SSID pool"""
        result = self._execute_pineap_command("list_ssids")
        ssids = []
        
        if result:
            try:
                lines = result.strip().split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        ssids.append(line.strip())
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error parsing SSIDs: {e}")
                    
        self.ssid_pool = ssids
        return ssids

    def clear_ssids(self) -> bool:
        """Clear all SSIDs from pool"""
        result = self._execute_pineap_command("clear_ssids")
        if result:
            self.ssid_pool.clear()
            self._notify_callbacks("ssids_cleared")
            return True
        return False

    def deauth_attack(self, target_mac: str, bssid: str, channel: int, multiplier: int = 1) -> bool:
        """Perform deauthentication attack"""
        try:
            command = f"deauth {target_mac} {bssid} {channel} {multiplier}"
            result = self._execute_pineap_command(command)
            if result:
                self._notify_callbacks("deauth_sent", {
                    "target": target_mac,
                    "bssid": bssid,
                    "channel": channel,
                    "multiplier": multiplier
                })
                if self.logger:
                    self.logger.info(f"Deauth attack: {target_mac} -> {bssid} on channel {channel}")
                return True
            return False
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in deauth attack: {e}")
            return False

    def set_ap_channel(self, channel: int) -> bool:
        """Set AP channel"""
        result = self._execute_pineap_command(f"ap_channel {channel}")
        if result:
            self.config.ap_channel = channel
            self._notify_callbacks("channel_changed", channel)
            return True
        return False

    def start_monitoring(self):
        """Start monitoring probe requests and status"""
        if self._monitoring:
            return
            
        self._monitoring = True
        
        # Start probe monitoring thread
        self._probe_thread = threading.Thread(target=self._monitor_probes, daemon=True)
        self._probe_thread.start()
        
    def stop_monitoring(self):
        """Stop monitoring"""
        self._monitoring = False
        
    def _monitor_probes(self):
        """Monitor probe requests in background"""
        while self._monitoring:
            try:
                probes = self.get_probe_requests()
                for probe in probes:
                    # Check if this is a new probe
                    if not any(p.mac == probe.mac and p.ssid == probe.ssid and p.timestamp == probe.timestamp 
                             for p in self.probe_requests):
                        self.probe_requests.append(probe)
                        self._notify_probe_callbacks(probe)
                        
                # Keep only recent probes (last 1000)
                if len(self.probe_requests) > 1000:
                    self.probe_requests = self.probe_requests[-1000:]
                    
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error monitoring probes: {e}")
                time.sleep(5)  # Wait longer on error