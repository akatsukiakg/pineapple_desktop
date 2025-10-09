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
        """Execute PineAP command via SSH using specific methods"""
        if self.logger:
            self.logger.debug(f"Executing PineAP command: {command}")
            
        if not self.pineapple_ssh:
            if self.logger:
                self.logger.error("SSH connection object is None - cannot execute command")
            return None
            
        if not hasattr(self.pineapple_ssh, 'connected') or not self.pineapple_ssh.connected:
            if self.logger:
                self.logger.error(f"SSH not connected - cannot execute PineAP command (connected={getattr(self.pineapple_ssh, 'connected', 'N/A')})")
            return None
            
        try:
            # Map PineAP manager commands to PineappleSSH methods
            if command.startswith("run_scan"):
                parts = command.split()
                duration = int(parts[1]) if len(parts) > 1 else 0
                frequency = int(parts[2]) if len(parts) > 2 else 2
                result = self.pineapple_ssh.run_scan(duration, frequency)
            elif command == "stop_scan":
                result = self.pineapple_ssh.stop_scan()
            elif command == "pause_scan":
                result = self.pineapple_ssh.pause_scan()
            elif command == "unpause_scan":
                result = self.pineapple_ssh.unpause_scan()
            elif command == "list_probes":
                result = self.pineapple_ssh.list_probes()
            elif command == "get_scan_results":
                result = self.pineapple_ssh.get_scan_results()
            elif command == "get_status":
                result = self.pineapple_ssh.get_status()
            elif command.startswith("logging"):
                parts = command.split()
                enable = parts[1] == "on" if len(parts) > 1 else True
                result = self.pineapple_ssh.logging(enable)
            else:
                # For other commands, use run_command directly
                full_command = f"/usr/bin/pineap /tmp/pineap.conf {command}"
                result = self.pineapple_ssh.run_command(full_command)
            
            if self.logger:
                self.logger.debug(f"Command '{command}' executed successfully")
                if result:
                    self.logger.debug(f"Command result (first 200 chars): {str(result)[:200]}")
                else:
                    self.logger.warning(f"Command '{command}' returned empty result")
                    
            return result
            
        except AttributeError as e:
            if self.logger:
                self.logger.error(f"SSH object missing required method for command '{command}': {e}")
            return None
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error executing PineAP command '{command}': {e}")
            return None

    def start_pineap(self) -> bool:
        """Start PineAP service"""
        if self.logger:
            self.logger.info("Attempting to start PineAP service")
            
        result = self._execute_pineap_command("start")
        if result is not None:
            self.is_running = True
            if self.logger:
                self.logger.info("PineAP service started successfully")
            return True
        else:
            if self.logger:
                self.logger.error("Failed to start PineAP service - command execution failed")
            return False

    def stop_pineap(self) -> bool:
        """Stop PineAP service"""
        if self.logger:
            self.logger.info("Attempting to stop PineAP service")
            
        result = self._execute_pineap_command("stop")
        if result is not None:
            self.is_running = False
            if self.logger:
                self.logger.info("PineAP service stopped successfully")
            return True
        else:
            if self.logger:
                self.logger.error("Failed to stop PineAP service - command execution failed")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get PineAP status"""
        if self.logger:
            self.logger.debug("Getting PineAP status")
            
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
                if self.logger:
                    self.logger.debug(f"Parsed PineAP status: {status_data}")
                return status_data
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error parsing status: {e}")
        else:
            if self.logger:
                self.logger.warning("No result from PineAP status command")
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
            if self.logger:
                self.logger.info(f"Starting WiFi scan with command: {command}")
                self.logger.debug(f"Scan parameters - Duration: {duration}s, Frequency: {frequency.name}")
                
            result = self._execute_pineap_command(command)
            if result:
                self.status = PineAPStatus.SCANNING
                self._notify_callbacks("scan_started", {"duration": duration, "frequency": frequency})
                if self.logger:
                    self.logger.info(f"WiFi scan started successfully")
                    self.logger.debug(f"Scan command result: {result}")
                return True
            else:
                if self.logger:
                    self.logger.error("Failed to start WiFi scan - no result from command")
                return False
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error starting scan: {e}")
            return False

    def stop_scan(self) -> bool:
        """Stop WiFi scan"""
        if self.logger:
            self.logger.info("Stopping WiFi scan")
            
        result = self._execute_pineap_command("stop_scan")
        if result:
            self.status = PineAPStatus.RUNNING
            self._notify_callbacks("scan_stopped")
            if self.logger:
                self.logger.info("WiFi scan stopped successfully")
                self.logger.debug(f"Stop scan result: {result}")
                
            # Get final scan results before stopping
            try:
                final_results = self.get_scan_results()
                if self.logger:
                    self.logger.info(f"Final scan results: {final_results['total_count']} networks found")
                    if final_results['networks']:
                        for network in final_results['networks'][:5]:  # Log first 5 networks
                            self.logger.debug(f"Network found: SSID='{network['ssid']}', BSSID={network['bssid']}, Channel={network['channel']}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error retrieving final scan results: {e}")
                    
            return True
        else:
            if self.logger:
                self.logger.error("Failed to stop WiFi scan - no result from command")
            return False

    def pause_scan(self) -> bool:
        """Pause WiFi scan"""
        if self.logger:
            self.logger.info("Pausing WiFi scan")
            
        result = self._execute_pineap_command("pause_scan")
        if result:
            self._notify_callbacks("scan_paused")
            if self.logger:
                self.logger.info("WiFi scan paused successfully")
                self.logger.debug(f"Pause scan result: {result}")
            return True
        else:
            if self.logger:
                self.logger.error("Failed to pause WiFi scan - no result from command")
            return False

    def unpause_scan(self) -> bool:
        """Unpause WiFi scan"""
        if self.logger:
            self.logger.info("Resuming WiFi scan")
            
        result = self._execute_pineap_command("unpause_scan")
        if result:
            self._notify_callbacks("scan_resumed")
            if self.logger:
                self.logger.info("WiFi scan resumed successfully")
                self.logger.debug(f"Resume scan result: {result}")
            return True
        else:
            if self.logger:
                self.logger.error("Failed to resume WiFi scan - no result from command")
            return False

    def get_probe_requests(self) -> List[ProbeRequest]:
        """Get current probe requests"""
        if self.logger:
            self.logger.debug("Retrieving probe requests from PineAP")
            
        result = self._execute_pineap_command("list_probes")
        probes = []
        
        if result:
            if self.logger:
                self.logger.debug(f"Raw probe data received: {result[:200]}...")  # Log first 200 chars
            try:
                # Parse probe request output
                lines = result.strip().split('\n')
                if self.logger:
                    self.logger.debug(f"Parsing {len(lines)} lines of probe data")
                    
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
                            if self.logger:
                                self.logger.debug(f"Parsed probe: SSID={probe.ssid}, MAC={probe.mac}, Time={probe.timestamp}")
                        else:
                            if self.logger:
                                self.logger.warning(f"Invalid probe line format: {line}")
                                
                if self.logger:
                    self.logger.info(f"Successfully parsed {len(probes)} probe requests")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error parsing probes: {e}")
                    self.logger.error(f"Raw data that failed to parse: {result}")
        else:
            if self.logger:
                self.logger.warning("No probe data received from PineAP")
                    
        return probes

    def get_scan_results(self) -> Dict[str, Any]:
        """Get WiFi scan results"""
        if self.logger:
            self.logger.debug("Retrieving WiFi scan results from PineAP")
            
        result = self._execute_pineap_command("get_scan_results")
        scan_data = {
            "networks": [],
            "total_count": 0,
            "scan_time": time.time(),
            "status": "no_data"
        }
        
        if result:
            if self.logger:
                self.logger.debug(f"Raw scan results received: {result[:500]}...")  # Log first 500 chars
            try:
                # Parse scan results - format may vary depending on PineAP implementation
                lines = result.strip().split('\n')
                networks = []
                
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        # Expected format: SSID BSSID CHANNEL SIGNAL ENCRYPTION
                        parts = line.split()
                        if len(parts) >= 4:
                            network = {
                                "ssid": parts[0] if parts[0] != "(hidden)" else "",
                                "bssid": parts[1],
                                "channel": parts[2],
                                "signal": parts[3],
                                "encryption": parts[4] if len(parts) > 4 else "Unknown",
                                "timestamp": time.time()
                            }
                            networks.append(network)
                            if self.logger:
                                self.logger.debug(f"Parsed network: SSID={network['ssid']}, BSSID={network['bssid']}, Channel={network['channel']}, Signal={network['signal']}")
                        else:
                            if self.logger:
                                self.logger.warning(f"Invalid scan result line format: {line}")
                
                scan_data["networks"] = networks
                scan_data["total_count"] = len(networks)
                scan_data["status"] = "success"
                
                if self.logger:
                    self.logger.info(f"Successfully parsed {len(networks)} WiFi networks from scan results")
                    
                # Notify callbacks with scan results
                self._notify_scan_callbacks(scan_data)
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error parsing scan results: {e}")
                    self.logger.error(f"Raw scan data that failed to parse: {result}")
                scan_data["status"] = "parse_error"
                scan_data["error"] = str(e)
        else:
            if self.logger:
                self.logger.warning("No scan results received from PineAP")
                
        return scan_data

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get detailed monitoring status and statistics"""
        if self.logger:
            self.logger.debug("Retrieving PineAP monitoring status")
            
        status_data = {
            "monitoring_active": self._monitoring,
            "probe_count": len(self.probe_requests),
            "recent_probes": [],
            "ssid_pool_count": len(self.ssid_pool),
            "pineap_status": self.status.value if self.status else "unknown",
            "ssh_connected": False,
            "last_update": time.time()
        }
        
        # Check SSH connection status
        if self.pineapple_ssh:
            status_data["ssh_connected"] = hasattr(self.pineapple_ssh, 'is_connected') and self.pineapple_ssh.is_connected()
            if self.logger:
                self.logger.debug(f"SSH connection status: {status_data['ssh_connected']}")
        
        # Get recent probes (last 10)
        if self.probe_requests:
            recent_probes = self.probe_requests[-10:]
            status_data["recent_probes"] = [
                {
                    "ssid": probe.ssid,
                    "mac": probe.mac,
                    "timestamp": probe.timestamp
                }
                for probe in recent_probes
            ]
            if self.logger:
                self.logger.debug(f"Including {len(recent_probes)} recent probes in status")
        
        # Get current PineAP status from device
        try:
            pineap_status = self.get_status()
            if pineap_status:
                status_data.update(pineap_status)
                if self.logger:
                    self.logger.debug(f"Updated status with PineAP device data: {pineap_status}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error getting PineAP device status: {e}")
        
        if self.logger:
            self.logger.info(f"Monitoring status: Active={status_data['monitoring_active']}, Probes={status_data['probe_count']}, SSH={status_data['ssh_connected']}")
            
        return status_data

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
        """Start monitoring PineAP status"""
        if self.logger:
            self.logger.info("Starting PineAP monitoring")
            
        if not self.pineapple_ssh:
            if self.logger:
                self.logger.error("Cannot start monitoring: SSH connection is None")
            return
            
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        if self.logger:
            self.logger.info("PineAP monitoring thread started")

    def stop_monitoring(self):
        """Stop monitoring PineAP status"""
        if self.logger:
            self.logger.info("Stopping PineAP monitoring")
            
        self._monitoring = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
            if self.logger:
                self.logger.info("PineAP monitoring thread stopped")
        else:
            if self.logger:
                self.logger.debug("PineAP monitoring thread was not running")
        
    def _monitor_loop(self):
        """Monitor PineAP status in background"""
        if self.logger:
            self.logger.debug("PineAP monitor loop started")
            
        while self._monitoring:
            try:
                if not self.pineapple_ssh:
                    if self.logger:
                        self.logger.error("Monitor loop: SSH connection is None")
                    break
                    
                # Check PineAP status
                status = self.get_status()
                if status and self.logger:
                    self.logger.debug(f"PineAP status check: {status}")
                    
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in PineAP monitor loop: {e}")
                time.sleep(15)  # Wait longer on error
                
        if self.logger:
            self.logger.debug("PineAP monitor loop ended")
        
    def _monitor_probes(self):
        """Monitor probe requests in background"""
        if self.logger:
            self.logger.info("Starting probe monitoring thread")
            
        while self._monitoring:
            try:
                if self.logger:
                    self.logger.debug("Checking for new probe requests...")
                    
                probes = self.get_probe_requests()
                new_probes_count = 0
                
                for probe in probes:
                    # Check if this is a new probe
                    if not any(p.mac == probe.mac and p.ssid == probe.ssid and p.timestamp == probe.timestamp 
                             for p in self.probe_requests):
                        self.probe_requests.append(probe)
                        self._notify_probe_callbacks(probe)
                        new_probes_count += 1
                        if self.logger:
                            self.logger.info(f"New probe detected: SSID='{probe.ssid}', MAC={probe.mac}")
                
                if new_probes_count > 0 and self.logger:
                    self.logger.info(f"Added {new_probes_count} new probe requests")
                        
                # Keep only recent probes (last 1000)
                if len(self.probe_requests) > 1000:
                    removed_count = len(self.probe_requests) - 1000
                    self.probe_requests = self.probe_requests[-1000:]
                    if self.logger:
                        self.logger.debug(f"Trimmed {removed_count} old probe requests, keeping last 1000")
                    
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error monitoring probes: {e}")
                time.sleep(5)  # Wait longer on error