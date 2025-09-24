"""
Scan Manager for Network Discovery and Port Scanning
Integrates with Nmap and provides scanning capabilities
"""

import subprocess
import threading
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
import time
import ipaddress

class ScanType(Enum):
    PING_SWEEP = "ping_sweep"
    PORT_SCAN = "port_scan"
    SERVICE_SCAN = "service_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    STEALTH_SCAN = "stealth_scan"

class ScanStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class ScanResult:
    ip: str
    hostname: str
    status: str
    ports: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    os_info: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    scan_time: float

@dataclass
class ScanJob:
    scan_id: str
    scan_type: ScanType
    target: str
    options: Dict[str, Any]
    status: ScanStatus
    progress: float
    start_time: float
    end_time: Optional[float]
    results: List[ScanResult]
    error_message: Optional[str]

class ScanManager:
    """Manages network scanning operations using Nmap"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.active_scans: Dict[str, ScanJob] = {}
        self.scan_history: List[ScanJob] = []
        self.callbacks: List[Callable] = []
        self._scan_counter = 0
        
    def add_callback(self, callback: Callable):
        """Add callback for scan updates"""
        self.callbacks.append(callback)
        
    def _notify_callbacks(self, scan_job: ScanJob):
        """Notify all callbacks of scan updates"""
        for callback in self.callbacks:
            try:
                callback(scan_job)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in scan callback: {e}")
    
    def start_scan(self, scan_type: ScanType, target: str, options: Dict[str, Any] = None) -> str:
        """Start a new scan"""
        self._scan_counter += 1
        scan_id = f"scan_{self._scan_counter}_{int(time.time())}"
        
        scan_job = ScanJob(
            scan_id=scan_id,
            scan_type=scan_type,
            target=target,
            options=options or {},
            status=ScanStatus.RUNNING,
            progress=0.0,
            start_time=time.time(),
            end_time=None,
            results=[],
            error_message=None
        )
        
        self.active_scans[scan_id] = scan_job
        
        # Start scan in background thread
        thread = threading.Thread(target=self._execute_scan, args=(scan_job,), daemon=True)
        thread.start()
        
        if self.logger:
            self.logger.info(f"Started {scan_type.value} scan on {target} (ID: {scan_id})")
        
        return scan_id
    
    def _execute_scan(self, scan_job: ScanJob):
        """Execute the actual scan"""
        try:
            if scan_job.scan_type == ScanType.PING_SWEEP:
                self._ping_sweep(scan_job)
            elif scan_job.scan_type == ScanType.PORT_SCAN:
                self._port_scan(scan_job)
            elif scan_job.scan_type == ScanType.SERVICE_SCAN:
                self._service_scan(scan_job)
            elif scan_job.scan_type == ScanType.VULNERABILITY_SCAN:
                self._vulnerability_scan(scan_job)
            elif scan_job.scan_type == ScanType.STEALTH_SCAN:
                self._stealth_scan(scan_job)
            
            scan_job.status = ScanStatus.COMPLETED
            scan_job.progress = 100.0
            scan_job.end_time = time.time()
            
        except Exception as e:
            scan_job.status = ScanStatus.ERROR
            scan_job.error_message = str(e)
            scan_job.end_time = time.time()
            
            if self.logger:
                self.logger.error(f"Scan {scan_job.scan_id} failed: {e}")
        
        finally:
            # Move to history and remove from active
            self.scan_history.append(scan_job)
            if scan_job.scan_id in self.active_scans:
                del self.active_scans[scan_job.scan_id]
            
            self._notify_callbacks(scan_job)
    
    def _ping_sweep(self, scan_job: ScanJob):
        """Perform ping sweep to discover live hosts"""
        target = scan_job.target
        
        # Build nmap command for ping sweep
        cmd = ["nmap", "-sn", "-T4", target]
        
        if self.logger:
            self.logger.debug(f"Running ping sweep: {' '.join(cmd)}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Execute nmap
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        if result.returncode == 0:
            # Parse results
            hosts = self._parse_ping_sweep_output(result.stdout)
            
            for host_ip in hosts:
                scan_result = ScanResult(
                    ip=host_ip,
                    hostname=self._resolve_hostname(host_ip),
                    status="up",
                    ports=[],
                    services=[],
                    os_info={},
                    vulnerabilities=[],
                    scan_time=time.time()
                )
                scan_job.results.append(scan_result)
        else:
            raise Exception(f"Nmap ping sweep failed: {result.stderr}")
    
    def _port_scan(self, scan_job: ScanJob):
        """Perform port scan on target"""
        target = scan_job.target
        ports = scan_job.options.get("ports", "1-1000")
        
        # Build nmap command for port scan
        cmd = ["nmap", "-sS", "-T4", "-p", ports, target]
        
        if self.logger:
            self.logger.debug(f"Running port scan: {' '.join(cmd)}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Execute nmap with XML output
        result = subprocess.run(cmd + ["-oX", "-"], capture_output=True, text=True, timeout=600)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        if result.returncode == 0:
            # Parse XML results
            scan_results = self._parse_nmap_xml(result.stdout)
            scan_job.results.extend(scan_results)
        else:
            raise Exception(f"Nmap port scan failed: {result.stderr}")
    
    def _service_scan(self, scan_job: ScanJob):
        """Perform service detection scan"""
        target = scan_job.target
        ports = scan_job.options.get("ports", "1-1000")
        
        # Build nmap command for service detection
        cmd = ["nmap", "-sV", "-T4", "-p", ports, target]
        
        if self.logger:
            self.logger.debug(f"Running service scan: {' '.join(cmd)}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Execute nmap with XML output
        result = subprocess.run(cmd + ["-oX", "-"], capture_output=True, text=True, timeout=900)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        if result.returncode == 0:
            # Parse XML results
            scan_results = self._parse_nmap_xml(result.stdout)
            scan_job.results.extend(scan_results)
        else:
            raise Exception(f"Nmap service scan failed: {result.stderr}")
    
    def _vulnerability_scan(self, scan_job: ScanJob):
        """Perform vulnerability scan using NSE scripts"""
        target = scan_job.target
        
        # Build nmap command for vulnerability scanning
        cmd = ["nmap", "--script", "vuln", "-T4", target]
        
        if self.logger:
            self.logger.debug(f"Running vulnerability scan: {' '.join(cmd)}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Execute nmap with XML output
        result = subprocess.run(cmd + ["-oX", "-"], capture_output=True, text=True, timeout=1200)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        if result.returncode == 0:
            # Parse XML results
            scan_results = self._parse_nmap_xml(result.stdout)
            scan_job.results.extend(scan_results)
        else:
            raise Exception(f"Nmap vulnerability scan failed: {result.stderr}")
    
    def _stealth_scan(self, scan_job: ScanJob):
        """Perform stealth SYN scan"""
        target = scan_job.target
        ports = scan_job.options.get("ports", "1-1000")
        
        # Build nmap command for stealth scan
        cmd = ["nmap", "-sS", "-T2", "-f", "-p", ports, target]
        
        if self.logger:
            self.logger.debug(f"Running stealth scan: {' '.join(cmd)}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Execute nmap with XML output
        result = subprocess.run(cmd + ["-oX", "-"], capture_output=True, text=True, timeout=1800)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        if result.returncode == 0:
            # Parse XML results
            scan_results = self._parse_nmap_xml(result.stdout)
            scan_job.results.extend(scan_results)
        else:
            raise Exception(f"Nmap stealth scan failed: {result.stderr}")
    
    def _parse_ping_sweep_output(self, output: str) -> List[str]:
        """Parse ping sweep output to extract live hosts"""
        hosts = []
        lines = output.split('\n')
        
        for line in lines:
            if "Nmap scan report for" in line:
                # Extract IP address
                parts = line.split()
                if len(parts) >= 5:
                    ip_part = parts[-1]
                    if ip_part.startswith('(') and ip_part.endswith(')'):
                        ip = ip_part[1:-1]
                    else:
                        ip = parts[4]
                    
                    try:
                        ipaddress.ip_address(ip)
                        hosts.append(ip)
                    except ValueError:
                        continue
        
        return hosts
    
    def _parse_nmap_xml(self, xml_output: str) -> List[ScanResult]:
        """Parse Nmap XML output"""
        results = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('host'):
                # Get host status
                status_elem = host.find('status')
                if status_elem is None or status_elem.get('state') != 'up':
                    continue
                
                # Get IP address
                address_elem = host.find('address[@addrtype="ipv4"]')
                if address_elem is None:
                    continue
                ip = address_elem.get('addr')
                
                # Get hostname
                hostname = ip
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name', ip)
                
                # Get ports
                ports = []
                services = []
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state_elem = port.find('state')
                        state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        port_info = {
                            'port': int(port_id),
                            'protocol': protocol,
                            'state': state
                        }
                        
                        # Get service information
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_info = {
                                'port': int(port_id),
                                'name': service_elem.get('name', ''),
                                'product': service_elem.get('product', ''),
                                'version': service_elem.get('version', ''),
                                'extrainfo': service_elem.get('extrainfo', '')
                            }
                            services.append(service_info)
                            port_info['service'] = service_info
                        
                        ports.append(port_info)
                
                # Get OS information
                os_info = {}
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch_elem = os_elem.find('osmatch')
                    if osmatch_elem is not None:
                        os_info = {
                            'name': osmatch_elem.get('name', ''),
                            'accuracy': osmatch_elem.get('accuracy', '0')
                        }
                
                # Get vulnerabilities from script results
                vulnerabilities = []
                hostscript_elem = host.find('hostscript')
                if hostscript_elem is not None:
                    for script in hostscript_elem.findall('script'):
                        script_id = script.get('id')
                        if 'vuln' in script_id:
                            vuln_info = {
                                'script': script_id,
                                'output': script.get('output', ''),
                                'severity': 'unknown'
                            }
                            vulnerabilities.append(vuln_info)
                
                result = ScanResult(
                    ip=ip,
                    hostname=hostname,
                    status='up',
                    ports=ports,
                    services=services,
                    os_info=os_info,
                    vulnerabilities=vulnerabilities,
                    scan_time=time.time()
                )
                results.append(result)
        
        except ET.ParseError as e:
            if self.logger:
                self.logger.error(f"Failed to parse Nmap XML: {e}")
        
        return results
    
    def _resolve_hostname(self, ip: str) -> str:
        """Try to resolve hostname from IP"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanJob]:
        """Get status of a specific scan"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        # Check history
        for scan in self.scan_history:
            if scan.scan_id == scan_id:
                return scan
        
        return None
    
    def get_active_scans(self) -> List[ScanJob]:
        """Get all active scans"""
        return list(self.active_scans.values())
    
    def get_scan_history(self) -> List[ScanJob]:
        """Get scan history"""
        return self.scan_history.copy()
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        if scan_id in self.active_scans:
            scan_job = self.active_scans[scan_id]
            scan_job.status = ScanStatus.ERROR
            scan_job.error_message = "Scan cancelled by user"
            scan_job.end_time = time.time()
            
            # Move to history
            self.scan_history.append(scan_job)
            del self.active_scans[scan_id]
            
            self._notify_callbacks(scan_job)
            
            if self.logger:
                self.logger.info(f"Cancelled scan {scan_id}")
            
            return True
        
        return False
    
    def export_results(self, scan_id: str, format: str = "json") -> Optional[str]:
        """Export scan results"""
        scan_job = self.get_scan_status(scan_id)
        if not scan_job:
            return None
        
        if format == "json":
            return json.dumps(asdict(scan_job), indent=2, default=str)
        
        return None