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
    ports: List[Dict]
    services: List[Dict]
    os_info: Dict
    vulnerabilities: List[Dict]
    scan_time: float

@dataclass
class ScanJob:
    scan_id: str
    scan_type: ScanType
    target: str
    status: ScanStatus
    progress: float
    start_time: float
    end_time: Optional[float]
    results: List[ScanResult]
    options: Dict[str, Any]
    error_message: Optional[str] = None

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
        
        if self.logger:
            self.logger.debug(f"Running alternative ping sweep on: {target}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Use alternative ping sweep method
        hosts = self._alternative_ping_sweep(target)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
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
    
    def _port_scan(self, scan_job: ScanJob):
        """Perform port scan on target"""
        target = scan_job.target
        ports = scan_job.options.get("ports", "1-1000")
        
        if self.logger:
            self.logger.debug(f"Running alternative port scan on: {target}, ports: {ports}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Use alternative port scan method
        scan_results = self._alternative_port_scan(target, ports)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        scan_job.results.extend(scan_results)
    
    def _service_scan(self, scan_job: ScanJob):
        """Perform service detection scan"""
        target = scan_job.target
        
        if self.logger:
            self.logger.debug(f"Running alternative service scan on: {target}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Use alternative service detection method
        scan_results = self._alternative_service_scan(target)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        scan_job.results.extend(scan_results)
    
    def _vulnerability_scan(self, scan_job: ScanJob):
        """Perform vulnerability scan"""
        target = scan_job.target
        
        if self.logger:
            self.logger.debug(f"Running alternative vulnerability scan on: {target}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Use alternative vulnerability detection method
        scan_results = self._alternative_vulnerability_scan(target)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        scan_job.results.extend(scan_results)
    
    def _stealth_scan(self, scan_job: ScanJob):
        """Perform stealth scan"""
        target = scan_job.target
        
        if self.logger:
            self.logger.debug(f"Running alternative stealth scan on: {target}")
        
        scan_job.progress = 10.0
        self._notify_callbacks(scan_job)
        
        # Use alternative stealth scan method
        scan_results = self._alternative_stealth_scan(target)
        
        scan_job.progress = 80.0
        self._notify_callbacks(scan_job)
        
        scan_job.results.extend(scan_results)
    
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
    
    def is_nmap_available(self) -> bool:
        """Check if nmap is available on the system"""
        try:
            result = subprocess.run(["nmap", "--version"], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    # Alternative scanning methods that don't require nmap
    
    def _alternative_ping_sweep(self, target: str) -> List[str]:
        """Alternative ping sweep using native ping and socket methods"""
        import ipaddress
        import socket
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        hosts = []
        
        try:
            # Parse target to get IP range
            if '/' in target:
                # CIDR notation
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    ip_list = [str(ip) for ip in network.hosts()]
                except ValueError:
                    if self.logger:
                        self.logger.error(f"Invalid network range: {target}")
                    return hosts
            elif '-' in target:
                # Range notation (e.g., 192.168.1.1-254)
                start_ip, end_range = target.split('-')
                base_ip = '.'.join(start_ip.split('.')[:-1])
                start_num = int(start_ip.split('.')[-1])
                end_num = int(end_range)
                ip_list = [f"{base_ip}.{i}" for i in range(start_num, end_num + 1)]
            else:
                # Single IP
                ip_list = [target]
            
            # Limit to reasonable number of IPs
            if len(ip_list) > 254:
                ip_list = ip_list[:254]
            
            if self.logger:
                self.logger.info(f"Scanning {len(ip_list)} hosts in {target}")
            
            def ping_host(ip):
                try:
                    # Try TCP connect to common ports as ping alternative
                    for port in [80, 443, 22, 21, 23, 25, 53, 135, 139, 445]:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            return ip
                    return None
                except:
                    return None
            
            # Use thread pool for concurrent pings
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
                for future in as_completed(future_to_ip, timeout=30):
                    try:
                        result = future.result(timeout=1)
                        if result:
                            hosts.append(result)
                    except Exception:
                        continue
            
            if self.logger:
                self.logger.info(f"Found {len(hosts)} active hosts")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Alternative ping sweep failed: {e}")
        
        return hosts
    
    def _alternative_port_scan(self, target: str, ports: str) -> List[ScanResult]:
        """Alternative port scan using socket connections"""
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []
        
        try:
            # Parse port range
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
                port_list = list(range(start_port, min(end_port + 1, 65536)))
            elif ',' in ports:
                port_list = [int(p.strip()) for p in ports.split(',')]
            else:
                port_list = [int(ports)]
            
            # Limit to reasonable number of ports
            if len(port_list) > 1000:
                port_list = port_list[:1000]
            
            def scan_port(ip, port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        return {
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open'
                        }
                except:
                    pass
                return None
            
            open_ports = []
            
            # Use thread pool for concurrent port scanning
            with ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {executor.submit(scan_port, target, port): port for port in port_list}
                for future in as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)
            
            if open_ports:
                scan_result = ScanResult(
                    ip=target,
                    hostname=self._resolve_hostname(target),
                    status="up",
                    ports=open_ports,
                    services=[],
                    os_info={},
                    vulnerabilities=[],
                    scan_time=time.time()
                )
                results.append(scan_result)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Alternative port scan failed: {e}")
        
        return results
    
    def _identify_service(self, port: int) -> str:
        """Identify service running on port"""
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy'
        }
        return common_services.get(port, 'unknown')
    
    def _alternative_service_scan(self, target: str) -> List[ScanResult]:
        """Alternative service detection using banner grabbing"""
        import socket
        
        results = []
        
        try:
            # Common ports and their typical services
            common_ports = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                53: 'dns', 80: 'http', 110: 'pop3', 135: 'rpc',
                139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb',
                993: 'imaps', 995: 'pop3s'
            }
            
            services = []
            open_ports = []
            
            for port, service_name in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        open_ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open'
                        })
                        
                        # Try to grab banner
                        banner = ""
                        try:
                            sock.send(b"GET / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        except:
                            pass
                        
                        services.append({
                            'port': port,
                            'name': service_name,
                            'product': '',
                            'version': '',
                            'extrainfo': banner[:100] if banner else ''
                        })
                    
                    sock.close()
                except:
                    pass
            
            if open_ports:
                scan_result = ScanResult(
                    ip=target,
                    hostname=self._resolve_hostname(target),
                    status="up",
                    ports=open_ports,
                    services=services,
                    os_info={},
                    vulnerabilities=[],
                    scan_time=time.time()
                )
                results.append(scan_result)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Alternative service scan failed: {e}")
        
        return results
    
    def _alternative_vulnerability_scan(self, target: str) -> List[ScanResult]:
        """Alternative vulnerability detection using basic checks"""
        results = []
        
        try:
            vulnerabilities = []
            
            # Basic vulnerability checks
            # Check for common vulnerable services
            vulnerable_services = {
                21: "FTP service detected - check for anonymous access",
                23: "Telnet service detected - unencrypted protocol",
                135: "RPC service detected - potential security risk",
                445: "SMB service detected - check for vulnerabilities"
            }
            
            open_ports = []
            
            for port, vuln_desc in vulnerable_services.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open'
                        })
                        
                        vulnerabilities.append({
                            'script': f'basic-vuln-check-{port}',
                            'output': vuln_desc,
                            'severity': 'medium'
                        })
                except:
                    pass
            
            if vulnerabilities:
                scan_result = ScanResult(
                    ip=target,
                    hostname=self._resolve_hostname(target),
                    status="up",
                    ports=open_ports,
                    services=[],
                    os_info={},
                    vulnerabilities=vulnerabilities,
                    scan_time=time.time()
                )
                results.append(scan_result)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Alternative vulnerability scan failed: {e}")
        
        return results
    
    def _alternative_stealth_scan(self, target: str) -> List[ScanResult]:
        """Alternative stealth scan using slower, less detectable methods"""
        import socket
        import time
        import random
        
        results = []
        
        try:
            # Use random delays and limited concurrent connections for stealth
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995]
            random.shuffle(common_ports)
            
            open_ports = []
            
            for port in common_ports:
                try:
                    # Random delay between scans for stealth
                    time.sleep(random.uniform(0.5, 2.0))
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open'
                        })
                except:
                    pass
            
            if open_ports:
                scan_result = ScanResult(
                    ip=target,
                    hostname=self._resolve_hostname(target),
                    status="up",
                    ports=open_ports,
                    services=[],
                    os_info={},
                    vulnerabilities=[],
                    scan_time=time.time()
                )
                results.append(scan_result)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Alternative stealth scan failed: {e}")
        
        return results