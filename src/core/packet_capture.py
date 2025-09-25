"""
Packet Capture Manager with Wireshark/tshark integration and fallback methods
Provides packet capture capabilities using tshark or native Python tools
"""

import subprocess
import threading
import time
import json
import os
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
import socket
import struct

try:
    from scapy.all import sniff, get_if_list, get_if_addr, Ether, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class CaptureStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    info: str

@dataclass
class CaptureJob:
    capture_id: str
    interface: str
    filter_expression: str
    status: CaptureStatus
    start_time: float
    end_time: Optional[float]
    packet_count: int
    packets: List[PacketInfo]
    output_file: Optional[str]
    error_message: Optional[str] = None

class PacketCaptureManager:
    """Manages packet capture operations using tshark or fallback methods"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.active_captures: Dict[str, CaptureJob] = {}
        self.capture_history: List[CaptureJob] = []
        self.callbacks: List[Callable] = []
        self._capture_counter = 0
        self._tshark_available = self._check_tshark_availability()
        
        if not self._tshark_available and self.logger:
            self.logger.warning("tshark not available, using fallback capture methods")
        
        if not SCAPY_AVAILABLE and self.logger:
            self.logger.warning("Scapy not available, limited fallback functionality")

    def _check_tshark_availability(self) -> bool:
        """Check if tshark is available on the system"""
        try:
            result = subprocess.run(["tshark", "--version"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def add_callback(self, callback: Callable):
        """Add callback for capture updates"""
        self.callbacks.append(callback)
        
    def _notify_callbacks(self, capture_job: CaptureJob):
        """Notify all callbacks of capture updates"""
        for callback in self.callbacks:
            try:
                callback(capture_job)
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
                            # Parse tshark interface format: "1. eth0 (Ethernet)"
                            parts = line.split('.', 1)
                            if len(parts) == 2:
                                interface_info = parts[1].strip()
                                name = interface_info.split()[0]
                                description = interface_info
                                interfaces.append({
                                    'name': name,
                                    'description': description
                                })
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to list interfaces with tshark: {e}")
        
        # Fallback to scapy or native methods
        if not interfaces:
            interfaces = self._list_interfaces_fallback()
        
        return interfaces

    def _list_interfaces_fallback(self) -> List[Dict[str, str]]:
        """Fallback method to list interfaces"""
        interfaces = []
        
        if SCAPY_AVAILABLE:
            try:
                scapy_interfaces = get_if_list()
                for iface in scapy_interfaces:
                    try:
                        addr = get_if_addr(iface)
                        interfaces.append({
                            'name': iface,
                            'description': f"{iface} ({addr})"
                        })
                    except:
                        interfaces.append({
                            'name': iface,
                            'description': iface
                        })
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to list interfaces with scapy: {e}")
        
        # Basic fallback using socket
        if not interfaces:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                interfaces.append({
                    'name': 'default',
                    'description': f"Default interface ({local_ip})"
                })
            except:
                interfaces.append({
                    'name': 'any',
                    'description': "Any interface"
                })
        
        return interfaces

    def start_capture(self, interface: str, filter_expression: str = "", 
                     output_file: Optional[str] = None, packet_limit: int = 1000) -> str:
        """Start packet capture"""
        capture_id = f"capture_{self._capture_counter}"
        self._capture_counter += 1
        
        capture_job = CaptureJob(
            capture_id=capture_id,
            interface=interface,
            filter_expression=filter_expression,
            status=CaptureStatus.RUNNING,
            start_time=time.time(),
            end_time=None,
            packet_count=0,
            packets=[],
            output_file=output_file
        )
        
        self.active_captures[capture_id] = capture_job
        
        # Start capture in background thread
        thread = threading.Thread(target=self._execute_capture, 
                                args=(capture_job, packet_limit))
        thread.daemon = True
        thread.start()
        
        return capture_id

    def _execute_capture(self, capture_job: CaptureJob, packet_limit: int):
        """Execute the packet capture"""
        try:
            if self._tshark_available:
                self._capture_with_tshark(capture_job, packet_limit)
            elif SCAPY_AVAILABLE:
                self._capture_with_scapy(capture_job, packet_limit)
            else:
                self._capture_with_socket(capture_job, packet_limit)
            
            capture_job.status = CaptureStatus.STOPPED
            capture_job.end_time = time.time()
            
        except Exception as e:
            capture_job.status = CaptureStatus.ERROR
            capture_job.error_message = str(e)
            capture_job.end_time = time.time()
            if self.logger:
                self.logger.error(f"Capture {capture_job.capture_id} failed: {e}")
        
        finally:
            # Move to history and remove from active
            self.capture_history.append(capture_job)
            if capture_job.capture_id in self.active_captures:
                del self.active_captures[capture_job.capture_id]
            
            self._notify_callbacks(capture_job)

    def _capture_with_tshark(self, capture_job: CaptureJob, packet_limit: int):
        """Capture packets using tshark"""
        cmd = ["tshark", "-i", capture_job.interface, "-c", str(packet_limit)]
        
        if capture_job.filter_expression:
            cmd.extend(["-f", capture_job.filter_expression])
        
        if capture_job.output_file:
            cmd.extend(["-w", capture_job.output_file])
        else:
            # Capture to text format for parsing
            cmd.extend(["-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", 
                       "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
                       "-e", "udp.srcport", "-e", "udp.dstport", "-e", "frame.protocols",
                       "-e", "frame.len", "-e", "_ws.col.Info"])
        
        if self.logger:
            self.logger.debug(f"Running tshark: {' '.join(cmd)}")
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                 text=True, bufsize=1, universal_newlines=True)
        
        try:
            for line in process.stdout:
                if capture_job.status != CaptureStatus.RUNNING:
                    break
                
                if line.strip():
                    packet_info = self._parse_tshark_line(line.strip())
                    if packet_info:
                        capture_job.packets.append(packet_info)
                        capture_job.packet_count += 1
                        
                        # Notify callbacks periodically
                        if capture_job.packet_count % 10 == 0:
                            self._notify_callbacks(capture_job)
        
        finally:
            process.terminate()
            process.wait()

    def _parse_tshark_line(self, line: str) -> Optional[PacketInfo]:
        """Parse tshark output line into PacketInfo"""
        try:
            fields = line.split('\t')
            if len(fields) >= 9:
                timestamp = float(fields[0]) if fields[0] else time.time()
                src_ip = fields[1] if fields[1] else "unknown"
                dst_ip = fields[2] if fields[2] else "unknown"
                
                # Try TCP ports first, then UDP
                src_port = None
                dst_port = None
                if fields[3] and fields[4]:  # TCP ports
                    src_port = int(fields[3])
                    dst_port = int(fields[4])
                elif fields[5] and fields[6]:  # UDP ports
                    src_port = int(fields[5])
                    dst_port = int(fields[6])
                
                protocol = fields[7] if fields[7] else "unknown"
                length = int(fields[8]) if fields[8] else 0
                info = fields[9] if len(fields) > 9 else ""
                
                return PacketInfo(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    length=length,
                    info=info
                )
        except (ValueError, IndexError):
            pass
        
        return None

    def _capture_with_scapy(self, capture_job: CaptureJob, packet_limit: int):
        """Capture packets using scapy"""
        if not SCAPY_AVAILABLE:
            raise Exception("Scapy not available for packet capture")
        
        def packet_handler(packet):
            if capture_job.status != CaptureStatus.RUNNING:
                return True  # Stop sniffing
            
            packet_info = self._parse_scapy_packet(packet)
            if packet_info:
                capture_job.packets.append(packet_info)
                capture_job.packet_count += 1
                
                # Notify callbacks periodically
                if capture_job.packet_count % 10 == 0:
                    self._notify_callbacks(capture_job)
            
            return capture_job.packet_count >= packet_limit
        
        # Convert interface name for scapy
        iface = capture_job.interface if capture_job.interface != "any" else None
        
        # Validate interface exists
        if iface:
            available_interfaces = get_if_list()
            if iface not in available_interfaces:
                # Try to find a similar interface name
                for available_iface in available_interfaces:
                    if iface.lower() in available_iface.lower() or available_iface.lower() in iface.lower():
                        iface = available_iface
                        break
                else:
                    if self.logger:
                        self.logger.warning(f"Interface {iface} not found, using first available interface")
                    iface = available_interfaces[0] if available_interfaces else None
        
        if not iface and capture_job.interface != "any":
            raise Exception(f"No suitable interface found for {capture_job.interface}")
        
        # Build filter - be more permissive with filter expressions
        filter_expr = None
        if capture_job.filter_expression:
            try:
                # Test the filter expression
                filter_expr = capture_job.filter_expression
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Invalid filter expression '{capture_job.filter_expression}': {e}")
                filter_expr = None
        
        try:
            if self.logger:
                self.logger.info(f"Starting scapy capture on interface {iface} with filter '{filter_expr}'")
            
            # Use timeout to prevent hanging
            sniff(iface=iface, filter=filter_expr, prn=packet_handler, 
                  count=packet_limit, store=0, timeout=30)
                  
        except Exception as e:
            if "Operation not permitted" in str(e):
                raise Exception("Packet capture requires administrator privileges")
            elif "No such device" in str(e):
                raise Exception(f"Network interface {iface} not accessible")
            else:
                raise Exception(f"Scapy capture failed: {e}")

    def _parse_scapy_packet(self, packet) -> Optional[PacketInfo]:
        """Parse scapy packet into PacketInfo"""
        try:
            timestamp = time.time()
            src_ip = "unknown"
            dst_ip = "unknown"
            src_port = None
            dst_port = None
            protocol = "unknown"
            length = len(packet)
            info = ""
            
            # Extract IP information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Extract port information
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = "TCP"
                    info = f"TCP {src_port} → {dst_port}"
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = "UDP"
                    info = f"UDP {src_port} → {dst_port}"
                elif ICMP in packet:
                    protocol = "ICMP"
                    info = f"ICMP {packet[ICMP].type}"
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                info=info
            )
        except Exception:
            return None

    def _capture_with_socket(self, capture_job: CaptureJob, packet_limit: int):
        """Basic packet capture using raw sockets (limited functionality)"""
        try:
            # Create raw socket (requires admin privileges on Windows)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Set socket timeout to prevent hanging
            sock.settimeout(1.0)
            
            # Get local IP address
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                sock.bind((local_ip, 0))
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Could not bind to local IP: {e}")
                # Try binding to any available address
                sock.bind(('0.0.0.0', 0))
            
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode (Windows)
            if os.name == 'nt':
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except Exception as e:
                    if self.logger:
                        self.logger.warning(f"Could not enable promiscuous mode: {e}")
            
            packet_count = 0
            start_time = time.time()
            max_duration = 60  # Maximum 60 seconds to prevent hanging
            
            if self.logger:
                self.logger.info(f"Starting raw socket capture (max {packet_limit} packets, {max_duration}s timeout)")
            
            while (packet_count < packet_limit and 
                   capture_job.status == CaptureStatus.RUNNING and
                   (time.time() - start_time) < max_duration):
                try:
                    data, addr = sock.recvfrom(65535)
                    packet_info = self._parse_raw_packet(data)
                    if packet_info:
                        capture_job.packets.append(packet_info)
                        capture_job.packet_count += 1
                        packet_count += 1
                        
                        # Notify callbacks periodically
                        if capture_job.packet_count % 10 == 0:
                            self._notify_callbacks(capture_job)
                
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Socket capture error: {e}")
                    break
                    
            if packet_count == 0:
                raise Exception("No packets captured - may require administrator privileges")
        
        except PermissionError:
            raise Exception("Raw socket capture requires administrator privileges")
        except Exception as e:
            if "permission" in str(e).lower() or "access" in str(e).lower():
                raise Exception("Raw socket capture requires administrator privileges")
            else:
                raise Exception(f"Raw socket capture failed: {e}")
        
        finally:
            try:
                if os.name == 'nt':
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sock.close()
            except:
                pass

    def _parse_raw_packet(self, data: bytes) -> Optional[PacketInfo]:
        """Parse raw packet data"""
        try:
            # Parse IP header
            if len(data) < 20:
                return None
            
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            if version != 4:
                return None
            
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Parse protocol-specific data
            src_port = None
            dst_port = None
            protocol_name = "IP"
            info = ""
            
            if protocol == 6:  # TCP
                if len(data) >= ihl * 4 + 4:
                    tcp_header = struct.unpack('!HH', data[ihl * 4:ihl * 4 + 4])
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    protocol_name = "TCP"
                    info = f"TCP {src_port} → {dst_port}"
            elif protocol == 17:  # UDP
                if len(data) >= ihl * 4 + 4:
                    udp_header = struct.unpack('!HH', data[ihl * 4:ihl * 4 + 4])
                    src_port = udp_header[0]
                    dst_port = udp_header[1]
                    protocol_name = "UDP"
                    info = f"UDP {src_port} → {dst_port}"
            elif protocol == 1:  # ICMP
                protocol_name = "ICMP"
                info = "ICMP"
            
            return PacketInfo(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                length=len(data),
                info=info
            )
        
        except Exception:
            return None

    def stop_capture(self, capture_id: str) -> bool:
        """Stop an active capture"""
        if capture_id in self.active_captures:
            capture_job = self.active_captures[capture_id]
            capture_job.status = CaptureStatus.STOPPED
            return True
        return False

    def get_capture_status(self, capture_id: str) -> Optional[CaptureJob]:
        """Get status of a capture"""
        if capture_id in self.active_captures:
            return self.active_captures[capture_id]
        
        # Check history
        for capture in self.capture_history:
            if capture.capture_id == capture_id:
                return capture
        
        return None

    def get_active_captures(self) -> List[CaptureJob]:
        """Get all active captures"""
        return list(self.active_captures.values())

    def get_capture_history(self) -> List[CaptureJob]:
        """Get capture history"""
        return self.capture_history.copy()

    def is_tshark_available(self) -> bool:
        """Check if tshark is available"""
        return self._tshark_available

    def is_scapy_available(self) -> bool:
        """Check if scapy is available"""
        return SCAPY_AVAILABLE