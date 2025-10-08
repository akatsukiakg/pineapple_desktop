"""
Serial Connection Manager for Pineapple Device
Handles serial communication via COM ports on Windows
"""

import serial
import threading
import time
from typing import Optional, Callable, List
from enum import Enum
import queue

class SerialConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"

class SerialConnection:
    """Manages serial connection to Pineapple device via COM port"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.serial_conn: Optional[serial.Serial] = None
        self.status = SerialConnectionStatus.DISCONNECTED
        self.com_port = None
        self.baud_rate = 115200
        self.status_callbacks: List[Callable] = []
        self._read_thread = None
        self._running = False
        self._command_queue = queue.Queue()
        self._response_queue = queue.Queue()
        
    def add_status_callback(self, callback: Callable):
        """Add callback for connection status changes"""
        self.status_callbacks.append(callback)
        
    def _notify_status_change(self, status: SerialConnectionStatus, message: str = ""):
        """Notify all status callbacks of connection changes"""
        self.status = status
        for callback in self.status_callbacks:
            try:
                callback(status, message)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in serial status callback: {e}")
    
    def connect(self, com_port: str, baud_rate: int = 115200) -> bool:
        """Connect to Pineapple device via serial port"""
        try:
            self._notify_status_change(SerialConnectionStatus.CONNECTING, f"Connecting to {com_port}...")
            
            # Create serial connection
            self.serial_conn = serial.Serial(
                port=com_port,
                baudrate=baud_rate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )
            
            if self.serial_conn.is_open:
                self.com_port = com_port
                self.baud_rate = baud_rate
                self._running = True
                
                # Start read thread
                self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
                self._read_thread.start()
                
                # Send initial ENTER to activate console
                self.send_command("")
                time.sleep(0.5)
                
                # Test connection
                response = self.send_command("echo 'test'", timeout=3)
                if response and "test" in response:
                    self._notify_status_change(SerialConnectionStatus.CONNECTED, f"Connected to Pineapple on {com_port}")
                    if self.logger:
                        self.logger.info(f"Successfully connected to Pineapple via {com_port}")
                    return True
                else:
                    # Connection established but no response - might need login
                    self._notify_status_change(SerialConnectionStatus.CONNECTED, f"Connected to {com_port} (login required)")
                    if self.logger:
                        self.logger.info(f"Connected to {com_port}, waiting for login prompt")
                    return True
            else:
                raise Exception(f"Failed to open serial port {com_port}")
                
        except Exception as e:
            error_msg = f"Error connecting to {com_port}: {str(e)}"
            self._notify_status_change(SerialConnectionStatus.ERROR, error_msg)
            if self.logger:
                self.logger.error(error_msg)
            return False
    
    def disconnect(self):
        """Disconnect from serial port"""
        self._running = False
        
        if self._read_thread and self._read_thread.is_alive():
            self._read_thread.join(timeout=2)
        
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.close()
            except:
                pass
            
        self.serial_conn = None
        self.com_port = None
        self._notify_status_change(SerialConnectionStatus.DISCONNECTED, "Disconnected")
        
        if self.logger:
            self.logger.info("Disconnected from serial port")
    
    def send_command(self, command: str, timeout: int = 5) -> Optional[str]:
        """Send command via serial and wait for response"""
        if not self.serial_conn or not self.serial_conn.is_open:
            return None
            
        try:
            # Clear any pending responses
            while not self._response_queue.empty():
                try:
                    self._response_queue.get_nowait()
                except queue.Empty:
                    break
            
            # Send command
            command_bytes = (command + '\n').encode('utf-8')
            self.serial_conn.write(command_bytes)
            self.serial_conn.flush()
            
            # Wait for response
            try:
                response = self._response_queue.get(timeout=timeout)
                return response
            except queue.Empty:
                if self.logger:
                    self.logger.warning(f"Timeout waiting for response to command: {command}")
                return None
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error sending command '{command}': {e}")
            return None
    
    def _read_loop(self):
        """Continuous read loop for serial data"""
        buffer = ""
        
        while self._running and self.serial_conn and self.serial_conn.is_open:
            try:
                if self.serial_conn.in_waiting > 0:
                    data = self.serial_conn.read(self.serial_conn.in_waiting).decode('utf-8', errors='ignore')
                    buffer += data
                    
                    # Process complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        
                        if line:  # Only process non-empty lines
                            try:
                                self._response_queue.put(line, timeout=1)
                            except queue.Full:
                                # Queue is full, remove oldest item
                                try:
                                    self._response_queue.get_nowait()
                                    self._response_queue.put(line, timeout=1)
                                except queue.Empty:
                                    pass
                
                time.sleep(0.01)  # Small delay to prevent excessive CPU usage
                
            except Exception as e:
                if self._running and self.logger:
                    self.logger.error(f"Error in serial read loop: {e}")
                time.sleep(0.1)
    
    def is_connected(self) -> bool:
        """Check if serial connection is active"""
        return (self.serial_conn is not None and 
                self.serial_conn.is_open and 
                self.status == SerialConnectionStatus.CONNECTED)
    
    def login(self, username: str = "root", password: str = "root") -> bool:
        """Attempt to login to the Pineapple console"""
        try:
            # Send username
            response = self.send_command(username, timeout=3)
            time.sleep(0.5)
            
            # Send password
            response = self.send_command(password, timeout=3)
            time.sleep(0.5)
            
            # Test if login was successful
            response = self.send_command("whoami", timeout=3)
            if response and "root" in response:
                if self.logger:
                    self.logger.info("Successfully logged in to Pineapple console")
                return True
            else:
                if self.logger:
                    self.logger.warning("Login may have failed or console not ready")
                return False
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during login: {e}")
            return False

    @staticmethod
    def get_available_ports():
        """Get list of available COM ports"""
        try:
            import serial.tools.list_ports
            ports = []
            for port in serial.tools.list_ports.comports():
                ports.append({
                    'device': port.device,
                    'description': port.description,
                    'hwid': port.hwid
                })
            return ports
        except ImportError:
            return []
        except Exception:
            return []