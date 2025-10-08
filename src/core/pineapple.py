"""SSH helper for WiFi Pineapple"""
from __future__ import annotations
import paramiko
import threading
import time
from typing import Optional

class PineappleSSH:
    def __init__(self, host: str = "172.16.42.1", username: str = "root", password: Optional[str] = "root", port: int = 22, timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None
        self.lock = threading.Lock()
        self.connected = False

    def connect(self) -> bool:
        """Establece una conexión SSH al Pineapple."""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=self.timeout)
            self.client = client
            self.connected = True
            return True
        except paramiko.AuthenticationException as e:
            print(f"[-] SSH authentication failed: {e}")
            self.connected = False
            return False
        except paramiko.SSHException as e:
            print(f"[-] SSH connection error: {e}")
            self.connected = False
            return False
        except ConnectionRefusedError as e:
            print(f"[-] Connection refused: {e}")
            self.connected = False
            return False
        except TimeoutError as e:
            print(f"[-] Connection timeout: {e}")
            self.connected = False
            return False
        except Exception as e:
            print(f"[-] SSH connect error: {e}")
            self.connected = False
            return False

    def execute(self, cmd: str, timeout: int = 30) -> str:
        """Ejecuta un comando y devuelve stdout como string."""
        if not self.connected or self.client is None:
            raise RuntimeError("Not connected")
        with self.lock:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode(errors='ignore')
            err = stderr.read().decode(errors='ignore')
            if err:
                return err
            return out

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.connected = False

    # --- PineAP / helper commands -------------------------------------------------
    def start_pineapd(self) -> str:
        """Start the PineAP daemon on the device."""
        return self.execute('/etc/init.d/pineapd start')

    def run_pineap(self, config: str, action: str, *args) -> str:
        """Run the pineap CLI with given action and args."""
        cmd = f"/usr/bin/pineap {config} {action} {' '.join(str(a) for a in args)}"
        return self.execute(cmd)

    def run_scan(self, duration: int = 0, frequencies: int = 2, config: str = '/tmp/pineap.conf') -> str:
        """Run run_scan on the device (duration in sec; 0 for continuous)."""
        return self.run_pineap(config, 'run_scan', str(duration), str(frequencies))

    def list_probes(self, config: str = '/tmp/pineap.conf') -> str:
        return self.run_pineap(config, 'list_probes')

    def handshake_capture_start(self, bssid: str, channel: int, config: str = '/tmp/pineap.conf') -> str:
        return self.run_pineap(config, 'handshake_capture_start', bssid, str(channel))

    def handshake_capture_stop(self, config: str = '/tmp/pineap.conf') -> str:
        return self.run_pineap(config, 'handshake_capture_stop')

    def deauth(self, mac: str, bssid: str, channel: int, multiplier: int = 1, config: str = '/tmp/pineap.conf') -> str:
        return self.run_pineap(config, 'deauth', mac, bssid, str(channel), str(multiplier))

    def get_status(self, config: str = '/tmp/pineap.conf') -> str:
        return self.run_pineap(config, 'get_status')

    def sftp_get(self, remote_path: str, local_path: str) -> bool:
        """Download a file from the Pineapple via SFTP."""
        if not self.connected or self.client is None:
            raise RuntimeError('Not connected')
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True
        except Exception as e:
            print(f"[-] SFTP get error: {e}")
            return False

    # --- Additional helpers for CLI parity -----------------------------------
    def logging(self, on: bool, config: str = '/tmp/pineap.conf') -> str:
        return self.run_pineap(config, 'logging', 'on' if on else 'off')

    def connect_notifications(self, on: bool, config: str = '/tmp/pineap.conf') -> str:
        action = 'connect_notifications' if on else 'disconnect_notifications'
        return self.run_pineap(config, action)

    def pineap_help(self) -> str:
        return self.execute('/usr/bin/pineap help')
    
    def run_command(self, command: str, timeout: int = 30) -> str:
        """Execute a command on the Pineapple device and return the output."""
        return self.execute(command, timeout)
