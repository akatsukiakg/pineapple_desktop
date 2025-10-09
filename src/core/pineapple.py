"""SSH helper for WiFi Pineapple"""
from __future__ import annotations
import paramiko
import threading
import time
import os
import ipaddress
from typing import Optional

class PineappleSSH:
    def __init__(self, host: str = "172.16.42.1", username: str = "root", password: Optional[str] = None, 
                 port: int = 22, timeout: int = 10, private_key_path: Optional[str] = None):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.private_key_path = private_key_path
        self.client: Optional[paramiko.SSHClient] = None
        self.lock = threading.Lock()
        self.connected = False

    def _validate_network(self) -> bool:
        """Valida que la IP esté en la subred 172.16.42.0/24 según documentación técnica."""
        try:
            ip = ipaddress.IPv4Address(self.host)
            pineapple_network = ipaddress.IPv4Network("172.16.42.0/24")
            return ip in pineapple_network
        except ipaddress.AddressValueError:
            return False

    def connect(self) -> bool:
        """Establece una conexión SSH al Pineapple con manejo mejorado de errores."""
        try:
            # Validar red según documentación técnica
            if not self._validate_network():
                print(f"[-] Warning: IP {self.host} no está en la subred recomendada 172.16.42.0/24")
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Configurar autenticación según documentación
            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'look_for_keys': True,  # Buscar claves SSH automáticamente
                'allow_agent': True     # Usar SSH agent si está disponible
            }
            
            # Priorizar autenticación por clave SSH (más segura)
            if self.private_key_path and os.path.exists(self.private_key_path):
                try:
                    # Intentar cargar clave privada
                    private_key = paramiko.RSAKey.from_private_key_file(self.private_key_path)
                    connect_kwargs['pkey'] = private_key
                    print(f"[+] Usando clave SSH privada: {self.private_key_path}")
                except Exception as e:
                    print(f"[-] Error cargando clave privada {self.private_key_path}: {e}")
                    # Continuar con autenticación por contraseña si falla la clave
                    if self.password:
                        connect_kwargs['password'] = self.password
            elif self.password:
                connect_kwargs['password'] = self.password
            else:
                # Sin contraseña ni clave, intentar solo con claves del sistema
                print("[+] Intentando autenticación solo con claves SSH del sistema")
            
            client.connect(**connect_kwargs)
            self.client = client
            self.connected = True
            print(f"[+] Conexión SSH establecida a {self.host}:{self.port}")
            return True
            
        except paramiko.AuthenticationException as e:
            print(f"[-] Autenticación SSH fallida: {e}")
            print(f"[-] Autenticación fallida para {self.username}@{self.host}.")
            print("[-] Verifique las credenciales. Para el Pineapple Nano,")
            print("[-] el usuario por defecto es 'root' y la contraseña se establece durante la configuración inicial.")
            self.connected = False
            return False
        except paramiko.SSHException as e:
            print(f"[-] Error de conexión SSH: {e}")
            self.connected = False
            return False
        except ConnectionRefusedError as e:
            print(f"[-] Conexión rechazada a {self.host}:{self.port}: {e}")
            print("[-] El servicio SSH puede no estar ejecutándose en el Pineapple.")
            print("[-] Sugerencia: Verificar que el Pineapple esté encendido y SSH habilitado")
            self.connected = False
            return False
        except TimeoutError as e:
            print(f"[-] Timeout de conexión a {self.host}:{self.port}: {e}")
            print("[-] Verifique que:")
            print("[-] 1. El Pineapple esté encendido y conectado")
            print("[-] 2. Su máquina tenga una IP estática en la red 172.16.42.0/24")
            print("[-] 3. No haya firewall bloqueando la conexión SSH")
            self.connected = False
            return False
        except OSError as e:
            if "Network is unreachable" in str(e):
                print(f"[-] Red inalcanzable para {self.host}: {e}")
                print("[-] Asegúrese de que su máquina esté configurada con una IP estática")
                print("[-] en la red 172.16.42.0/24 (ej: 172.16.42.42/24).")
            elif "No route to host" in str(e):
                print(f"[-] No hay ruta al host {self.host}: {e}")
                print("[-] Verifique la conectividad de red y configuración de IP estática")
            else:
                print(f"[-] Error de red: {e}")
            self.connected = False
            return False
        except Exception as e:
            if "idna" in str(e).lower():
                print(f"[-] Formato de IP inválido: {self.host}")
                print("[-] Use una dirección IPv4 válida como 172.16.42.1")
            else:
                print(f"[-] Error de conexión SSH: {e}")
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
        """Start WiFi scanning through PineAP daemon (duration in sec; 0 for continuous)."""
        # Según la documentación, el scanning se maneja a través del daemon PineAP
        # No existe un comando directo 'run_scan' en /usr/bin/pineap
        # En su lugar, necesitamos usar la API o comandos específicos del daemon
        return self.execute('iwlist scan')  # Comando alternativo para escaneo WiFi

    def list_probes(self, config: str = '/tmp/pineap.conf') -> str:
        """List probe requests - usando comando alternativo ya que list_probes no existe en /usr/bin/pineap"""
        # La documentación no muestra list_probes como comando válido
        # Usamos un comando alternativo para obtener información de probes
        return self.execute('cat /tmp/pineap_probes.log 2>/dev/null || echo "No probe data available"')

    def stop_scan(self, config: str = '/tmp/pineap.conf') -> str:
        """Stop WiFi scanning - comando no disponible en /usr/bin/pineap"""
        # No existe stop_scan en la documentación real
        return self.execute('killall iwlist 2>/dev/null || echo "No scan process to stop"')

    def pause_scan(self, config: str = '/tmp/pineap.conf') -> str:
        """Pause WiFi scanning - comando no disponible en /usr/bin/pineap"""
        # No existe pause_scan en la documentación real
        return self.execute('echo "Pause scan not supported by current PineAP implementation"')

    def unpause_scan(self, config: str = '/tmp/pineap.conf') -> str:
        """Resume WiFi scanning - comando no disponible en /usr/bin/pineap"""
        # No existe unpause_scan en la documentación real
        return self.execute('echo "Unpause scan not supported by current PineAP implementation"')

    def get_scan_results(self, config: str = '/tmp/pineap.conf') -> str:
        """Get WiFi scan results - usando comando alternativo"""
        # No existe get_scan_results en /usr/bin/pineap según la documentación
        # Usamos iwlist para obtener resultados de escaneo
        return self.execute('iwlist wlan0 scan | grep -E "(ESSID|Address|Channel|Quality)" || echo "No scan results available"')

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
        """Control PineAP logging - comando válido según documentación"""
        return self.run_pineap(config, 'logging', 'on' if on else 'off')

    def connect_notifications(self, on: bool, config: str = '/tmp/pineap.conf') -> str:
        """Control connection notifications - comando válido según documentación"""
        action = 'connect_notifications' if on else 'disconnect_notifications'
        return self.run_pineap(config, action)

    def pineap_help(self) -> str:
        """Get PineAP help - verificar si el comando help existe"""
        return self.execute('/usr/bin/pineap help 2>/dev/null || echo "PineAP help not available"')
    
    def run_command(self, command: str, timeout: int = 30) -> str:
        """Execute a command on the Pineapple device and return the output."""
        return self.execute(command, timeout)
