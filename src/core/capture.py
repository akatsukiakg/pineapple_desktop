"""Capture helpers (tshark/wireshark)"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import Optional

class CaptureManager:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.process: Optional[subprocess.Popen] = None

    def start_tshark(self, iface: str, filename: str = "capture.pcapng", duration: Optional[int] = None) -> Path:
        out_path = self.output_dir / filename
        cmd = ["tshark", "-i", str(iface), "-w", str(out_path)]
        if duration and duration > 0:
            # Compatible con Windows/Linux/macOS: límite por duración
            cmd += ["-a", f"duration:{int(duration)}"]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return out_path

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None

    def list_interfaces(self) -> list[str]:
        """Devuelve la lista de interfaces que reporta tshark -D."""
        try:
            res = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True)
            lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
            # Ejemplo de línea: "1. Intel(R) Wi-Fi 6 AX200 ..."
            return lines
        except FileNotFoundError:
            # tshark no está instalado o no está en PATH
            return []
        except Exception:
            return []

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None
