"""Minimal Tkinter GUI to control PineappleSSH"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from pathlib import Path
from src.core.pineapple import PineappleSSH
from src.core.module_manager import get_default_manager
from src.core.modules import Request

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pineapple Desktop")
        self.geometry("700x480")
        self._build()
        self.pine = None
        # Integraciones locales
        from src.core.capture import CaptureManager
        from src.core.burp import BurpForwarder
        self.capture = CaptureManager(Path.cwd())
        self.burp = BurpForwarder()
        # Module/Request manager
        self.manager = get_default_manager()

    def _build(self):
        frame = ttk.Frame(self)
        frame.pack(fill='both', expand=True, padx=12, pady=12)

        # Connection row
        ttk.Label(frame, text="Pineapple Host:").grid(column=0, row=0, sticky='w')
        self.host_var = tk.StringVar(value='172.16.42.1')
        ttk.Entry(frame, textvariable=self.host_var).grid(column=1, row=0, sticky='ew')

        ttk.Label(frame, text="User:").grid(column=0, row=1, sticky='w')
        self.user_var = tk.StringVar(value='root')
        ttk.Entry(frame, textvariable=self.user_var).grid(column=1, row=1, sticky='ew')

        ttk.Label(frame, text="Password:").grid(column=0, row=2, sticky='w')
        self.pass_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.pass_var, show='*').grid(column=1, row=2, sticky='ew')

        self.connect_btn = ttk.Button(frame, text='Connect', command=self.toggle_connect)
        self.connect_btn.grid(column=0, row=3, columnspan=2, sticky='ew')

        # Notebook for features
        self.notebook = ttk.Notebook(frame)
        self.notebook.grid(column=0, row=4, columnspan=2, sticky='nsew', pady=(8,0))

        # Scan tab
        scan_frame = ttk.Frame(self.notebook)
        ttk.Button(scan_frame, text='Start Scan (run_scan)', command=self.cmd_run_scan).pack(fill='x', padx=6, pady=6)
        ttk.Button(scan_frame, text='List Probes', command=self.cmd_list_probes).pack(fill='x', padx=6, pady=6)
        self.notebook.add(scan_frame, text='Scan')

        # Attack tab
        attack_frame = ttk.Frame(self.notebook)
        ttk.Label(attack_frame, text='Deauth target MAC:').pack(anchor='w', padx=6)
        self.deauth_mac = tk.StringVar()
        ttk.Entry(attack_frame, textvariable=self.deauth_mac).pack(fill='x', padx=6)
        ttk.Button(attack_frame, text='Deauth', command=self.cmd_deauth).pack(fill='x', padx=6, pady=6)
        self.notebook.add(attack_frame, text='Attack')

        # Capture tab (acciones en el Pineapple)
        capture_frame = ttk.Frame(self.notebook)
        ttk.Button(capture_frame, text='Handshake Capture Start', command=self.cmd_handshake_start).pack(fill='x', padx=6, pady=6)
        ttk.Button(capture_frame, text='Handshake Capture Stop', command=self.cmd_handshake_stop).pack(fill='x', padx=6, pady=6)
        ttk.Button(capture_frame, text='Download /tmp/handshake.cap', command=self.cmd_download_handshake).pack(fill='x', padx=6, pady=6)
        self.notebook.add(capture_frame, text='Capture')

        # PCAP tab (captura local con TShark)
        pcap_frame = ttk.Frame(self.notebook)
        pcap_top = ttk.Frame(pcap_frame)
        pcap_top.pack(fill='x', padx=6, pady=6)
        ttk.Label(pcap_top, text='Interfaces (tshark -D):').grid(column=0, row=0, sticky='w')
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(pcap_top, textvariable=self.iface_var, values=[])
        self.iface_combo.grid(column=1, row=0, sticky='ew', padx=6)
        ttk.Button(pcap_top, text='Listar interfaces', command=self.cmd_list_ifaces).grid(column=2, row=0, padx=6)

        ttk.Label(pcap_top, text='Duración (s):').grid(column=0, row=1, sticky='w', pady=(6,0))
        self.duration_var = tk.IntVar(value=60)
        ttk.Spinbox(pcap_top, from_=0, to=3600, textvariable=self.duration_var, width=6).grid(column=1, row=1, sticky='w', padx=6, pady=(6,0))

        ttk.Label(pcap_top, text='Archivo:').grid(column=0, row=2, sticky='w', pady=(6,0))
        self.pcap_name_var = tk.StringVar(value='capture.pcapng')
        ttk.Entry(pcap_top, textvariable=self.pcap_name_var).grid(column=1, row=2, sticky='ew', padx=6, pady=(6,0))

        pcap_btns = ttk.Frame(pcap_frame)
        pcap_btns.pack(fill='x', padx=6, pady=6)
        ttk.Button(pcap_btns, text='Start TShark', command=self.cmd_start_tshark).pack(side='left', padx=4)
        ttk.Button(pcap_btns, text='Stop TShark', command=self.cmd_stop_tshark).pack(side='left', padx=4)

        self.notebook.add(pcap_frame, text='PCAP')

        # Burp tab
        burp_frame = ttk.Frame(self.notebook)
        burp_top = ttk.Frame(burp_frame)
        burp_top.pack(fill='x', padx=6, pady=6)
        ttk.Label(burp_top, text='Proxy URL:').grid(column=0, row=0, sticky='w')
        self.burp_proxy_var = tk.StringVar(value='http://127.0.0.1:8080')
        ttk.Entry(burp_top, textvariable=self.burp_proxy_var).grid(column=1, row=0, sticky='ew', padx=6)
        ttk.Button(burp_top, text='Aplicar', command=self.cmd_burp_set_proxy).grid(column=2, row=0, padx=6)

        ttk.Label(burp_top, text='URL destino:').grid(column=0, row=1, sticky='w', pady=(6,0))
        self.burp_url_var = tk.StringVar(value='http://example.com/')
        ttk.Entry(burp_top, textvariable=self.burp_url_var).grid(column=1, row=1, sticky='ew', padx=6, pady=(6,0))
        burp_btns = ttk.Frame(burp_frame)
        burp_btns.pack(fill='x', padx=6, pady=6)
        ttk.Button(burp_btns, text='GET via Burp', command=self.cmd_burp_get).pack(side='left', padx=4)
        ttk.Button(burp_btns, text='POST via Burp', command=self.cmd_burp_post).pack(side='left', padx=4)

        self.notebook.add(burp_frame, text='Burp')

        # Logs tab
        logs_frame = ttk.Frame(self.notebook)
        ttk.Label(logs_frame, text='Output:').pack(anchor='w', padx=6, pady=(6,0))
        self.output = tk.Text(logs_frame, height=12)
        self.output.pack(fill='both', expand=True, padx=6, pady=6)
        self.notebook.add(logs_frame, text='Logs')

        # Disable tabs until connected (solo deshabilito las tabs de Pineapple)
        for i, label in enumerate(['Scan', 'Attack', 'Capture']):
            self.notebook.tab(i, state='disabled')

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

    def toggle_connect(self):
        if not self.pine or not self.pine.connected:
            self.pine = PineappleSSH(self.host_var.get(), self.user_var.get(), self.pass_var.get())
            ok = self.pine.connect()
            if ok:
                self.connect_btn.configure(text='Disconnect')
                self.append_output('[+] Connected')
                # enable all tabs
                for i in range(self.notebook.index('end')):
                    self.notebook.tab(i, state='normal')
                # Auto-init PineAP: start daemon, logging on, run_scan 0 2
                req = Request('pineapple', 'init_pineap', pine=self.pine, logging=True, notifications=False, duration=0, frequencies=2)
                payload, ok = self.manager.handle(req)
                self.append_output(payload if ok else f"[-] init_pineap error: {payload}")
            else:
                messagebox.showerror('Error', 'Failed to connect')
        else:
            self.pine.close()
            self.append_output('[+] Disconnected')
            self.connect_btn.configure(text='Connect')
            for i in range(self.notebook.index('end')):
                self.notebook.tab(i, state='disabled')

    # --- Commands bound to UI -------------------------------------------------
    def cmd_run_scan(self):
        if not self.pine or not self.pine.connected:
            messagebox.showerror('Error', 'Not connected')
            return
        req = Request('pineapple', 'run_scan', pine=self.pine, duration=0, frequencies=2)
        payload, ok = self.manager.handle(req)
        self.append_output(payload if ok else f"[-] run_scan error: {payload}")

    def cmd_list_probes(self):
        if not self.pine or not self.pine.connected:
            messagebox.showerror('Error', 'Not connected')
            return
        req = Request('pineapple', 'list_probes', pine=self.pine)
        payload, ok = self.manager.handle(req)
        self.append_output(payload if ok else f"[-] list_probes error: {payload}")

    def cmd_handshake_start(self):
        if not self.pine or not self.pine.connected:
            messagebox.showerror('Error', 'Not connected')
            return
        bssid = tk.simpledialog.askstring('BSSID', 'Enter target BSSID')
        channel = tk.simpledialog.askinteger('Channel', 'Enter channel', initialvalue=1)
        if not bssid or not channel:
            return
        req = Request('pineapple', 'handshake_capture_start', pine=self.pine, bssid=bssid, channel=channel)
        payload, ok = self.manager.handle(req)
        self.append_output(payload if ok else f"[-] handshake_start error: {payload}")

    def cmd_handshake_stop(self):
        if not self.pine or not self.pine.connected:
            messagebox.showerror('Error', 'Not connected')
            return
        req = Request('pineapple', 'handshake_capture_stop', pine=self.pine)
        payload, ok = self.manager.handle(req)
        self.append_output(payload if ok else f"[-] handshake_stop error: {payload}")

    def cmd_download_handshake(self):
        if not self.pine or not self.pine.connected:
            messagebox.showerror('Error', 'Not connected')
            return
        local = str(Path.cwd() / 'handshake.cap')
        req = Request('pineapple', 'download_file', pine=self.pine, remote_path='/tmp/handshake.cap', local_path=local)
        payload, ok = self.manager.handle(req)
        if ok:
            self.append_output(f"[+] Downloaded to {payload.get('local_path', local)}")
        else:
            self.append_output(f"[-] Failed to download: {payload}")

    def cmd_deauth(self):
        if not self.pine or not self.pine.connected:
            messagebox.showerror('Error', 'Not connected')
            return
        mac = self.deauth_mac.get().strip()
        if not mac:
            messagebox.showerror('Error', 'Enter target MAC')
            return
        req = Request('pineapple', 'deauth', pine=self.pine, mac=mac, bssid='ff:ff:ff:ff:ff:ff', channel=6, multiplier=1)
        payload, ok = self.manager.handle(req)
        self.append_output(payload if ok else f"[-] deauth error: {payload}")

    # --- Comandos TShark / PCAP ---
    def cmd_list_ifaces(self):
        try:
            lines = self.capture.list_interfaces()
        except Exception as e:
            self.append_output(f'[-] Error list_interfaces: {e}')
            return
        if not lines:
            self.append_output('[-] tshark no disponible o sin interfaces.')
            return
        self.iface_combo['values'] = lines
        if lines:
            # Por defecto seleccionar la primera línea / id "1"
            self.iface_var.set(lines[0])
        self.append_output('[+] Interfaces actualizadas.')

    def cmd_start_tshark(self):
        iface = self.iface_var.get().strip()
        if not iface:
            tk.messagebox.showerror('Error', 'Seleccione una interfaz (ej. "1. ...")')
            return
        # tshark acepta índice (número) o nombre. Intentamos extraer el índice si viene "N. ..."
        if '.' in iface.split(' ')[0]:
            try:
                iface = iface.split('.')[0]  # "1. Intel ..." -> "1"
            except Exception:
                pass
        filename = self.pcap_name_var.get().strip() or 'capture.pcapng'
        duration = int(self.duration_var.get())
        try:
            path = self.capture.start_tshark(iface, filename=filename, duration=duration if duration > 0 else None)
            self.append_output(f'[+] TShark iniciado -> {path}')
        except FileNotFoundError:
            tk.messagebox.showerror('Error', 'tshark no está instalado o no está en PATH.')
        except Exception as e:
            tk.messagebox.showerror('Error', str(e))

    def cmd_stop_tshark(self):
        try:
            self.capture.stop()
            self.append_output('[+] TShark detenido.')
        except Exception as e:
            self.append_output(f'[-] Error al detener TShark: {e}')

    # --- Comandos Burp ---
    def cmd_burp_set_proxy(self):
        proxy_url = self.burp_proxy_var.get().strip()
        try:
            self.burp.proxy = {'http': proxy_url, 'https': proxy_url}
            self.append_output(f'[+] Proxy Burp actualizado: {proxy_url}')
        except Exception as e:
            self.append_output(f'[-] Error actualizando proxy: {e}')

    def cmd_burp_get(self):
        if not self.burp:
            self.append_output('[-] BurpForwarder no inicializado.')
            return
        url = self.burp_url_var.get().strip()
        try:
            resp = self.burp.forward_get(url)
            self.append_output(f'[GET {url}] -> {resp.status_code}, {len(resp.content)} bytes')
        except Exception as e:
            self.append_output(f'[-] Error GET via Burp: {e}')

    def cmd_burp_post(self):
        if not self.burp:
            self.append_output('[-] BurpForwarder no inicializado.')
            return
        url = self.burp_url_var.get().strip()
        # Para demo: pedir JSON simple
        data = simpledialog.askstring('POST body', 'JSON body (opcional):')
        json_body = None
        if data:
            try:
                import json as _json
                json_body = _json.loads(data)
            except Exception:
                self.append_output('[-] JSON inválido. Enviando como form data.')
                json_body = None
        try:
            if json_body is not None:
                resp = self.burp.forward_post(url, json=json_body)
            else:
                resp = self.burp.forward_post(url, data={'demo': '1'})
            self.append_output(f'[POST {url}] -> {resp.status_code}, {len(resp.content)} bytes')
        except Exception as e:
            self.append_output(f'[-] Error POST via Burp: {e}')
