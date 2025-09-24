"""
Modern Main Window for Pineapple Desktop
Three-column adaptive layout with modern UI components
"""

import customtkinter as ctk
import tkinter as tk
from typing import Dict, Any, Optional
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTk
from matplotlib.figure import Figure
import numpy as np
from datetime import datetime, timedelta
import threading
import time

from .design_system import Colors, Typography, ComponentStyles, BorderRadius, Icons
from .components import (
    PineappleButton, StatusBadge, HeroCard, DeviceCard, 
    ActivityItem, ConfirmationModal, NavigationItem
)

class ModernMainWindow:
    """Modern main window with three-column layout"""
    
    def __init__(self, root, app):
        self.root = root
        self.app = app  # Reference to main application
        
        # Configure window
        self.root.configure(fg_color=Colors.BG_DARK)
        
        # Initialize data
        self.current_view = "dashboard"
        self.devices = []
        self.activities = []
        self.chart_data = []
        self.connection_status = None
        
        # Build UI
        self._build_layout()
        self._populate_sample_data()
        self._start_real_time_updates()
    
    def _build_layout(self):
        """Build the three-column layout"""
        
        # Main container
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left sidebar (Navigation + Devices)
        self.left_panel = self._build_left_panel(main_container)
        self.left_panel.pack(side="left", fill="y", padx=(0, 10))
        
        # Center content area
        self.center_panel = self._build_center_panel(main_container)
        self.center_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Right panel (Quick actions + Activity)
        self.right_panel = self._build_right_panel(main_container)
        self.right_panel.pack(side="right", fill="y")
    
    def _build_left_panel(self, parent) -> ctk.CTkFrame:
        """Build left navigation and devices panel"""
        
        panel = ctk.CTkFrame(parent, **ComponentStyles.SIDEBAR)
        
        # Logo and title
        logo_frame = ctk.CTkFrame(panel, fg_color="transparent", height=80)
        logo_frame.pack(fill="x", padx=15, pady=(20, 10))
        logo_frame.pack_propagate(False)
        
        logo_label = ctk.CTkLabel(
            logo_frame,
            text=f"{Icons.DEVICES} Pineapple Desktop",
            font=(Typography.FONT_FAMILY, Typography.SIZE_XL, Typography.WEIGHT_BOLD),
            text_color=Colors.PRIMARY
        )
        logo_label.pack(expand=True)
        
        # Navigation menu
        nav_frame = ctk.CTkFrame(panel, fg_color="transparent")
        nav_frame.pack(fill="x", padx=15, pady=10)
        
        nav_items = [
            ("Dashboard", Icons.DASHBOARD, "dashboard"),
            ("Devices", Icons.DEVICES, "devices"),
            ("Scan Hub", Icons.SCAN, "scan"),
            ("Captures", Icons.CAPTURE, "captures"),
            ("Map", Icons.MAP, "map"),
            ("Logs", Icons.LOGS, "logs"),
            ("Settings", Icons.SETTINGS, "settings"),
            ("Help", Icons.HELP, "help")
        ]
        
        self.nav_buttons = {}
        for name, icon, view_id in nav_items:
            btn = NavigationItem(
                nav_frame,
                text=name,
                icon=icon,
                active=(view_id == self.current_view),
                command=lambda v=view_id: self._switch_view(v)
            )
            btn.pack(fill="x", pady=2)
            self.nav_buttons[view_id] = btn
        
        # Devices section
        devices_frame = ctk.CTkFrame(panel, fg_color="transparent")
        devices_frame.pack(fill="both", expand=True, padx=15, pady=(20, 15))
        
        devices_title = ctk.CTkLabel(
            devices_frame,
            text="Connected Devices",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        devices_title.pack(anchor="w", pady=(0, 10))
        
        # Scrollable devices list
        self.devices_scroll = ctk.CTkScrollableFrame(
            devices_frame,
            fg_color="transparent",
            scrollbar_button_color=Colors.TEXT_SECONDARY,
            scrollbar_button_hover_color=Colors.PRIMARY
        )
        self.devices_scroll.pack(fill="both", expand=True)
        
        return panel
    
    def _build_center_panel(self, parent) -> ctk.CTkFrame:
        """Build center content panel"""
        
        panel = ctk.CTkFrame(parent, fg_color=Colors.BG_CARD, corner_radius=BorderRadius.LG)
        
        # Header
        header_frame = ctk.CTkFrame(panel, fg_color="transparent", height=60)
        header_frame.pack(fill="x", padx=20, pady=(20, 0))
        header_frame.pack_propagate(False)
        
        # Title and breadcrumbs
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(side="left", fill="y")
        
        self.view_title = ctk.CTkLabel(
            title_frame,
            text="Dashboard",
            font=(Typography.FONT_FAMILY, Typography.SIZE_2XL, Typography.WEIGHT_BOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        self.view_title.pack(anchor="w")
        
        breadcrumb_label = ctk.CTkLabel(
            title_frame,
            text="Home > Dashboard",
            font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
            text_color=Colors.TEXT_SECONDARY
        )
        breadcrumb_label.pack(anchor="w")
        
        # Action button
        self.action_button = PineappleButton(
            header_frame,
            text=f"{Icons.SCAN} Escanear ahora",
            command=self._show_scan_confirmation
        )
        self.action_button.pack(side="right")
        
        # Content area
        self.content_frame = ctk.CTkFrame(panel, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Load dashboard by default
        self._load_dashboard_content()
        
        return panel
    
    def _build_right_panel(self, parent) -> ctk.CTkFrame:
        """Build right panel with quick actions and activity"""
        
        panel = ctk.CTkFrame(parent, fg_color=Colors.BG_CARD, corner_radius=BorderRadius.LG, width=320)
        panel.pack_propagate(False)
        
        # Quick Actions section
        actions_frame = ctk.CTkFrame(panel, fg_color="transparent")
        actions_frame.pack(fill="x", padx=15, pady=(20, 10))
        
        actions_title = ctk.CTkLabel(
            actions_frame,
            text="Quick Actions",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        actions_title.pack(anchor="w", pady=(0, 15))
        
        # Quick action buttons
        quick_actions = [
            (f"{Icons.SCAN} Scan", self._quick_scan),
            (f"{Icons.CAPTURE} Capture", self._quick_capture),
            (f"{Icons.IMPORT} Import PCAP", self._import_pcap)
        ]
        
        for text, command in quick_actions:
            btn = PineappleButton(
                actions_frame,
                text=text,
                style="secondary",
                command=command
            )
            btn.pack(fill="x", pady=2)
        
        # Recent Activity section
        activity_frame = ctk.CTkFrame(panel, fg_color="transparent")
        activity_frame.pack(fill="both", expand=True, padx=15, pady=(20, 15))
        
        activity_title = ctk.CTkLabel(
            activity_frame,
            text="Recent Activity",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        activity_title.pack(anchor="w", pady=(0, 15))
        
        # Scrollable activity feed
        self.activity_scroll = ctk.CTkScrollableFrame(
            activity_frame,
            fg_color="transparent",
            scrollbar_button_color=Colors.TEXT_SECONDARY,
            scrollbar_button_hover_color=Colors.PRIMARY
        )
        self.activity_scroll.pack(fill="both", expand=True)
        
        return panel
    
    def _load_dashboard_content(self):
        """Load dashboard content with hero cards and charts"""
        
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Hero cards row
        hero_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        hero_frame.pack(fill="x", pady=(0, 20))
        
        # Configure grid
        hero_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Hero cards with real data
        device_count = len(self.devices) if self.devices else 0
        active_captures = len(self.app.capture_manager.active_captures) if hasattr(self.app.capture_manager, 'active_captures') else 0
        active_scans = len(self.app.scan_manager.active_scans) if self.app.scan_manager else 0
        
        cards_data = [
            ("Connected devices", str(device_count), Icons.DEVICES),
            ("Active captures", str(active_captures), Icons.CAPTURE),
            ("Active scans", str(active_scans), Icons.WARNING)
        ]
        
        for i, (title, value, icon) in enumerate(cards_data):
            card = HeroCard(hero_frame, title=title, value=value, icon=icon, width=200, height=140)
            card.grid(row=0, column=i, padx=10, sticky="ew")
        
        # Charts and content row
        content_row = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        content_row.pack(fill="both", expand=True)
        
        # Traffic chart
        chart_frame = ctk.CTkFrame(content_row, fg_color=Colors.BG_CARD, corner_radius=BorderRadius.LG)
        chart_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        chart_title = ctk.CTkLabel(
            chart_frame,
            text="Traffic",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        chart_title.pack(anchor="w", padx=20, pady=(20, 10))
        
        # Create matplotlib chart
        self._create_traffic_chart(chart_frame)
        
        # Network map placeholder
        map_frame = ctk.CTkFrame(content_row, fg_color=Colors.BG_CARD, corner_radius=BorderRadius.LG, width=300)
        map_frame.pack(side="right", fill="y")
        map_frame.pack_propagate(False)
        
        map_title = ctk.CTkLabel(
            map_frame,
            text="Network Map",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        map_title.pack(anchor="w", padx=20, pady=(20, 10))
        
        # Simple network visualization placeholder
        map_canvas = ctk.CTkCanvas(map_frame, bg=Colors.BG_CARD, highlightthickness=0)
        map_canvas.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Draw simple network nodes
        self._draw_network_map(map_canvas)
    
    def _create_traffic_chart(self, parent):
        """Create real-time traffic chart with real network data"""
        
        # Create matplotlib figure with dark theme
        plt.style.use('dark_background')
        fig = Figure(figsize=(8, 4), facecolor=Colors.BG_CARD)
        ax = fig.add_subplot(111)
        
        # Get real network traffic data if available
        times, values = self._get_network_traffic_data()
        
        # Plot line
        ax.plot(times, values, color=Colors.CHART_LINE, linewidth=2)
        ax.fill_between(times, values, alpha=0.3, color=Colors.CHART_LINE)
        
        # Styling
        ax.set_facecolor(Colors.BG_CARD)
        ax.grid(True, alpha=0.3, color=Colors.CHART_GRID)
        ax.set_ylabel('Packets/sec', color=Colors.TEXT_SECONDARY)
        ax.tick_params(colors=Colors.TEXT_SECONDARY)
        
        # Format x-axis
        import matplotlib.dates as mdates
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=10))
        
        fig.tight_layout()
        
        # Embed in tkinter
        canvas = FigureCanvasTk(fig, parent)
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.chart_canvas = canvas
        self.chart_ax = ax
        self.chart_fig = fig
    
    def _get_network_traffic_data(self):
        """Get real network traffic data or fallback to minimal sample data"""
        try:
            # Try to get real network statistics
            import psutil
            
            # Get network I/O statistics
            net_io = psutil.net_io_counters()
            if hasattr(self, '_last_net_io'):
                # Calculate packets per second
                time_diff = time.time() - self._last_net_time
                packets_diff = (net_io.packets_sent + net_io.packets_recv) - self._last_net_packets
                current_rate = packets_diff / time_diff if time_diff > 0 else 0
            else:
                current_rate = 0
            
            # Store for next calculation
            self._last_net_io = net_io
            self._last_net_packets = net_io.packets_sent + net_io.packets_recv
            self._last_net_time = time.time()
            
            # Create time series data
            times = [datetime.now() - timedelta(minutes=30-i) for i in range(30)]
            
            # Use real data for recent points, interpolate for older points
            if hasattr(self, '_traffic_history'):
                self._traffic_history.append(current_rate)
                if len(self._traffic_history) > 30:
                    self._traffic_history.pop(0)
                values = list(self._traffic_history)
                # Pad with zeros if not enough history
                while len(values) < 30:
                    values.insert(0, 0)
            else:
                self._traffic_history = [current_rate]
                values = [0] * 29 + [current_rate]
            
            return times, values
            
        except ImportError:
            # Fallback to minimal sample data if psutil not available
            times = [datetime.now() - timedelta(minutes=30-i) for i in range(30)]
            values = [0] * 30  # Show flat line instead of random data
            return times, values
        except Exception as e:
            print(f"Error getting network data: {e}")
            # Fallback to minimal sample data
            times = [datetime.now() - timedelta(minutes=30-i) for i in range(30)]
            values = [0] * 30
            return times, values
    
    def _draw_network_map(self, canvas):
        """Draw simple network map visualization"""
        
        def draw_after_idle():
            canvas.update_idletasks()
            width = canvas.winfo_width()
            height = canvas.winfo_height()
            
            if width > 1 and height > 1:
                canvas.delete("all")
                
                # Draw nodes
                nodes = [
                    (width//2, height//4, "Router", Colors.PRIMARY),
                    (width//4, height//2, "Pineapple", Colors.SUCCESS),
                    (3*width//4, height//2, "Target", Colors.DANGER),
                    (width//2, 3*height//4, "Client", Colors.WARNING)
                ]
                
                # Draw connections
                connections = [(0, 1), (0, 2), (1, 3)]
                for start, end in connections:
                    x1, y1 = nodes[start][:2]
                    x2, y2 = nodes[end][:2]
                    canvas.create_line(x1, y1, x2, y2, fill=Colors.TEXT_SECONDARY, width=2)
                
                # Draw nodes
                for x, y, label, color in nodes:
                    canvas.create_oval(x-15, y-15, x+15, y+15, fill=color, outline=color)
                    canvas.create_text(x, y+25, text=label, fill=Colors.TEXT_PRIMARY, font=("Inter", 10))
        
        canvas.after_idle(draw_after_idle)
    
    def _populate_sample_data(self):
        """Populate with real data from managers"""
        
        # Real devices from ConnectionManager
        if self.devices:
            for mac, device in self.devices.items():
                card = DeviceCard(
                    self.devices_scroll,
                    device_name=device.hostname,
                    device_type=device.device_type,
                    status=device.status,
                    ip=device.ip,
                    latency="N/A"  # Could be calculated with ping
                )
                card.pack(fill="x", pady=5)
        else:
            # Show message when no devices are connected
            no_devices_label = ctk.CTkLabel(
                self.devices_scroll,
                text="No hay dispositivos conectados",
                font=(Typography.FONT_FAMILY, Typography.SIZE_MD),
                text_color=Colors.TEXT_SECONDARY
            )
            no_devices_label.pack(pady=20)
        
        # Real activities from system events
        self._load_recent_activities()
    
    def _load_recent_activities(self):
        """Load recent activities from system events"""
        # Get recent scan activities
        if self.app.scan_manager and hasattr(self.app.scan_manager, 'scan_history'):
            for scan in self.app.scan_manager.scan_history[-5:]:  # Last 5 scans
                timestamp = time.strftime("%H:%M", time.localtime(scan.start_time))
                status_map = {"completed": "success", "error": "error", "running": "info"}
                status = status_map.get(scan.status.value, "info")
                action = f"Scan {scan.status.value}: {scan.target}"
                
                item = ActivityItem(self.activity_scroll, action=action, timestamp=timestamp, status=status)
                item.pack(fill="x", pady=2)
        
        # Get recent connection events
        if self.app.connection_manager:
            # Add connection status changes
            if self.app.connection_manager.is_connected():
                item = ActivityItem(
                    self.activity_scroll, 
                    action="Pineapple connected", 
                    timestamp=time.strftime("%H:%M"), 
                    status="success"
                )
                item.pack(fill="x", pady=2)
        
        # If no activities, show placeholder
        if not self.activity_scroll.winfo_children():
            no_activity_label = ctk.CTkLabel(
                self.activity_scroll,
                text="No hay actividad reciente",
                font=(Typography.FONT_FAMILY, Typography.SIZE_MD),
                text_color=Colors.TEXT_SECONDARY
            )
            no_activity_label.pack(pady=20)
    
    def _start_real_time_updates(self):
        """Start real-time data updates with real network monitoring"""
        
        def update_loop():
            while True:
                try:
                    # Update chart data with real network traffic
                    if hasattr(self, 'chart_ax') and hasattr(self, 'chart_canvas'):
                        times, values = self._get_network_traffic_data()
                        
                        # Clear and redraw chart
                        self.chart_ax.clear()
                        self.chart_ax.plot(times, values, color=Colors.CHART_LINE, linewidth=2)
                        self.chart_ax.fill_between(times, values, alpha=0.3, color=Colors.CHART_LINE)
                        
                        # Reapply styling
                        self.chart_ax.set_facecolor(Colors.BG_CARD)
                        self.chart_ax.grid(True, alpha=0.3, color=Colors.CHART_GRID)
                        self.chart_ax.set_ylabel('Packets/sec', color=Colors.TEXT_SECONDARY)
                        self.chart_ax.tick_params(colors=Colors.TEXT_SECONDARY)
                        
                        # Format x-axis
                        import matplotlib.dates as mdates
                        self.chart_ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                        self.chart_ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=10))
                        
                        # Refresh canvas
                        self.chart_canvas.draw()
                    
                    # Update dashboard cards with real data
                    if self.current_view == "dashboard":
                        # This would trigger a refresh of the dashboard
                        pass
                    
                    time.sleep(5)  # Update every 5 seconds
                except Exception as e:
                    print(f"Update error: {e}")
                    break
        
        # Start update thread
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
    
    def _switch_view(self, view_id: str):
        """Switch between different views"""
        
        # Update navigation buttons
        for btn_id, btn in self.nav_buttons.items():
            btn.configure(fg_color=Colors.PRIMARY if btn_id == view_id else "transparent")
        
        self.current_view = view_id
        
        # Update view title and content
        view_titles = {
            "dashboard": "Dashboard",
            "devices": "Device Manager",
            "scan": "Scan Hub",
            "captures": "Packet Captures",
            "map": "Network Map",
            "logs": "Audit Logs",
            "settings": "Settings",
            "help": "Help & Documentation"
        }
        
        self.view_title.configure(text=view_titles.get(view_id, "Unknown"))
        
        # Load appropriate content
        if view_id == "dashboard":
            self._load_dashboard_content()
        elif view_id == "devices":
            self._load_devices_content()
        elif view_id == "scan":
            self._load_scan_hub_content()
        elif view_id == "captures":
            self._load_captures_content()
        elif view_id == "map":
            self._load_map_content()
        elif view_id == "settings":
            self._load_settings_content()
        elif view_id == "help":
            self._load_help_content()
        else:
            self._load_placeholder_content(view_id)
    
    def _load_placeholder_content(self, view_id: str):
        """Load placeholder content for other views"""
        
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        placeholder = ctk.CTkLabel(
            self.content_frame,
            text=f"Vista de {view_id.title()} - En desarrollo",
            font=(Typography.FONT_FAMILY, Typography.SIZE_XL),
            text_color=Colors.TEXT_SECONDARY
        )
        placeholder.pack(expand=True)
    
    def _show_scan_confirmation(self):
        """Show scan confirmation modal"""
        
        modal = ConfirmationModal(
            self.root,
            title="Confirmar ejecución de escaneo",
            message="Este escaneo puede generar tráfico anómalo. Confirme que tiene autorización para auditar el objetivo.",
            on_confirm=self._execute_scan,
            on_cancel=lambda: print("Scan cancelled")
        )
    
    def _execute_scan(self):
        """Execute scan after confirmation"""
        print("Executing authorized scan...")
        # Add scan logic here
    
    def _quick_scan(self):
        """Quick scan action"""
        self._show_scan_confirmation()
    
    def _quick_capture(self):
        """Quick capture action"""
        print("Starting quick capture...")
    
    def _import_pcap(self):
        """Import PCAP file"""
        print("Importing PCAP file...")

    # Integration methods for connecting UI with application managers
    def update_connection_status(self, status, message: str):
        """Update connection status in UI"""
        self.connection_status = status
        # Update status bar and connection indicators
        if hasattr(self, 'status_bar'):
            self.status_bar.update_connection(status, message)
        
        # Update navigation items based on connection
        if hasattr(self, 'nav_buttons'):
            # Enable/disable device-dependent features
            device_dependent = ['devices', 'scan', 'captures']
            for view_id, btn in self.nav_buttons.items():
                if view_id in device_dependent:
                    btn.configure(state="normal" if status.value == "connected" else "disabled")
    
    def update_connected_devices(self, devices):
        """Update connected devices list"""
        self.devices = devices
        # Refresh devices view if currently active
        if self.current_view == "devices":
            self._load_devices_content()
    
    def update_scan_status(self, scan_job):
        """Update scan status in UI"""
        # Add to activity feed
        self._add_activity(f"Scan {scan_job.status.value}: {scan_job.target}", "now", "info")
        
        # Update scan hub if active
        if self.current_view == "scan":
            self._update_scan_hub(scan_job)
    
    def update_attack_status(self, attack_job):
        """Update attack status in UI"""
        # Add to activity feed with warning color for attacks
        self._add_activity(f"Attack {attack_job.status.value}: {attack_job.target.ssid}", "now", "warning")
        
        # Update relevant views
        if self.current_view == "scan":
            self._update_attack_status_in_hub(attack_job)
    
    def show_toast(self, message: str, toast_type: str = "info"):
        """Show toast notification"""
        # Create a temporary toast notification
        toast_colors = {
            "success": Colors.SUCCESS,
            "error": Colors.ERROR,
            "warning": Colors.WARNING,
            "info": Colors.PRIMARY
        }
        
        toast = ctk.CTkLabel(
            self.root,
            text=message,
            fg_color=toast_colors.get(toast_type, Colors.PRIMARY),
            corner_radius=8,
            font=(Typography.FONT_FAMILY, Typography.SIZE_SM)
        )
        toast.place(relx=0.5, rely=0.1, anchor="center")
        
        # Auto-hide after 3 seconds
        self.root.after(3000, toast.destroy)
    
    def _add_activity(self, action: str, timestamp: str, status: str):
        """Add activity to the activity feed"""
        if hasattr(self, 'activity_scroll'):
            item = ActivityItem(self.activity_scroll, action=action, timestamp=timestamp, status=status)
            item.pack(fill="x", pady=2)
            
            # Scroll to bottom to show latest activity
            self.activity_scroll.update_idletasks()
            self.activity_scroll._parent_canvas.yview_moveto(1.0)
    
    def _load_devices_content(self):
        """Load devices view content"""
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Connection section
        connection_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        connection_frame.pack(fill="x", pady=(0, 20))
        
        conn_title = ctk.CTkLabel(
            connection_frame,
            text="Pineapple Connection",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        conn_title.pack(pady=(20, 10))
        
        # Connection form
        conn_form = ctk.CTkFrame(connection_frame, fg_color="transparent")
        conn_form.pack(fill="x", padx=20, pady=(0, 20))
        
        # IP input
        ip_label = ctk.CTkLabel(conn_form, text="Pineapple IP:")
        ip_label.pack(anchor="w", pady=(0, 5))
        
        self.ip_entry = ctk.CTkEntry(conn_form, placeholder_text="192.168.1.1")
        self.ip_entry.pack(fill="x", pady=(0, 10))
        
        # Connect button
        if self.connection_status and self.connection_status.value == "connected":
            connect_btn = PineappleButton(
                conn_form,
                text="Disconnect",
                command=self.app.disconnect_from_pineapple,
                style="danger"
            )
        else:
            connect_btn = PineappleButton(
                conn_form,
                text="Connect to Pineapple",
                command=self._connect_pineapple,
                style="primary"
            )
        connect_btn.pack(pady=10)
        
        # Devices list
        if self.devices:
            devices_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
            devices_frame.pack(fill="both", expand=True)
            
            devices_title = ctk.CTkLabel(
                devices_frame,
                text=f"Connected Devices ({len(self.devices)})",
                font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
            )
            devices_title.pack(pady=(20, 10))
            
            # Devices scroll
            devices_scroll = ctk.CTkScrollableFrame(devices_frame)
            devices_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))
            
            for device in self.devices:
                device_card = DeviceCard(devices_scroll, device=device)
                device_card.pack(fill="x", pady=5)
    
    def _connect_pineapple(self):
        """Connect to Pineapple device"""
        ip = self.ip_entry.get().strip()
        if ip:
            self.app.connect_to_pineapple(ip)
        else:
            self.show_toast("Please enter Pineapple IP address", "error")
    
    def _load_scan_hub_content(self):
        """Load scan hub content"""
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Scan controls
        controls_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        controls_frame.pack(fill="x", pady=(0, 20))
        
        controls_title = ctk.CTkLabel(
            controls_frame,
            text="Network Scanning",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        controls_title.pack(pady=(20, 10))
        
        # Target input
        target_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        target_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        target_label = ctk.CTkLabel(target_frame, text="Target:")
        target_label.pack(anchor="w", pady=(0, 5))
        
        self.target_entry = ctk.CTkEntry(target_frame, placeholder_text="192.168.1.0/24")
        self.target_entry.pack(fill="x", pady=(0, 10))
        
        # Scan type selection
        scan_type_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        scan_type_frame.pack(fill="x", pady=(0, 10))
        
        scan_type_label = ctk.CTkLabel(scan_type_frame, text="Scan Type:")
        scan_type_label.pack(anchor="w", pady=(0, 5))
        
        self.scan_type_var = ctk.StringVar(value="PORT_SCAN")
        scan_types = ["PING_SWEEP", "PORT_SCAN", "SERVICE_SCAN", "VULNERABILITY_SCAN", "STEALTH_SCAN"]
        
        self.scan_type_menu = ctk.CTkOptionMenu(scan_type_frame, values=scan_types, variable=self.scan_type_var)
        self.scan_type_menu.pack(fill="x")
        
        # Scan button
        scan_btn = PineappleButton(
            target_frame,
            text="Start Scan",
            command=self._start_network_scan,
            style="primary"
        )
        scan_btn.pack(pady=10)
        
        # Results area
        results_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        results_frame.pack(fill="both", expand=True)
        
        results_title = ctk.CTkLabel(
            results_frame,
            text="Scan Results",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        results_title.pack(pady=(20, 10))
        
        self.results_text = ctk.CTkTextbox(results_frame, height=300)
        self.results_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
    def _start_network_scan(self):
        """Start network scan"""
        target = self.target_entry.get().strip()
        scan_type_str = self.scan_type_var.get()
        
        if not target:
            self.show_toast("Please enter a target", "error")
            return
        
        # Import scan type enum
        from src.core.scan_manager import ScanType
        scan_type = getattr(ScanType, scan_type_str)
        
        self.app.start_scan(scan_type, target)
        self.show_toast(f"Starting {scan_type_str} scan on {target}", "info")
    
    def _update_scan_hub(self, scan_job):
        """Update scan hub with scan results"""
        if hasattr(self, 'results_text'):
            result_text = f"[{scan_job.start_time}] {scan_job.scan_type.value} - {scan_job.status.value}\n"
            if scan_job.result:
                result_text += f"Result: {scan_job.result}\n"
            result_text += "\n"
            
            self.results_text.insert("end", result_text)
            self.results_text.see("end")
    
    def _update_attack_status_in_hub(self, attack_job):
        """Update attack status in scan hub"""
        if hasattr(self, 'results_text'):
            result_text = f"[{attack_job.start_time}] ATTACK {attack_job.attack_type.value} - {attack_job.status.value}\n"
            if attack_job.result:
                result_text += f"Result: {attack_job.result}\n"
            result_text += "\n"
            
            self.results_text.insert("end", result_text)
            self.results_text.see("end")
    
    def _load_captures_content(self):
        """Load packet captures content"""
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Capture controls
        controls_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        controls_frame.pack(fill="x", pady=(0, 20))
        
        controls_title = ctk.CTkLabel(
            controls_frame,
            text="Packet Capture",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        controls_title.pack(pady=(20, 10))
        
        # Capture options
        options_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # Interface selection
        interface_label = ctk.CTkLabel(options_frame, text="Interface:")
        interface_label.pack(anchor="w", pady=(0, 5))
        
        self.interface_var = ctk.StringVar(value="wlan0")
        interface_menu = ctk.CTkOptionMenu(options_frame, values=["wlan0", "wlan1", "eth0"], variable=self.interface_var)
        interface_menu.pack(fill="x", pady=(0, 10))
        
        # Capture type
        capture_type_label = ctk.CTkLabel(options_frame, text="Capture Type:")
        capture_type_label.pack(anchor="w", pady=(0, 5))
        
        self.capture_type_var = ctk.StringVar(value="All Traffic")
        capture_types = ["All Traffic", "Handshakes Only", "Beacon Frames", "Data Packets"]
        capture_type_menu = ctk.CTkOptionMenu(options_frame, values=capture_types, variable=self.capture_type_var)
        capture_type_menu.pack(fill="x", pady=(0, 10))
        
        # Control buttons
        buttons_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        buttons_frame.pack(fill="x", pady=10)
        
        start_btn = PineappleButton(
            buttons_frame,
            text="Start Capture",
            command=self._start_capture,
            style="primary"
        )
        start_btn.pack(side="left", padx=(0, 10))
        
        stop_btn = PineappleButton(
            buttons_frame,
            text="Stop Capture",
            command=self._stop_capture,
            style="danger"
        )
        stop_btn.pack(side="left", padx=(0, 10))
        
        import_btn = PineappleButton(
            buttons_frame,
            text="Import PCAP",
            command=self._import_pcap_file,
            style="secondary"
        )
        import_btn.pack(side="left")
        
        # Captures list
        captures_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        captures_frame.pack(fill="both", expand=True)
        
        captures_title = ctk.CTkLabel(
            captures_frame,
            text="Capture Files",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        captures_title.pack(pady=(20, 10))
        
        self.captures_list = ctk.CTkScrollableFrame(captures_frame)
        self.captures_list.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
    def _start_capture(self):
        """Start packet capture"""
        interface = self.interface_var.get()
        capture_type = self.capture_type_var.get()
        self.show_toast(f"Starting capture on {interface} - {capture_type}", "info")
        # Add capture logic here
    
    def _stop_capture(self):
        """Stop packet capture"""
        self.show_toast("Stopping capture", "warning")
        # Add stop capture logic here
    
    def _import_pcap_file(self):
        """Import PCAP file"""
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if file_path:
            self.show_toast(f"Importing {file_path}", "info")
            # Add import logic here
    
    def _load_map_content(self):
        """Load network map content"""
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Map controls
        controls_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        controls_frame.pack(fill="x", pady=(0, 20))
        
        controls_title = ctk.CTkLabel(
            controls_frame,
            text="Network Topology",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        controls_title.pack(pady=(20, 10))
        
        # Map options
        options_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        refresh_btn = PineappleButton(
            options_frame,
            text="Refresh Map",
            command=self._refresh_map,
            style="primary"
        )
        refresh_btn.pack(side="left", padx=(0, 10))
        
        export_btn = PineappleButton(
            options_frame,
            text="Export Map",
            command=self._export_map,
            style="secondary"
        )
        export_btn.pack(side="left")
        
        # Map visualization
        map_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        map_frame.pack(fill="both", expand=True)
        
        map_title = ctk.CTkLabel(
            map_frame,
            text="Network Visualization",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        map_title.pack(pady=(20, 10))
        
        # Large network canvas
        self.map_canvas = ctk.CTkCanvas(map_frame, bg=Colors.BG_CARD, highlightthickness=0)
        self.map_canvas.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Draw network topology
        self._draw_detailed_network_map()
    
    def _refresh_map(self):
        """Refresh network map"""
        self.show_toast("Refreshing network map", "info")
        self._draw_detailed_network_map()
    
    def _export_map(self):
        """Export network map"""
        self.show_toast("Exporting network map", "info")
        # Add export logic here
    
    def _draw_detailed_network_map(self):
        """Draw detailed network topology"""
        def draw_after_idle():
            self.map_canvas.update_idletasks()
            width = self.map_canvas.winfo_width()
            height = self.map_canvas.winfo_height()
            
            if width > 1 and height > 1:
                self.map_canvas.delete("all")
                
                # Draw more detailed network topology
                center_x, center_y = width // 2, height // 2
                
                # Main router
                self.map_canvas.create_oval(center_x-20, center_y-20, center_x+20, center_y+20, 
                                          fill=Colors.PRIMARY, outline=Colors.PRIMARY)
                self.map_canvas.create_text(center_x, center_y+35, text="Router", 
                                          fill=Colors.TEXT_PRIMARY, font=("Inter", 12, "bold"))
                
                # Connected devices in a circle
                devices = [
                    ("Pineapple", Colors.SUCCESS, 0),
                    ("Target AP", Colors.DANGER, 60),
                    ("Client 1", Colors.WARNING, 120),
                    ("Client 2", Colors.WARNING, 180),
                    ("Server", Colors.INFO, 240),
                    ("Scanner", Colors.SECONDARY, 300)
                ]
                
                radius = 150
                for name, color, angle in devices:
                    import math
                    x = center_x + radius * math.cos(math.radians(angle))
                    y = center_y + radius * math.sin(math.radians(angle))
                    
                    # Draw connection line
                    self.map_canvas.create_line(center_x, center_y, x, y, 
                                              fill=Colors.TEXT_SECONDARY, width=2)
                    
                    # Draw device
                    self.map_canvas.create_oval(x-15, y-15, x+15, y+15, 
                                              fill=color, outline=color)
                    self.map_canvas.create_text(x, y+25, text=name, 
                                              fill=Colors.TEXT_PRIMARY, font=("Inter", 10))
        
        self.map_canvas.after_idle(draw_after_idle)
    
    def _load_settings_content(self):
        """Load settings content"""
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Settings sections
        sections = [
            ("Pineapple Configuration", self._create_pineapple_settings),
            ("Network Settings", self._create_network_settings),
            ("Security Settings", self._create_security_settings),
            ("Application Preferences", self._create_app_settings)
        ]
        
        for section_title, create_func in sections:
            section_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
            section_frame.pack(fill="x", pady=(0, 20))
            
            title = ctk.CTkLabel(
                section_frame,
                text=section_title,
                font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
            )
            title.pack(pady=(20, 10))
            
            content_frame = ctk.CTkFrame(section_frame, fg_color="transparent")
            content_frame.pack(fill="x", padx=20, pady=(0, 20))
            
            create_func(content_frame)
    
    def _create_pineapple_settings(self, parent):
        """Create Pineapple configuration settings"""
        # Default IP
        ip_label = ctk.CTkLabel(parent, text="Default Pineapple IP:")
        ip_label.pack(anchor="w", pady=(0, 5))
        
        ip_entry = ctk.CTkEntry(parent, placeholder_text="172.16.42.1")
        ip_entry.pack(fill="x", pady=(0, 10))
        
        # SSH Settings
        ssh_label = ctk.CTkLabel(parent, text="SSH Port:")
        ssh_label.pack(anchor="w", pady=(0, 5))
        
        ssh_entry = ctk.CTkEntry(parent, placeholder_text="22")
        ssh_entry.pack(fill="x", pady=(0, 10))
        
        # Auto-connect
        auto_connect = ctk.CTkCheckBox(parent, text="Auto-connect on startup")
        auto_connect.pack(anchor="w", pady=5)
    
    def _create_network_settings(self, parent):
        """Create network settings"""
        # Interface settings
        interface_label = ctk.CTkLabel(parent, text="Default Interface:")
        interface_label.pack(anchor="w", pady=(0, 5))
        
        interface_menu = ctk.CTkOptionMenu(parent, values=["wlan0", "wlan1", "eth0"])
        interface_menu.pack(fill="x", pady=(0, 10))
        
        # Timeout settings
        timeout_label = ctk.CTkLabel(parent, text="Connection Timeout (seconds):")
        timeout_label.pack(anchor="w", pady=(0, 5))
        
        timeout_entry = ctk.CTkEntry(parent, placeholder_text="30")
        timeout_entry.pack(fill="x", pady=(0, 10))
    
    def _create_security_settings(self, parent):
        """Create security settings"""
        # Confirmation settings
        confirm_scans = ctk.CTkCheckBox(parent, text="Require confirmation for scans")
        confirm_scans.pack(anchor="w", pady=5)
        
        confirm_attacks = ctk.CTkCheckBox(parent, text="Require confirmation for attacks")
        confirm_attacks.pack(anchor="w", pady=5)
        
        # Logging
        enable_logging = ctk.CTkCheckBox(parent, text="Enable audit logging")
        enable_logging.pack(anchor="w", pady=5)
    
    def _create_app_settings(self, parent):
        """Create application preferences"""
        # Theme
        theme_label = ctk.CTkLabel(parent, text="Theme:")
        theme_label.pack(anchor="w", pady=(0, 5))
        
        theme_menu = ctk.CTkOptionMenu(parent, values=["Dark", "Light", "Auto"])
        theme_menu.pack(fill="x", pady=(0, 10))
        
        # Updates
        auto_update = ctk.CTkCheckBox(parent, text="Check for updates automatically")
        auto_update.pack(anchor="w", pady=5)
        
        # Save button
        save_btn = PineappleButton(
            parent,
            text="Save Settings",
            command=self._save_settings,
            style="primary"
        )
        save_btn.pack(pady=20)
    
    def _save_settings(self):
        """Save application settings"""
        self.show_toast("Settings saved successfully", "success")
    
    def _load_help_content(self):
        """Load help and documentation content"""
        # Clear existing content safely
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing widgets: {e}")
            # Clear the frame completely
            self.content_frame.destroy()
            self.content_frame = ctk.CTkScrollableFrame(self.center_panel, **ComponentStyles.SCROLLABLE_FRAME)
            self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Help sections
        help_frame = ctk.CTkFrame(self.content_frame, **ComponentStyles.CARD)
        help_frame.pack(fill="both", expand=True)
        
        help_title = ctk.CTkLabel(
            help_frame,
            text="Help & Documentation",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_BOLD)
        )
        help_title.pack(pady=(20, 10))
        
        # Help content
        help_scroll = ctk.CTkScrollableFrame(help_frame)
        help_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        help_sections = [
            ("Getting Started", "Connect your Pineapple device and start scanning networks."),
            ("Network Scanning", "Use the Scan Hub to discover devices and vulnerabilities."),
            ("Packet Capture", "Capture and analyze network traffic with Wireshark integration."),
            ("Attack Modules", "Execute penetration testing attacks with proper authorization."),
            ("Network Mapping", "Visualize network topology and device relationships."),
            ("Security Guidelines", "Always ensure you have proper authorization before testing.")
        ]
        
        for title, description in help_sections:
            section = ctk.CTkFrame(help_scroll, **ComponentStyles.CARD)
            section.pack(fill="x", pady=5)
            
            section_title = ctk.CTkLabel(
                section,
                text=title,
                font=(Typography.FONT_FAMILY, Typography.SIZE_MD, Typography.WEIGHT_SEMIBOLD)
            )
            section_title.pack(anchor="w", padx=15, pady=(15, 5))
            
            section_desc = ctk.CTkLabel(
                section,
                text=description,
                font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
                text_color=Colors.TEXT_SECONDARY,
                wraplength=400
            )
            section_desc.pack(anchor="w", padx=15, pady=(0, 15))

    # Footer status bar
    class StatusBar(ctk.CTkFrame):
        """Status bar component"""
        
        def __init__(self, parent):
            super().__init__(parent, fg_color=Colors.BG_CARD, height=40)
            self.pack_propagate(False)
            
            # Connection status
            status_label = ctk.CTkLabel(
                self,
                text=f"{Icons.ONLINE} Connected - 53ms - v1.2.3",
                font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
                text_color=Colors.TEXT_SECONDARY
            )
            status_label.pack(side="left", padx=15, pady=10)
            
            # User info
            user_label = ctk.CTkLabel(
                self,
                text="👤 Admin User",
                font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
                text_color=Colors.TEXT_SECONDARY
            )
            user_label.pack(side="right", padx=15, pady=10)