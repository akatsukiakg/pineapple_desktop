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

class ModernMainWindow(ctk.CTk):
    """Modern main window with three-column layout"""
    
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("Pineapple Desktop - Modern Interface")
        self.geometry("1400x900")
        self.configure(fg_color=Colors.BG_DARK)
        
        # Set appearance mode
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize data
        self.current_view = "dashboard"
        self.devices = []
        self.activities = []
        self.chart_data = []
        
        # Build UI
        self._build_layout()
        self._populate_sample_data()
        self._start_real_time_updates()
    
    def _build_layout(self):
        """Build the three-column layout"""
        
        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
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
        
        # Clear existing content
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Hero cards row
        hero_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        hero_frame.pack(fill="x", pady=(0, 20))
        
        # Configure grid
        hero_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Hero cards
        cards_data = [
            ("Connected devices", "3", Icons.DEVICES),
            ("Active captures", "2", Icons.CAPTURE),
            ("Alerts", "4", Icons.WARNING)
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
        """Create real-time traffic chart"""
        
        # Create matplotlib figure with dark theme
        plt.style.use('dark_background')
        fig = Figure(figsize=(8, 4), facecolor=Colors.BG_CARD)
        ax = fig.add_subplot(111)
        
        # Generate sample data
        times = [datetime.now() - timedelta(minutes=30-i) for i in range(30)]
        values = np.random.normal(50, 15, 30)
        values = np.maximum(values, 0)  # Ensure non-negative
        
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
        """Populate with sample data"""
        
        # Sample devices
        sample_devices = [
            {"name": "Pineapple-001", "type": "WiFi Pineapple", "status": "online", "ip": "172.16.42.1", "latency": "23ms"},
            {"name": "Probe-Alpha", "type": "Network Probe", "status": "online", "ip": "192.168.1.100", "latency": "15ms"},
            {"name": "Scanner-Beta", "type": "Port Scanner", "status": "offline", "ip": "192.168.1.101", "latency": "N/A"}
        ]
        
        for device in sample_devices:
            card = DeviceCard(
                self.devices_scroll,
                device_name=device["name"],
                device_type=device["type"],
                status=device["status"],
                ip=device["ip"],
                latency=device["latency"]
            )
            card.pack(fill="x", pady=5)
        
        # Sample activities
        sample_activities = [
            ("Scan started", "11:22 AM", "info"),
            ("Scan completed", "11:22 AM", "success"),
            ("Capture started", "11:05 AM", "info"),
            ("Device connected", "10:50 AM", "success"),
            ("Configuration changed", "10:30 AM", "warning")
        ]
        
        for action, timestamp, status in sample_activities:
            item = ActivityItem(self.activity_scroll, action=action, timestamp=timestamp, status=status)
            item.pack(fill="x", pady=2)
    
    def _start_real_time_updates(self):
        """Start real-time data updates"""
        
        def update_loop():
            while True:
                try:
                    # Update chart data (simulate real-time)
                    if hasattr(self, 'chart_ax'):
                        # This would be replaced with real data updates
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
        else:
            self._load_placeholder_content(view_id)
    
    def _load_placeholder_content(self, view_id: str):
        """Load placeholder content for other views"""
        
        # Clear existing content
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
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
            self,
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