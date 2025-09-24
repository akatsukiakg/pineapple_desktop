"""
Reusable UI Components for Pineapple Desktop
Modern components following the design system
"""

import customtkinter as ctk
from typing import Optional, Callable, Dict, Any
from .design_system import Colors, Typography, ComponentStyles, BorderRadius, Icons
import tkinter as tk

class PineappleButton(ctk.CTkButton):
    """Custom button with predefined styles"""
    
    def __init__(self, parent, text: str, style: str = "primary", **kwargs):
        styles = {
            "primary": ComponentStyles.BUTTON_PRIMARY,
            "secondary": ComponentStyles.BUTTON_SECONDARY,
            "danger": ComponentStyles.BUTTON_DANGER
        }
        
        button_style = styles.get(style, ComponentStyles.BUTTON_PRIMARY)
        button_style.update(kwargs)
        
        super().__init__(parent, text=text, **button_style)

class StatusBadge(ctk.CTkLabel):
    """Status badge component"""
    
    def __init__(self, parent, status: str, **kwargs):
        status_config = {
            "online": {"text": f"{Icons.ONLINE} Online", "text_color": Colors.ONLINE},
            "offline": {"text": f"{Icons.OFFLINE} Offline", "text_color": Colors.OFFLINE},
            "connecting": {"text": f"{Icons.CONNECTING} Connecting", "text_color": Colors.CONNECTING}
        }
        
        config = status_config.get(status.lower(), status_config["offline"])
        config.update({
            "fg_color": Colors.BG_CARD,
            "corner_radius": BorderRadius.FULL,
            "font": (Typography.FONT_FAMILY, Typography.SIZE_SM, Typography.WEIGHT_MEDIUM),
            "width": 100,
            "height": 28
        })
        config.update(kwargs)
        
        super().__init__(parent, **config)

class HeroCard(ctk.CTkFrame):
    """Hero card component for dashboard metrics"""
    
    def __init__(self, parent, title: str, value: str, icon: str = "", **kwargs):
        card_style = ComponentStyles.CARD.copy()
        card_style.update(kwargs)
        
        super().__init__(parent, **card_style)
        
        # Icon
        if icon:
            icon_label = ctk.CTkLabel(
                self, 
                text=icon,
                font=(Typography.FONT_FAMILY, Typography.SIZE_2XL),
                text_color=Colors.PRIMARY
            )
            icon_label.pack(pady=(20, 10))
        
        # Value
        value_label = ctk.CTkLabel(
            self,
            text=value,
            font=(Typography.FONT_FAMILY, Typography.SIZE_3XL, Typography.WEIGHT_BOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        value_label.pack()
        
        # Title
        title_label = ctk.CTkLabel(
            self,
            text=title,
            font=(Typography.FONT_FAMILY, Typography.SIZE_BASE),
            text_color=Colors.TEXT_SECONDARY
        )
        title_label.pack(pady=(5, 20))

class DeviceCard(ctk.CTkFrame):
    """Device card component"""
    
    def __init__(self, parent, device_name: str, device_type: str, status: str, 
                 ip: str = "", latency: str = "", **kwargs):
        card_style = ComponentStyles.CARD.copy()
        card_style.update({"height": 120})
        card_style.update(kwargs)
        
        super().__init__(parent, **card_style)
        
        # Header with device name and status
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        name_label = ctk.CTkLabel(
            header_frame,
            text=device_name,
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        name_label.pack(side="left")
        
        status_badge = StatusBadge(header_frame, status)
        status_badge.pack(side="right")
        
        # Device info
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.pack(fill="x", padx=15, pady=5)
        
        type_label = ctk.CTkLabel(
            info_frame,
            text=f"Type: {device_type}",
            font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
            text_color=Colors.TEXT_SECONDARY
        )
        type_label.pack(anchor="w")
        
        if ip:
            ip_label = ctk.CTkLabel(
                info_frame,
                text=f"IP: {ip}",
                font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
                text_color=Colors.TEXT_SECONDARY
            )
            ip_label.pack(anchor="w")
        
        if latency:
            latency_label = ctk.CTkLabel(
                info_frame,
                text=f"Latency: {latency}",
                font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
                text_color=Colors.TEXT_SECONDARY
            )
            latency_label.pack(anchor="w")

class ActivityItem(ctk.CTkFrame):
    """Activity feed item component"""
    
    def __init__(self, parent, action: str, timestamp: str, status: str = "info", **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        
        # Status indicator
        status_colors = {
            "success": Colors.SUCCESS,
            "error": Colors.DANGER,
            "warning": Colors.WARNING,
            "info": Colors.INFO
        }
        
        indicator = ctk.CTkLabel(
            self,
            text="●",
            font=(Typography.FONT_FAMILY, Typography.SIZE_LG),
            text_color=status_colors.get(status, Colors.INFO),
            width=20
        )
        indicator.pack(side="left", padx=(0, 10))
        
        # Content
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.pack(side="left", fill="x", expand=True)
        
        action_label = ctk.CTkLabel(
            content_frame,
            text=action,
            font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
            text_color=Colors.TEXT_PRIMARY
        )
        action_label.pack(anchor="w")
        
        time_label = ctk.CTkLabel(
            content_frame,
            text=timestamp,
            font=(Typography.FONT_FAMILY, Typography.SIZE_XS),
            text_color=Colors.TEXT_SECONDARY
        )
        time_label.pack(anchor="w")

class ConfirmationModal(ctk.CTkToplevel):
    """Confirmation modal for dangerous actions"""
    
    def __init__(self, parent, title: str, message: str, 
                 on_confirm: Callable = None, on_cancel: Callable = None):
        super().__init__(parent)
        
        self.on_confirm = on_confirm
        self.on_cancel = on_cancel
        self.result = None
        
        # Window configuration
        self.title(title)
        self.geometry("500x300")
        self.resizable(False, False)
        self.configure(fg_color=Colors.BG_DARK)
        
        # Center the window
        self.transient(parent)
        self.grab_set()
        
        # Content
        content_frame = ctk.CTkFrame(self, fg_color=Colors.BG_CARD, corner_radius=BorderRadius.LG)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(
            content_frame,
            text=title,
            font=(Typography.FONT_FAMILY, Typography.SIZE_XL, Typography.WEIGHT_SEMIBOLD),
            text_color=Colors.TEXT_PRIMARY
        )
        title_label.pack(pady=(20, 10))
        
        # Message
        message_label = ctk.CTkLabel(
            content_frame,
            text=message,
            font=(Typography.FONT_FAMILY, Typography.SIZE_BASE),
            text_color=Colors.TEXT_SECONDARY,
            wraplength=400
        )
        message_label.pack(pady=10)
        
        # Consent checkbox
        self.consent_var = ctk.BooleanVar()
        consent_checkbox = ctk.CTkCheckBox(
            content_frame,
            text="Confirmo que tengo autorización",
            variable=self.consent_var,
            font=(Typography.FONT_FAMILY, Typography.SIZE_SM),
            text_color=Colors.TEXT_PRIMARY
        )
        consent_checkbox.pack(pady=20)
        
        # Buttons
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(side="bottom", fill="x", padx=20, pady=20)
        
        cancel_btn = PineappleButton(
            button_frame,
            text="Cancelar",
            style="secondary",
            command=self._on_cancel
        )
        cancel_btn.pack(side="right", padx=(10, 0))
        
        confirm_btn = PineappleButton(
            button_frame,
            text="Ejecutar",
            style="danger",
            command=self._on_confirm
        )
        confirm_btn.pack(side="right")
    
    def _on_confirm(self):
        if self.consent_var.get():
            self.result = True
            if self.on_confirm:
                self.on_confirm()
            self.destroy()
    
    def _on_cancel(self):
        self.result = False
        if self.on_cancel:
            self.on_cancel()
        self.destroy()

class NavigationItem(ctk.CTkButton):
    """Navigation sidebar item"""
    
    def __init__(self, parent, text: str, icon: str = "", active: bool = False, **kwargs):
        style = {
            "fg_color": Colors.PRIMARY if active else "transparent",
            "hover_color": Colors.BG_HOVER if not active else Colors.PRIMARY,
            "text_color": Colors.TEXT_PRIMARY,
            "font": (Typography.FONT_FAMILY, Typography.SIZE_BASE, Typography.WEIGHT_MEDIUM),
            "height": 48,
            "anchor": "w",
            "corner_radius": BorderRadius.MD
        }
        style.update(kwargs)
        
        display_text = f"{icon} {text}" if icon else text
        super().__init__(parent, text=display_text, **style)