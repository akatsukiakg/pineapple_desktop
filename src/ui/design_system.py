"""
Design System for Pineapple Desktop
Modern, professional color palette and typography system
"""

class Colors:
    """Color palette following the design specifications"""
    
    # Primary colors
    PRIMARY = "#0F62FE"  # Azul brillante
    SECONDARY = "#00B39F"  # Verde teals
    
    # Background colors
    BG_DARK = "#0B0E11"  # Fondo oscuro principal
    BG_CARD = "#0F1720"  # Cards y paneles
    BG_HOVER = "#1A2332"  # Hover states
    
    # Accent colors
    DANGER = "#FF6B6B"  # Rojo para alertas
    WARNING = "#FFB020"  # Ámbar para advertencias
    SUCCESS = "#00B39F"  # Verde para éxito
    INFO = "#0F62FE"  # Azul para información
    ERROR = "#FF6B6B"  # Rojo para errores (alias for DANGER)
    
    # Text colors
    TEXT_PRIMARY = "#E6EEF8"  # Texto principal
    TEXT_SECONDARY = "#9AA7B2"  # Texto secundario
    TEXT_MUTED = "#6B7280"  # Texto deshabilitado
    
    # Status colors
    ONLINE = "#10B981"  # Verde para online
    OFFLINE = "#EF4444"  # Rojo para offline
    CONNECTING = "#F59E0B"  # Ámbar para conectando
    
    # Chart colors
    CHART_LINE = "#0F62FE"
    CHART_AREA = "#0F62FE33"  # Con transparencia
    CHART_GRID = "#374151"

class Typography:
    """Typography system with font families, sizes, and weights"""
    
    # Font families
    FONT_FAMILY = "Inter"  # Primary font
    FONT_FAMILY_MONO = "JetBrains Mono"  # Monospace font
    
    # Font sizes (in pixels)
    SIZE_XS = 12
    SIZE_SM = 14
    SIZE_BASE = 16
    SIZE_MD = 16  # Alias for SIZE_BASE
    SIZE_LG = 18
    SIZE_XL = 20
    SIZE_2XL = 24
    SIZE_3XL = 30
    SIZE_4XL = 36
    
    # Font weights (using standard names instead of numbers)
    WEIGHT_NORMAL = "normal"
    WEIGHT_MEDIUM = "bold"  # Using bold instead of 500
    WEIGHT_SEMIBOLD = "bold"
    WEIGHT_BOLD = "bold"

class Spacing:
    """Spacing system for consistent layouts"""
    
    XS = 4
    SM = 8
    MD = 16
    LG = 24
    XL = 32
    XXL = 48
    XXXL = 64

class BorderRadius:
    """Border radius tokens"""
    
    SM = 4
    MD = 8
    LG = 12
    XL = 16
    FULL = 9999

class Shadows:
    """Shadow definitions for depth"""
    
    SM = "0 1px 2px 0 rgba(0, 0, 0, 0.05)"
    MD = "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)"
    LG = "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)"
    XL = "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)"

class ComponentStyles:
    """Pre-defined component styles"""
    
    BUTTON_PRIMARY = {
        "fg_color": Colors.PRIMARY,
        "hover_color": "#0D52D1",
        "text_color": Colors.TEXT_PRIMARY,
        "corner_radius": BorderRadius.MD,
        "height": 40,
        "font": (Typography.FONT_FAMILY, Typography.SIZE_BASE, Typography.WEIGHT_MEDIUM)
    }
    
    BUTTON_SECONDARY = {
        "fg_color": "transparent",
        "hover_color": Colors.BG_HOVER,
        "text_color": Colors.TEXT_PRIMARY,
        "border_width": 1,
        "border_color": Colors.TEXT_SECONDARY,
        "corner_radius": BorderRadius.MD,
        "height": 40,
        "font": (Typography.FONT_FAMILY, Typography.SIZE_BASE, Typography.WEIGHT_MEDIUM)
    }
    
    BUTTON_DANGER = {
        "fg_color": Colors.DANGER,
        "hover_color": "#E53E3E",
        "text_color": Colors.TEXT_PRIMARY,
        "corner_radius": BorderRadius.MD,
        "height": 40,
        "font": (Typography.FONT_FAMILY, Typography.SIZE_BASE, Typography.WEIGHT_MEDIUM)
    }
    
    CARD = {
        "fg_color": Colors.BG_CARD,
        "corner_radius": BorderRadius.LG,
        "border_width": 1,
        "border_color": "#1F2937"
    }
    
    SIDEBAR = {
        "fg_color": Colors.BG_CARD,
        "width": 280,
        "corner_radius": 0
    }

class Icons:
    """Icon definitions using Unicode symbols"""
    
    # Navigation icons
    DASHBOARD = "📊"
    DEVICES = "📱"
    SCAN = "🔍"
    WIFI = "📶"
    CAPTURE = "📹"
    MAP = "🗺️"
    LOGS = "📋"
    SETTINGS = "⚙️"
    HELP = "❓"
    
    # Status icons
    ONLINE = "🟢"
    OFFLINE = "🔴"
    CONNECTING = "🟡"
    
    # Action icons
    PLAY = "▶️"
    STOP = "⏹️"
    PAUSE = "⏸️"
    REFRESH = "🔄"
    EXPORT = "📤"
    IMPORT = "📥"
    
    # Alert icons
    WARNING = "⚠️"
    ERROR = "❌"
    SUCCESS = "✅"
    INFO = "ℹ️"

class Animations:
    """Animation timing and easing"""
    
    DURATION_FAST = 150
    DURATION_NORMAL = 300
    DURATION_SLOW = 500
    
    EASING_EASE = "ease"
    EASING_EASE_IN = "ease-in"
    EASING_EASE_OUT = "ease-out"
    EASING_EASE_IN_OUT = "ease-in-out"