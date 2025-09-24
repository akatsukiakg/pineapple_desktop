"""Logging utilities for Pineapple Desktop"""
from __future__ import annotations
import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

class Logger:
    """Simple logger for application events"""
    
    def __init__(self, log_file: str = "pineapple_desktop.log", level: int = logging.INFO):
        self.log_file = Path(log_file)
        self.logger = logging.getLogger('pineapple_desktop')
        self.logger.setLevel(level)
        
        # Create logs directory if it doesn't exist
        self.log_file.parent.mkdir(exist_ok=True)
        
        # Configure file handler
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(level)
        
        # Configure console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers if not already added
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)
    
    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)
    
    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(message)
    
    def log_action(self, action: str, details: str = "") -> None:
        """Log user action for audit purposes"""
        timestamp = datetime.now().isoformat()
        audit_message = f"ACTION: {action}"
        if details:
            audit_message += f" - {details}"
        self.info(audit_message)