"""Enhanced logging system for JSEye v2."""

import logging
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class JSEyeFormatter(logging.Formatter):
    """Custom formatter for JSEye logs with JSON support."""
    
    def __init__(self, json_format: bool = False):
        self.json_format = json_format
        if json_format:
            super().__init__()
        else:
            super().__init__(
                fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    
    def format(self, record: logging.LogRecord) -> str:
        if self.json_format:
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            # Add exception info if present
            if record.exc_info:
                log_entry['exception'] = self.formatException(record.exc_info)
            
            # Add extra fields
            if hasattr(record, 'target'):
                log_entry['target'] = record.target
            if hasattr(record, 'operation'):
                log_entry['operation'] = record.operation
            if hasattr(record, 'duration'):
                log_entry['duration'] = record.duration
            
            return json.dumps(log_entry)
        else:
            return super().format(record)


class JSEyeLogger:
    """Enhanced logger for JSEye with structured logging capabilities."""
    
    def __init__(self, name: str = 'jseye'):
        self.logger = logging.getLogger(name)
        self._configured = False
    
    def configure(self, level: str = 'INFO', json_format: bool = False, 
                 log_file: Optional[str] = None, debug: bool = False, trace: bool = False):
        """Configure the logger with specified settings."""
        if self._configured:
            return
        
        # Set level
        if trace:
            log_level = logging.DEBUG
        elif debug:
            log_level = logging.DEBUG
        else:
            log_level = getattr(logging, level.upper(), logging.INFO)
        
        self.logger.setLevel(log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(JSEyeFormatter(json_format=json_format))
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(JSEyeFormatter(json_format=True))  # Always JSON for files
            self.logger.addHandler(file_handler)
        
        # Prevent propagation to root logger
        self.logger.propagate = False
        self._configured = True
    
    def info(self, message: str, **kwargs):
        """Log info message with optional structured data."""
        self.logger.info(message, extra=kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with optional structured data."""
        self.logger.debug(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with optional structured data."""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with optional structured data."""
        self.logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with optional structured data."""
        self.logger.critical(message, extra=kwargs)
    
    def log_operation(self, operation: str, target: str, duration: float, success: bool, **kwargs):
        """Log operation with timing and success status."""
        level = logging.INFO if success else logging.WARNING
        message = f"Operation {operation} {'completed' if success else 'failed'} for {target}"
        
        extra = {
            'operation': operation,
            'target': target,
            'duration': duration,
            'success': success,
            **kwargs
        }
        
        self.logger.log(level, message, extra=extra)
    
    def log_finding(self, finding_type: str, severity: str, target: str, details: Dict[str, Any]):
        """Log security finding with structured data."""
        message = f"Found {finding_type} ({severity}) in {target}"
        
        extra = {
            'finding_type': finding_type,
            'severity': severity,
            'target': target,
            'details': details
        }
        
        self.logger.info(message, extra=extra)


# Global logger instance
logger = JSEyeLogger()


def get_logger(name: str = 'jseye') -> JSEyeLogger:
    """Get a logger instance."""
    if name == 'jseye':
        return logger
    return JSEyeLogger(name)