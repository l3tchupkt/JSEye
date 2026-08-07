"""Custom exception hierarchy for JSEye v2."""

from typing import Optional, Dict, Any


class JSEyeException(Exception):
    """Base exception for all JSEye errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class JSEyeConfigurationError(JSEyeException):
    """Raised when there's a configuration error."""
    pass


class JSEyeNetworkError(JSEyeException):
    """Raised when there's a network-related error."""
    
    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None, **kwargs):
        super().__init__(message, kwargs)
        self.url = url
        self.status_code = status_code


class JSEyeTimeoutError(JSEyeException):
    """Raised when an operation times out."""
    
    def __init__(self, message: str, timeout: float, operation: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.timeout = timeout
        self.operation = operation


class JSEyeParsingError(JSEyeException):
    """Raised when there's an error parsing JavaScript or other content."""
    
    def __init__(self, message: str, content_type: Optional[str] = None, source: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.content_type = content_type
        self.source = source


class JSEyeToolError(JSEyeException):
    """Raised when an external tool fails or is unavailable."""
    
    def __init__(self, message: str, tool_name: Optional[str] = None, exit_code: Optional[int] = None, **kwargs):
        super().__init__(message, kwargs)
        self.tool_name = tool_name
        self.exit_code = exit_code


class JSEyeValidationError(JSEyeException):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.field = field
        self.value = value


class JSEyeResourceError(JSEyeException):
    """Raised when there's a resource-related error (memory, disk, etc.)."""
    
    def __init__(self, message: str, resource_type: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.resource_type = resource_type


class JSEyeAnalysisError(JSEyeException):
    """Raised when analysis fails."""
    
    def __init__(self, message: str, analysis_type: Optional[str] = None, target: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.analysis_type = analysis_type
        self.target = target