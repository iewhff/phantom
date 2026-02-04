"""
Custom exceptions for PetNTester AI.

Provides specific exception types for better error handling throughout the codebase.
Replaces bare 'except:' clauses with specific exception types.

Usage:
    from core.exceptions import (
        PetNTesterError,
        ScanError,
        ConfigurationError,
        NetworkError,
    )

    try:
        await scanner.scan(target)
    except ScanTimeoutError as e:
        logger.warning(f"Scan timed out: {e}")
    except ScanError as e:
        logger.error(f"Scan failed: {e}")
"""

from __future__ import annotations


# =============================================================================
# BASE EXCEPTIONS
# =============================================================================

class PetNTesterError(Exception):
    """Base exception for all PetNTester errors."""

    def __init__(self, message: str = "", details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


# =============================================================================
# CONFIGURATION EXCEPTIONS
# =============================================================================

class ConfigurationError(PetNTesterError):
    """Error in configuration settings."""
    pass


class InvalidConfigValueError(ConfigurationError):
    """Invalid value in configuration."""

    def __init__(self, key: str, value: object, expected: str):
        message = f"Invalid config value for '{key}': got {value!r}, expected {expected}"
        super().__init__(message, {"key": key, "value": value, "expected": expected})


class MissingConfigError(ConfigurationError):
    """Required configuration is missing."""

    def __init__(self, key: str):
        message = f"Missing required configuration: {key}"
        super().__init__(message, {"key": key})


# =============================================================================
# SCANNING EXCEPTIONS
# =============================================================================

class ScanError(PetNTesterError):
    """Base exception for scanning errors."""
    pass


class ScanTimeoutError(ScanError):
    """Scan operation timed out."""

    def __init__(self, module: str, timeout: float, target: str = ""):
        message = f"Scan timed out after {timeout}s"
        super().__init__(message, {"module": module, "timeout": timeout, "target": target})
        self.module = module
        self.timeout = timeout
        self.target = target


class ScanAbortedError(ScanError):
    """Scan was aborted by user or system."""
    pass


class ModuleLoadError(ScanError):
    """Failed to load scanning module."""

    def __init__(self, module_name: str, reason: str):
        message = f"Failed to load module '{module_name}': {reason}"
        super().__init__(message, {"module": module_name, "reason": reason})


class InvalidTargetError(ScanError):
    """Invalid or unreachable target."""

    def __init__(self, target: str, reason: str):
        message = f"Invalid target '{target}': {reason}"
        super().__init__(message, {"target": target, "reason": reason})


class PayloadError(ScanError):
    """Error with payload generation or execution."""
    pass


# =============================================================================
# NETWORK EXCEPTIONS
# =============================================================================

class NetworkError(PetNTesterError):
    """Base exception for network errors."""
    pass


class ConnectionError(NetworkError):
    """Failed to establish connection."""

    def __init__(self, host: str, port: int = 0, reason: str = ""):
        message = f"Failed to connect to {host}"
        if port:
            message += f":{port}"
        if reason:
            message += f": {reason}"
        super().__init__(message, {"host": host, "port": port, "reason": reason})


class TimeoutError(NetworkError):
    """Network operation timed out."""

    def __init__(self, operation: str, timeout: float):
        message = f"{operation} timed out after {timeout}s"
        super().__init__(message, {"operation": operation, "timeout": timeout})


class SSLError(NetworkError):
    """SSL/TLS error."""
    pass


class ProxyError(NetworkError):
    """Proxy-related error."""

    def __init__(self, proxy: str, reason: str):
        message = f"Proxy error ({proxy}): {reason}"
        super().__init__(message, {"proxy": proxy, "reason": reason})


class RateLimitError(NetworkError):
    """Rate limit exceeded."""

    def __init__(self, domain: str, retry_after: float | None = None):
        message = f"Rate limit exceeded for {domain}"
        if retry_after:
            message += f" (retry after {retry_after}s)"
        super().__init__(message, {"domain": domain, "retry_after": retry_after})


# =============================================================================
# AI ENGINE EXCEPTIONS
# =============================================================================

class AIError(PetNTesterError):
    """Base exception for AI engine errors."""
    pass


class ModelNotAvailableError(AIError):
    """AI model is not available."""

    def __init__(self, model_name: str, reason: str = ""):
        message = f"Model '{model_name}' is not available"
        if reason:
            message += f": {reason}"
        super().__init__(message, {"model": model_name, "reason": reason})


class ModelResponseError(AIError):
    """Invalid response from AI model."""
    pass


class PromptInjectionError(AIError):
    """Detected potential prompt injection attempt."""

    def __init__(self, field: str, pattern: str):
        message = f"Potential prompt injection in field '{field}'"
        super().__init__(message, {"field": field, "pattern": pattern})


# =============================================================================
# STORAGE EXCEPTIONS
# =============================================================================

class StorageError(PetNTesterError):
    """Base exception for storage errors."""
    pass


class CheckpointError(StorageError):
    """Error with checkpoint save/load."""
    pass


class IntegrityError(StorageError):
    """Data integrity verification failed."""

    def __init__(self, file_path: str, reason: str):
        message = f"Integrity check failed for {file_path}: {reason}"
        super().__init__(message, {"file_path": file_path, "reason": reason})


class DatabaseError(StorageError):
    """Database operation error."""
    pass


# =============================================================================
# SECURITY EXCEPTIONS
# =============================================================================

class SecurityError(PetNTesterError):
    """Base exception for security-related errors."""
    pass


class KillSwitchActiveError(SecurityError):
    """Kill switch is active, blocking all traffic."""

    def __init__(self, reason: str = ""):
        message = "Kill switch is active - all outbound traffic blocked"
        if reason:
            message += f": {reason}"
        super().__init__(message, {"reason": reason})


class ProtectionFailureError(SecurityError):
    """Network protection verification failed."""

    def __init__(self, original_ip: str, proxied_ip: str):
        message = "IP leak detected - protection failure"
        super().__init__(message, {"original_ip": original_ip, "proxied_ip": proxied_ip})


class AuthorizationError(SecurityError):
    """Missing or invalid authorization."""
    pass


# =============================================================================
# REPORTING EXCEPTIONS
# =============================================================================

class ReportError(PetNTesterError):
    """Base exception for reporting errors."""
    pass


class TemplateError(ReportError):
    """Error with report template."""
    pass


class ExportError(ReportError):
    """Error exporting report."""

    def __init__(self, format: str, reason: str):
        message = f"Failed to export report as {format}: {reason}"
        super().__init__(message, {"format": format, "reason": reason})


# =============================================================================
# VALIDATION EXCEPTIONS
# =============================================================================

class ValidationError(PetNTesterError):
    """Base exception for validation errors."""
    pass


class InvalidURLError(ValidationError):
    """Invalid URL format."""

    def __init__(self, url: str, reason: str = ""):
        message = f"Invalid URL: {url}"
        if reason:
            message += f" ({reason})"
        super().__init__(message, {"url": url, "reason": reason})


class InvalidParameterError(ValidationError):
    """Invalid parameter value."""

    def __init__(self, param: str, value: object, reason: str = ""):
        message = f"Invalid value for parameter '{param}': {value!r}"
        if reason:
            message += f" ({reason})"
        super().__init__(message, {"param": param, "value": value, "reason": reason})
