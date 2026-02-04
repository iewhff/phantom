"""
Centralized Scanner Configuration

Provides unified access to scanner configuration with sensible defaults.
Eliminates scattered hardcoded values across scanning modules.

Usage:
    from config.scanner_config import get_scanner_config, ScannerDefaults

    config = get_scanner_config("sqli")
    timeout = config.get("timeout", ScannerDefaults.TIMEOUT)

Author: PetNTester AI Enterprise
Version: 1.0.0
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# DEFAULT VALUES
# =============================================================================

@dataclass
class ScannerDefaults:
    """Default values for scanner configuration."""

    # Timeouts (seconds)
    TIMEOUT: float = 30.0
    CONNECTION_TIMEOUT: float = 10.0
    READ_TIMEOUT: float = 30.0

    # Rate limiting
    REQUESTS_PER_SECOND: float = 10.0
    MIN_DELAY: float = 0.1
    MAX_DELAY: float = 5.0
    BURST_SIZE: int = 5

    # Payloads
    MAX_PAYLOADS: int = 100
    MAX_MUTATIONS: int = 15

    # Detection thresholds
    CONFIDENCE_THRESHOLD: float = 0.6
    FALSE_POSITIVE_THRESHOLD: float = 0.9

    # Time-based detection
    TIME_DELAY: float = 5.0
    TIME_THRESHOLD: float = 4.0

    # Union-based SQLi
    MAX_UNION_COLUMNS: int = 20

    # Directory traversal
    MAX_TRAVERSAL_DEPTH: int = 10

    # Concurrency
    MAX_CONCURRENT_REQUESTS: int = 10

    # Content limits
    MAX_RESPONSE_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_CONTENT_LENGTH: int = 5 * 1024 * 1024  # 5MB

    # Retry settings
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 1.0
    BACKOFF_FACTOR: float = 2.0


# =============================================================================
# SCANNER-SPECIFIC DEFAULTS
# =============================================================================

@dataclass
class SQLiConfig:
    """SQL Injection scanner configuration."""
    timeout: float = 30.0
    time_delay: float = 5.0
    time_threshold: float = 4.0
    max_union_columns: int = 20
    techniques: list[str] = field(default_factory=lambda: ["boolean", "time", "error", "union"])
    risk_level: int = 2
    dbms: list[str] = field(default_factory=lambda: ["mysql", "postgresql", "mssql", "oracle", "sqlite"])
    tamper_scripts: bool = True
    waf_bypass: bool = True
    max_payloads: int = 100


@dataclass
class XSSConfig:
    """XSS scanner configuration."""
    timeout: float = 30.0
    contexts: list[str] = field(default_factory=lambda: ["html", "attr", "js", "url"])
    dom_xss: bool = True
    stored_xss: bool = True
    polyglot_payloads: bool = True
    waf_bypass: bool = True
    confidence_threshold: float = 0.75
    max_payloads: int = 100


@dataclass
class SSRFConfig:
    """SSRF scanner configuration."""
    timeout: float = 30.0
    test_internal_ips: bool = False
    test_cloud_metadata: bool = True
    protocols: list[str] = field(default_factory=lambda: ["http", "https"])
    callback_timeout: float = 10.0
    max_payloads: int = 50


@dataclass
class LFIConfig:
    """LFI scanner configuration."""
    timeout: float = 30.0
    max_depth: int = 10
    test_rfi: bool = False
    wrappers: list[str] = field(default_factory=lambda: ["php", "data"])
    null_byte: bool = True
    encoding_bypass: bool = True
    max_payloads: int = 100


@dataclass
class NoSQLConfig:
    """NoSQL injection scanner configuration."""
    timeout: float = 30.0
    databases: list[str] = field(default_factory=lambda: ["mongodb", "couchdb", "redis"])
    injection_types: list[str] = field(default_factory=lambda: ["auth_bypass", "data_extraction"])
    max_payloads: int = 50


@dataclass
class AuthConfig:
    """Authentication scanner configuration."""
    timeout: float = 30.0
    max_login_attempts: int = 5
    test_default_credentials: bool = True
    test_brute_force_protection: bool = True
    test_jwt: bool = True
    test_oauth: bool = True
    test_session: bool = True


# =============================================================================
# CONFIGURATION LOADER
# =============================================================================

class ScannerConfigLoader:
    """
    Load and manage scanner configuration from settings.yaml.

    Provides:
    - Centralized access to all scanner settings
    - Default values for missing configuration
    - Type-safe configuration access
    """

    _instance: Optional["ScannerConfigLoader"] = None
    _config: dict[str, Any] = {}
    _loaded: bool = False

    def __new__(cls) -> "ScannerConfigLoader":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> None:
        """Load configuration from settings.yaml."""
        if cls._loaded:
            return

        if config_path is None:
            # Find settings.yaml
            possible_paths = [
                Path("config/settings.yaml"),
                Path("../config/settings.yaml"),
                Path(os.environ.get("PETNTESTER_CONFIG", "config/settings.yaml")),
            ]

            for path in possible_paths:
                if path.exists():
                    config_path = path
                    break

        if config_path and Path(config_path).exists():
            try:
                with open(config_path) as f:
                    cls._config = yaml.safe_load(f) or {}
                logger.info(f"Loaded scanner config from {config_path}")
            except yaml.YAMLError as e:
                logger.error(f"Failed to parse config: {e}")
                cls._config = {}
        else:
            logger.warning("Config file not found, using defaults")
            cls._config = {}

        cls._loaded = True

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key."""
        if not cls._loaded:
            cls.load()

        keys = key.split(".")
        value = cls._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        return value if value is not None else default

    @classmethod
    def get_module_config(cls, module_name: str) -> dict[str, Any]:
        """Get configuration for a specific scanning module."""
        if not cls._loaded:
            cls.load()

        # Get module-specific config
        modules = cls._config.get("scanning", {}).get("modules", {})
        module_config = modules.get(module_name, {})

        # Merge with defaults
        return cls._apply_defaults(module_name, module_config)

    @classmethod
    def _apply_defaults(cls, module_name: str, config: dict[str, Any]) -> dict[str, Any]:
        """Apply default values for missing configuration."""
        defaults = ScannerDefaults()

        # Common defaults
        result = {
            "timeout": config.get("timeout", defaults.TIMEOUT),
            "max_retries": config.get("max_retries", defaults.MAX_RETRIES),
            "confidence_threshold": config.get("confidence_threshold", defaults.CONFIDENCE_THRESHOLD),
            "waf_bypass": config.get("waf_bypass", True),
            "enabled": config.get("enabled", True),
        }

        # Module-specific defaults
        if module_name == "sqli":
            sqli_defaults = SQLiConfig()
            result.update({
                "time_delay": config.get("time_delay", sqli_defaults.time_delay),
                "time_threshold": config.get("time_threshold", sqli_defaults.time_threshold),
                "max_union_columns": config.get("max_union_columns", sqli_defaults.max_union_columns),
                "techniques": config.get("techniques", sqli_defaults.techniques),
                "risk_level": config.get("risk_level", sqli_defaults.risk_level),
                "dbms": config.get("dbms", sqli_defaults.dbms),
            })
        elif module_name == "xss":
            xss_defaults = XSSConfig()
            result.update({
                "contexts": config.get("contexts", xss_defaults.contexts),
                "dom_xss": config.get("dom_xss", xss_defaults.dom_xss),
                "stored_xss": config.get("stored_xss", xss_defaults.stored_xss),
                "polyglot_payloads": config.get("polyglot_payloads", xss_defaults.polyglot_payloads),
            })
        elif module_name == "ssrf":
            ssrf_defaults = SSRFConfig()
            result.update({
                "test_internal_ips": config.get("test_internal_ips", ssrf_defaults.test_internal_ips),
                "test_cloud_metadata": config.get("test_cloud_metadata", ssrf_defaults.test_cloud_metadata),
                "protocols": config.get("protocols", ssrf_defaults.protocols),
            })
        elif module_name == "lfi":
            lfi_defaults = LFIConfig()
            result.update({
                "depth": config.get("depth", lfi_defaults.max_depth),
                "test_rfi": config.get("test_rfi", lfi_defaults.test_rfi),
                "wrappers": config.get("wrappers", lfi_defaults.wrappers),
            })

        # Override with any explicit config values
        result.update(config)

        return result

    @classmethod
    def get_rate_limit_config(cls) -> dict[str, Any]:
        """Get rate limiting configuration."""
        if not cls._loaded:
            cls.load()

        rate_config = cls._config.get("rate_limit", {})
        defaults = ScannerDefaults()

        return {
            "requests_per_second": rate_config.get("requests_per_second", defaults.REQUESTS_PER_SECOND),
            "min_delay": rate_config.get("min_delay", defaults.MIN_DELAY),
            "max_delay": rate_config.get("max_delay", defaults.MAX_DELAY),
            "adaptive": rate_config.get("adaptive", True),
            "backoff_factor": rate_config.get("backoff_factor", defaults.BACKOFF_FACTOR),
        }

    @classmethod
    def get_timeout_config(cls) -> dict[str, Any]:
        """Get timeout configuration."""
        if not cls._loaded:
            cls.load()

        timeout_config = cls._config.get("timeouts", {})
        defaults = ScannerDefaults()

        return {
            "connection": timeout_config.get("connection", defaults.CONNECTION_TIMEOUT),
            "read": timeout_config.get("read", defaults.READ_TIMEOUT),
            "vuln_scan": timeout_config.get("vuln_scan", 3600),
            "ai_analysis": timeout_config.get("ai_analysis", 300),
        }

    @classmethod
    def reset(cls) -> None:
        """Reset configuration (useful for testing)."""
        cls._config = {}
        cls._loaded = False


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_scanner_config(module_name: str) -> dict[str, Any]:
    """
    Get configuration for a scanning module.

    Args:
        module_name: Name of the scanner module (sqli, xss, ssrf, etc.)

    Returns:
        Dictionary with configuration values

    Example:
        config = get_scanner_config("sqli")
        timeout = config["timeout"]
        techniques = config["techniques"]
    """
    return ScannerConfigLoader.get_module_config(module_name)


def get_config(key: str, default: Any = None) -> Any:
    """
    Get any configuration value by dot-notation key.

    Args:
        key: Configuration key (e.g., "scanning.modules.sqli.timeout")
        default: Default value if key not found

    Returns:
        Configuration value or default
    """
    return ScannerConfigLoader.get(key, default)


def get_rate_limits() -> dict[str, Any]:
    """Get rate limiting configuration."""
    return ScannerConfigLoader.get_rate_limit_config()


def get_timeouts() -> dict[str, Any]:
    """Get timeout configuration."""
    return ScannerConfigLoader.get_timeout_config()
