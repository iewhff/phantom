"""
PHANTOM AI - Network Protection Module v3.0

Enterprise-grade network protection and OPSEC monitoring for PHANTOM AI.
Builds on top of the existing utils/network_protection.py and utils/http_client.py
infrastructure to provide PHANTOM-specific features.

Features:
- Centralized Kill Switch with configurable triggers
- Traffic Monitoring and Statistics
- Target Accessibility Verification
- OPSEC Status Monitoring
- Request Budget Tracking
- Anomaly Detection
- Emergency Stop Capability
- Audit Logging

Author: PHANTOM AI Team
Version: 3.0.0
Date: 2026-01-30

Usage:
    from phantom.network_protection import PhantomNetworkProtection

    # Initialize
    protection = PhantomNetworkProtection.get_instance()

    # Verify target accessibility before scan
    accessible = await protection.verify_target_accessible("https://target.com")

    # Monitor during scan
    protection.record_request("target.com", success=True, status_code=200)

    # Check kill switch triggers
    if protection.should_trigger_kill_switch():
        protection.activate_kill_switch("Threshold exceeded")
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional
import json

import httpx
import yaml

from utils.logger import get_logger
from utils.http_client import (
    activate_kill_switch as base_activate_kill_switch,
    deactivate_kill_switch as base_deactivate_kill_switch,
    is_kill_switch_active as base_is_kill_switch_active,
    get_network_protection,
    get_protection_status,
    KillSwitchActive,
)

if TYPE_CHECKING:
    from utils.network_protection import NetworkProtection

logger = get_logger(__name__)


# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

class KillSwitchTrigger(Enum):
    """
    Kill switch trigger types.

    These define the conditions that can automatically activate the kill switch.
    """
    CONSECUTIVE_ERRORS = auto()          # Too many consecutive errors
    RATE_LIMIT_EXCEEDED = auto()         # Target responded with 429
    OUT_OF_SCOPE_DETECTED = auto()       # Attempted out-of-scope request
    UNUSUAL_RESPONSE_PATTERN = auto()    # Anomalous response patterns
    PROTECTION_FAILURE = auto()          # Network protection failed
    MANUAL = auto()                      # Manual activation
    BUDGET_EXHAUSTED = auto()            # Global request budget exhausted
    TARGET_UNREACHABLE = auto()          # Target became unreachable


class RequestOutcome(Enum):
    """Outcome of an HTTP request."""
    SUCCESS = "success"              # 2xx response
    CLIENT_ERROR = "client_error"    # 4xx response
    SERVER_ERROR = "server_error"    # 5xx response
    RATE_LIMITED = "rate_limited"    # 429 response
    TIMEOUT = "timeout"              # Request timed out
    CONNECTION_ERROR = "connection_error"  # Connection failed
    BLOCKED = "blocked"              # Kill switch blocked request


@dataclass
class RequestRecord:
    """
    Record of a single HTTP request.

    Used for traffic monitoring, statistics, and anomaly detection.
    """
    timestamp: datetime
    domain: str
    endpoint: str
    method: str
    outcome: RequestOutcome
    status_code: Optional[int]
    response_time_ms: float
    response_size_bytes: int
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "endpoint": self.endpoint,
            "method": self.method,
            "outcome": self.outcome.value,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "response_size_bytes": self.response_size_bytes,
            "error_message": self.error_message,
        }


@dataclass
class DomainStatistics:
    """
    Statistics for a specific domain.

    Tracks request counts, error rates, and response times.
    """
    domain: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_requests: int = 0
    consecutive_errors: int = 0
    total_response_time_ms: float = 0.0
    total_response_size_bytes: int = 0
    first_request_time: Optional[datetime] = None
    last_request_time: Optional[datetime] = None
    last_error_message: Optional[str] = None

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

    @property
    def average_response_time_ms(self) -> float:
        """Calculate average response time."""
        if self.total_requests == 0:
            return 0.0
        return self.total_response_time_ms / self.total_requests

    @property
    def error_rate(self) -> float:
        """Calculate error rate as percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.failed_requests / self.total_requests) * 100

    @property
    def requests_per_second(self) -> float:
        """Calculate requests per second."""
        if not self.first_request_time or not self.last_request_time:
            return 0.0
        duration = (self.last_request_time - self.first_request_time).total_seconds()
        if duration <= 0:
            return self.total_requests
        return self.total_requests / duration

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "domain": self.domain,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rate_limited_requests": self.rate_limited_requests,
            "consecutive_errors": self.consecutive_errors,
            "success_rate": round(self.success_rate, 2),
            "error_rate": round(self.error_rate, 2),
            "average_response_time_ms": round(self.average_response_time_ms, 2),
            "requests_per_second": round(self.requests_per_second, 2),
            "first_request_time": self.first_request_time.isoformat() if self.first_request_time else None,
            "last_request_time": self.last_request_time.isoformat() if self.last_request_time else None,
        }


@dataclass
class KillSwitchConfig:
    """
    Configuration for kill switch triggers.

    Loaded from phantom_config.yaml or set programmatically.
    """
    enabled: bool = True

    # Trigger thresholds
    consecutive_errors_threshold: int = 10
    rate_limit_threshold: int = 3              # Number of 429s before trigger
    rate_limit_window_seconds: int = 60        # Window for counting 429s
    unusual_response_threshold: float = 0.5    # 50% anomalous responses

    # Auto-triggers
    trigger_on_consecutive_errors: bool = True
    trigger_on_rate_limit: bool = True
    trigger_on_out_of_scope: bool = True
    trigger_on_unusual_response: bool = True
    trigger_on_protection_failure: bool = True

    # Recovery
    auto_recover: bool = False
    recovery_delay_seconds: int = 300          # 5 minutes


@dataclass
class PhantomNetworkConfig:
    """
    PHANTOM AI network protection configuration.
    """
    kill_switch: KillSwitchConfig = field(default_factory=KillSwitchConfig)

    # Traffic monitoring
    enable_traffic_monitoring: bool = True
    max_records_per_domain: int = 1000         # Rolling window

    # Target verification
    verification_timeout_seconds: float = 30.0
    verification_retries: int = 3

    # Audit logging
    enable_audit_logging: bool = True
    audit_log_path: str = "data/logs/network_audit.jsonl"

    @classmethod
    def from_yaml(cls, config_path: str = "config/phantom_config.yaml") -> "PhantomNetworkConfig":
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            network_config = config.get("network_protection", {})
            kill_switch_config = network_config.get("kill_switch_triggers", [])

            # Parse kill switch triggers from list format
            ks_config = KillSwitchConfig()
            for trigger in kill_switch_config:
                if isinstance(trigger, dict):
                    if "consecutive_errors" in trigger:
                        ks_config.consecutive_errors_threshold = trigger["consecutive_errors"]
                    if "rate_limit_exceeded" in trigger:
                        ks_config.trigger_on_rate_limit = trigger["rate_limit_exceeded"]
                    if "out_of_scope_detected" in trigger:
                        ks_config.trigger_on_out_of_scope = trigger["out_of_scope_detected"]
                    if "unusual_response_pattern" in trigger:
                        ks_config.trigger_on_unusual_response = trigger["unusual_response_pattern"]

            return cls(
                kill_switch=ks_config,
                enable_traffic_monitoring=True,
                enable_audit_logging=True,
            )

        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return cls()
        except Exception as e:
            logger.error(f"Failed to load config: {e}, using defaults")
            return cls()


# =============================================================================
# PHANTOM NETWORK PROTECTION
# =============================================================================

class PhantomNetworkProtection:
    """
    PHANTOM AI Network Protection Manager.

    Singleton class that provides centralized network protection and
    monitoring for all PHANTOM AI operations.

    Features:
    - Centralized kill switch with configurable triggers
    - Real-time traffic monitoring and statistics
    - Target accessibility verification
    - OPSEC status monitoring
    - Anomaly detection
    - Audit logging

    Thread Safety:
    - All public methods are thread-safe
    - Uses asyncio.Lock for async operations
    - Uses threading.RLock for sync operations

    Usage:
        # Get singleton instance
        protection = PhantomNetworkProtection.get_instance()

        # Initialize with config
        await protection.initialize()

        # Verify target before scanning
        if await protection.verify_target_accessible("https://target.com"):
            # Proceed with scan
            ...

        # Record requests during scanning
        protection.record_request(
            domain="target.com",
            endpoint="/api/users",
            method="GET",
            outcome=RequestOutcome.SUCCESS,
            status_code=200,
            response_time_ms=150.0,
            response_size_bytes=1024,
        )

        # Check if kill switch should trigger
        if protection.check_triggers():
            # Handle kill switch activation
            ...

        # Get statistics
        stats = protection.get_statistics()
    """

    _instance: Optional["PhantomNetworkProtection"] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        """
        Initialize PhantomNetworkProtection.

        Note: Use get_instance() instead of direct instantiation.
        """
        self._config = PhantomNetworkConfig()
        self._initialized = False

        # Thread safety
        self._lock = threading.RLock()
        self._async_lock: Optional[asyncio.Lock] = None

        # Kill switch state
        self._kill_switch_reason: Optional[str] = None
        self._kill_switch_trigger: Optional[KillSwitchTrigger] = None
        self._kill_switch_time: Optional[datetime] = None

        # Traffic monitoring
        self._domain_stats: dict[str, DomainStatistics] = {}
        self._recent_records: dict[str, list[RequestRecord]] = defaultdict(list)
        self._global_stats = DomainStatistics(domain="__global__")

        # Scope tracking
        self._in_scope_domains: set[str] = set()
        self._out_of_scope_attempts: int = 0

        # Rate limit tracking
        self._rate_limit_times: list[datetime] = []

        # Audit log
        self._audit_log_file: Optional[Path] = None

        # Callbacks for kill switch
        self._kill_switch_callbacks: list[Callable[[str, KillSwitchTrigger], None]] = []

    @classmethod
    def get_instance(cls) -> "PhantomNetworkProtection":
        """
        Get the singleton instance.

        Thread-safe singleton pattern.

        Returns:
            PhantomNetworkProtection: The singleton instance
        """
        if cls._instance is None:
            with cls._instance_lock:
                # Double-check pattern
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """
        Reset the singleton instance.

        Useful for testing or reconfiguration.
        """
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance._cleanup()
            cls._instance = None

    async def initialize(
        self,
        config: Optional[PhantomNetworkConfig] = None,
        config_path: str = "config/phantom_config.yaml",
    ) -> bool:
        """
        Initialize the network protection system.

        Args:
            config: Optional configuration (loads from file if None)
            config_path: Path to configuration file

        Returns:
            bool: True if initialization successful
        """
        with self._lock:
            if self._initialized:
                logger.debug("PhantomNetworkProtection already initialized")
                return True

            # Load configuration
            if config:
                self._config = config
            else:
                self._config = PhantomNetworkConfig.from_yaml(config_path)

            # Initialize async lock
            self._async_lock = asyncio.Lock()

            # Setup audit logging
            if self._config.enable_audit_logging:
                self._setup_audit_logging()

            self._initialized = True
            logger.info("PHANTOM Network Protection initialized")

            # Log initial status
            self._audit_log({
                "event": "PROTECTION_INITIALIZED",
                "config": {
                    "kill_switch_enabled": self._config.kill_switch.enabled,
                    "traffic_monitoring": self._config.enable_traffic_monitoring,
                    "audit_logging": self._config.enable_audit_logging,
                },
            })

            return True

    def _cleanup(self) -> None:
        """Clean up resources."""
        with self._lock:
            self._domain_stats.clear()
            self._recent_records.clear()
            self._rate_limit_times.clear()
            self._in_scope_domains.clear()
            self._initialized = False

    def _setup_audit_logging(self) -> None:
        """Setup audit log file."""
        try:
            log_path = Path(self._config.audit_log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._audit_log_file = log_path
            logger.debug(f"Audit logging enabled: {log_path}")
        except Exception as e:
            logger.warning(f"Failed to setup audit logging: {e}")
            self._audit_log_file = None

    def _audit_log(self, event: dict[str, Any]) -> None:
        """
        Write event to audit log.

        Args:
            event: Event data to log
        """
        if not self._audit_log_file:
            return

        try:
            event["timestamp"] = datetime.now().isoformat()
            event["source"] = "phantom_network_protection"

            with open(self._audit_log_file, 'a') as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.warning(f"Failed to write audit log: {e}")

    # =========================================================================
    # SCOPE MANAGEMENT
    # =========================================================================

    def set_scope(self, domains: list[str]) -> None:
        """
        Set the in-scope domains for the scan.

        Args:
            domains: List of in-scope domain names
        """
        with self._lock:
            self._in_scope_domains = set(domains)
            logger.info(f"Scope set: {len(domains)} domains")

            self._audit_log({
                "event": "SCOPE_SET",
                "domains": list(domains),
            })

    def add_to_scope(self, domain: str) -> None:
        """Add a domain to the scope."""
        with self._lock:
            self._in_scope_domains.add(domain)

    def is_in_scope(self, domain: str) -> bool:
        """
        Check if a domain is in scope.

        Args:
            domain: Domain to check

        Returns:
            bool: True if in scope or no scope defined
        """
        with self._lock:
            # If no scope defined, everything is in scope
            if not self._in_scope_domains:
                return True

            # Check exact match
            if domain in self._in_scope_domains:
                return True

            # Check wildcard matches (*.example.com)
            for scope_domain in self._in_scope_domains:
                if scope_domain.startswith("*."):
                    base_domain = scope_domain[2:]
                    if domain.endswith(base_domain):
                        return True

            return False

    def record_out_of_scope_attempt(self, domain: str, endpoint: str) -> bool:
        """
        Record an out-of-scope access attempt.

        Args:
            domain: Domain that was attempted
            endpoint: Endpoint that was attempted

        Returns:
            bool: True if kill switch was triggered
        """
        with self._lock:
            self._out_of_scope_attempts += 1

            self._audit_log({
                "event": "OUT_OF_SCOPE_ATTEMPT",
                "domain": domain,
                "endpoint": endpoint,
                "total_attempts": self._out_of_scope_attempts,
            })

            logger.warning(f"Out-of-scope attempt: {domain}{endpoint}")

            # Check if we should trigger kill switch
            if self._config.kill_switch.trigger_on_out_of_scope:
                self.activate_kill_switch(
                    f"Out-of-scope access attempted: {domain}",
                    KillSwitchTrigger.OUT_OF_SCOPE_DETECTED,
                )
                return True

            return False

    # =========================================================================
    # KILL SWITCH MANAGEMENT
    # =========================================================================

    def activate_kill_switch(
        self,
        reason: str,
        trigger: KillSwitchTrigger = KillSwitchTrigger.MANUAL,
    ) -> None:
        """
        Activate the kill switch.

        Stops all outbound traffic immediately.

        Args:
            reason: Human-readable reason for activation
            trigger: The trigger that caused activation
        """
        with self._lock:
            if not self._config.kill_switch.enabled:
                logger.warning("Kill switch disabled in config, not activating")
                return

            self._kill_switch_reason = reason
            self._kill_switch_trigger = trigger
            self._kill_switch_time = datetime.now()

            # Activate base kill switch
            base_activate_kill_switch(reason)

            # Log to audit
            self._audit_log({
                "event": "KILL_SWITCH_ACTIVATED",
                "reason": reason,
                "trigger": trigger.name,
            })

            logger.critical(f"KILL SWITCH ACTIVATED: {reason}")
            logger.critical(f"   Trigger: {trigger.name}")

            # Call registered callbacks
            for callback in self._kill_switch_callbacks:
                try:
                    callback(reason, trigger)
                except Exception as e:
                    logger.error(f"Kill switch callback error: {e}")

    def deactivate_kill_switch(self) -> None:
        """
        Deactivate the kill switch.

        Allows traffic to resume.
        """
        with self._lock:
            base_deactivate_kill_switch()

            old_reason = self._kill_switch_reason
            self._kill_switch_reason = None
            self._kill_switch_trigger = None
            self._kill_switch_time = None

            self._audit_log({
                "event": "KILL_SWITCH_DEACTIVATED",
                "previous_reason": old_reason,
            })

            logger.warning("Kill switch deactivated - traffic allowed")

    def is_kill_switch_active(self) -> bool:
        """Check if kill switch is currently active."""
        return base_is_kill_switch_active()

    def get_kill_switch_info(self) -> dict[str, Any]:
        """
        Get information about current kill switch state.

        Returns:
            dict with active, reason, trigger, and time
        """
        with self._lock:
            return {
                "active": self.is_kill_switch_active(),
                "reason": self._kill_switch_reason,
                "trigger": self._kill_switch_trigger.name if self._kill_switch_trigger else None,
                "activated_at": self._kill_switch_time.isoformat() if self._kill_switch_time else None,
            }

    def register_kill_switch_callback(
        self,
        callback: Callable[[str, KillSwitchTrigger], None],
    ) -> None:
        """
        Register a callback to be called when kill switch activates.

        Args:
            callback: Function(reason, trigger) to call
        """
        with self._lock:
            self._kill_switch_callbacks.append(callback)

    def check_triggers(self) -> bool:
        """
        Check all kill switch triggers.

        Returns:
            bool: True if kill switch was triggered
        """
        with self._lock:
            if not self._config.kill_switch.enabled:
                return False

            if self.is_kill_switch_active():
                return False  # Already active

            config = self._config.kill_switch

            # Check consecutive errors
            if config.trigger_on_consecutive_errors:
                if self._global_stats.consecutive_errors >= config.consecutive_errors_threshold:
                    self.activate_kill_switch(
                        f"Consecutive errors threshold exceeded: {self._global_stats.consecutive_errors}",
                        KillSwitchTrigger.CONSECUTIVE_ERRORS,
                    )
                    return True

            # Check rate limits
            if config.trigger_on_rate_limit:
                recent_rate_limits = self._count_recent_rate_limits(
                    config.rate_limit_window_seconds
                )
                if recent_rate_limits >= config.rate_limit_threshold:
                    self.activate_kill_switch(
                        f"Rate limit threshold exceeded: {recent_rate_limits} in {config.rate_limit_window_seconds}s",
                        KillSwitchTrigger.RATE_LIMIT_EXCEEDED,
                    )
                    return True

            return False

    def _count_recent_rate_limits(self, window_seconds: int) -> int:
        """Count rate limit responses in the given time window."""
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        return sum(1 for t in self._rate_limit_times if t > cutoff)

    # =========================================================================
    # TRAFFIC MONITORING
    # =========================================================================

    def record_request(
        self,
        domain: str,
        endpoint: str,
        method: str,
        outcome: RequestOutcome,
        status_code: Optional[int],
        response_time_ms: float,
        response_size_bytes: int,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Record an HTTP request for monitoring and statistics.

        Args:
            domain: Target domain
            endpoint: Request endpoint
            method: HTTP method
            outcome: Request outcome
            status_code: HTTP status code (if available)
            response_time_ms: Response time in milliseconds
            response_size_bytes: Response body size
            error_message: Error message (if applicable)
        """
        if not self._config.enable_traffic_monitoring:
            return

        with self._lock:
            now = datetime.now()

            # Create record
            record = RequestRecord(
                timestamp=now,
                domain=domain,
                endpoint=endpoint,
                method=method,
                outcome=outcome,
                status_code=status_code,
                response_time_ms=response_time_ms,
                response_size_bytes=response_size_bytes,
                error_message=error_message,
            )

            # Update domain statistics
            self._update_domain_stats(domain, record)

            # Update global statistics
            self._update_domain_stats("__global__", record)

            # Store recent record
            records = self._recent_records[domain]
            records.append(record)

            # Trim to max records
            if len(records) > self._config.max_records_per_domain:
                self._recent_records[domain] = records[-self._config.max_records_per_domain:]

            # Track rate limits
            if outcome == RequestOutcome.RATE_LIMITED:
                self._rate_limit_times.append(now)
                # Trim old rate limit records
                cutoff = now - timedelta(minutes=5)
                self._rate_limit_times = [t for t in self._rate_limit_times if t > cutoff]

            # Check triggers
            self.check_triggers()

    def _update_domain_stats(self, domain: str, record: RequestRecord) -> None:
        """Update statistics for a domain."""
        if domain not in self._domain_stats:
            self._domain_stats[domain] = DomainStatistics(domain=domain)

        stats = self._domain_stats[domain]
        stats.total_requests += 1
        stats.total_response_time_ms += record.response_time_ms
        stats.total_response_size_bytes += record.response_size_bytes

        if stats.first_request_time is None:
            stats.first_request_time = record.timestamp
        stats.last_request_time = record.timestamp

        # Update outcome-specific stats
        if record.outcome == RequestOutcome.SUCCESS:
            stats.successful_requests += 1
            stats.consecutive_errors = 0  # Reset on success
        elif record.outcome == RequestOutcome.RATE_LIMITED:
            stats.rate_limited_requests += 1
            stats.failed_requests += 1
            stats.consecutive_errors += 1
            stats.last_error_message = "Rate limited (429)"
        elif record.outcome in (
            RequestOutcome.CLIENT_ERROR,
            RequestOutcome.SERVER_ERROR,
            RequestOutcome.TIMEOUT,
            RequestOutcome.CONNECTION_ERROR,
        ):
            stats.failed_requests += 1
            stats.consecutive_errors += 1
            stats.last_error_message = record.error_message

    def get_domain_statistics(self, domain: str) -> Optional[DomainStatistics]:
        """
        Get statistics for a specific domain.

        Args:
            domain: Domain to get stats for

        Returns:
            DomainStatistics or None if no data
        """
        with self._lock:
            return self._domain_stats.get(domain)

    def get_global_statistics(self) -> DomainStatistics:
        """
        Get global statistics across all domains.

        Returns:
            Global DomainStatistics
        """
        with self._lock:
            return self._domain_stats.get("__global__", DomainStatistics(domain="__global__"))

    def get_all_statistics(self) -> dict[str, dict[str, Any]]:
        """
        Get statistics for all domains.

        Returns:
            Dict mapping domain -> statistics dict
        """
        with self._lock:
            return {
                domain: stats.to_dict()
                for domain, stats in self._domain_stats.items()
                if domain != "__global__"
            }

    def get_recent_records(
        self,
        domain: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get recent request records.

        Args:
            domain: Specific domain (None for all)
            limit: Maximum records to return

        Returns:
            List of request record dicts
        """
        with self._lock:
            if domain:
                records = self._recent_records.get(domain, [])
            else:
                # Merge all domains
                records = []
                for domain_records in self._recent_records.values():
                    records.extend(domain_records)
                # Sort by timestamp
                records.sort(key=lambda r: r.timestamp, reverse=True)

            return [r.to_dict() for r in records[:limit]]

    # =========================================================================
    # TARGET VERIFICATION
    # =========================================================================

    async def verify_target_accessible(
        self,
        target_url: str,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> bool:
        """
        Verify that a target is accessible before scanning.

        Performs a lightweight HEAD request to check connectivity.

        Args:
            target_url: Target URL to verify
            timeout: Request timeout (uses config default if None)
            retries: Number of retries (uses config default if None)

        Returns:
            bool: True if target is accessible
        """
        timeout = timeout or self._config.verification_timeout_seconds
        retries = retries or self._config.verification_retries

        self._audit_log({
            "event": "TARGET_VERIFICATION_START",
            "target": target_url,
        })

        for attempt in range(retries):
            try:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    follow_redirects=True,
                    verify=False,  # Allow self-signed certs for verification
                ) as client:
                    response = await client.head(target_url)

                    # Any response (even 4xx/5xx) means target is reachable
                    logger.info(f"Target accessible: {target_url} (status: {response.status_code})")

                    self._audit_log({
                        "event": "TARGET_VERIFICATION_SUCCESS",
                        "target": target_url,
                        "status_code": response.status_code,
                        "attempts": attempt + 1,
                    })

                    return True

            except httpx.TimeoutException:
                logger.warning(f"Target verification timeout (attempt {attempt + 1}/{retries}): {target_url}")
            except httpx.ConnectError as e:
                logger.warning(f"Target connection error (attempt {attempt + 1}/{retries}): {e}")
            except Exception as e:
                logger.warning(f"Target verification error (attempt {attempt + 1}/{retries}): {e}")

            # Wait before retry
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

        # All retries failed
        logger.error(f"Target unreachable after {retries} attempts: {target_url}")

        self._audit_log({
            "event": "TARGET_VERIFICATION_FAILED",
            "target": target_url,
            "attempts": retries,
        })

        return False

    async def verify_protection_working(self) -> bool:
        """
        Verify that network protection is working correctly.

        Checks proxy/Tor if configured.

        Returns:
            bool: True if protection verified or not required
        """
        try:
            protection = get_network_protection()

            if not protection.proxy_config.enabled:
                logger.warning("Network protection disabled - IP is visible")
                return True

            result = await protection.verify_proxy_working()

            if not result:
                if self._config.kill_switch.trigger_on_protection_failure:
                    self.activate_kill_switch(
                        "Network protection verification failed - IP leak detected",
                        KillSwitchTrigger.PROTECTION_FAILURE,
                    )
                return False

            return True

        except Exception as e:
            logger.error(f"Protection verification error: {e}")

            if self._config.kill_switch.trigger_on_protection_failure:
                self.activate_kill_switch(
                    f"Protection verification error: {e}",
                    KillSwitchTrigger.PROTECTION_FAILURE,
                )

            return False

    # =========================================================================
    # STATUS AND REPORTING
    # =========================================================================

    def get_status(self) -> dict[str, Any]:
        """
        Get comprehensive protection status.

        Returns:
            Dict with all status information
        """
        with self._lock:
            base_status = get_protection_status()
            global_stats = self.get_global_statistics()

            return {
                "initialized": self._initialized,
                "kill_switch": self.get_kill_switch_info(),
                "network_protection": base_status,
                "scope": {
                    "domains_in_scope": len(self._in_scope_domains),
                    "out_of_scope_attempts": self._out_of_scope_attempts,
                },
                "traffic": {
                    "total_requests": global_stats.total_requests,
                    "successful_requests": global_stats.successful_requests,
                    "failed_requests": global_stats.failed_requests,
                    "success_rate": round(global_stats.success_rate, 2),
                    "average_response_time_ms": round(global_stats.average_response_time_ms, 2),
                    "domains_monitored": len(self._domain_stats) - 1,  # Exclude __global__
                },
                "triggers": {
                    "consecutive_errors": global_stats.consecutive_errors,
                    "recent_rate_limits": self._count_recent_rate_limits(60),
                },
            }

    def print_status_banner(self) -> None:
        """Print a formatted status banner to console."""
        status = self.get_status()

        if status["kill_switch"]["active"]:
            print("""
╔════════════════════════════════════════════════════════════════════╗
║  🛑 PHANTOM KILL SWITCH ACTIVE - ALL TRAFFIC BLOCKED                ║
╠════════════════════════════════════════════════════════════════════╣""")
            print(f"║  Reason: {status['kill_switch']['reason'][:55]:<55} ║")
            print(f"║  Trigger: {status['kill_switch']['trigger']:<54} ║")
            print("""╚════════════════════════════════════════════════════════════════════╝
""")
            return

        traffic = status["traffic"]
        triggers = status["triggers"]

        print(f"""
╔════════════════════════════════════════════════════════════════════╗
║  🛡️  PHANTOM Network Protection Status                              ║
╠════════════════════════════════════════════════════════════════════╣
║  Kill Switch: {'ARMED' if self._config.kill_switch.enabled else 'DISABLED':<10}  Protection: {'✅ Active' if status['network_protection']['enabled'] else '⚠️ Disabled':<15}     ║
║                                                                    ║
║  Traffic Statistics:                                               ║
║    Total Requests:    {traffic['total_requests']:<10}                                 ║
║    Success Rate:      {traffic['success_rate']:.1f}%                                       ║
║    Avg Response Time: {traffic['average_response_time_ms']:.0f}ms                                      ║
║    Domains Monitored: {traffic['domains_monitored']:<10}                                 ║
║                                                                    ║
║  Trigger Status:                                                   ║
║    Consecutive Errors: {triggers['consecutive_errors']:<5} / {self._config.kill_switch.consecutive_errors_threshold:<5}                           ║
║    Recent Rate Limits: {triggers['recent_rate_limits']:<5} / {self._config.kill_switch.rate_limit_threshold:<5}                           ║
╚════════════════════════════════════════════════════════════════════╝
""")


# =============================================================================
# MODULE-LEVEL CONVENIENCE FUNCTIONS
# =============================================================================

def get_phantom_protection() -> PhantomNetworkProtection:
    """
    Get the PHANTOM network protection singleton.

    Convenience function for easy access.

    Returns:
        PhantomNetworkProtection instance
    """
    return PhantomNetworkProtection.get_instance()


async def verify_target_and_protection(target_url: str) -> bool:
    """
    Verify both target accessibility and network protection.

    Convenience function for pre-scan checks.

    Args:
        target_url: Target to verify

    Returns:
        bool: True if both checks pass
    """
    protection = get_phantom_protection()

    # Initialize if needed
    if not protection._initialized:
        await protection.initialize()

    # Verify protection first
    if not await protection.verify_protection_working():
        return False

    # Verify target
    if not await protection.verify_target_accessible(target_url):
        return False

    return True


def record_request_outcome(
    domain: str,
    endpoint: str,
    method: str,
    response: Optional[httpx.Response] = None,
    error: Optional[Exception] = None,
    response_time_ms: float = 0.0,
) -> None:
    """
    Convenience function to record request outcome.

    Automatically determines outcome from response or error.

    Args:
        domain: Target domain
        endpoint: Request endpoint
        method: HTTP method
        response: HTTP response (if successful)
        error: Exception (if failed)
        response_time_ms: Response time
    """
    protection = get_phantom_protection()

    if error:
        if isinstance(error, httpx.TimeoutException):
            outcome = RequestOutcome.TIMEOUT
        elif isinstance(error, httpx.ConnectError):
            outcome = RequestOutcome.CONNECTION_ERROR
        elif isinstance(error, KillSwitchActive):
            outcome = RequestOutcome.BLOCKED
        else:
            outcome = RequestOutcome.CONNECTION_ERROR

        protection.record_request(
            domain=domain,
            endpoint=endpoint,
            method=method,
            outcome=outcome,
            status_code=None,
            response_time_ms=response_time_ms,
            response_size_bytes=0,
            error_message=str(error),
        )
        return

    if response:
        if response.status_code == 429:
            outcome = RequestOutcome.RATE_LIMITED
        elif 200 <= response.status_code < 300:
            outcome = RequestOutcome.SUCCESS
        elif 400 <= response.status_code < 500:
            outcome = RequestOutcome.CLIENT_ERROR
        else:
            outcome = RequestOutcome.SERVER_ERROR

        protection.record_request(
            domain=domain,
            endpoint=endpoint,
            method=method,
            outcome=outcome,
            status_code=response.status_code,
            response_time_ms=response_time_ms,
            response_size_bytes=len(response.content) if response.content else 0,
        )
