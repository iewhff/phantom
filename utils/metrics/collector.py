"""
Operational Metrics Collector - Central metrics collection for scans.

Provides a singleton MetricsCollector that aggregates all operational
metrics (counters, timers, gauges) for observability during scans.

Usage:
    from utils.metrics import get_metrics

    metrics = get_metrics()
    metrics.counters.requests_total.inc()
    metrics.timers.request_latency.observe(0.5)
    metrics.gauges.active_modules.inc()

    # Export for analysis
    snapshot = metrics.snapshot()
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from .counters import ScanCounters
from .gauges import ScanGauges
from .timers import ScanTimers


@dataclass
class ScanContext:
    """Context information for a scan session."""
    scan_id: str
    target: str
    started_at: datetime
    safe_mode: str = "safe"
    modules_requested: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class OperationalMetricsCollector:
    """
    Central collector for all operational metrics.

    Features:
    - Aggregates counters, timers, and gauges
    - Scan-scoped metrics with context
    - Thread-safe operations
    - JSON export for analysis
    - Prometheus-compatible export format

    Example:
        collector = OperationalMetricsCollector()

        # Start a scan
        collector.start_scan("scan-001", "https://example.com")

        # Record metrics
        collector.counters.requests_total.inc()
        collector.timers.request_latency.observe(0.15)
        collector.gauges.active_modules.set(5)

        # Get snapshot
        data = collector.snapshot()

        # End scan
        collector.end_scan()
    """

    _instance: Optional["OperationalMetricsCollector"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "OperationalMetricsCollector":
        """Singleton pattern - only one collector per process."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self):
        """Initialize metrics collector (only runs once due to singleton)."""
        if getattr(self, "_initialized", False):
            return

        self._initialized = True
        self._init_lock = threading.Lock()

        # Core metric collections
        self.counters = ScanCounters()
        self.timers = ScanTimers()
        self.gauges = ScanGauges()

        # Scan context
        self._context: Optional[ScanContext] = None
        self._scan_started: Optional[float] = None
        self._history: list = []
        self._max_history: int = 100

        # Custom metrics registry
        self._custom_counters: Dict[str, Any] = {}
        self._custom_timers: Dict[str, Any] = {}
        self._custom_gauges: Dict[str, Any] = {}

    def start_scan(
        self,
        scan_id: str,
        target: str,
        safe_mode: str = "safe",
        modules: list = None,
        **metadata
    ) -> None:
        """Start a new scan session and reset metrics."""
        with self._init_lock:
            # Save previous scan to history
            if self._context is not None:
                self._save_to_history()

            # Reset metrics
            self.counters.reset_all()
            self.timers.reset_all()
            self.gauges.reset_all()

            # Set new context
            self._context = ScanContext(
                scan_id=scan_id,
                target=target,
                started_at=datetime.now(),
                safe_mode=safe_mode,
                modules_requested=modules or [],
                metadata=metadata,
            )
            self._scan_started = time.time()

            # Start total scan timer
            self.timers.total_scan.start()

    def end_scan(self) -> dict:
        """End scan and return final metrics snapshot."""
        with self._init_lock:
            # Stop total scan timer
            self.timers.total_scan.stop()

            # Get final snapshot
            snapshot = self.snapshot()

            # Save to history
            self._save_to_history()

            # Clear context
            self._context = None
            self._scan_started = None

            return snapshot

    def _save_to_history(self) -> None:
        """Save current scan metrics to history."""
        if self._context is None:
            return

        entry = {
            "scan_id": self._context.scan_id,
            "target": self._context.target,
            "started_at": self._context.started_at.isoformat(),
            "ended_at": datetime.now().isoformat(),
            "duration_seconds": time.time() - (self._scan_started or time.time()),
            "summary": {
                "requests": self.counters.requests_total.value,
                "findings": self.counters.findings_total.value,
                "modules_started": self.counters.modules_started.value,
                "modules_failed": self.counters.modules_failed.value,
            },
        }
        self._history.append(entry)

        # Trim history
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

    @property
    def context(self) -> Optional[ScanContext]:
        """Get current scan context."""
        return self._context

    @property
    def scan_duration_seconds(self) -> float:
        """Get current scan duration in seconds."""
        if self._scan_started is None:
            return 0.0
        return time.time() - self._scan_started

    def snapshot(self) -> dict:
        """Get complete metrics snapshot.

        Returns dict suitable for JSON serialization with all
        counters, timers, gauges, and context.
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "context": self._context_to_dict(),
            "counters": self.counters.to_dict(),
            "timers": self.timers.to_dict(),
            "gauges": self.gauges.to_dict(),
            "custom": {
                "counters": {k: v.to_dict() for k, v in self._custom_counters.items()},
                "timers": {k: v.to_dict() for k, v in self._custom_timers.items()},
                "gauges": {k: v.to_dict() for k, v in self._custom_gauges.items()},
            },
            "duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def _context_to_dict(self) -> dict:
        """Convert context to dict."""
        if self._context is None:
            return {}
        return {
            "scan_id": self._context.scan_id,
            "target": self._context.target,
            "started_at": self._context.started_at.isoformat(),
            "safe_mode": self._context.safe_mode,
            "modules_requested": self._context.modules_requested,
            "metadata": self._context.metadata,
        }

    def summary(self) -> dict:
        """Get concise metrics summary (for logging/display)."""
        return {
            "scan_id": self._context.scan_id if self._context else None,
            "duration_seconds": round(self.scan_duration_seconds, 1),
            "requests": self.counters.requests_total.value,
            "findings": self.counters.findings_total.value,
            "findings_by_severity": self.counters.findings_by_severity.values,
            "modules_completed": self.counters.modules_completed.value,
            "modules_failed": self.counters.modules_failed.value,
            "rate_limits_hit": self.counters.rate_limits_hit.value,
            "memory_mb": round(self.gauges.memory.rss_mb, 1),
            "memory_peak_mb": round(self.gauges.memory.peak_mb, 1),
            "request_rate": round(self.counters.request_rate.rate_per_second, 2),
        }

    def save_to_file(self, filepath: str | Path) -> None:
        """Save metrics snapshot to JSON file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(self.snapshot(), indent=2))

    def get_history(self) -> list:
        """Get scan history."""
        return list(self._history)

    # Convenience methods for recording common metrics

    def record_request(
        self,
        method: str = "GET",
        size_bytes: int = 0,
        latency_seconds: float = None
    ) -> None:
        """Record an HTTP request with all related metrics."""
        self.counters.record_request(method, size_bytes)
        if latency_seconds is not None:
            self.timers.record_request_latency(latency_seconds)

    def record_response(
        self,
        status_code: int,
        size_bytes: int = 0
    ) -> None:
        """Record an HTTP response."""
        self.counters.record_response(status_code, size_bytes)

    def record_finding(
        self,
        severity: str,
        vuln_type: str
    ) -> None:
        """Record a discovered finding."""
        self.counters.record_finding(severity, vuln_type)

    def record_module_start(self, module_name: str = None) -> None:
        """Record a module starting."""
        self.counters.record_module_start()
        self.gauges.active_modules.inc()

    def record_module_complete(
        self,
        success: bool = True,
        duration_seconds: float = None,
        module_name: str = None
    ) -> None:
        """Record a module completing."""
        self.counters.record_module_complete(success)
        self.gauges.active_modules.dec()
        if duration_seconds is not None:
            self.timers.record_module_duration(duration_seconds)

    def record_error(self, error_type: str) -> None:
        """Record an error occurrence."""
        self.counters.module_errors_by_type.inc(error_type=error_type)

    def record_rate_limit(self) -> None:
        """Record a rate limit hit."""
        self.counters.rate_limits_hit.inc()

    def record_waf_block(self) -> None:
        """Record a WAF block."""
        self.counters.waf_blocks.inc()


# Global singleton instance
_collector: Optional[OperationalMetricsCollector] = None


def get_metrics() -> OperationalMetricsCollector:
    """Get the global metrics collector singleton.

    Usage:
        from utils.metrics import get_metrics

        metrics = get_metrics()
        metrics.record_request("GET", latency_seconds=0.1)
    """
    global _collector
    if _collector is None:
        _collector = OperationalMetricsCollector()
    return _collector


def reset_metrics() -> None:
    """Reset the global metrics collector (useful for testing)."""
    global _collector
    # Reset both the module-level cache and the class-level singleton
    _collector = None
    OperationalMetricsCollector._instance = None
