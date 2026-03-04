"""
Counter Metrics - Thread-safe counters for operational metrics.

Provides:
- Counter: Simple incrementing counter
- LabeledCounter: Counter with labels for dimensional data
- RateCounter: Counter that tracks rate per time window
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Counter:
    """Thread-safe counter for tracking occurrences.

    Example:
        requests = Counter("http_requests_total", "Total HTTP requests sent")
        requests.inc()
        requests.inc(5)
        print(requests.value)  # 6
    """
    name: str
    description: str = ""
    _value: int = field(default=0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, amount: int = 1) -> None:
        """Increment counter by amount (default 1)."""
        with self._lock:
            self._value += amount

    @property
    def value(self) -> int:
        """Get current counter value."""
        with self._lock:
            return self._value

    def reset(self) -> int:
        """Reset counter and return previous value."""
        with self._lock:
            prev = self._value
            self._value = 0
            return prev

    def to_dict(self) -> dict:
        """Export counter as dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "type": "counter",
            "value": self.value,
        }


@dataclass
class LabeledCounter:
    """Counter with labels for dimensional metrics.

    Example:
        errors = LabeledCounter("errors_total", "Total errors by type")
        errors.inc(error_type="timeout")
        errors.inc(error_type="connection", count=3)
        print(errors.values)  # {'timeout': 1, 'connection': 3}
    """
    name: str
    description: str = ""
    _values: Dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, count: int = 1, **labels) -> None:
        """Increment counter for given label combination."""
        label_key = self._labels_to_key(labels)
        with self._lock:
            self._values[label_key] += count

    def _labels_to_key(self, labels: dict) -> str:
        """Convert labels dict to hashable string key."""
        if not labels:
            return "__default__"
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))

    @property
    def values(self) -> Dict[str, int]:
        """Get all counter values by label."""
        with self._lock:
            return dict(self._values)

    def get(self, **labels) -> int:
        """Get counter value for specific label combination."""
        label_key = self._labels_to_key(labels)
        with self._lock:
            return self._values.get(label_key, 0)

    @property
    def total(self) -> int:
        """Get sum of all counters."""
        with self._lock:
            return sum(self._values.values())

    def reset(self) -> Dict[str, int]:
        """Reset all counters and return previous values."""
        with self._lock:
            prev = dict(self._values)
            self._values.clear()
            return prev

    def to_dict(self) -> dict:
        """Export counter as dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "type": "labeled_counter",
            "values": self.values,
            "total": self.total,
        }


@dataclass
class RateCounter:
    """Counter that tracks rate over a sliding time window.

    Example:
        rate = RateCounter("requests_per_second", window_seconds=60)
        rate.inc()
        time.sleep(1)
        rate.inc(10)
        print(rate.rate_per_second)  # ~5.5 (11 events in ~2 seconds)
    """
    name: str
    description: str = ""
    window_seconds: float = 60.0
    _events: list = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, amount: int = 1) -> None:
        """Record events at current time."""
        now = time.time()
        with self._lock:
            for _ in range(amount):
                self._events.append(now)
            self._prune_old_events(now)

    def _prune_old_events(self, now: float) -> None:
        """Remove events outside the window."""
        cutoff = now - self.window_seconds
        # Keep only events within window
        self._events = [t for t in self._events if t > cutoff]

    @property
    def count_in_window(self) -> int:
        """Get count of events in current window."""
        now = time.time()
        with self._lock:
            self._prune_old_events(now)
            return len(self._events)

    @property
    def rate_per_second(self) -> float:
        """Get events per second over the window."""
        now = time.time()
        with self._lock:
            self._prune_old_events(now)
            if not self._events:
                return 0.0
            # Calculate actual time span
            oldest = min(self._events)
            span = now - oldest
            if span <= 0:
                return float(len(self._events))
            return len(self._events) / span

    @property
    def rate_per_minute(self) -> float:
        """Get events per minute."""
        return self.rate_per_second * 60

    def reset(self) -> int:
        """Reset and return count of cleared events."""
        with self._lock:
            count = len(self._events)
            self._events.clear()
            return count

    def to_dict(self) -> dict:
        """Export counter as dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "type": "rate_counter",
            "window_seconds": self.window_seconds,
            "count_in_window": self.count_in_window,
            "rate_per_second": round(self.rate_per_second, 2),
            "rate_per_minute": round(self.rate_per_minute, 2),
        }


# Pre-defined counters for common scan operations
class ScanCounters:
    """Collection of commonly used scan counters."""

    def __init__(self):
        # Network counters
        self.requests_total = Counter(
            "http_requests_total",
            "Total HTTP requests sent during scan"
        )
        self.requests_by_method = LabeledCounter(
            "http_requests_by_method",
            "HTTP requests by method (GET, POST, etc.)"
        )
        self.bytes_sent = Counter(
            "bytes_sent_total",
            "Total bytes sent in requests"
        )
        self.bytes_received = Counter(
            "bytes_received_total",
            "Total bytes received in responses"
        )

        # Response counters
        self.responses_by_status = LabeledCounter(
            "http_responses_by_status",
            "HTTP responses by status code category"
        )

        # Finding counters
        self.findings_total = Counter(
            "findings_total",
            "Total vulnerabilities discovered"
        )
        self.findings_by_severity = LabeledCounter(
            "findings_by_severity",
            "Findings by severity level"
        )
        self.findings_by_type = LabeledCounter(
            "findings_by_type",
            "Findings by vulnerability type"
        )

        # Module counters
        self.modules_started = Counter(
            "modules_started_total",
            "Total scanner modules started"
        )
        self.modules_completed = Counter(
            "modules_completed_total",
            "Total scanner modules completed successfully"
        )
        self.modules_failed = Counter(
            "modules_failed_total",
            "Total scanner modules that failed"
        )
        self.module_errors_by_type = LabeledCounter(
            "module_errors_by_type",
            "Module errors by error type"
        )

        # Rate limiting
        self.rate_limits_hit = Counter(
            "rate_limits_hit_total",
            "Times rate limiting was triggered"
        )
        self.waf_blocks = Counter(
            "waf_blocks_total",
            "Times WAF blocked requests"
        )

        # Request rate tracking
        self.request_rate = RateCounter(
            "request_rate",
            "Request rate over last 60 seconds",
            window_seconds=60.0
        )

    def record_request(self, method: str, size_bytes: int = 0) -> None:
        """Record an HTTP request."""
        self.requests_total.inc()
        self.requests_by_method.inc(method=method)
        if size_bytes > 0:
            self.bytes_sent.inc(size_bytes)
        self.request_rate.inc()

    def record_response(self, status_code: int, size_bytes: int = 0) -> None:
        """Record an HTTP response."""
        # Categorize by status code range
        category = f"{status_code // 100}xx"
        self.responses_by_status.inc(status=category)
        if size_bytes > 0:
            self.bytes_received.inc(size_bytes)

    def record_finding(self, severity: str, vuln_type: str) -> None:
        """Record a discovered finding."""
        self.findings_total.inc()
        self.findings_by_severity.inc(severity=severity.lower())
        self.findings_by_type.inc(type=vuln_type)

    def record_module_start(self) -> None:
        """Record a module starting."""
        self.modules_started.inc()

    def record_module_complete(self, success: bool = True) -> None:
        """Record a module completing."""
        if success:
            self.modules_completed.inc()
        else:
            self.modules_failed.inc()

    def record_module_error(self, error_type: str) -> None:
        """Record a module error."""
        self.module_errors_by_type.inc(error_type=error_type)

    def to_dict(self) -> dict:
        """Export all counters as dictionary."""
        return {
            "network": {
                "requests": self.requests_total.to_dict(),
                "requests_by_method": self.requests_by_method.to_dict(),
                "bytes_sent": self.bytes_sent.to_dict(),
                "bytes_received": self.bytes_received.to_dict(),
                "responses_by_status": self.responses_by_status.to_dict(),
                "request_rate": self.request_rate.to_dict(),
            },
            "findings": {
                "total": self.findings_total.to_dict(),
                "by_severity": self.findings_by_severity.to_dict(),
                "by_type": self.findings_by_type.to_dict(),
            },
            "modules": {
                "started": self.modules_started.to_dict(),
                "completed": self.modules_completed.to_dict(),
                "failed": self.modules_failed.to_dict(),
                "errors_by_type": self.module_errors_by_type.to_dict(),
            },
            "protection": {
                "rate_limits_hit": self.rate_limits_hit.to_dict(),
                "waf_blocks": self.waf_blocks.to_dict(),
            },
        }

    def reset_all(self) -> None:
        """Reset all counters."""
        self.requests_total.reset()
        self.requests_by_method.reset()
        self.bytes_sent.reset()
        self.bytes_received.reset()
        self.responses_by_status.reset()
        self.findings_total.reset()
        self.findings_by_severity.reset()
        self.findings_by_type.reset()
        self.modules_started.reset()
        self.modules_completed.reset()
        self.modules_failed.reset()
        self.module_errors_by_type.reset()
        self.rate_limits_hit.reset()
        self.waf_blocks.reset()
        self.request_rate.reset()
