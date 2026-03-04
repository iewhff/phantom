"""
Gauge Metrics - Point-in-time value metrics.

Provides:
- Gauge: Simple value that can increase or decrease
- MemoryGauge: Track memory usage
- ConnectionGauge: Track active connections
"""

from __future__ import annotations

import os
import resource
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class Gauge:
    """Thread-safe gauge for tracking current values.

    Unlike counters, gauges can go up and down.

    Example:
        active_requests = Gauge("active_requests", "Currently active requests")
        active_requests.inc()
        active_requests.inc()
        active_requests.dec()
        print(active_requests.value)  # 1
    """
    name: str
    description: str = ""
    _value: float = field(default=0.0, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _history: List[tuple] = field(default_factory=list, repr=False)
    _history_max: int = field(default=100, repr=False)

    def set(self, value: float) -> None:
        """Set the gauge to a specific value."""
        with self._lock:
            self._value = value
            self._record_history()

    def inc(self, amount: float = 1) -> None:
        """Increment gauge by amount (default 1)."""
        with self._lock:
            self._value += amount
            self._record_history()

    def dec(self, amount: float = 1) -> None:
        """Decrement gauge by amount (default 1)."""
        with self._lock:
            self._value -= amount
            self._record_history()

    def _record_history(self) -> None:
        """Record value in history (must be called with lock held)."""
        self._history.append((time.time(), self._value))
        # Trim history to max size
        if len(self._history) > self._history_max:
            self._history = self._history[-self._history_max:]

    @property
    def value(self) -> float:
        """Get current gauge value."""
        with self._lock:
            return self._value

    @property
    def history(self) -> List[tuple]:
        """Get value history as list of (timestamp, value) tuples."""
        with self._lock:
            return list(self._history)

    @property
    def peak(self) -> float:
        """Get highest recorded value."""
        with self._lock:
            if not self._history:
                return self._value
            return max(v for _, v in self._history)

    @property
    def min(self) -> float:
        """Get lowest recorded value."""
        with self._lock:
            if not self._history:
                return self._value
            return min(v for _, v in self._history)

    def reset(self) -> float:
        """Reset gauge and return previous value."""
        with self._lock:
            prev = self._value
            self._value = 0.0
            self._history.clear()
            return prev

    def to_dict(self) -> dict:
        """Export gauge as dictionary."""
        with self._lock:
            return {
                "name": self.name,
                "description": self.description,
                "type": "gauge",
                "value": self._value,
                "peak": self.peak,
                "min": self.min,
            }


@dataclass
class LabeledGauge:
    """Gauge with labels for dimensional metrics.

    Example:
        connections = LabeledGauge("active_connections", "Active connections by host")
        connections.set(5, host="api.example.com")
        connections.inc(host="db.example.com")
    """
    name: str
    description: str = ""
    _values: Dict[str, float] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def _labels_to_key(self, labels: dict) -> str:
        """Convert labels dict to hashable string key."""
        if not labels:
            return "__default__"
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))

    def set(self, value: float, **labels) -> None:
        """Set gauge value for given labels."""
        label_key = self._labels_to_key(labels)
        with self._lock:
            self._values[label_key] = value

    def inc(self, amount: float = 1, **labels) -> None:
        """Increment gauge for given labels."""
        label_key = self._labels_to_key(labels)
        with self._lock:
            self._values[label_key] = self._values.get(label_key, 0) + amount

    def dec(self, amount: float = 1, **labels) -> None:
        """Decrement gauge for given labels."""
        label_key = self._labels_to_key(labels)
        with self._lock:
            self._values[label_key] = self._values.get(label_key, 0) - amount

    def get(self, **labels) -> float:
        """Get gauge value for specific labels."""
        label_key = self._labels_to_key(labels)
        with self._lock:
            return self._values.get(label_key, 0)

    @property
    def values(self) -> Dict[str, float]:
        """Get all gauge values."""
        with self._lock:
            return dict(self._values)

    @property
    def total(self) -> float:
        """Get sum of all gauge values."""
        with self._lock:
            return sum(self._values.values())

    def reset(self) -> Dict[str, float]:
        """Reset all gauges and return previous values."""
        with self._lock:
            prev = dict(self._values)
            self._values.clear()
            return prev

    def to_dict(self) -> dict:
        """Export gauge as dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "type": "labeled_gauge",
            "values": self.values,
            "total": self.total,
        }


class MemoryGauge:
    """Track process memory usage.

    Example:
        memory = MemoryGauge()
        print(f"RSS: {memory.rss_mb:.1f} MB")
        print(f"Peak: {memory.peak_mb:.1f} MB")
    """

    def __init__(self):
        self._peak_rss: int = 0
        self._initial_rss: int = self._get_rss()
        self._lock = threading.Lock()

    def _get_rss(self) -> int:
        """Get current RSS in bytes."""
        try:
            # Try /proc/self/statm first (Linux)
            with open("/proc/self/statm", "r") as f:
                # statm format: size resident shared text lib data dt
                fields = f.read().split()
                page_size = resource.getpagesize()
                return int(fields[1]) * page_size
        except (FileNotFoundError, IndexError):
            pass

        # Fallback to resource module
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return usage.ru_maxrss * 1024  # ru_maxrss is in KB on Linux
        except Exception:
            return 0

    def sample(self) -> int:
        """Sample current memory and update peak."""
        rss = self._get_rss()
        with self._lock:
            if rss > self._peak_rss:
                self._peak_rss = rss
        return rss

    @property
    def rss_bytes(self) -> int:
        """Get current RSS in bytes."""
        return self.sample()

    @property
    def rss_mb(self) -> float:
        """Get current RSS in megabytes."""
        return self.rss_bytes / (1024 * 1024)

    @property
    def peak_bytes(self) -> int:
        """Get peak RSS in bytes."""
        self.sample()  # Update peak
        with self._lock:
            return self._peak_rss

    @property
    def peak_mb(self) -> float:
        """Get peak RSS in megabytes."""
        return self.peak_bytes / (1024 * 1024)

    @property
    def increase_bytes(self) -> int:
        """Get memory increase since init."""
        return self.rss_bytes - self._initial_rss

    @property
    def increase_mb(self) -> float:
        """Get memory increase in MB since init."""
        return self.increase_bytes / (1024 * 1024)

    def reset(self) -> None:
        """Reset peak and initial tracking."""
        with self._lock:
            self._peak_rss = self._get_rss()
            self._initial_rss = self._peak_rss

    def to_dict(self) -> dict:
        """Export memory metrics as dictionary."""
        return {
            "name": "memory_usage",
            "type": "memory_gauge",
            "rss_bytes": self.rss_bytes,
            "rss_mb": round(self.rss_mb, 2),
            "peak_bytes": self.peak_bytes,
            "peak_mb": round(self.peak_mb, 2),
            "increase_bytes": self.increase_bytes,
            "increase_mb": round(self.increase_mb, 2),
        }


class ConnectionGauge:
    """Track active network connections.

    Example:
        conn = ConnectionGauge()
        conn.connection_opened("api.example.com")
        conn.connection_opened("api.example.com")
        conn.connection_closed("api.example.com")
        print(conn.active_by_host)  # {'api.example.com': 1}
    """

    def __init__(self):
        self._by_host: Dict[str, int] = {}
        self._total_opened: int = 0
        self._total_closed: int = 0
        self._lock = threading.Lock()

    def connection_opened(self, host: str) -> None:
        """Record a connection being opened."""
        with self._lock:
            self._by_host[host] = self._by_host.get(host, 0) + 1
            self._total_opened += 1

    def connection_closed(self, host: str) -> None:
        """Record a connection being closed."""
        with self._lock:
            if host in self._by_host and self._by_host[host] > 0:
                self._by_host[host] -= 1
            self._total_closed += 1

    @property
    def active(self) -> int:
        """Get total active connections."""
        with self._lock:
            return sum(self._by_host.values())

    @property
    def active_by_host(self) -> Dict[str, int]:
        """Get active connections by host."""
        with self._lock:
            return {k: v for k, v in self._by_host.items() if v > 0}

    @property
    def total_opened(self) -> int:
        """Get total connections ever opened."""
        with self._lock:
            return self._total_opened

    @property
    def total_closed(self) -> int:
        """Get total connections ever closed."""
        with self._lock:
            return self._total_closed

    def reset(self) -> None:
        """Reset all connection tracking."""
        with self._lock:
            self._by_host.clear()
            self._total_opened = 0
            self._total_closed = 0

    def to_dict(self) -> dict:
        """Export connection metrics as dictionary."""
        return {
            "name": "connections",
            "type": "connection_gauge",
            "active": self.active,
            "active_by_host": self.active_by_host,
            "total_opened": self.total_opened,
            "total_closed": self.total_closed,
        }


class ScanGauges:
    """Collection of commonly used scan gauges."""

    def __init__(self):
        # Module tracking
        self.active_modules = Gauge(
            "active_modules",
            "Currently running scanner modules"
        )
        self.pending_findings = Gauge(
            "pending_findings",
            "Findings awaiting validation"
        )
        self.queue_depth = Gauge(
            "queue_depth",
            "Depth of request/task queue"
        )

        # Resource tracking
        self.memory = MemoryGauge()
        self.connections = ConnectionGauge()

        # Budget tracking
        self.budget_remaining = Gauge(
            "budget_remaining",
            "Remaining request budget"
        )
        self.budget_by_module = LabeledGauge(
            "budget_by_module",
            "Remaining budget per module"
        )

        # Progress tracking
        self.scan_progress = Gauge(
            "scan_progress",
            "Scan progress percentage (0-100)"
        )
        self.endpoints_remaining = Gauge(
            "endpoints_remaining",
            "Endpoints remaining to scan"
        )

    def to_dict(self) -> dict:
        """Export all gauges as dictionary."""
        return {
            "modules": {
                "active": self.active_modules.to_dict(),
            },
            "findings": {
                "pending": self.pending_findings.to_dict(),
            },
            "queue": {
                "depth": self.queue_depth.to_dict(),
            },
            "resources": {
                "memory": self.memory.to_dict(),
                "connections": self.connections.to_dict(),
            },
            "budget": {
                "remaining": self.budget_remaining.to_dict(),
                "by_module": self.budget_by_module.to_dict(),
            },
            "progress": {
                "percentage": self.scan_progress.to_dict(),
                "endpoints_remaining": self.endpoints_remaining.to_dict(),
            },
        }

    def reset_all(self) -> None:
        """Reset all gauges."""
        self.active_modules.reset()
        self.pending_findings.reset()
        self.queue_depth.reset()
        self.memory.reset()
        self.connections.reset()
        self.budget_remaining.reset()
        self.budget_by_module.reset()
        self.scan_progress.reset()
        self.endpoints_remaining.reset()
