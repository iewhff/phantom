"""
Timer Metrics - Timing utilities for performance measurement.

Provides:
- Timer: Simple start/stop timer
- Histogram: Distribution of timing values
- ContextTimer: Context manager for timing code blocks
- async_timer: Decorator for timing async functions
"""

from __future__ import annotations

import asyncio
import functools
import statistics
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, TypeVar

T = TypeVar("T")


@dataclass
class Timer:
    """Simple start/stop timer for measuring duration.

    Example:
        timer = Timer("api_request")
        timer.start()
        response = api.call()
        timer.stop()
        print(f"Request took {timer.duration_ms:.2f}ms")
    """
    name: str
    description: str = ""
    _start_time: Optional[float] = field(default=None, repr=False)
    _end_time: Optional[float] = field(default=None, repr=False)
    _durations: List[float] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def start(self) -> "Timer":
        """Start the timer."""
        with self._lock:
            self._start_time = time.perf_counter()
            self._end_time = None
        return self

    def stop(self) -> float:
        """Stop the timer and return duration in seconds."""
        with self._lock:
            if self._start_time is None:
                return 0.0
            self._end_time = time.perf_counter()
            duration = self._end_time - self._start_time
            self._durations.append(duration)
            return duration

    def record(self, duration_seconds: float) -> None:
        """Manually record a duration without start/stop."""
        with self._lock:
            self._durations.append(duration_seconds)

    @property
    def duration_seconds(self) -> float:
        """Get last recorded duration in seconds."""
        with self._lock:
            if not self._durations:
                return 0.0
            return self._durations[-1]

    @property
    def duration_ms(self) -> float:
        """Get last recorded duration in milliseconds."""
        return self.duration_seconds * 1000

    @property
    def count(self) -> int:
        """Get number of timing samples."""
        with self._lock:
            return len(self._durations)

    @property
    def total_seconds(self) -> float:
        """Get total of all recorded durations."""
        with self._lock:
            return sum(self._durations)

    @property
    def avg_seconds(self) -> float:
        """Get average duration in seconds."""
        with self._lock:
            if not self._durations:
                return 0.0
            return statistics.mean(self._durations)

    @property
    def avg_ms(self) -> float:
        """Get average duration in milliseconds."""
        return self.avg_seconds * 1000

    def reset(self) -> List[float]:
        """Reset timer and return all recorded durations."""
        with self._lock:
            prev = list(self._durations)
            self._durations.clear()
            self._start_time = None
            self._end_time = None
            return prev

    def to_dict(self) -> dict:
        """Export timer as dictionary."""
        with self._lock:
            durations = list(self._durations)

        return {
            "name": self.name,
            "description": self.description,
            "type": "timer",
            "count": len(durations),
            "total_ms": round(sum(durations) * 1000, 2),
            "avg_ms": round(statistics.mean(durations) * 1000, 2) if durations else 0,
            "min_ms": round(min(durations) * 1000, 2) if durations else 0,
            "max_ms": round(max(durations) * 1000, 2) if durations else 0,
            "last_ms": round(durations[-1] * 1000, 2) if durations else 0,
        }


@dataclass
class Histogram:
    """Distribution of timing values with percentiles.

    Example:
        hist = Histogram("request_latency", buckets=[0.01, 0.05, 0.1, 0.5, 1.0])
        hist.observe(0.023)
        hist.observe(0.089)
        print(hist.p50)  # 50th percentile
        print(hist.p99)  # 99th percentile
    """
    name: str
    description: str = ""
    buckets: List[float] = field(default_factory=lambda: [
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
    ])
    _values: List[float] = field(default_factory=list, repr=False)
    _bucket_counts: Dict[float, int] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        """Initialize bucket counts."""
        with self._lock:
            for bucket in self.buckets:
                self._bucket_counts[bucket] = 0
            self._bucket_counts[float("inf")] = 0

    def observe(self, value: float) -> None:
        """Record an observation."""
        with self._lock:
            self._values.append(value)
            # Update bucket counts
            for bucket in self.buckets:
                if value <= bucket:
                    self._bucket_counts[bucket] += 1
            self._bucket_counts[float("inf")] += 1  # Always increment +Inf

    @property
    def count(self) -> int:
        """Get number of observations."""
        with self._lock:
            return len(self._values)

    @property
    def sum(self) -> float:
        """Get sum of all observations."""
        with self._lock:
            return sum(self._values)

    @property
    def avg(self) -> float:
        """Get average of observations."""
        with self._lock:
            if not self._values:
                return 0.0
            return statistics.mean(self._values)

    def percentile(self, p: float) -> float:
        """Get percentile value (0-100)."""
        with self._lock:
            if not self._values:
                return 0.0
            sorted_values = sorted(self._values)
            idx = int(len(sorted_values) * (p / 100))
            idx = min(idx, len(sorted_values) - 1)
            return sorted_values[idx]

    @property
    def p50(self) -> float:
        """Get 50th percentile (median)."""
        return self.percentile(50)

    @property
    def p90(self) -> float:
        """Get 90th percentile."""
        return self.percentile(90)

    @property
    def p95(self) -> float:
        """Get 95th percentile."""
        return self.percentile(95)

    @property
    def p99(self) -> float:
        """Get 99th percentile."""
        return self.percentile(99)

    def reset(self) -> List[float]:
        """Reset histogram and return previous values."""
        with self._lock:
            prev = list(self._values)
            self._values.clear()
            for bucket in self._bucket_counts:
                self._bucket_counts[bucket] = 0
            return prev

    def to_dict(self) -> dict:
        """Export histogram as dictionary."""
        with self._lock:
            values = list(self._values)
            buckets = dict(self._bucket_counts)

        return {
            "name": self.name,
            "description": self.description,
            "type": "histogram",
            "count": len(values),
            "sum": round(sum(values), 4) if values else 0,
            "avg": round(statistics.mean(values), 4) if values else 0,
            "min": round(min(values), 4) if values else 0,
            "max": round(max(values), 4) if values else 0,
            "percentiles": {
                "p50": round(self.p50, 4),
                "p90": round(self.p90, 4),
                "p95": round(self.p95, 4),
                "p99": round(self.p99, 4),
            },
            "buckets": {str(k): v for k, v in buckets.items()},
        }


@contextmanager
def context_timer(timer: Timer):
    """Context manager for timing code blocks.

    Example:
        timer = Timer("operation")
        with context_timer(timer):
            do_something()
        print(f"Took {timer.duration_ms}ms")
    """
    timer.start()
    try:
        yield timer
    finally:
        timer.stop()


class ContextTimer:
    """Reusable context manager timer.

    Example:
        timer = ContextTimer("db_query")
        with timer:
            db.query()
        print(timer.stats)
    """

    def __init__(self, name: str, description: str = ""):
        self.timer = Timer(name, description)

    def __enter__(self) -> "ContextTimer":
        self.timer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.timer.stop()

    @property
    def duration_ms(self) -> float:
        return self.timer.duration_ms

    @property
    def stats(self) -> dict:
        return self.timer.to_dict()


def sync_timer(name: str = None, timer: Timer = None):
    """Decorator for timing synchronous functions.

    Example:
        @sync_timer("process_data")
        def process_data(items):
            return [transform(i) for i in items]
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        nonlocal timer
        if timer is None:
            timer_name = name or func.__name__
            timer = Timer(timer_name)

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            timer.start()
            try:
                return func(*args, **kwargs)
            finally:
                timer.stop()

        wrapper._timer = timer
        return wrapper
    return decorator


def async_timer(name: str = None, timer: Timer = None):
    """Decorator for timing async functions.

    Example:
        @async_timer("fetch_data")
        async def fetch_data(url):
            return await client.get(url)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        nonlocal timer
        if timer is None:
            timer_name = name or func.__name__
            timer = Timer(timer_name)

        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            timer.start()
            try:
                return await func(*args, **kwargs)
            finally:
                timer.stop()

        wrapper._timer = timer
        return wrapper
    return decorator


class ScanTimers:
    """Collection of commonly used scan timers."""

    def __init__(self):
        # Phase timers
        self.phase_discovery = Timer("phase_discovery", "Phase 0: Discovery duration")
        self.phase_fingerprint = Timer("phase_fingerprint", "Phase 1: Fingerprinting duration")
        self.phase_scanning = Timer("phase_scanning", "Phase 2-3: Module execution duration")
        self.phase_analysis = Timer("phase_analysis", "Phase 4: Analysis duration")
        self.phase_validation = Timer("phase_validation", "Phase 5: Validation duration")
        self.phase_reporting = Timer("phase_reporting", "Phase 6: Report generation duration")

        # Component timers
        self.total_scan = Timer("total_scan", "Total scan duration")
        self.auth_acquisition = Timer("auth_acquisition", "Authentication acquisition time")
        self.chain_analysis = Timer("chain_analysis", "Attack chain analysis duration")
        self.proof_generation = Timer("proof_generation", "Proof of concept generation")

        # Histograms for distribution analysis
        self.request_latency = Histogram(
            "request_latency_seconds",
            "HTTP request latency distribution",
            buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        self.module_duration = Histogram(
            "module_duration_seconds",
            "Scanner module execution duration",
            buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
        )

    def record_request_latency(self, latency_seconds: float) -> None:
        """Record an HTTP request latency."""
        self.request_latency.observe(latency_seconds)

    def record_module_duration(self, duration_seconds: float) -> None:
        """Record a module execution duration."""
        self.module_duration.observe(duration_seconds)

    def to_dict(self) -> dict:
        """Export all timers as dictionary."""
        return {
            "phases": {
                "discovery": self.phase_discovery.to_dict(),
                "fingerprint": self.phase_fingerprint.to_dict(),
                "scanning": self.phase_scanning.to_dict(),
                "analysis": self.phase_analysis.to_dict(),
                "validation": self.phase_validation.to_dict(),
                "reporting": self.phase_reporting.to_dict(),
            },
            "components": {
                "total_scan": self.total_scan.to_dict(),
                "auth_acquisition": self.auth_acquisition.to_dict(),
                "chain_analysis": self.chain_analysis.to_dict(),
                "proof_generation": self.proof_generation.to_dict(),
            },
            "histograms": {
                "request_latency": self.request_latency.to_dict(),
                "module_duration": self.module_duration.to_dict(),
            },
        }

    def reset_all(self) -> None:
        """Reset all timers."""
        self.phase_discovery.reset()
        self.phase_fingerprint.reset()
        self.phase_scanning.reset()
        self.phase_analysis.reset()
        self.phase_validation.reset()
        self.phase_reporting.reset()
        self.total_scan.reset()
        self.auth_acquisition.reset()
        self.chain_analysis.reset()
        self.proof_generation.reset()
        self.request_latency.reset()
        self.module_duration.reset()
