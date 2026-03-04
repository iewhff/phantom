"""
Operational Metrics System - Central metrics collection for scan observability.

This module provides counters, timers, and gauges for tracking scan operations
in real-time. All metrics are thread-safe and can be exported in multiple formats.

Quick Start:
    from utils.metrics import get_metrics

    # Get the global metrics collector
    metrics = get_metrics()

    # Start a scan session
    metrics.start_scan("scan-001", "https://example.com")

    # Record metrics as you scan
    metrics.record_request("GET", latency_seconds=0.15)
    metrics.record_response(200, size_bytes=1024)
    metrics.record_finding("high", "sqli")
    metrics.record_module_start()
    metrics.record_module_complete(success=True, duration_seconds=30.5)

    # Get metrics snapshot
    print(metrics.summary())

    # End scan and get final metrics
    final = metrics.end_scan()

For advanced usage, access the underlying components:
    metrics.counters.requests_total.inc()
    metrics.timers.request_latency.observe(0.5)
    metrics.gauges.active_modules.set(5)

Exported Classes:
- Counters: Counter, LabeledCounter, RateCounter, ScanCounters
- Timers: Timer, Histogram, ContextTimer, ScanTimers
- Gauges: Gauge, LabeledGauge, MemoryGauge, ConnectionGauge, ScanGauges
- Collector: OperationalMetricsCollector, get_metrics, reset_metrics
- Exporters: JSONExporter, PrometheusExporter, CSVExporter, MetricsReporter
"""

# Counters
from .counters import (
    Counter,
    LabeledCounter,
    RateCounter,
    ScanCounters,
)

# Timers
from .timers import (
    Timer,
    Histogram,
    ContextTimer,
    ScanTimers,
    context_timer,
    sync_timer,
    async_timer,
)

# Gauges
from .gauges import (
    Gauge,
    LabeledGauge,
    MemoryGauge,
    ConnectionGauge,
    ScanGauges,
)

# Collector (main entry point)
from .collector import (
    OperationalMetricsCollector,
    ScanContext,
    get_metrics,
    reset_metrics,
)

# Exporters
from .exporters import (
    JSONExporter,
    PrometheusExporter,
    CSVExporter,
    MetricsReporter,
)

__all__ = [
    # Counters
    "Counter",
    "LabeledCounter",
    "RateCounter",
    "ScanCounters",
    # Timers
    "Timer",
    "Histogram",
    "ContextTimer",
    "ScanTimers",
    "context_timer",
    "sync_timer",
    "async_timer",
    # Gauges
    "Gauge",
    "LabeledGauge",
    "MemoryGauge",
    "ConnectionGauge",
    "ScanGauges",
    # Collector
    "OperationalMetricsCollector",
    "ScanContext",
    "get_metrics",
    "reset_metrics",
    # Exporters
    "JSONExporter",
    "PrometheusExporter",
    "CSVExporter",
    "MetricsReporter",
]
