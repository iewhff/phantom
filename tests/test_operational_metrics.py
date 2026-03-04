"""
Tests for the operational metrics system.

Tests cover:
- Counters (Counter, LabeledCounter, RateCounter)
- Timers (Timer, Histogram, ContextTimer)
- Gauges (Gauge, LabeledGauge, MemoryGauge, ConnectionGauge)
- Collector (OperationalMetricsCollector, get_metrics)
- Exporters (JSONExporter, PrometheusExporter, CSVExporter)
"""

import json
import pytest
import time
import threading
from pathlib import Path
from unittest.mock import patch

from utils.metrics import (
    # Counters
    Counter,
    LabeledCounter,
    RateCounter,
    ScanCounters,
    # Timers
    Timer,
    Histogram,
    ContextTimer,
    ScanTimers,
    context_timer,
    # Gauges
    Gauge,
    LabeledGauge,
    MemoryGauge,
    ConnectionGauge,
    ScanGauges,
    # Collector
    OperationalMetricsCollector,
    ScanContext,
    get_metrics,
    reset_metrics,
    # Exporters
    JSONExporter,
    PrometheusExporter,
    CSVExporter,
    MetricsReporter,
)


# =============================================================================
# Counter Tests
# =============================================================================

class TestCounter:
    """Tests for simple Counter."""

    def test_counter_init(self):
        """Counter initializes with zero value."""
        c = Counter("test_counter", "A test counter")
        assert c.value == 0
        assert c.name == "test_counter"
        assert c.description == "A test counter"

    def test_counter_inc(self):
        """Counter increments correctly."""
        c = Counter("test")
        c.inc()
        assert c.value == 1
        c.inc()
        assert c.value == 2

    def test_counter_inc_amount(self):
        """Counter increments by specific amount."""
        c = Counter("test")
        c.inc(5)
        assert c.value == 5
        c.inc(10)
        assert c.value == 15

    def test_counter_reset(self):
        """Counter reset returns previous value and resets to zero."""
        c = Counter("test")
        c.inc(10)
        prev = c.reset()
        assert prev == 10
        assert c.value == 0

    def test_counter_to_dict(self):
        """Counter exports to dictionary correctly."""
        c = Counter("requests", "Total requests")
        c.inc(100)
        d = c.to_dict()
        assert d["name"] == "requests"
        assert d["description"] == "Total requests"
        assert d["type"] == "counter"
        assert d["value"] == 100

    def test_counter_thread_safety(self):
        """Counter is thread-safe for concurrent increments."""
        c = Counter("concurrent")
        threads = []
        for _ in range(10):
            t = threading.Thread(target=lambda: [c.inc() for _ in range(1000)])
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        assert c.value == 10000


class TestLabeledCounter:
    """Tests for LabeledCounter."""

    def test_labeled_counter_init(self):
        """LabeledCounter initializes empty."""
        lc = LabeledCounter("errors", "Errors by type")
        assert lc.total == 0
        assert lc.values == {}

    def test_labeled_counter_inc_with_labels(self):
        """LabeledCounter increments with labels."""
        lc = LabeledCounter("errors")
        lc.inc(error_type="timeout")
        lc.inc(error_type="connection")
        lc.inc(error_type="timeout", count=2)
        assert lc.get(error_type="timeout") == 3
        assert lc.get(error_type="connection") == 1
        assert lc.total == 4

    def test_labeled_counter_multiple_labels(self):
        """LabeledCounter handles multiple labels."""
        lc = LabeledCounter("requests")
        lc.inc(method="GET", status="200")
        lc.inc(method="POST", status="200")
        lc.inc(method="GET", status="404")
        assert lc.get(method="GET", status="200") == 1
        assert lc.get(method="GET", status="404") == 1
        assert lc.total == 3

    def test_labeled_counter_to_dict(self):
        """LabeledCounter exports to dictionary."""
        lc = LabeledCounter("by_type", "Count by type")
        lc.inc(type="a")
        lc.inc(type="b", count=5)
        d = lc.to_dict()
        assert d["name"] == "by_type"
        assert d["type"] == "labeled_counter"
        assert d["total"] == 6

    def test_labeled_counter_reset(self):
        """LabeledCounter reset clears all labels."""
        lc = LabeledCounter("test")
        lc.inc(a="1")
        lc.inc(b="2")
        prev = lc.reset()
        assert len(prev) == 2
        assert lc.total == 0


class TestRateCounter:
    """Tests for RateCounter."""

    def test_rate_counter_init(self):
        """RateCounter initializes with zero rate."""
        rc = RateCounter("request_rate", window_seconds=60)
        assert rc.count_in_window == 0
        assert rc.rate_per_second == 0.0

    def test_rate_counter_records_events(self):
        """RateCounter records events and calculates rate."""
        rc = RateCounter("rate", window_seconds=60)
        rc.inc(10)
        assert rc.count_in_window == 10
        # Rate should be positive
        assert rc.rate_per_second > 0

    def test_rate_counter_window_expiry(self):
        """RateCounter expires events outside window."""
        rc = RateCounter("rate", window_seconds=0.1)  # 100ms window
        rc.inc(5)
        assert rc.count_in_window == 5
        time.sleep(0.15)  # Wait for events to expire
        assert rc.count_in_window == 0

    def test_rate_counter_to_dict(self):
        """RateCounter exports to dictionary."""
        rc = RateCounter("rate", "Request rate", window_seconds=60)
        rc.inc(10)
        d = rc.to_dict()
        assert d["name"] == "rate"
        assert d["type"] == "rate_counter"
        assert d["window_seconds"] == 60
        assert d["count_in_window"] == 10


class TestScanCounters:
    """Tests for ScanCounters collection."""

    def test_scan_counters_init(self):
        """ScanCounters initializes all counters."""
        sc = ScanCounters()
        assert sc.requests_total.value == 0
        assert sc.findings_total.value == 0
        assert sc.modules_started.value == 0

    def test_record_request(self):
        """ScanCounters records request correctly."""
        sc = ScanCounters()
        sc.record_request("GET", 1024)
        assert sc.requests_total.value == 1
        assert sc.requests_by_method.get(method="GET") == 1
        assert sc.bytes_sent.value == 1024

    def test_record_response(self):
        """ScanCounters records response by status category."""
        sc = ScanCounters()
        sc.record_response(200, 2048)
        sc.record_response(404)
        sc.record_response(500)
        assert sc.responses_by_status.get(status="2xx") == 1
        assert sc.responses_by_status.get(status="4xx") == 1
        assert sc.responses_by_status.get(status="5xx") == 1
        assert sc.bytes_received.value == 2048

    def test_record_finding(self):
        """ScanCounters records finding."""
        sc = ScanCounters()
        sc.record_finding("high", "sqli")
        sc.record_finding("medium", "xss")
        assert sc.findings_total.value == 2
        assert sc.findings_by_severity.get(severity="high") == 1
        assert sc.findings_by_type.get(type="sqli") == 1

    def test_record_module(self):
        """ScanCounters records module lifecycle."""
        sc = ScanCounters()
        sc.record_module_start()
        sc.record_module_start()
        sc.record_module_complete(success=True)
        sc.record_module_complete(success=False)
        assert sc.modules_started.value == 2
        assert sc.modules_completed.value == 1
        assert sc.modules_failed.value == 1

    def test_reset_all(self):
        """ScanCounters reset_all clears everything."""
        sc = ScanCounters()
        sc.record_request("GET")
        sc.record_finding("high", "sqli")
        sc.reset_all()
        assert sc.requests_total.value == 0
        assert sc.findings_total.value == 0


# =============================================================================
# Timer Tests
# =============================================================================

class TestTimer:
    """Tests for Timer."""

    def test_timer_init(self):
        """Timer initializes with zero duration."""
        t = Timer("test_timer", "A test timer")
        assert t.duration_seconds == 0
        assert t.count == 0

    def test_timer_start_stop(self):
        """Timer measures duration between start and stop."""
        t = Timer("test")
        t.start()
        time.sleep(0.05)
        t.stop()
        assert 0.04 < t.duration_seconds < 0.15  # Allow some tolerance
        assert t.count == 1

    def test_timer_multiple_samples(self):
        """Timer records multiple samples."""
        t = Timer("test")
        for _ in range(3):
            t.start()
            time.sleep(0.01)
            t.stop()
        assert t.count == 3
        assert t.avg_seconds > 0

    def test_timer_record_direct(self):
        """Timer records duration directly."""
        t = Timer("test")
        t.record(0.5)
        t.record(1.0)
        assert t.count == 2
        assert t.total_seconds == 1.5
        assert t.avg_seconds == 0.75

    def test_timer_to_dict(self):
        """Timer exports to dictionary."""
        t = Timer("api_latency", "API request latency")
        t.record(0.1)
        t.record(0.2)
        d = t.to_dict()
        assert d["name"] == "api_latency"
        assert d["type"] == "timer"
        assert d["count"] == 2
        assert d["total_ms"] == 300.0
        assert d["avg_ms"] == 150.0

    def test_timer_reset(self):
        """Timer reset clears all samples."""
        t = Timer("test")
        t.record(0.5)
        prev = t.reset()
        assert len(prev) == 1
        assert t.count == 0


class TestHistogram:
    """Tests for Histogram."""

    def test_histogram_init(self):
        """Histogram initializes with custom buckets."""
        h = Histogram("latency", buckets=[0.1, 0.5, 1.0])
        assert h.count == 0
        assert h.sum == 0

    def test_histogram_observe(self):
        """Histogram records observations."""
        h = Histogram("latency")
        h.observe(0.1)
        h.observe(0.5)
        h.observe(1.0)
        assert h.count == 3
        assert h.sum == 1.6
        assert h.avg == pytest.approx(0.533, abs=0.01)

    def test_histogram_percentiles(self):
        """Histogram calculates percentiles."""
        h = Histogram("latency")
        for i in range(100):
            h.observe(i / 100)  # 0.00, 0.01, ..., 0.99
        assert h.p50 == pytest.approx(0.50, abs=0.02)
        assert h.p90 == pytest.approx(0.90, abs=0.02)
        assert h.p99 == pytest.approx(0.99, abs=0.02)

    def test_histogram_to_dict(self):
        """Histogram exports to dictionary."""
        h = Histogram("test", "Test histogram", buckets=[0.1, 0.5, 1.0])
        h.observe(0.2)
        h.observe(0.8)
        d = h.to_dict()
        assert d["name"] == "test"
        assert d["type"] == "histogram"
        assert d["count"] == 2
        assert "percentiles" in d
        assert "buckets" in d


class TestContextTimer:
    """Tests for ContextTimer."""

    def test_context_timer_basic(self):
        """ContextTimer measures block duration."""
        ct = ContextTimer("operation")
        with ct:
            time.sleep(0.05)
        assert ct.duration_ms > 40

    def test_context_timer_function(self):
        """context_timer function works with Timer."""
        t = Timer("test")
        with context_timer(t):
            time.sleep(0.01)
        assert t.count == 1
        assert t.duration_ms > 0


class TestScanTimers:
    """Tests for ScanTimers collection."""

    def test_scan_timers_init(self):
        """ScanTimers initializes all timers."""
        st = ScanTimers()
        assert st.total_scan.count == 0
        assert st.phase_discovery.count == 0

    def test_record_latency(self):
        """ScanTimers records request latency."""
        st = ScanTimers()
        st.record_request_latency(0.1)
        st.record_request_latency(0.2)
        assert st.request_latency.count == 2

    def test_record_module_duration(self):
        """ScanTimers records module duration."""
        st = ScanTimers()
        st.record_module_duration(30.0)
        st.record_module_duration(60.0)
        assert st.module_duration.count == 2

    def test_to_dict(self):
        """ScanTimers exports to dictionary."""
        st = ScanTimers()
        st.phase_discovery.start()
        st.phase_discovery.stop()
        d = st.to_dict()
        assert "phases" in d
        assert "histograms" in d


# =============================================================================
# Gauge Tests
# =============================================================================

class TestGauge:
    """Tests for Gauge."""

    def test_gauge_init(self):
        """Gauge initializes with zero value."""
        g = Gauge("active", "Active count")
        assert g.value == 0

    def test_gauge_set(self):
        """Gauge sets value correctly."""
        g = Gauge("test")
        g.set(10)
        assert g.value == 10
        g.set(5)
        assert g.value == 5

    def test_gauge_inc_dec(self):
        """Gauge increments and decrements."""
        g = Gauge("test")
        g.inc()
        g.inc(5)
        assert g.value == 6
        g.dec(2)
        assert g.value == 4
        g.dec()
        assert g.value == 3

    def test_gauge_peak_tracking(self):
        """Gauge tracks peak value."""
        g = Gauge("test")
        g.set(10)
        g.set(20)
        g.set(5)
        assert g.peak == 20
        assert g.min == 5

    def test_gauge_to_dict(self):
        """Gauge exports to dictionary."""
        g = Gauge("active_connections", "Active connections")
        g.set(10)
        d = g.to_dict()
        assert d["name"] == "active_connections"
        assert d["type"] == "gauge"
        assert d["value"] == 10


class TestLabeledGauge:
    """Tests for LabeledGauge."""

    def test_labeled_gauge_set(self):
        """LabeledGauge sets values with labels."""
        lg = LabeledGauge("connections")
        lg.set(5, host="api.example.com")
        lg.set(3, host="db.example.com")
        assert lg.get(host="api.example.com") == 5
        assert lg.get(host="db.example.com") == 3
        assert lg.total == 8

    def test_labeled_gauge_inc_dec(self):
        """LabeledGauge increments/decrements with labels."""
        lg = LabeledGauge("pool")
        lg.inc(host="a")
        lg.inc(host="a")
        lg.dec(host="a")
        assert lg.get(host="a") == 1


class TestMemoryGauge:
    """Tests for MemoryGauge."""

    def test_memory_gauge_reads_memory(self):
        """MemoryGauge reads current memory usage."""
        mg = MemoryGauge()
        assert mg.rss_bytes > 0
        assert mg.rss_mb > 0

    def test_memory_gauge_peak_tracking(self):
        """MemoryGauge tracks peak memory."""
        mg = MemoryGauge()
        _ = mg.rss_bytes  # Sample
        assert mg.peak_bytes >= mg.rss_bytes

    def test_memory_gauge_to_dict(self):
        """MemoryGauge exports to dictionary."""
        mg = MemoryGauge()
        d = mg.to_dict()
        assert d["name"] == "memory_usage"
        assert d["type"] == "memory_gauge"
        assert "rss_mb" in d
        assert "peak_mb" in d


class TestConnectionGauge:
    """Tests for ConnectionGauge."""

    def test_connection_gauge_tracking(self):
        """ConnectionGauge tracks connections."""
        cg = ConnectionGauge()
        cg.connection_opened("api.example.com")
        cg.connection_opened("api.example.com")
        cg.connection_opened("db.example.com")
        assert cg.active == 3
        assert cg.active_by_host["api.example.com"] == 2

        cg.connection_closed("api.example.com")
        assert cg.active == 2
        assert cg.total_opened == 3
        assert cg.total_closed == 1


class TestScanGauges:
    """Tests for ScanGauges collection."""

    def test_scan_gauges_init(self):
        """ScanGauges initializes all gauges."""
        sg = ScanGauges()
        assert sg.active_modules.value == 0
        assert sg.memory is not None
        assert sg.connections is not None

    def test_scan_gauges_to_dict(self):
        """ScanGauges exports to dictionary."""
        sg = ScanGauges()
        sg.active_modules.set(5)
        d = sg.to_dict()
        assert "modules" in d
        assert "resources" in d
        assert "progress" in d


# =============================================================================
# Collector Tests
# =============================================================================

class TestOperationalMetricsCollector:
    """Tests for OperationalMetricsCollector."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset singleton before each test."""
        reset_metrics()
        yield
        reset_metrics()

    def test_collector_singleton(self):
        """Collector is a singleton."""
        c1 = get_metrics()
        c2 = get_metrics()
        assert c1 is c2

    def test_collector_start_scan(self):
        """Collector starts scan session."""
        c = get_metrics()
        c.start_scan("scan-001", "https://example.com", safe_mode="aggressive")
        assert c.context is not None
        assert c.context.scan_id == "scan-001"
        assert c.context.target == "https://example.com"
        assert c.context.safe_mode == "aggressive"

    def test_collector_end_scan(self):
        """Collector ends scan and returns metrics."""
        c = get_metrics()
        c.start_scan("scan-001", "https://example.com")
        c.record_request("GET")
        final = c.end_scan()
        assert final is not None
        assert c.context is None

    def test_collector_record_methods(self):
        """Collector convenience methods work."""
        c = get_metrics()
        c.start_scan("test", "http://test.com")
        c.record_request("GET", latency_seconds=0.1)
        c.record_response(200, size_bytes=1024)
        c.record_finding("high", "sqli")
        c.record_module_start()
        c.record_module_complete(success=True, duration_seconds=30)
        c.record_error("timeout")
        c.record_rate_limit()
        c.record_waf_block()

        assert c.counters.requests_total.value == 1
        assert c.counters.findings_total.value == 1
        assert c.counters.rate_limits_hit.value == 1

    def test_collector_snapshot(self):
        """Collector snapshot includes all data."""
        c = get_metrics()
        c.start_scan("test", "http://test.com")
        c.record_request("GET")
        snapshot = c.snapshot()
        assert "timestamp" in snapshot
        assert "context" in snapshot
        assert "counters" in snapshot
        assert "timers" in snapshot
        assert "gauges" in snapshot

    def test_collector_summary(self):
        """Collector summary is concise."""
        c = get_metrics()
        c.start_scan("test", "http://test.com")
        c.record_request("GET")
        c.record_finding("critical", "rce")
        summary = c.summary()
        assert summary["requests"] == 1
        assert summary["findings"] == 1

    def test_collector_history(self):
        """Collector maintains scan history."""
        c = get_metrics()
        c.start_scan("scan-001", "http://a.com")
        c.record_request("GET")
        c.end_scan()

        c.start_scan("scan-002", "http://b.com")
        c.record_request("POST")
        c.end_scan()

        history = c.get_history()
        assert len(history) == 2
        assert history[0]["scan_id"] == "scan-001"
        assert history[1]["scan_id"] == "scan-002"


# =============================================================================
# Exporter Tests
# =============================================================================

class TestJSONExporter:
    """Tests for JSONExporter."""

    @pytest.fixture
    def collector(self):
        reset_metrics()
        c = get_metrics()
        c.start_scan("test", "http://test.com")
        c.record_request("GET")
        c.record_finding("high", "sqli")
        return c

    def test_json_export(self, collector):
        """JSONExporter produces valid JSON."""
        exporter = JSONExporter(collector)
        json_str = exporter.export()
        data = json.loads(json_str)
        assert "timestamp" in data
        assert "counters" in data

    def test_json_export_summary(self, collector):
        """JSONExporter exports concise summary."""
        exporter = JSONExporter(collector)
        summary_str = exporter.export_summary()
        data = json.loads(summary_str)
        assert "requests" in data
        assert "findings" in data

    def test_json_export_to_file(self, collector, tmp_path):
        """JSONExporter exports to file."""
        exporter = JSONExporter(collector)
        filepath = tmp_path / "metrics.json"
        exporter.export_to_file(filepath)
        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert "counters" in data


class TestPrometheusExporter:
    """Tests for PrometheusExporter."""

    @pytest.fixture
    def collector(self):
        reset_metrics()
        c = get_metrics()
        c.start_scan("test", "http://test.com")
        c.record_request("GET")
        c.record_response(200)
        c.record_finding("high", "sqli")
        return c

    def test_prometheus_export(self, collector):
        """PrometheusExporter produces valid format."""
        exporter = PrometheusExporter(collector)
        text = exporter.export()
        # Check format
        assert "# HELP" in text
        assert "# TYPE" in text
        assert "phantom_scan_requests_total" in text

    def test_prometheus_counters(self, collector):
        """PrometheusExporter exports counters correctly."""
        exporter = PrometheusExporter(collector, prefix="test_")
        text = exporter.export()
        assert "test_requests_total" in text
        assert "test_findings_total" in text

    def test_prometheus_labeled_counters(self, collector):
        """PrometheusExporter exports labeled counters."""
        exporter = PrometheusExporter(collector)
        text = exporter.export()
        # Should have method label
        assert 'method="GET"' in text or "method=GET" in text


class TestCSVExporter:
    """Tests for CSVExporter."""

    @pytest.fixture
    def collector(self):
        reset_metrics()
        return get_metrics()

    def test_csv_export_empty(self, collector):
        """CSVExporter handles empty samples."""
        exporter = CSVExporter(collector)
        assert exporter.export() == ""

    def test_csv_export_with_samples(self, collector):
        """CSVExporter exports time series."""
        collector.start_scan("test", "http://test.com")
        exporter = CSVExporter(collector)

        collector.record_request("GET")
        exporter.sample()

        collector.record_request("POST")
        exporter.sample()

        csv_text = exporter.export()
        lines = csv_text.strip().split("\n")
        assert len(lines) == 3  # Header + 2 rows

    def test_csv_export_to_file(self, collector, tmp_path):
        """CSVExporter exports to file."""
        collector.start_scan("test", "http://test.com")
        exporter = CSVExporter(collector)
        exporter.sample()

        filepath = tmp_path / "metrics.csv"
        exporter.export_to_file(filepath)
        assert filepath.exists()


class TestMetricsReporter:
    """Tests for MetricsReporter."""

    @pytest.fixture
    def collector(self):
        reset_metrics()
        c = get_metrics()
        c.start_scan("test", "http://test.com")
        c.record_request("GET")
        return c

    def test_generate_report(self, collector, tmp_path):
        """MetricsReporter generates all formats."""
        reporter = MetricsReporter(collector)
        files = reporter.generate_report(tmp_path)

        assert "json" in files
        assert "summary" in files
        assert "prometheus" in files
        assert files["json"].exists()
        assert files["summary"].exists()
        assert files["prometheus"].exists()

    def test_dashboard_data(self, collector):
        """MetricsReporter produces dashboard data."""
        collector.record_finding("high", "sqli")
        reporter = MetricsReporter(collector)
        data = reporter.get_dashboard_data()

        assert "summary" in data
        assert "findings_by_severity" in data
        assert "latency_percentiles" in data
        assert "memory" in data


# =============================================================================
# Integration Tests
# =============================================================================

class TestMetricsIntegration:
    """Integration tests for the full metrics system."""

    @pytest.fixture(autouse=True)
    def reset(self):
        reset_metrics()
        yield
        reset_metrics()

    def test_full_scan_workflow(self, tmp_path):
        """Test complete scan metrics workflow."""
        metrics = get_metrics()

        # Start scan
        metrics.start_scan(
            scan_id="integration-001",
            target="https://example.com",
            safe_mode="safe",
            modules=["sqli", "xss", "cors"],
        )

        # Simulate module execution
        for module in ["sqli", "xss", "cors"]:
            metrics.record_module_start(module)
            for _ in range(10):
                metrics.record_request("GET", latency_seconds=0.1)
                metrics.record_response(200, size_bytes=1024)
            metrics.record_module_complete(success=True, duration_seconds=30)

        # Record findings
        metrics.record_finding("high", "sqli")
        metrics.record_finding("medium", "xss")

        # Get summary
        summary = metrics.summary()
        assert summary["requests"] == 30  # 10 per module * 3 modules
        assert summary["findings"] == 2
        assert summary["modules_completed"] == 3

        # Export
        reporter = MetricsReporter(metrics)
        files = reporter.generate_report(tmp_path / "report")
        assert all(f.exists() for f in files.values())

        # End scan
        final = metrics.end_scan()
        assert final["context"]["scan_id"] == "integration-001"

    def test_concurrent_metrics_recording(self):
        """Test thread-safe concurrent metrics recording."""
        metrics = get_metrics()
        metrics.start_scan("concurrent-test", "https://test.com")

        def worker():
            for _ in range(100):
                metrics.record_request("GET", latency_seconds=0.01)
                metrics.record_response(200)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert metrics.counters.requests_total.value == 1000
