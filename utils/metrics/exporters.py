"""
Metrics Exporters - Export metrics in various formats.

Provides:
- JSONExporter: Export to JSON format
- PrometheusExporter: Export in Prometheus text format
- CSVExporter: Export time series to CSV
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .collector import OperationalMetricsCollector


class JSONExporter:
    """Export metrics in JSON format.

    Example:
        exporter = JSONExporter(metrics_collector)
        json_str = exporter.export()
        exporter.export_to_file("metrics.json")
    """

    def __init__(self, collector: "OperationalMetricsCollector"):
        self.collector = collector

    def export(self, indent: int = 2) -> str:
        """Export metrics as JSON string."""
        snapshot = self.collector.snapshot()
        return json.dumps(snapshot, indent=indent, default=str)

    def export_to_file(self, filepath: str | Path, indent: int = 2) -> None:
        """Export metrics to JSON file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(self.export(indent=indent))

    def export_summary(self, indent: int = 2) -> str:
        """Export concise summary as JSON."""
        summary = self.collector.summary()
        return json.dumps(summary, indent=indent, default=str)


class PrometheusExporter:
    """Export metrics in Prometheus text exposition format.

    Supports counters, gauges, and histograms.
    Compatible with Prometheus scraping endpoints.

    Example:
        exporter = PrometheusExporter(metrics_collector, prefix="phantom_")
        prometheus_text = exporter.export()
    """

    def __init__(
        self,
        collector: "OperationalMetricsCollector",
        prefix: str = "phantom_scan_",
    ):
        self.collector = collector
        self.prefix = prefix

    def export(self) -> str:
        """Export all metrics in Prometheus text format."""
        lines = []
        timestamp_ms = int(time.time() * 1000)

        # Export counters
        lines.extend(self._export_counters(timestamp_ms))

        # Export timers as histograms
        lines.extend(self._export_timers(timestamp_ms))

        # Export gauges
        lines.extend(self._export_gauges(timestamp_ms))

        return "\n".join(lines)

    def _export_counters(self, timestamp_ms: int) -> List[str]:
        """Export counter metrics."""
        lines = []
        counters = self.collector.counters

        # Simple counters
        simple_counters = [
            ("requests_total", counters.requests_total),
            ("bytes_sent_total", counters.bytes_sent),
            ("bytes_received_total", counters.bytes_received),
            ("findings_total", counters.findings_total),
            ("modules_started_total", counters.modules_started),
            ("modules_completed_total", counters.modules_completed),
            ("modules_failed_total", counters.modules_failed),
            ("rate_limits_hit_total", counters.rate_limits_hit),
            ("waf_blocks_total", counters.waf_blocks),
        ]

        for name, counter in simple_counters:
            metric_name = f"{self.prefix}{name}"
            lines.append(f"# HELP {metric_name} {counter.description}")
            lines.append(f"# TYPE {metric_name} counter")
            lines.append(f"{metric_name} {counter.value} {timestamp_ms}")

        # Labeled counters
        labeled_counters = [
            ("requests_by_method", counters.requests_by_method, "method"),
            ("responses_by_status", counters.responses_by_status, "status"),
            ("findings_by_severity", counters.findings_by_severity, "severity"),
            ("findings_by_type", counters.findings_by_type, "type"),
            ("module_errors_by_type", counters.module_errors_by_type, "error_type"),
        ]

        for name, counter, label_name in labeled_counters:
            metric_name = f"{self.prefix}{name}"
            lines.append(f"# HELP {metric_name} {counter.description}")
            lines.append(f"# TYPE {metric_name} counter")
            for label_key, value in counter.values.items():
                # Parse label from key
                if "=" in label_key:
                    label_value = label_key.split("=")[1]
                else:
                    label_value = label_key
                lines.append(
                    f'{metric_name}{{{label_name}="{label_value}"}} {value} {timestamp_ms}'
                )

        return lines

    def _export_timers(self, timestamp_ms: int) -> List[str]:
        """Export timer metrics as histograms/summaries."""
        lines = []
        timers = self.collector.timers

        # Export histograms
        histograms = [
            ("request_latency_seconds", timers.request_latency),
            ("module_duration_seconds", timers.module_duration),
        ]

        for name, hist in histograms:
            metric_name = f"{self.prefix}{name}"
            lines.append(f"# HELP {metric_name} {hist.description}")
            lines.append(f"# TYPE {metric_name} histogram")

            # Bucket values (cumulative)
            for bucket, count in sorted(hist._bucket_counts.items()):
                bucket_str = "+Inf" if bucket == float("inf") else str(bucket)
                lines.append(
                    f'{metric_name}_bucket{{le="{bucket_str}"}} {count} {timestamp_ms}'
                )

            lines.append(f"{metric_name}_sum {hist.sum} {timestamp_ms}")
            lines.append(f"{metric_name}_count {hist.count} {timestamp_ms}")

        # Export simple timers as gauges (last value)
        simple_timers = [
            ("total_scan_duration_seconds", timers.total_scan),
            ("phase_discovery_duration_seconds", timers.phase_discovery),
            ("phase_fingerprint_duration_seconds", timers.phase_fingerprint),
            ("phase_scanning_duration_seconds", timers.phase_scanning),
            ("phase_analysis_duration_seconds", timers.phase_analysis),
            ("phase_validation_duration_seconds", timers.phase_validation),
            ("phase_reporting_duration_seconds", timers.phase_reporting),
        ]

        for name, timer in simple_timers:
            if timer.count > 0:
                metric_name = f"{self.prefix}{name}"
                lines.append(f"# HELP {metric_name} {timer.description}")
                lines.append(f"# TYPE {metric_name} gauge")
                lines.append(f"{metric_name} {timer.duration_seconds} {timestamp_ms}")

        return lines

    def _export_gauges(self, timestamp_ms: int) -> List[str]:
        """Export gauge metrics."""
        lines = []
        gauges = self.collector.gauges

        # Simple gauges
        simple_gauges = [
            ("active_modules", gauges.active_modules),
            ("pending_findings", gauges.pending_findings),
            ("queue_depth", gauges.queue_depth),
            ("budget_remaining", gauges.budget_remaining),
            ("scan_progress_percent", gauges.scan_progress),
            ("endpoints_remaining", gauges.endpoints_remaining),
        ]

        for name, gauge in simple_gauges:
            metric_name = f"{self.prefix}{name}"
            lines.append(f"# HELP {metric_name} {gauge.description}")
            lines.append(f"# TYPE {metric_name} gauge")
            lines.append(f"{metric_name} {gauge.value} {timestamp_ms}")

        # Memory gauges
        memory = gauges.memory
        lines.append(f"# HELP {self.prefix}memory_rss_bytes Current RSS memory usage")
        lines.append(f"# TYPE {self.prefix}memory_rss_bytes gauge")
        lines.append(f"{self.prefix}memory_rss_bytes {memory.rss_bytes} {timestamp_ms}")

        lines.append(f"# HELP {self.prefix}memory_peak_bytes Peak RSS memory usage")
        lines.append(f"# TYPE {self.prefix}memory_peak_bytes gauge")
        lines.append(f"{self.prefix}memory_peak_bytes {memory.peak_bytes} {timestamp_ms}")

        # Connection gauges
        conn = gauges.connections
        lines.append(f"# HELP {self.prefix}connections_active Active connections")
        lines.append(f"# TYPE {self.prefix}connections_active gauge")
        lines.append(f"{self.prefix}connections_active {conn.active} {timestamp_ms}")

        lines.append(f"# HELP {self.prefix}connections_total_opened Total connections opened")
        lines.append(f"# TYPE {self.prefix}connections_total_opened counter")
        lines.append(f"{self.prefix}connections_total_opened {conn.total_opened} {timestamp_ms}")

        return lines

    def export_to_file(self, filepath: str | Path) -> None:
        """Export to file in Prometheus format."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(self.export())


class CSVExporter:
    """Export metrics time series to CSV.

    Useful for importing into spreadsheets or analysis tools.

    Example:
        exporter = CSVExporter(metrics_collector)
        exporter.sample()  # Take snapshot
        time.sleep(10)
        exporter.sample()  # Take another snapshot
        csv_data = exporter.export()
    """

    def __init__(self, collector: "OperationalMetricsCollector"):
        self.collector = collector
        self._samples: List[Dict[str, Any]] = []

    def sample(self) -> None:
        """Take a metrics snapshot and add to time series."""
        summary = self.collector.summary()
        summary["timestamp"] = datetime.now().isoformat()
        summary["timestamp_unix"] = time.time()
        self._samples.append(summary)

    def clear(self) -> None:
        """Clear all samples."""
        self._samples.clear()

    def export(self) -> str:
        """Export all samples as CSV string."""
        if not self._samples:
            return ""

        # Flatten nested dicts and get all keys
        flat_samples = []
        all_keys = set()

        for sample in self._samples:
            flat = self._flatten_dict(sample)
            flat_samples.append(flat)
            all_keys.update(flat.keys())

        # Sort keys for consistent column order
        columns = sorted(all_keys)

        # Build CSV
        output = StringIO()
        output.write(",".join(columns) + "\n")

        for flat in flat_samples:
            row = []
            for col in columns:
                value = flat.get(col, "")
                # Escape commas and quotes
                if isinstance(value, str) and ("," in value or '"' in value):
                    value = f'"{value.replace(chr(34), chr(34) + chr(34))}"'
                row.append(str(value))
            output.write(",".join(row) + "\n")

        return output.getvalue()

    def _flatten_dict(
        self,
        d: Dict[str, Any],
        parent_key: str = "",
        sep: str = "_"
    ) -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                # Convert list to string
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)

    def export_to_file(self, filepath: str | Path) -> None:
        """Export to CSV file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(self.export())


class MetricsReporter:
    """High-level reporter that combines multiple export formats.

    Example:
        reporter = MetricsReporter(metrics_collector)
        reporter.generate_report("output/scan-001")
        # Creates:
        #   output/scan-001/metrics.json
        #   output/scan-001/metrics.prom
        #   output/scan-001/summary.json
    """

    def __init__(self, collector: "OperationalMetricsCollector"):
        self.collector = collector
        self.json_exporter = JSONExporter(collector)
        self.prometheus_exporter = PrometheusExporter(collector)
        self.csv_exporter = CSVExporter(collector)

    def generate_report(
        self,
        output_dir: str | Path,
        include_csv: bool = False
    ) -> Dict[str, Path]:
        """Generate metrics report in multiple formats.

        Returns dict of format -> filepath.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        files = {}

        # Full JSON metrics
        json_path = output_dir / "metrics.json"
        self.json_exporter.export_to_file(json_path)
        files["json"] = json_path

        # Summary JSON
        summary_path = output_dir / "summary.json"
        summary_path.write_text(self.json_exporter.export_summary())
        files["summary"] = summary_path

        # Prometheus format
        prom_path = output_dir / "metrics.prom"
        self.prometheus_exporter.export_to_file(prom_path)
        files["prometheus"] = prom_path

        # CSV (optional, for time series)
        if include_csv and self.csv_exporter._samples:
            csv_path = output_dir / "metrics.csv"
            self.csv_exporter.export_to_file(csv_path)
            files["csv"] = csv_path

        return files

    def get_dashboard_data(self) -> dict:
        """Get data formatted for dashboard display."""
        summary = self.collector.summary()
        snapshot = self.collector.snapshot()

        return {
            "summary": summary,
            "request_rate": self.collector.counters.request_rate.to_dict(),
            "findings_by_severity": self.collector.counters.findings_by_severity.values,
            "findings_by_type": self.collector.counters.findings_by_type.values,
            "latency_percentiles": {
                "p50": self.collector.timers.request_latency.p50,
                "p90": self.collector.timers.request_latency.p90,
                "p95": self.collector.timers.request_latency.p95,
                "p99": self.collector.timers.request_latency.p99,
            },
            "memory": self.collector.gauges.memory.to_dict(),
            "progress": self.collector.gauges.scan_progress.value,
        }
