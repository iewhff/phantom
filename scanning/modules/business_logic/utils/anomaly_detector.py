"""
Business Logic Scanner - Anomaly Detection Engine.

Statistical anomaly detection for business logic vulnerabilities.
Uses Z-score and IQR for detecting deviations from normal behavior.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from utils.logger import get_logger

from scanning.modules.business_logic.business_base import (
    ResponseBehavior,
    AnomalyResult,
)

logger = get_logger(__name__)


class AnomalyDetector:
    """Statistical anomaly detection for business logic vulnerabilities.

    Detects:
    1. Timing anomalies (race conditions, denial of service)
    2. Response size anomalies (data leakage, injection)
    3. Numeric value anomalies (overflow, boundary issues)
    4. Behavioral anomalies (unexpected state transitions)
    5. Sequence anomalies (workflow violations)
    """

    # Z-score threshold for anomaly detection
    Z_SCORE_THRESHOLD = 2.5
    # IQR multiplier for outlier detection
    IQR_MULTIPLIER = 1.5
    # Minimum samples for statistical analysis
    MIN_SAMPLES = 5

    def __init__(self) -> None:
        self._baseline_data: dict[str, list[ResponseBehavior]] = {}
        self._value_distributions: dict[str, list[float]] = {}
        self._timing_distributions: dict[str, list[float]] = {}
        self._size_distributions: dict[str, list[int]] = {}

    def record_baseline(self, behavior: ResponseBehavior) -> None:
        """Record a normal response behavior for baseline building."""
        key = f"{behavior.method}:{behavior.endpoint}"

        if key not in self._baseline_data:
            self._baseline_data[key] = []
        self._baseline_data[key].append(behavior)

        # Track distributions
        if key not in self._timing_distributions:
            self._timing_distributions[key] = []
        self._timing_distributions[key].append(behavior.response_time_ms)

        if key not in self._size_distributions:
            self._size_distributions[key] = []
        self._size_distributions[key].append(behavior.body_size)

        # Track numeric field values
        for field_name, value in behavior.numeric_fields.items():
            field_key = f"{key}:{field_name}"
            if field_key not in self._value_distributions:
                self._value_distributions[field_key] = []
            self._value_distributions[field_key].append(value)

    def detect_anomalies(self, behavior: ResponseBehavior) -> list[AnomalyResult]:
        """Detect anomalies in a response compared to baseline."""
        anomalies: list[AnomalyResult] = []
        key = f"{behavior.method}:{behavior.endpoint}"

        # Check timing anomaly
        timing_anomaly = self._check_timing_anomaly(key, behavior.response_time_ms)
        if timing_anomaly:
            anomalies.append(timing_anomaly)

        # Check size anomaly
        size_anomaly = self._check_size_anomaly(key, behavior.body_size)
        if size_anomaly:
            anomalies.append(size_anomaly)

        # Check numeric field anomalies
        for field_name, value in behavior.numeric_fields.items():
            field_key = f"{key}:{field_name}"
            value_anomaly = self._check_value_anomaly(field_key, value, field_name)
            if value_anomaly:
                anomalies.append(value_anomaly)

        return anomalies

    def _check_timing_anomaly(
        self,
        key: str,
        response_time: float,
    ) -> AnomalyResult | None:
        """Check for timing anomalies using Z-score."""
        times = self._timing_distributions.get(key, [])
        if len(times) < self.MIN_SAMPLES:
            return None

        try:
            mean = statistics.mean(times)
            stdev = statistics.stdev(times)
            if stdev == 0:
                return None

            z_score = (response_time - mean) / stdev

            if abs(z_score) > self.Z_SCORE_THRESHOLD:
                anomaly_type = "slow_response" if z_score > 0 else "fast_response"
                suggested = "race_condition" if z_score < 0 else "denial_of_service"

                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_type="timing",
                    anomaly_score=min(abs(z_score) * 20, 100),
                    normal_range=f"{mean - 2*stdev:.0f}-{mean + 2*stdev:.0f}ms",
                    observed_value=f"{response_time:.0f}ms",
                    evidence=[
                        f"Z-score: {z_score:.2f}",
                        f"Mean: {mean:.0f}ms",
                        f"StdDev: {stdev:.0f}ms",
                        f"Anomaly type: {anomaly_type}",
                    ],
                    suggested_finding_type=suggested,
                )
        except statistics.StatisticsError:
            pass

        return None

    def _check_size_anomaly(
        self,
        key: str,
        body_size: int,
    ) -> AnomalyResult | None:
        """Check for response size anomalies using IQR."""
        sizes = self._size_distributions.get(key, [])
        if len(sizes) < self.MIN_SAMPLES:
            return None

        try:
            sorted_sizes = sorted(sizes)
            q1_idx = len(sorted_sizes) // 4
            q3_idx = (3 * len(sorted_sizes)) // 4
            q1 = sorted_sizes[q1_idx]
            q3 = sorted_sizes[q3_idx]
            iqr = q3 - q1

            lower_bound = q1 - self.IQR_MULTIPLIER * iqr
            upper_bound = q3 + self.IQR_MULTIPLIER * iqr

            if body_size < lower_bound or body_size > upper_bound:
                anomaly_type = "large_response" if body_size > upper_bound else "small_response"
                suggested = "data_leakage" if body_size > upper_bound else "missing_data"

                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_type="size",
                    anomaly_score=min(abs(body_size - (q1 + q3) / 2) / (iqr + 1) * 30, 100),
                    normal_range=f"{lower_bound:.0f}-{upper_bound:.0f} bytes",
                    observed_value=f"{body_size} bytes",
                    evidence=[
                        f"Q1: {q1}, Q3: {q3}",
                        f"IQR: {iqr}",
                        f"Anomaly type: {anomaly_type}",
                    ],
                    suggested_finding_type=suggested,
                )
        except (IndexError, ZeroDivisionError):
            pass

        return None

    def _check_value_anomaly(
        self,
        field_key: str,
        value: float,
        field_name: str,
    ) -> AnomalyResult | None:
        """Check for numeric value anomalies."""
        values = self._value_distributions.get(field_key, [])
        if len(values) < self.MIN_SAMPLES:
            return None

        try:
            mean = statistics.mean(values)
            stdev = statistics.stdev(values)
            if stdev == 0:
                return None

            z_score = (value - mean) / stdev

            if abs(z_score) > self.Z_SCORE_THRESHOLD:
                # Check for potential overflow/underflow
                if value < 0 and all(v >= 0 for v in values):
                    suggested = "negative_value_bypass"
                elif value > max(values) * 10:
                    suggested = "integer_overflow"
                elif value == 0 and all(v > 0 for v in values):
                    suggested = "zero_value_bypass"
                else:
                    suggested = "boundary_violation"

                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_type="value",
                    anomaly_score=min(abs(z_score) * 20, 100),
                    normal_range=f"{mean - 2*stdev:.2f}-{mean + 2*stdev:.2f}",
                    observed_value=f"{value} (field: {field_name})",
                    evidence=[
                        f"Field: {field_name}",
                        f"Z-score: {z_score:.2f}",
                        f"Mean: {mean:.2f}",
                        f"StdDev: {stdev:.2f}",
                    ],
                    suggested_finding_type=suggested,
                )
        except statistics.StatisticsError:
            pass

        return None

    def get_baseline_stats(self, endpoint: str, method: str = "POST") -> dict[str, Any]:
        """Get baseline statistics for an endpoint."""
        key = f"{method}:{endpoint}"
        stats = {
            "samples": 0,
            "timing": {},
            "size": {},
        }

        times = self._timing_distributions.get(key, [])
        if times:
            stats["samples"] = len(times)
            stats["timing"] = {
                "mean": statistics.mean(times),
                "stdev": statistics.stdev(times) if len(times) > 1 else 0,
                "min": min(times),
                "max": max(times),
            }

        sizes = self._size_distributions.get(key, [])
        if sizes:
            stats["size"] = {
                "mean": statistics.mean(sizes),
                "stdev": statistics.stdev(sizes) if len(sizes) > 1 else 0,
                "min": min(sizes),
                "max": max(sizes),
            }

        return stats

    def reset(self) -> None:
        """Reset all baseline data."""
        self._baseline_data.clear()
        self._value_distributions.clear()
        self._timing_distributions.clear()
        self._size_distributions.clear()


__all__ = ["AnomalyDetector"]
