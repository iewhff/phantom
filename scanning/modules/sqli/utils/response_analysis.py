"""
SQL Injection Scanner - Response Analysis.

Provides statistical anomaly detection for response analysis.
Used for ML-like detection of SQL injection behavior without ML dependencies.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import math
import statistics
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanning.modules.sqli.sqli_base import ResponseFingerprint


class AnomalyDetector:
    """Statistical anomaly detection for response analysis."""

    def __init__(self, baseline_samples: int = 5):
        self.baseline_samples = baseline_samples
        self.baseline_lengths: list[int] = []
        self.baseline_times: list[float] = []
        self.baseline_fingerprints: list["ResponseFingerprint"] = []

    def add_baseline(self, fp: "ResponseFingerprint") -> None:
        """Add a baseline sample."""
        self.baseline_fingerprints.append(fp)
        self.baseline_lengths.append(fp.content_length)
        self.baseline_times.append(fp.response_time)

    def is_length_anomaly(self, length: int, threshold: float = 2.5) -> tuple[bool, float]:
        """
        Check if content length is anomalous using z-score.
        Returns (is_anomaly, z_score)
        """
        if len(self.baseline_lengths) < 2:
            return False, 0.0

        mean = statistics.mean(self.baseline_lengths)
        stdev = statistics.stdev(self.baseline_lengths)

        if stdev == 0:
            return length != mean, 10.0 if length != mean else 0.0  # Fixed: use bounded value instead of inf

        z_score = abs(length - mean) / stdev
        return z_score > threshold, z_score

    def is_time_anomaly(self, time_val: float, threshold: float = 3.0) -> tuple[bool, float]:
        """
        Check if response time is anomalous.
        Returns (is_anomaly, z_score)
        """
        if len(self.baseline_times) < 2:
            return time_val > 5, 0.0  # Default 5s threshold

        mean = statistics.mean(self.baseline_times)
        stdev = statistics.stdev(self.baseline_times)

        if stdev == 0:
            stdev = 0.1  # Minimum stdev

        z_score = (time_val - mean) / stdev
        return z_score > threshold, z_score

    def is_structure_anomaly(self, fp: "ResponseFingerprint") -> tuple[bool, float]:
        """Check if response structure is anomalous."""
        if not self.baseline_fingerprints:
            return False, 0.0

        similarities = [base.similarity_score(fp) for base in self.baseline_fingerprints]
        avg_similarity = statistics.mean(similarities)

        # If average similarity is below 70%, it's anomalous
        return avg_similarity < 70, 100 - avg_similarity

    def get_confidence_boost(self, fp: "ResponseFingerprint") -> int:
        """Get confidence boost based on anomaly detection."""
        boost = 0

        # Length anomaly
        is_len_anomaly, z_len = self.is_length_anomaly(fp.content_length)
        if is_len_anomaly and math.isfinite(z_len):
            boost += min(int(z_len * 5), 15)

        # Time anomaly
        is_time_anomaly_result, z_time = self.is_time_anomaly(fp.response_time)
        if is_time_anomaly_result and math.isfinite(z_time):
            boost += min(int(z_time * 5), 20)

        # Structure anomaly
        is_struct_anomaly, diff = self.is_structure_anomaly(fp)
        if is_struct_anomaly and math.isfinite(diff):
            boost += min(int(diff / 3), 15)

        return boost


__all__ = ["AnomalyDetector"]
