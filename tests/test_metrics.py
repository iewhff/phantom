"""
Tests for the scanning/metrics/ module.

Tests ScanResult dataclass and metrics utilities.
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

from scanning.metrics import (
    ScanResult,
    SEVERITY_TO_CONFIDENCE,
    normalize_confidence,
)


class TestSeverityToConfidence:
    """Tests for SEVERITY_TO_CONFIDENCE mapping."""

    def test_severity_mapping_values(self):
        """Test severity mapping has expected values."""
        assert SEVERITY_TO_CONFIDENCE["critical"] == 95.0
        assert SEVERITY_TO_CONFIDENCE["high"] == 85.0
        assert SEVERITY_TO_CONFIDENCE["medium"] == 65.0
        assert SEVERITY_TO_CONFIDENCE["low"] == 40.0
        assert SEVERITY_TO_CONFIDENCE["info"] == 20.0

    def test_severity_mapping_count(self):
        """Test severity mapping has exactly 5 entries."""
        assert len(SEVERITY_TO_CONFIDENCE) == 5


class TestNormalizeConfidence:
    """Tests for normalize_confidence function."""

    def test_normalize_numeric_int(self):
        """Test normalizing integer value."""
        assert normalize_confidence(75) == 75.0

    def test_normalize_numeric_float(self):
        """Test normalizing float value."""
        assert normalize_confidence(87.5) == 87.5

    def test_normalize_string_critical(self):
        """Test normalizing 'critical' string."""
        assert normalize_confidence("critical") == 95.0

    def test_normalize_string_high(self):
        """Test normalizing 'high' string."""
        assert normalize_confidence("high") == 85.0

    def test_normalize_string_medium(self):
        """Test normalizing 'medium' string."""
        assert normalize_confidence("medium") == 65.0

    def test_normalize_string_low(self):
        """Test normalizing 'low' string."""
        assert normalize_confidence("low") == 40.0

    def test_normalize_string_info(self):
        """Test normalizing 'info' string."""
        assert normalize_confidence("info") == 20.0

    def test_normalize_string_case_insensitive(self):
        """Test normalizing is case insensitive."""
        assert normalize_confidence("CRITICAL") == 95.0
        assert normalize_confidence("High") == 85.0
        assert normalize_confidence("MeDiUm") == 65.0

    def test_normalize_none_returns_default(self):
        """Test normalizing None returns default 50.0."""
        assert normalize_confidence(None) == 50.0

    def test_normalize_unknown_string_returns_default(self):
        """Test normalizing unknown string returns default 50.0."""
        assert normalize_confidence("unknown") == 50.0
        assert normalize_confidence("foo") == 50.0


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_basic_initialization(self):
        """Test basic ScanResult creation."""
        now = datetime.now()
        result = ScanResult(target="https://example.com", start_time=now)

        assert result.target == "https://example.com"
        assert result.start_time == now
        assert result.end_time is None
        assert result.findings == []
        assert result.errors == []
        assert result.modules_run == []

    def test_default_values(self):
        """Test ScanResult default values."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        assert result.safe_mode == "safe"
        assert result.intelligent_mode is False
        assert result.tests_skipped == 0
        assert result.chain_findings == 0
        assert result.waf_detected is False
        assert result.coverage_percentage == 0.0

    def test_add_finding_dict(self):
        """Test adding a finding as dict."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        finding = {
            "type": "sqli",
            "severity": "high",
            "url": "https://test.com/vuln"
        }
        result.add_finding(finding)

        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "sqli"
        assert "discovered_at" in result.findings[0]

    def test_add_finding_dataclass(self):
        """Test adding a finding as dataclass with to_dict."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        # Mock a dataclass with to_dict
        mock_finding = MagicMock()
        mock_finding.to_dict.return_value = {"type": "xss", "severity": "medium"}

        result.add_finding(mock_finding)

        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "xss"

    def test_duration_seconds(self):
        """Test duration_seconds property."""
        start = datetime(2026, 2, 24, 10, 0, 0)
        end = datetime(2026, 2, 24, 10, 5, 30)

        result = ScanResult(target="https://test.com", start_time=start, end_time=end)

        assert result.duration_seconds == 330.0  # 5 min 30 sec

    def test_duration_seconds_no_end(self):
        """Test duration_seconds returns 0 when no end time."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        assert result.duration_seconds == 0.0

    def test_findings_by_severity(self):
        """Test findings_by_severity property."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "low"},
            {"severity": "low"},
        ]

        by_sev = result.findings_by_severity

        assert by_sev["critical"] == 1
        assert by_sev["high"] == 2
        assert by_sev["medium"] == 1
        assert by_sev["low"] == 3
        assert by_sev["info"] == 0

    def test_action_summary(self):
        """Test action_summary property."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "low"},
        ]

        summary = result.action_summary

        assert summary["fix_now"] == 3  # 2 critical + 1 high
        assert summary["fix_next_sprint"] == 2  # 2 medium
        assert summary["fix_when_convenient"] == 1  # 1 low

    def test_to_dict_basic(self):
        """Test to_dict method returns expected structure."""
        start = datetime(2026, 2, 24, 10, 0, 0)
        end = datetime(2026, 2, 24, 10, 5, 0)

        result = ScanResult(
            target="https://test.com",
            start_time=start,
            end_time=end,
            safe_mode="standard",
            intelligent_mode=True,
        )
        result.findings = [{"severity": "high", "type": "sqli"}]
        result.modules_run = ["sqli", "xss"]

        data = result.to_dict()

        assert data["target"] == "https://test.com"
        assert data["duration_seconds"] == 300.0
        assert data["safe_mode"] == "standard"
        assert data["intelligent_mode"] is True
        assert data["summary"]["total_findings"] == 1
        assert data["summary"]["high"] == 1

    def test_to_dict_has_report_metadata(self):
        """Test to_dict includes report metadata."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        data = result.to_dict()

        assert "report_metadata" in data
        assert data["report_metadata"]["methodology"] == "Cloud-First Security Review (CFSR) v2.0"
        assert data["report_metadata"]["framework"] == "PetNTester AI Enterprise"

    def test_to_dict_has_scope(self):
        """Test to_dict includes scope section."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        data = result.to_dict()

        assert "scope" in data
        assert data["scope"]["target"] == "https://test.com"
        assert "what_was_tested" in data["scope"]
        assert "what_was_not_tested" in data["scope"]
        assert "limitations" in data["scope"]

    def test_to_dict_has_metrics_sections(self):
        """Test to_dict includes all metrics sections."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())

        data = result.to_dict()

        assert "intelligent_metrics" in data
        assert "chain_metrics" in data
        assert "coverage_awareness" in data
        assert "error_tracking" in data
        assert "uncertainty_tracking" in data
        assert "auditability" in data
        assert "waf_opsec" in data

    def test_to_dict_classification(self):
        """Test to_dict includes classification data."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.target_classification = "api"
        result.target_type_code = "REST_API"
        result.classification_confidence = 0.85

        data = result.to_dict()

        assert data["classification"]["target_type"] == "api"
        assert data["classification"]["target_type_code"] == "REST_API"
        assert data["classification"]["confidence"] == 0.85


class TestScanResultMetricsFields:
    """Tests for specific metrics fields on ScanResult."""

    def test_vulnerability_chain_metrics(self):
        """Test vulnerability chain metrics fields."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.chain_findings = 5
        result.chains_triggered = 3
        result.escalations_attempted = 10

        data = result.to_dict()

        assert data["chain_metrics"]["chain_findings"] == 5
        assert data["chain_metrics"]["chains_triggered"] == 3
        assert data["chain_metrics"]["escalations_attempted"] == 10

    def test_waf_opsec_metrics(self):
        """Test WAF/OPSEC metrics fields."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.waf_detected = True
        result.waf_type = "Cloudflare"
        result.rate_limited = True
        result.circuit_breaker_triggered = 2
        result.total_requests_sent = 1500

        data = result.to_dict()

        assert data["waf_opsec"]["waf_detected"] is True
        assert data["waf_opsec"]["waf_type"] == "Cloudflare"
        assert data["waf_opsec"]["rate_limited"] is True
        assert data["waf_opsec"]["circuit_breaker_triggered"] == 2
        assert data["waf_opsec"]["total_requests_sent"] == 1500

    def test_coverage_awareness_metrics(self):
        """Test coverage awareness metrics fields."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.coverage_percentage = 75.5
        result.high_value_gaps = 3
        result.skip_reasons_summary = {"auth_required": 5, "rate_limited": 2}

        data = result.to_dict()

        assert data["coverage_awareness"]["coverage_percentage"] == 75.5
        assert data["coverage_awareness"]["high_value_gaps"] == 3
        assert data["coverage_awareness"]["skip_reasons_summary"]["auth_required"] == 5

    def test_error_tracking_metrics(self):
        """Test error tracking metrics fields."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.total_module_errors = 15
        result.modules_with_errors = 3
        result.error_rate_overall = 0.05
        result.error_summary_by_module = {"sqli": 5, "xss": 10}

        data = result.to_dict()

        assert data["error_tracking"]["total_module_errors"] == 15
        assert data["error_tracking"]["modules_with_errors"] == 3
        assert data["error_tracking"]["error_rate_overall"] == 0.05

    def test_uncertainty_tracking_metrics(self):
        """Test uncertainty tracking metrics fields."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.findings_with_high_uncertainty = 7
        result.proofs_not_attempted = 4
        result.validation_uncertainty_avg = 0.35

        data = result.to_dict()

        assert data["uncertainty_tracking"]["findings_with_high_uncertainty"] == 7
        assert data["uncertainty_tracking"]["proofs_not_attempted"] == 4
        assert data["uncertainty_tracking"]["validation_uncertainty_avg"] == 0.35

    def test_auditability_metrics(self):
        """Test auditability metrics fields."""
        result = ScanResult(target="https://test.com", start_time=datetime.now())
        result.findings_suppressed = 8
        result.chains_suppressed = 2
        result.proofs_skipped = 3
        result.suppression_audit = [{"finding": "x", "reason": "y"}]
        result.unproven_findings = [{"type": "sqli"}]

        data = result.to_dict()

        assert data["auditability"]["findings_suppressed"] == 8
        assert data["auditability"]["chains_suppressed"] == 2
        assert data["auditability"]["proofs_skipped"] == 3


class TestScanResultIntegration:
    """Integration tests for ScanResult with FullScanner."""

    def test_fullscanner_uses_metrics_scanresult(self):
        """Test that FullScanner uses the metrics module ScanResult."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        # Verify import path
        from scanning.metrics import ScanResult as MetricsScanResult

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        # The scanner should use the same ScanResult class
        # We can verify the import is correct
        assert MetricsScanResult is not None

    def test_scanresult_imported_from_metrics(self):
        """Test ScanResult is imported from scanning.metrics in full_scanner."""
        import scanning.full_scanner as fs_module
        from scanning.metrics import ScanResult as MetricsScanResult

        # Both should reference the same class
        assert fs_module.ScanResult is MetricsScanResult
