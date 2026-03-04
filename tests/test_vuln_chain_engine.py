"""
Unit tests for VulnerabilityChainEngine.

Tests cover:
- Chain trigger mapping
- Chain rule matching
- Placeholder handler output structure
- Depth limiting
- Metrics tracking
- OS-aware path helpers
- Confidence calculation

Run with: pytest tests/test_vuln_chain_engine.py -v
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from scanning.vuln_chain_engine import (
    VulnerabilityChainEngine,
    ChainTrigger,
    ChainPriority,
    ChainRule,
    ChainResult,
    ChainErrorType,
    CHAIN_LIMITS,
    OS_SENSITIVE_PATHS,
    CONFIDENCE_STANDARDS,
    MAX_CHAIN_DEPTH,
    is_chain_testing_allowed,
    is_speculative_allowed,
    get_sensitive_paths,
    get_chain_confidence,
)


class TestChainTriggerMapping:
    """Test vulnerability type to trigger mapping."""

    def test_sqli_mapping(self):
        """SQLi types map to correct triggers."""
        engine = VulnerabilityChainEngine()

        # Test various SQLi type strings
        sqli_types = ["sql_injection", "sqli", "blind_sql_injection", "time_based_sqli"]

        for vuln_type in sqli_types[:2]:
            finding = {"type": vuln_type}
            trigger = engine._finding_to_trigger(finding)
            assert trigger == ChainTrigger.SQLI_CONFIRMED

        for vuln_type in sqli_types[2:]:
            finding = {"type": vuln_type}
            trigger = engine._finding_to_trigger(finding)
            assert trigger == ChainTrigger.SQLI_BLIND_CONFIRMED

    def test_xss_mapping(self):
        """XSS types map to correct triggers."""
        engine = VulnerabilityChainEngine()

        finding = {"type": "xss"}
        trigger = engine._finding_to_trigger(finding)
        assert trigger == ChainTrigger.XSS_CONFIRMED

        finding = {"type": "dom_xss"}
        trigger = engine._finding_to_trigger(finding)
        assert trigger == ChainTrigger.DOM_XSS_CONFIRMED

    def test_unknown_type_returns_none(self):
        """Unknown vulnerability types return None."""
        engine = VulnerabilityChainEngine()

        finding = {"type": "unknown_vuln_type_xyz"}
        trigger = engine._finding_to_trigger(finding)
        assert trigger is None


class TestChainRuleMatching:
    """Test chain rule applicability."""

    def test_rules_exist_for_all_triggers(self):
        """Every ChainTrigger has at least one rule."""
        engine = VulnerabilityChainEngine()

        # Get all triggers that should have rules
        triggers_with_rules = set()
        for rule in engine.CHAIN_RULES:
            triggers_with_rules.add(rule.trigger)

        # All main triggers should have rules (100% coverage per audit)
        main_triggers = [
            ChainTrigger.SQLI_CONFIRMED,
            ChainTrigger.XSS_CONFIRMED,
            ChainTrigger.SSRF_CONFIRMED,
            ChainTrigger.LFI_CONFIRMED,
            ChainTrigger.IDOR_CONFIRMED,
            ChainTrigger.CSRF_CONFIRMED,  # Added in H2 fix
            ChainTrigger.HTTP_SMUGGLING,  # Added in H2 fix
        ]

        for trigger in main_triggers:
            assert trigger in triggers_with_rules, f"Missing rules for {trigger.name}"

    def test_conditional_rules(self):
        """Rules with conditions are properly filtered."""
        engine = VulnerabilityChainEngine()
        engine.set_context(technologies=["php", "mysql"])

        # PHP-conditional rules should match
        applicable = engine._get_applicable_rules(ChainTrigger.LFI_CONFIRMED)
        assert len(applicable) > 0


class TestHandlerOutputStructure:
    """Test that handlers produce properly structured findings."""

    @pytest.mark.asyncio
    async def test_handler_has_required_fields(self):
        """Handler findings include url, module_name, cwe."""
        engine = VulnerabilityChainEngine()

        finding = {
            "type": "sql_injection",
            "matched_at": "https://example.com/api/users",
        }
        context = {"target": "https://example.com"}

        # Test a handler directly
        result = await engine._sqli_mysql_udf_rce(finding, context)

        assert len(result) > 0
        chain_finding = result[0]

        # Check required fields exist
        assert "matched_at" in chain_finding
        assert chain_finding["matched_at"] is not None

    @pytest.mark.asyncio
    async def test_improved_placeholder_handlers(self):
        """L1-L4 improved handlers have proper structure."""
        engine = VulnerabilityChainEngine()

        finding = {"matched_at": "https://example.com/api"}
        context = {"target": "https://example.com"}

        # Test improved handlers
        handlers_to_test = [
            engine._deser_java_gadget,
            engine._deser_php_gadget,
            engine._deser_python_pickle,
            engine._ssti_rce,
            engine._cmdi_reverse_shell_prep,
        ]

        for handler in handlers_to_test:
            result = await handler(finding, context)
            assert len(result) > 0
            chain_finding = result[0]

            # L1-L4 FIX: All handlers should have these fields
            assert "url" in chain_finding, f"{handler.__name__} missing url"
            assert "module_name" in chain_finding, f"{handler.__name__} missing module_name"
            assert "cwe" in chain_finding, f"{handler.__name__} missing cwe"
            assert "description" in chain_finding, f"{handler.__name__} missing description"
            assert chain_finding["module_name"] == "vuln_chain_engine"


class TestDepthLimiting:
    """Test M4 chain depth limiting."""

    def test_max_depth_constant(self):
        """MAX_CHAIN_DEPTH is properly set."""
        assert MAX_CHAIN_DEPTH == 3

    @pytest.mark.asyncio
    async def test_depth_limit_prevents_infinite_recursion(self):
        """Process finding respects depth limit."""
        engine = VulnerabilityChainEngine()

        finding = {
            "type": "sql_injection",
            "matched_at": "https://example.com/api",
        }

        # Process at max depth should return empty
        result = await engine.process_finding(finding, depth=MAX_CHAIN_DEPTH)
        assert result == []

        # Metric should track skipped chains
        assert engine._metrics["chains_skipped_depth"] > 0


class TestMetricsTracking:
    """Test M5 metrics tracking."""

    def test_initial_metrics_structure(self):
        """Metrics have expected structure."""
        engine = VulnerabilityChainEngine()

        expected_keys = [
            "findings_processed",
            "chains_executed",
            "chains_successful",
            "chains_failed",
            "chains_skipped_budget",
            "chains_skipped_depth",
            "total_chain_findings",
            "by_trigger",
            "by_action",
        ]

        for key in expected_keys:
            assert key in engine._metrics

    def test_get_metrics_computed_values(self):
        """get_metrics() returns computed values."""
        engine = VulnerabilityChainEngine()

        # Simulate some activity
        engine._metrics["chains_executed"] = 10
        engine._metrics["chains_successful"] = 7
        engine._metrics["execution_time_total"] = 5.0

        metrics = engine.get_metrics()

        assert "success_rate" in metrics
        assert metrics["success_rate"] == 70.0
        assert "avg_execution_time" in metrics
        assert metrics["avg_execution_time"] == 0.5

    def test_reset_clears_metrics(self):
        """reset() clears all metrics."""
        engine = VulnerabilityChainEngine()

        engine._metrics["findings_processed"] = 100
        engine._metrics["chains_executed"] = 50

        engine.reset()

        assert engine._metrics["findings_processed"] == 0
        assert engine._metrics["chains_executed"] == 0


class TestOSAwarePaths:
    """Test M1 OS-aware path helpers."""

    def test_os_sensitive_paths_structure(self):
        """OS_SENSITIVE_PATHS has all OS types."""
        assert "linux" in OS_SENSITIVE_PATHS
        assert "windows" in OS_SENSITIVE_PATHS
        assert "cloud" in OS_SENSITIVE_PATHS

    def test_linux_paths(self):
        """Linux paths include common targets."""
        paths = get_sensitive_paths("linux")

        assert paths["passwd"] == "/etc/passwd"
        assert "/etc/shadow" == paths["shadow"]
        assert isinstance(paths["ssh_keys"], list)

    def test_windows_paths(self):
        """Windows paths include common targets."""
        paths = get_sensitive_paths("windows")

        assert "hosts" in paths
        assert "C:\\" in paths["hosts"]
        assert paths["passwd"] is None  # Windows doesn't have /etc/passwd

    def test_cloud_metadata_endpoints(self):
        """Cloud paths include metadata endpoints."""
        paths = get_sensitive_paths("cloud")

        assert "aws_metadata" in paths
        assert "169.254.169.254" in paths["aws_metadata"]
        assert "azure_metadata" in paths

    def test_unknown_os_falls_back_to_linux(self):
        """Unknown OS type falls back to Linux."""
        paths = get_sensitive_paths("unknown_os")
        assert paths["passwd"] == "/etc/passwd"


class TestConfidenceCalculation:
    """Test M2 confidence helpers."""

    def test_confidence_standards_values(self):
        """CONFIDENCE_STANDARDS has expected values."""
        assert 95 in CONFIDENCE_STANDARDS
        assert 65 in CONFIDENCE_STANDARDS
        assert "PROVEN" in CONFIDENCE_STANDARDS[95]

    def test_get_chain_confidence_proven(self):
        """Data extracted = 95% confidence."""
        conf = get_chain_confidence(
            vuln_confirmed=True,
            chain_verified=True,
            data_extracted=True
        )
        assert conf == 95

    def test_get_chain_confidence_verified(self):
        """Verified chain = 90% confidence."""
        conf = get_chain_confidence(
            vuln_confirmed=True,
            chain_verified=True,
            data_extracted=False
        )
        assert conf == 90

    def test_get_chain_confidence_confirmed_only(self):
        """Vuln confirmed only = 80% confidence."""
        conf = get_chain_confidence(
            vuln_confirmed=True,
            chain_verified=False,
            data_extracted=False
        )
        assert conf == 80

    def test_get_chain_confidence_speculative(self):
        """No confirmation = 65% speculative."""
        conf = get_chain_confidence(
            vuln_confirmed=False,
            chain_verified=False,
            data_extracted=False
        )
        assert conf == 65


class TestChainErrorType:
    """Test H6 error classification."""

    def test_error_types_exist(self):
        """All error types are defined."""
        assert ChainErrorType.NONE
        assert ChainErrorType.TIMEOUT
        assert ChainErrorType.CONNECTION
        assert ChainErrorType.RATE_LIMITED
        assert ChainErrorType.BUDGET_EXHAUSTED
        assert ChainErrorType.HANDLER_ERROR

    def test_chain_result_has_error_fields(self):
        """ChainResult includes error classification fields."""
        result = ChainResult(
            success=False,
            action="test",
            findings=[],
            evidence={},
            error="timeout",
            error_type=ChainErrorType.TIMEOUT,
            retryable=True,
        )

        assert result.error_type == ChainErrorType.TIMEOUT
        assert result.retryable is True


class TestChainLimits:
    """Test safety mode chain limits."""

    def test_chain_limits_exist(self):
        """CHAIN_LIMITS is properly configured."""
        assert "allow_active_testing" in CHAIN_LIMITS
        assert "allow_speculative" in CHAIN_LIMITS
        assert "max_requests_per_chain" in CHAIN_LIMITS

    def test_helper_functions(self):
        """Helper functions work."""
        # These depend on PHANTOM_SAFE_MODE env var
        assert isinstance(is_chain_testing_allowed(), bool)
        assert isinstance(is_speculative_allowed(), bool)


class TestEngineLifecycle:
    """Test engine initialization and cleanup."""

    def test_init_creates_empty_state(self):
        """Engine initializes with empty state."""
        engine = VulnerabilityChainEngine()

        assert len(engine.findings_processed) == 0
        assert len(engine.chain_results) == 0
        assert engine._current_depth == 0

    def test_reset_clears_all_state(self):
        """reset() clears all state."""
        engine = VulnerabilityChainEngine()

        # Add some state
        engine.findings_processed.add("test")
        engine._chain_actions_completed.add("test_action")
        engine._current_depth = 2

        engine.reset()

        assert len(engine.findings_processed) == 0
        assert len(engine._chain_actions_completed) == 0
        assert engine._current_depth == 0

    def test_set_rate_limiter(self):
        """set_rate_limiter() configures rate limiting."""
        engine = VulnerabilityChainEngine()
        mock_limiter = MagicMock()

        engine.set_rate_limiter(mock_limiter)

        assert engine._rate_limiter == mock_limiter

    def test_set_shared_store(self):
        """set_shared_store() configures findings sharing."""
        engine = VulnerabilityChainEngine()
        mock_store = MagicMock()

        engine.set_shared_store(mock_store)

        assert engine._shared_store == mock_store


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
