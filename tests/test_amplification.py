"""
Tests for the amplification module.

Tests the extracted amplification system from scanning/amplification/.
"""

import pytest
from unittest.mock import MagicMock

from scanning.amplification import (
    AmplificationAction,
    AmplificationGuardrails,
    AmplificationTracker,
    ScanAmplifier,
    GuardrailBlockReason,
    SuspensionLevel,
    ProgressMetrics,
    ActionFingerprint,
)


class TestAmplificationModels:
    """Test amplification data models."""

    def test_amplification_action_creation(self):
        """Test AmplificationAction dataclass."""
        action = AmplificationAction(
            trigger_type="sqli",
            action="expand_sqli_extraction",
            target="http://example.com/api/users",
            params={"database_type": "mysql"},
            priority=8,
        )
        assert action.trigger_type == "sqli"
        assert action.action == "expand_sqli_extraction"
        assert action.target == "http://example.com/api/users"
        assert action.params["database_type"] == "mysql"
        assert action.priority == 8
        assert action.cost == 1  # default

    def test_guardrail_block_reason_enum(self):
        """Test GuardrailBlockReason enum values."""
        assert GuardrailBlockReason.BUDGET_EXCEEDED.value == "global_budget_exceeded"
        assert GuardrailBlockReason.PER_FINDING_LIMIT.value == "max_actions_per_finding_reached"
        assert GuardrailBlockReason.HARD_SUSPENDED.value == "finding_hard_suspended"

    def test_suspension_level_enum(self):
        """Test SuspensionLevel enum values."""
        assert SuspensionLevel.NONE.value == "none"
        assert SuspensionLevel.SOFT.value == "soft"
        assert SuspensionLevel.HARD.value == "hard"

    def test_progress_metrics_score(self):
        """Test ProgressMetrics progress score calculation."""
        metrics = ProgressMetrics(
            new_state_changes=2,
            new_endpoints=3,
            new_headers=1,
            new_findings=1,
            retries=0,
        )
        # 2*3 + 3*2 + 1*1 + 1*5 - 0*2 = 6 + 6 + 1 + 5 = 18
        assert metrics.progress_score == 18
        assert metrics.is_dead_target is False

    def test_progress_metrics_dead_target(self):
        """Test ProgressMetrics dead target detection."""
        metrics = ProgressMetrics(
            new_state_changes=0,
            new_endpoints=0,
            new_headers=0,
            new_findings=0,
            retries=5,
            actions_total=5,
        )
        # 0 - 5*2 = -10
        assert metrics.progress_score == -10
        assert metrics.is_dead_target is True

    def test_action_fingerprint_equality(self):
        """Test ActionFingerprint equality and hashing."""
        fp1 = ActionFingerprint(
            finding_id="abc123",
            action_type="test",
            target="http://example.com",
            param_hash="xyz789",
        )
        fp2 = ActionFingerprint(
            finding_id="abc123",
            action_type="test",
            target="http://example.com",
            param_hash="xyz789",
        )
        fp3 = ActionFingerprint(
            finding_id="different",
            action_type="test",
            target="http://example.com",
            param_hash="xyz789",
        )
        assert fp1 == fp2
        assert fp1 != fp3
        assert hash(fp1) == hash(fp2)


class TestAmplificationGuardrails:
    """Test amplification guardrails configuration."""

    def test_default_guardrails(self):
        """Test default guardrail values."""
        guardrails = AmplificationGuardrails()
        assert guardrails.max_actions_per_finding == 20
        assert guardrails.max_retries_per_action == 3
        assert guardrails.global_action_budget == 1000
        assert guardrails.soft_suspend_threshold == 5
        assert guardrails.hard_suspend_threshold == 10

    def test_action_costs(self):
        """Test default action costs."""
        guardrails = AmplificationGuardrails()
        assert guardrails.action_costs["expand_idor_range"] == 3
        assert guardrails.action_costs["test_race_condition"] == 5
        assert guardrails.action_costs["default"] == 1

    def test_failure_threshold_legacy_alias(self):
        """Test legacy alias for failure_threshold_to_suspend."""
        guardrails = AmplificationGuardrails()
        assert guardrails.failure_threshold_to_suspend == guardrails.soft_suspend_threshold


class TestAmplificationTracker:
    """Test amplification tracker functionality."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        guardrails = AmplificationGuardrails()
        tracker = AmplificationTracker(guardrails)
        assert tracker._budget_used == 0
        assert len(tracker._actions_per_finding) == 0
        assert len(tracker._soft_suspended) == 0
        assert len(tracker._hard_suspended) == 0

    def test_can_execute_action_budget_limit(self):
        """Test budget limit enforcement."""
        guardrails = AmplificationGuardrails()
        guardrails.global_action_budget = 5
        tracker = AmplificationTracker(guardrails)
        tracker._budget_used = 5  # Exhaust budget

        action = AmplificationAction(
            trigger_type="test",
            action="test_action",
            target="http://example.com",
        )
        allowed, reason, detail = tracker.can_execute_action(action, "finding1")
        assert allowed is False
        assert reason == GuardrailBlockReason.BUDGET_EXCEEDED

    def test_can_execute_action_hard_suspended(self):
        """Test hard suspension enforcement."""
        guardrails = AmplificationGuardrails()
        tracker = AmplificationTracker(guardrails)
        tracker._hard_suspended.add("finding1")

        action = AmplificationAction(
            trigger_type="test",
            action="test_action",
            target="http://example.com",
        )
        allowed, reason, detail = tracker.can_execute_action(action, "finding1")
        assert allowed is False
        assert reason == GuardrailBlockReason.HARD_SUSPENDED

    def test_record_action_start(self):
        """Test action start recording."""
        guardrails = AmplificationGuardrails()
        tracker = AmplificationTracker(guardrails)

        action = AmplificationAction(
            trigger_type="test",
            action="test_action",
            target="http://example.com",
            cost=2,
        )
        tracker.record_action_start(action, "finding1")

        assert tracker._budget_used == 1  # default cost since "test_action" not in costs
        assert tracker._actions_per_finding.get("finding1") == 1

    def test_record_action_result_success(self):
        """Test successful action result recording."""
        guardrails = AmplificationGuardrails()
        tracker = AmplificationTracker(guardrails)

        action = AmplificationAction(
            trigger_type="test",
            action="test_action",
            target="http://example.com",
            priority=5,
        )
        priority, is_progress = tracker.record_action_result(
            action, "finding1", success=True, state_changed=True
        )

        assert is_progress is True
        assert priority == 5.0

    def test_record_action_result_failure_suspension(self):
        """Test failure leading to suspension."""
        guardrails = AmplificationGuardrails()
        guardrails.soft_suspend_threshold = 2
        tracker = AmplificationTracker(guardrails)

        action = AmplificationAction(
            trigger_type="test",
            action="test_action",
            target="http://example.com",
            priority=5,
        )

        # Record multiple failures
        tracker.record_action_result(action, "finding1", success=False)
        assert "finding1" not in tracker._soft_suspended

        tracker.record_action_result(action, "finding1", success=False)
        assert "finding1" in tracker._soft_suspended

    def test_get_summary(self):
        """Test summary generation."""
        guardrails = AmplificationGuardrails()
        tracker = AmplificationTracker(guardrails)
        tracker._budget_used = 50
        tracker._soft_suspended.add("f1")
        tracker._hard_suspended.add("f2")

        summary = tracker.get_summary()
        assert summary["budget_used"] == 50
        assert summary["soft_suspended"] == 1
        assert summary["hard_suspended"] == 1
        assert summary["total_suspended"] == 2


class TestScanAmplifier:
    """Test scan amplifier functionality."""

    def test_amplifier_initialization(self):
        """Test amplifier initializes with mocked scanner."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        assert amplifier._scanner == mock_scanner
        assert len(amplifier._discovered_types) == 0
        assert len(amplifier._amplification_queue) == 0

    def test_on_finding_discovered_idor(self):
        """Test IDOR finding triggers expected actions."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        finding = {
            "type": "idor",
            "severity": "HIGH",
            "matched_at": "http://example.com/api/users/1",
            "metadata": {"original_id": "1", "test_id": "2"},
        }
        actions = amplifier.on_finding_discovered(finding)

        # Should have expand_idor_range, test_method_escalation, and cross-module actions
        action_types = [a.action for a in actions]
        assert "expand_idor_range" in action_types
        assert "test_method_escalation" in action_types

    def test_on_finding_discovered_sqli(self):
        """Test SQLi finding triggers extraction expansion."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        finding = {
            "type": "sqli",
            "severity": "CRITICAL",
            "matched_at": "http://example.com/api/search",
            "metadata": {"database_type": "mysql", "parameter": "q"},
        }
        actions = amplifier.on_finding_discovered(finding)

        action_types = [a.action for a in actions]
        assert "expand_sqli_extraction" in action_types

    def test_on_finding_discovered_smuggling(self):
        """Test HTTP smuggling triggers amplifier mode."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        finding = {
            "type": "http_smuggling",
            "severity": "CRITICAL",
            "matched_at": "http://example.com/",
            "metadata": {"smuggling_type": "cl_te"},
        }
        actions = amplifier.on_finding_discovered(finding)

        action_types = [a.action for a in actions]
        assert "xss_via_smuggling" in action_types
        assert "cache_poison_via_smuggling" in action_types
        assert "auth_bypass_via_smuggling" in action_types
        assert "rescan_with_desync" in action_types

    def test_record_negative_result_xss(self):
        """Test negative XSS result suggests alternatives."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        actions = amplifier.record_negative_result(
            vuln_type="xss",
            endpoint="http://example.com/search",
            payload="<script>alert(1)</script>",
            reason="filtered",
        )

        action_types = [a.action for a in actions]
        assert "try_xss_alternatives" in action_types

    def test_get_amplification_summary(self):
        """Test amplification summary generation."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        # Discover some findings
        amplifier._discovered_types.add("sqli")
        amplifier._discovered_types.add("xss")
        amplifier._executed_amplifications.add("test:action")

        summary = amplifier.get_amplification_summary()
        assert "sqli" in summary["discovered_types"]
        assert "xss" in summary["discovered_types"]
        assert summary["executed_amplifications"] == 1

    def test_normalize_type(self):
        """Test vulnerability type normalization."""
        mock_scanner = MagicMock()
        mock_scanner.focus_lock = None
        amplifier = ScanAmplifier(mock_scanner)

        assert amplifier._normalize_type("sql_injection") == "sqli"
        assert amplifier._normalize_type("SQL_INJECTION") == "sqli"
        assert amplifier._normalize_type("cross_site_scripting") == "xss"
        assert amplifier._normalize_type("idor") == "idor"
        assert amplifier._normalize_type("unknown_type") == "unknown_type"

    def test_amplification_map_coverage(self):
        """Test that AMPLIFICATION_MAP has key vulnerability types."""
        assert "idor" in ScanAmplifier.AMPLIFICATION_MAP
        assert "sqli" in ScanAmplifier.AMPLIFICATION_MAP
        assert "xss" in ScanAmplifier.AMPLIFICATION_MAP
        assert "http_smuggling" in ScanAmplifier.AMPLIFICATION_MAP
        assert "auth_bypass" in ScanAmplifier.AMPLIFICATION_MAP
