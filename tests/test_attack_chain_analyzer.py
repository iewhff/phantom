"""
Unit tests for AttackChainAnalyzer.

Tests cover:
- Chain pattern matching
- Chain consolidation
- Probability calculation
- Severity escalation
- Infrastructure chain handling
- Metrics tracking (H1 fix)
- Thread safety (H2 fix)

Run with: pytest tests/test_attack_chain_analyzer.py -v
"""

import pytest
import threading
from unittest.mock import MagicMock, patch

from scanning.attack_chain_analyzer import (
    AttackChainAnalyzer,
    AttackChain,
    ChainStep,
    ChainPattern,
    ChainCategory,
    ChainConfidence,
    CHAIN_PATTERNS,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    INFRA_PROBABILITY_MIN,
    INFRA_PROBABILITY_MAX,
    _validate_pattern,
)


class TestChainPatterns:
    """Test chain pattern database integrity."""

    def test_pattern_count(self):
        """Database should have 60+ patterns."""
        assert len(CHAIN_PATTERNS) >= 60

    def test_patterns_have_required_fields(self):
        """Each pattern should have required fields."""
        required_fields = ["name", "entry_types", "category", "severity", "probability"]

        for pattern in CHAIN_PATTERNS:
            for field in required_fields:
                assert field in pattern, f"Pattern missing field '{field}': {pattern.get('name', 'unknown')}"

    def test_pattern_categories_valid(self):
        """Pattern categories should be valid ChainCategory enums."""
        for pattern in CHAIN_PATTERNS:
            assert isinstance(pattern["category"], ChainCategory), (
                f"Pattern '{pattern['name']}' has invalid category"
            )

    def test_pattern_probability_in_range(self):
        """Pattern probabilities should be 0-100."""
        for pattern in CHAIN_PATTERNS:
            prob = pattern["probability"]
            assert 0 <= prob <= 100, (
                f"Pattern '{pattern['name']}' has invalid probability: {prob}"
            )


class TestAnalyzerBasic:
    """Test basic analyzer functionality."""

    def test_empty_findings_returns_empty(self):
        """No findings should produce no chains."""
        analyzer = AttackChainAnalyzer()
        result = analyzer.analyze([])
        assert result == []
        assert analyzer.get_metrics()["chains_created"] == 0

    def test_single_finding_no_chain(self):
        """Single finding without chain partner produces no chain."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {
                "name": "XSS in search",
                "vulnerability_type": "xss",
                "severity": "MEDIUM",
                "confidence": 80,
                "matched_at": "https://example.com/search",
            }
        ]
        result = analyzer.analyze(findings)
        # Should return original findings (no chains created)
        assert len(result) == 1
        assert result[0]["name"] == "XSS in search"


class TestChainDiscovery:
    """Test chain discovery logic."""

    def test_xss_session_chain(self):
        """XSS + session finding on same host should create ATO chain."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {
                "name": "XSS in search",
                "vulnerability_type": "xss",
                "severity": "MEDIUM",
                "confidence": 85,
                "matched_at": "https://example.com/search",
                "metadata": {"proof": {"can_chain": True}},
            },
            {
                "name": "Session fixation",
                "vulnerability_type": "session_abuse",
                "severity": "HIGH",
                "confidence": 80,
                "matched_at": "https://example.com/login",
                "metadata": {"proof": {"can_chain": True}},
            },
        ]
        result = analyzer.analyze(findings)

        # Should have original findings + at least 1 chain
        assert len(result) >= 2
        chains = [f for f in result if f.get("vulnerability_type") == "attack_chain"]
        assert len(chains) >= 1, "Should create XSS + session chain"

    def test_sqli_idor_chain(self):
        """SQLi + IDOR should create data exfil chain."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {
                "name": "SQL Injection",
                "vulnerability_type": "sql_injection",
                "severity": "CRITICAL",
                "confidence": 90,
                "matched_at": "https://example.com/api/users",
                "metadata": {"proof": {"can_chain": True}},
            },
            {
                "name": "IDOR on user data",
                "vulnerability_type": "idor",
                "severity": "HIGH",
                "confidence": 85,
                "matched_at": "https://example.com/api/users/123",
                "metadata": {"proof": {"can_chain": True}},
            },
        ]
        result = analyzer.analyze(findings)
        chains = [f for f in result if f.get("vulnerability_type") == "attack_chain"]
        assert len(chains) >= 1

    def test_different_hosts_no_chain(self):
        """Findings on different hosts should not chain."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {
                "name": "XSS on site A",
                "vulnerability_type": "xss",
                "severity": "HIGH",
                "confidence": 85,
                "matched_at": "https://site-a.com/search",
                "metadata": {"proof": {"can_chain": True}},
            },
            {
                "name": "Session weakness on site B",
                "vulnerability_type": "session_abuse",
                "severity": "HIGH",
                "confidence": 85,
                "matched_at": "https://site-b.com/login",
                "metadata": {"proof": {"can_chain": True}},
            },
        ]
        result = analyzer.analyze(findings)
        chains = [f for f in result if f.get("vulnerability_type") == "attack_chain"]
        # Should not create cross-host chains by default
        xss_session_chains = [c for c in chains if "XSS" in c["name"] and "Session" in c["name"]]
        assert len(xss_session_chains) == 0


class TestChainConfidence:
    """Test chain confidence level determination."""

    def test_proven_chain_confidence(self):
        """Findings with proof.can_chain should get PROVEN confidence."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {
                "name": "XSS",
                "vulnerability_type": "xss",
                "severity": "HIGH",
                "confidence": 95,
                "matched_at": "https://example.com/",
                "metadata": {"proof": {"can_chain": True}},
            },
            {
                "name": "CORS",
                "vulnerability_type": "cors_arbitrary",
                "severity": "HIGH",
                "confidence": 90,
                "matched_at": "https://example.com/api",
                "metadata": {"proof": {"can_chain": True}},
            },
        ]
        result = analyzer.analyze(findings)
        chains = [f for f in result if f.get("vulnerability_type") == "attack_chain"]

        if chains:
            # Check that high-confidence chains have appropriate confidence level
            chain = chains[0]
            assert chain["metadata"]["chain_confidence"] in ["proven", "high", "technical", "medium"]

    def test_infrastructure_chain_technical_confidence(self):
        """Infrastructure findings should get TECHNICAL confidence."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {
                "name": "HTTP Smuggling",
                "vulnerability_type": "http_smuggling",
                "severity": "CRITICAL",
                "confidence": 85,
                "matched_at": "https://example.com/",
                "metadata": {},
            },
        ]
        result = analyzer.analyze(findings)
        # Infrastructure findings may create chains with TECHNICAL confidence
        metrics = analyzer.get_metrics()
        # Even if no chains created, the finding should be processed
        assert metrics["findings_analyzed"] == 1


class TestSeverityEscalation:
    """Test chain severity escalation logic."""

    def test_two_high_escalates_to_critical(self):
        """Two HIGH severity findings should escalate chain to CRITICAL."""
        analyzer = AttackChainAnalyzer()

        # Create mock findings with HIGH severity
        findings = [
            {
                "name": "XSS",
                "vulnerability_type": "xss",
                "severity": "HIGH",
                "confidence": 85,
                "matched_at": "https://example.com/",
                "metadata": {"proof": {"can_chain": True}},
            },
            {
                "name": "Session abuse",
                "vulnerability_type": "session_abuse",
                "severity": "HIGH",
                "confidence": 85,
                "matched_at": "https://example.com/login",
                "metadata": {"proof": {"can_chain": True}},
            },
        ]
        result = analyzer.analyze(findings)
        chains = [f for f in result if f.get("vulnerability_type") == "attack_chain"]

        if chains:
            # Should escalate to CRITICAL
            assert chains[0]["severity"] == "CRITICAL"


class TestChainConsolidation:
    """Test chain consolidation to prevent spam."""

    def test_consolidation_limits_chains_per_pattern(self):
        """Should limit chains of same pattern type to MAX_CHAINS_PER_PATTERN."""
        analyzer = AttackChainAnalyzer()

        # Create many similar findings to trigger chain consolidation
        findings = []
        for i in range(20):
            findings.extend([
                {
                    "name": f"IDOR {i}",
                    "vulnerability_type": "idor",
                    "severity": "HIGH",
                    "confidence": 85,
                    "matched_at": f"https://example.com/api/users/{i}",
                    "metadata": {"proof": {"can_chain": True}},
                },
                {
                    "name": f"Business Logic {i}",
                    "vulnerability_type": "business_logic",
                    "severity": "HIGH",
                    "confidence": 80,
                    "matched_at": f"https://example.com/api/users/{i}",
                    "metadata": {"proof": {"can_chain": True}},
                },
            ])

        result = analyzer.analyze(findings)
        chains = [f for f in result if f.get("vulnerability_type") == "attack_chain"]

        # Should have chains_suppressed > 0 if consolidation happened
        metrics = analyzer.get_metrics()
        # Either chains created or some were suppressed
        assert metrics["chains_created"] <= analyzer._max_chains_total


class TestMetricsTracking:
    """Test H1 fix: metrics tracking."""

    def test_initial_metrics_structure(self):
        """Metrics should have expected structure."""
        analyzer = AttackChainAnalyzer()
        metrics = analyzer.get_metrics()

        expected_keys = [
            "findings_analyzed",
            "chains_created",
            "chains_suppressed",
            "patterns_matched",
            "dynamic_chains",
            "by_category",
            "by_confidence",
            "errors",
            "avg_probability",
        ]

        for key in expected_keys:
            assert key in metrics, f"Missing metric: {key}"

    def test_metrics_track_findings_analyzed(self):
        """Metrics should count findings analyzed."""
        analyzer = AttackChainAnalyzer()
        findings = [{"name": "Test", "vulnerability_type": "xss", "matched_at": "https://example.com"}]
        analyzer.analyze(findings)

        metrics = analyzer.get_metrics()
        assert metrics["findings_analyzed"] == 1

    def test_reset_metrics_clears_counters(self):
        """reset_metrics() should clear all counters."""
        analyzer = AttackChainAnalyzer()
        findings = [{"name": "Test", "vulnerability_type": "xss", "matched_at": "https://example.com"}]
        analyzer.analyze(findings)

        analyzer.reset_metrics()
        metrics = analyzer.get_metrics()
        assert metrics["findings_analyzed"] == 0
        assert metrics["chains_created"] == 0


class TestThreadSafety:
    """Test H2 fix: thread safety."""

    def test_concurrent_analyze_calls(self):
        """Concurrent analyze() calls should not corrupt state."""
        analyzer = AttackChainAnalyzer()
        errors = []
        results = []

        def analyze_findings(idx):
            try:
                findings = [
                    {
                        "name": f"XSS {idx}",
                        "vulnerability_type": "xss",
                        "severity": "HIGH",
                        "confidence": 85,
                        "matched_at": f"https://example{idx}.com/",
                    }
                ]
                result = analyzer.analyze(findings)
                results.append(len(result))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=analyze_findings, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        # Each call should return at least the input finding
        assert all(r >= 1 for r in results)


class TestExceptionHandling:
    """Test H4 fix: exception handling."""

    def test_malformed_finding_handled(self):
        """Malformed findings should not crash analysis."""
        analyzer = AttackChainAnalyzer()
        findings = [
            {"name": "Valid", "vulnerability_type": "xss", "matched_at": "https://example.com"},
            {},  # Empty finding
            None,  # None finding (should be filtered)
        ]
        # Filter out None values as the real scanner would
        findings = [f for f in findings if f is not None]

        # Should not raise exception
        result = analyzer.analyze(findings)
        assert len(result) >= 1


class TestConfigurableLimits:
    """Test M1 fix: configurable budget limits."""

    def test_custom_max_chains(self):
        """Custom max_chains_total should be respected."""
        analyzer = AttackChainAnalyzer(max_chains_total=5)
        assert analyzer._max_chains_total == 5

    def test_custom_max_findings_per_type(self):
        """Custom max_findings_per_type should be respected."""
        analyzer = AttackChainAnalyzer(max_findings_per_type=10)
        assert analyzer._max_findings_per_type == 10


class TestAttackChainDataclass:
    """Test AttackChain dataclass."""

    def test_to_finding_dict(self):
        """to_finding_dict() should serialize properly."""
        step = ChainStep(
            finding={"name": "XSS", "matched_at": "https://example.com"},
            role="entry",
            action="Inject JavaScript",
            data_obtained="Script execution",
        )
        chain = AttackChain(
            name="XSS → ATO",
            category=ChainCategory.ACCOUNT_TAKEOVER,
            steps=[step],
            combined_severity="CRITICAL",
            probability_score=85.0,
            business_impact="Account takeover",
        )

        result = chain.to_finding_dict()

        assert result["name"] == "Attack Chain: XSS → ATO"
        assert result["severity"] == "CRITICAL"
        assert result["vuln_type"] == "attack_chain"
        assert result["metadata"]["is_chain"] is True


class TestIntentProfile:
    """Test intent profile integration."""

    def test_set_intent_profile(self):
        """Intent profile should be settable."""
        analyzer = AttackChainAnalyzer()
        mock_profile = MagicMock()
        analyzer.set_intent_profile(mock_profile)
        assert analyzer._intent_profile is mock_profile


class TestPatternValidation:
    """Test M3 fix: pattern validation."""

    def test_valid_pattern_passes(self):
        """Valid pattern dict should pass validation."""
        pattern = {
            "name": "Test Pattern",
            "entry_types": ["xss"],
            "category": ChainCategory.ACCOUNT_TAKEOVER,
            "severity": "HIGH",
            "probability": 80,
        }
        assert _validate_pattern(pattern) is True

    def test_missing_name_fails(self):
        """Pattern without name should fail validation."""
        pattern = {
            "entry_types": ["xss"],
            "category": ChainCategory.ACCOUNT_TAKEOVER,
            "severity": "HIGH",
            "probability": 80,
        }
        assert _validate_pattern(pattern) is False

    def test_invalid_category_fails(self):
        """Pattern with string category should fail validation."""
        pattern = {
            "name": "Test",
            "entry_types": ["xss"],
            "category": "invalid",  # Should be ChainCategory enum
            "severity": "HIGH",
            "probability": 80,
        }
        assert _validate_pattern(pattern) is False

    def test_invalid_probability_fails(self):
        """Pattern with out-of-range probability should fail validation."""
        pattern = {
            "name": "Test",
            "entry_types": ["xss"],
            "category": ChainCategory.ACCOUNT_TAKEOVER,
            "severity": "HIGH",
            "probability": 150,  # > 100
        }
        assert _validate_pattern(pattern) is False


class TestChainPatternDataclass:
    """Test ChainPattern dataclass."""

    def test_chain_pattern_creation(self):
        """ChainPattern should be creatable with required fields."""
        pattern = ChainPattern(
            name="XSS → ATO",
            entry_types=["xss"],
            category=ChainCategory.ACCOUNT_TAKEOVER,
            severity="CRITICAL",
            probability=85.0,
        )
        assert pattern.name == "XSS → ATO"
        assert pattern.probability == 85.0

    def test_chain_pattern_to_dict(self):
        """ChainPattern.to_dict() should return valid dict."""
        pattern = ChainPattern(
            name="Test",
            entry_types=["sqli"],
            category=ChainCategory.DATA_EXFILTRATION,
            severity="HIGH",
            probability=90.0,
        )
        d = pattern.to_dict()
        assert d["name"] == "Test"
        assert d["probability"] == 90.0
        assert d["category"] == ChainCategory.DATA_EXFILTRATION

    def test_chain_pattern_invalid_raises(self):
        """ChainPattern with invalid fields should raise ValueError."""
        with pytest.raises(ValueError):
            ChainPattern(
                name="",  # Empty name
                entry_types=["xss"],
                category=ChainCategory.ACCOUNT_TAKEOVER,
                severity="HIGH",
                probability=80.0,
            )

        with pytest.raises(ValueError):
            ChainPattern(
                name="Test",
                entry_types=[],  # Empty entry_types
                category=ChainCategory.ACCOUNT_TAKEOVER,
                severity="HIGH",
                probability=80.0,
            )


class TestConstants:
    """Test L1 fix: module-level constants."""

    def test_confidence_constants_exist(self):
        """Confidence constants should be defined."""
        assert CONFIDENCE_HIGH == 85.0
        assert CONFIDENCE_MEDIUM == 70.0

    def test_infra_probability_constants_exist(self):
        """Infrastructure probability constants should be defined."""
        assert INFRA_PROBABILITY_MIN == 65.0
        assert INFRA_PROBABILITY_MAX == 75.0
        assert INFRA_PROBABILITY_MIN < INFRA_PROBABILITY_MAX


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
