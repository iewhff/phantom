"""
Tests for phantom/bounty_estimator.py

Comprehensive tests for the bounty estimation engine covering:
- BountyPlatform, ProgramTier, SeverityLevel, VulnerabilityImpact enums
- ProgramConfig, BountyEstimate, ChainBountyEstimate dataclasses
- BountyEstimator class (estimation, chains, totals)
- Convenience functions
"""

import pytest
from datetime import datetime

from phantom.bounty_estimator import (
    # Enums
    BountyPlatform,
    ProgramTier,
    SeverityLevel,
    VulnerabilityImpact,
    # Dataclasses
    ProgramConfig,
    BountyEstimate,
    ChainBountyEstimate,
    # Main class
    BountyEstimator,
    # Constants
    PLATFORM_RANGES,
    DEFAULT_RANGES,
    VULNERABILITY_MODIFIERS,
    IMPACT_MODIFIERS,
    CHAIN_BONUSES,
    # Convenience functions
    estimate_bounty,
    create_program_config,
)


# =============================================================================
# ENUM TESTS
# =============================================================================


class TestBountyPlatformEnum:
    """Tests for BountyPlatform enum."""

    def test_all_platforms_defined(self):
        """All expected platforms are defined."""
        platforms = {p.value for p in BountyPlatform}
        expected = {"hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "cobalt", "private", "custom", "other"}
        assert platforms == expected

    def test_platform_from_value(self):
        """Can create platform from value string."""
        assert BountyPlatform("hackerone") == BountyPlatform.HACKERONE
        assert BountyPlatform("bugcrowd") == BountyPlatform.BUGCROWD

    def test_invalid_platform_raises(self):
        """Invalid platform value raises ValueError."""
        with pytest.raises(ValueError):
            BountyPlatform("invalid_platform")


class TestProgramTierEnum:
    """Tests for ProgramTier enum."""

    def test_all_tiers_defined(self):
        """All expected tiers are defined."""
        tiers = [t.name for t in ProgramTier]
        assert "ENTRY" in tiers
        assert "STANDARD" in tiers
        assert "PREMIUM" in tiers
        assert "ENTERPRISE" in tiers
        assert "TOP_TIER" in tiers

    def test_tier_from_name(self):
        """Can get tier from name."""
        assert ProgramTier["STANDARD"] == ProgramTier.STANDARD
        assert ProgramTier["TOP_TIER"] == ProgramTier.TOP_TIER


class TestSeverityLevelEnum:
    """Tests for SeverityLevel enum."""

    def test_all_severities_defined(self):
        """All expected severities are defined."""
        severities = {s.value for s in SeverityLevel}
        expected = {"critical", "high", "medium", "low", "informational"}
        assert severities == expected

    def test_severity_from_value(self):
        """Can create severity from value string."""
        assert SeverityLevel("critical") == SeverityLevel.CRITICAL
        assert SeverityLevel("medium") == SeverityLevel.MEDIUM


class TestVulnerabilityImpactEnum:
    """Tests for VulnerabilityImpact enum."""

    def test_all_impacts_defined(self):
        """All expected impacts are defined."""
        impacts = {i.value for i in VulnerabilityImpact}
        expected = {
            "rce", "account_takeover", "data_breach", "privilege_escalation",
            "authentication_bypass", "sensitive_data_exposure", "business_logic",
            "information_disclosure", "denial_of_service", "low_impact"
        }
        assert impacts == expected


# =============================================================================
# DATACLASS TESTS
# =============================================================================


class TestProgramConfig:
    """Tests for ProgramConfig dataclass."""

    def test_default_values(self):
        """ProgramConfig has correct defaults."""
        config = ProgramConfig(name="Test")
        assert config.name == "Test"
        assert config.platform == BountyPlatform.HACKERONE
        assert config.tier == ProgramTier.STANDARD
        assert config.custom_ranges is None
        assert config.bonus_multiplier == 1.0
        assert config.in_scope_bonus == 1.0
        assert config.vdp_only is False

    def test_get_range_standard(self):
        """get_range returns correct range for standard config."""
        config = ProgramConfig(
            name="Test",
            platform=BountyPlatform.HACKERONE,
            tier=ProgramTier.STANDARD,
        )
        range_result = config.get_range(SeverityLevel.CRITICAL)
        assert range_result == (3000, 10000)

    def test_get_range_vdp_returns_zero(self):
        """VDP programs return (0, 0) for all severities."""
        config = ProgramConfig(name="VDP Test", vdp_only=True)
        assert config.get_range(SeverityLevel.CRITICAL) == (0, 0)
        assert config.get_range(SeverityLevel.HIGH) == (0, 0)
        assert config.get_range(SeverityLevel.LOW) == (0, 0)

    def test_get_range_custom_ranges(self):
        """Custom ranges override platform defaults."""
        custom = {SeverityLevel.CRITICAL: (50000, 100000)}
        config = ProgramConfig(
            name="Custom Test",
            custom_ranges=custom,
        )
        assert config.get_range(SeverityLevel.CRITICAL) == (50000, 100000)
        # Non-custom severity falls back to default
        assert config.get_range(SeverityLevel.LOW) != (0, 0)

    def test_get_range_different_platforms(self):
        """Different platforms have different ranges."""
        h1_config = ProgramConfig(name="H1", platform=BountyPlatform.HACKERONE, tier=ProgramTier.STANDARD)
        bc_config = ProgramConfig(name="BC", platform=BountyPlatform.BUGCROWD, tier=ProgramTier.STANDARD)

        h1_range = h1_config.get_range(SeverityLevel.CRITICAL)
        bc_range = bc_config.get_range(SeverityLevel.CRITICAL)

        # Both should have valid ranges but may differ
        assert h1_range[0] > 0
        assert bc_range[0] > 0


class TestBountyEstimate:
    """Tests for BountyEstimate dataclass."""

    def test_creation(self):
        """Can create BountyEstimate with required fields."""
        estimate = BountyEstimate(
            vulnerability_id="vuln-001",
            vulnerability_type="sqli",
            severity=SeverityLevel.HIGH,
            estimated_range=(1000, 5000),
            expected_value=3400.0,
            confidence=0.75,
        )
        assert estimate.vulnerability_id == "vuln-001"
        assert estimate.vulnerability_type == "sqli"
        assert estimate.severity == SeverityLevel.HIGH
        assert estimate.estimated_range == (1000, 5000)
        assert estimate.expected_value == 3400.0
        assert estimate.confidence == 0.75

    def test_default_values(self):
        """BountyEstimate has correct defaults."""
        estimate = BountyEstimate(
            vulnerability_id="test",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            estimated_range=(100, 500),
            expected_value=340.0,
            confidence=0.7,
        )
        assert estimate.modifiers_applied == []
        assert estimate.notes == []
        assert estimate.is_chain is False
        assert estimate.chain_size == 1
        assert estimate.chain_bonus == 1.0
        assert estimate.program_name is None
        assert estimate.platform is None

    def test_formatted_range(self):
        """formatted_range property formats correctly."""
        estimate = BountyEstimate(
            vulnerability_id="test",
            vulnerability_type="rce",
            severity=SeverityLevel.CRITICAL,
            estimated_range=(10000, 50000),
            expected_value=34000.0,
            confidence=0.8,
        )
        assert estimate.formatted_range == "$10,000 - $50,000"

    def test_formatted_range_vdp(self):
        """formatted_range returns N/A for VDP."""
        estimate = BountyEstimate(
            vulnerability_id="test",
            vulnerability_type="info_disclosure",
            severity=SeverityLevel.LOW,
            estimated_range=(0, 0),
            expected_value=0,
            confidence=0.6,
        )
        assert estimate.formatted_range == "N/A (VDP)"

    def test_formatted_expected(self):
        """formatted_expected property formats correctly."""
        estimate = BountyEstimate(
            vulnerability_id="test",
            vulnerability_type="ssrf",
            severity=SeverityLevel.HIGH,
            estimated_range=(3000, 10000),
            expected_value=7200.0,
            confidence=0.75,
        )
        assert estimate.formatted_expected == "$7,200"

    def test_formatted_expected_zero(self):
        """formatted_expected returns N/A for zero value."""
        estimate = BountyEstimate(
            vulnerability_id="test",
            vulnerability_type="info",
            severity=SeverityLevel.INFORMATIONAL,
            estimated_range=(0, 0),
            expected_value=0,
            confidence=0.5,
        )
        assert estimate.formatted_expected == "N/A"

    def test_to_dict(self):
        """to_dict returns complete dictionary."""
        estimate = BountyEstimate(
            vulnerability_id="vuln-001",
            vulnerability_type="sqli",
            severity=SeverityLevel.HIGH,
            estimated_range=(1000, 5000),
            expected_value=3400.0,
            confidence=0.75,
            modifiers_applied=["vuln_type:1.0"],
            notes=["Test note"],
            is_chain=True,
            chain_size=2,
            chain_bonus=1.2,
            program_name="Test Program",
            platform="hackerone",
        )
        d = estimate.to_dict()

        assert d["vulnerability_id"] == "vuln-001"
        assert d["vulnerability_type"] == "sqli"
        assert d["severity"] == "high"
        assert d["estimated_range"]["min"] == 1000
        assert d["estimated_range"]["max"] == 5000
        assert d["expected_value"] == 3400.0
        assert d["confidence"] == 0.75
        assert d["modifiers_applied"] == ["vuln_type:1.0"]
        assert d["notes"] == ["Test note"]
        assert d["is_chain"] is True
        assert d["chain_size"] == 2
        assert d["chain_bonus"] == 1.2
        assert d["program_name"] == "Test Program"
        assert d["platform"] == "hackerone"
        assert "timestamp" in d


class TestChainBountyEstimate:
    """Tests for ChainBountyEstimate dataclass."""

    def test_creation(self):
        """Can create ChainBountyEstimate."""
        individual = BountyEstimate(
            vulnerability_id="v1",
            vulnerability_type="xss",
            severity=SeverityLevel.MEDIUM,
            estimated_range=(500, 1500),
            expected_value=1100.0,
            confidence=0.7,
        )
        chain = ChainBountyEstimate(
            chain_id="chain-001",
            chain_size=2,
            individual_estimates=[individual],
            total_range=(600, 1800),
            total_expected=1320.0,
            chain_bonus_applied=1.2,
            severity=SeverityLevel.HIGH,
        )

        assert chain.chain_id == "chain-001"
        assert chain.chain_size == 2
        assert len(chain.individual_estimates) == 1
        assert chain.total_range == (600, 1800)
        assert chain.total_expected == 1320.0
        assert chain.chain_bonus_applied == 1.2
        assert chain.severity == SeverityLevel.HIGH

    def test_formatted_total(self):
        """formatted_total property formats correctly."""
        chain = ChainBountyEstimate(
            chain_id="chain-002",
            chain_size=3,
            individual_estimates=[],
            total_range=(15000, 45000),
            total_expected=34000.0,
            chain_bonus_applied=1.4,
            severity=SeverityLevel.CRITICAL,
        )
        assert chain.formatted_total == "$15,000 - $45,000"

    def test_to_dict(self):
        """to_dict returns complete dictionary."""
        individual = BountyEstimate(
            vulnerability_id="v1",
            vulnerability_type="ssrf",
            severity=SeverityLevel.HIGH,
            estimated_range=(3000, 10000),
            expected_value=7200.0,
            confidence=0.75,
        )
        chain = ChainBountyEstimate(
            chain_id="chain-003",
            chain_size=2,
            individual_estimates=[individual],
            total_range=(3600, 12000),
            total_expected=8640.0,
            chain_bonus_applied=1.2,
            severity=SeverityLevel.HIGH,
            notes=["SSRF to internal access"],
        )
        d = chain.to_dict()

        assert d["chain_id"] == "chain-003"
        assert d["chain_size"] == 2
        assert len(d["individual_estimates"]) == 1
        assert d["total_range"]["min"] == 3600
        assert d["total_range"]["max"] == 12000
        assert d["total_expected"] == 8640.0
        assert d["chain_bonus_applied"] == 1.2
        assert d["severity"] == "high"
        assert "SSRF to internal access" in d["notes"]


# =============================================================================
# CONSTANTS TESTS
# =============================================================================


class TestConstants:
    """Tests for bounty estimation constants."""

    def test_platform_ranges_has_major_platforms(self):
        """PLATFORM_RANGES has all major platforms."""
        assert BountyPlatform.HACKERONE in PLATFORM_RANGES
        assert BountyPlatform.BUGCROWD in PLATFORM_RANGES
        assert BountyPlatform.INTIGRITI in PLATFORM_RANGES

    def test_platform_ranges_has_all_tiers(self):
        """Each platform has all tiers."""
        for platform, tiers in PLATFORM_RANGES.items():
            for tier in ProgramTier:
                assert tier in tiers, f"{platform} missing {tier}"

    def test_platform_ranges_has_all_severities(self):
        """Each tier has all severities."""
        for platform, tiers in PLATFORM_RANGES.items():
            for tier, severities in tiers.items():
                for severity in SeverityLevel:
                    assert severity in severities, f"{platform}.{tier} missing {severity}"

    def test_default_ranges_complete(self):
        """DEFAULT_RANGES has all tiers and severities."""
        for tier in ProgramTier:
            assert tier in DEFAULT_RANGES
            for severity in SeverityLevel:
                assert severity in DEFAULT_RANGES[tier]

    def test_vulnerability_modifiers_common_vulns(self):
        """VULNERABILITY_MODIFIERS has common vulnerability types."""
        common_vulns = ["sqli", "xss", "rce", "ssrf", "idor", "csrf", "cmdi"]
        for vuln in common_vulns:
            assert vuln in VULNERABILITY_MODIFIERS

    def test_vulnerability_modifiers_reasonable_range(self):
        """All modifiers are in reasonable range (0.3 to 1.5)."""
        for vuln_type, modifier in VULNERABILITY_MODIFIERS.items():
            assert 0.3 <= modifier <= 1.5, f"{vuln_type} modifier {modifier} out of range"

    def test_impact_modifiers_all_impacts(self):
        """IMPACT_MODIFIERS has all impact types."""
        for impact in VulnerabilityImpact:
            assert impact in IMPACT_MODIFIERS

    def test_chain_bonuses_incremental(self):
        """CHAIN_BONUSES increase with chain size."""
        sizes = sorted(CHAIN_BONUSES.keys())
        prev_bonus = 0
        for size in sizes:
            assert CHAIN_BONUSES[size] > prev_bonus
            prev_bonus = CHAIN_BONUSES[size]


# =============================================================================
# BOUNTYESTIMATOR CLASS TESTS
# =============================================================================


class TestBountyEstimator:
    """Tests for BountyEstimator class."""

    def test_initialization_default(self):
        """Initializes with default program config."""
        estimator = BountyEstimator()
        assert estimator.program is not None
        assert estimator.program.name == "Default Program"
        assert estimator.program.platform == BountyPlatform.HACKERONE
        assert estimator.program.tier == ProgramTier.STANDARD

    def test_initialization_with_program(self):
        """Initializes with custom program config."""
        program = ProgramConfig(
            name="Custom Program",
            platform=BountyPlatform.BUGCROWD,
            tier=ProgramTier.PREMIUM,
        )
        estimator = BountyEstimator(program=program)
        assert estimator.program.name == "Custom Program"
        assert estimator.program.platform == BountyPlatform.BUGCROWD
        assert estimator.program.tier == ProgramTier.PREMIUM

    def test_set_program(self):
        """Can change program after initialization."""
        estimator = BountyEstimator()
        new_program = ProgramConfig(
            name="New Program",
            platform=BountyPlatform.INTIGRITI,
            tier=ProgramTier.ENTERPRISE,
        )
        estimator.set_program(new_program)
        assert estimator.program.name == "New Program"

    def test_estimate_basic(self):
        """Basic estimate returns valid BountyEstimate."""
        estimator = BountyEstimator()
        estimate = estimator.estimate(
            vulnerability_id="test-001",
            vulnerability_type="sqli",
            severity="high",
        )

        assert isinstance(estimate, BountyEstimate)
        assert estimate.vulnerability_id == "test-001"
        assert estimate.vulnerability_type == "sqli"
        assert estimate.severity == SeverityLevel.HIGH
        assert estimate.estimated_range[0] < estimate.estimated_range[1]
        assert estimate.expected_value > 0
        assert 0 < estimate.confidence <= 1

    def test_estimate_with_cvss(self):
        """CVSS score affects estimation when severity is invalid."""
        estimator = BountyEstimator()
        estimate = estimator.estimate(
            vulnerability_id="test-002",
            vulnerability_type="unknown",
            severity="invalid_severity",  # Invalid severity triggers CVSS fallback
            cvss_score=9.5,
        )

        # High CVSS should result in critical severity when original is invalid
        assert estimate.severity == SeverityLevel.CRITICAL

    def test_estimate_with_impact(self):
        """Impact modifier affects range."""
        estimator = BountyEstimator()

        # RCE impact has highest modifier
        rce_estimate = estimator.estimate(
            vulnerability_id="test-rce",
            vulnerability_type="rce",
            severity="critical",
            impact=VulnerabilityImpact.RCE,
        )

        # Low impact
        low_estimate = estimator.estimate(
            vulnerability_id="test-low",
            vulnerability_type="info_disclosure",
            severity="critical",
            impact=VulnerabilityImpact.LOW_IMPACT,
        )

        assert rce_estimate.expected_value > low_estimate.expected_value

    def test_estimate_chain_bonus(self):
        """Chain bonus increases estimate."""
        estimator = BountyEstimator()

        single = estimator.estimate(
            vulnerability_id="single",
            vulnerability_type="sqli",
            severity="high",
            is_chain=False,
        )

        chain = estimator.estimate(
            vulnerability_id="chain",
            vulnerability_type="sqli",
            severity="high",
            is_chain=True,
            chain_size=3,
        )

        assert chain.expected_value > single.expected_value
        assert chain.chain_bonus > 1.0

    def test_estimate_stores_result(self):
        """Estimates are stored internally."""
        estimator = BountyEstimator()

        estimator.estimate(
            vulnerability_id="stored-1",
            vulnerability_type="xss",
            severity="medium",
        )
        estimator.estimate(
            vulnerability_id="stored-2",
            vulnerability_type="csrf",
            severity="low",
        )

        assert len(estimator._estimates) == 2

    def test_estimate_quality_bonus(self):
        """Quality bonus modifier affects estimate."""
        estimator = BountyEstimator()

        normal = estimator.estimate(
            vulnerability_id="normal",
            vulnerability_type="sqli",
            severity="high",
            quality_bonus=1.0,
        )

        high_quality = estimator.estimate(
            vulnerability_id="quality",
            vulnerability_type="sqli",
            severity="high",
            quality_bonus=1.3,
        )

        assert high_quality.expected_value > normal.expected_value

    def test_estimate_chain_chain_data(self):
        """estimate_chain processes chain data correctly."""
        estimator = BountyEstimator()

        chain_data = {
            "chain_id": "chain-test-001",
            "vulnerabilities": [
                {"id": "v1", "type": "xss", "severity": "medium"},
                {"id": "v2", "type": "session_hijacking", "severity": "high"},
            ],
            "outcome": "Account takeover",
        }

        result = estimator.estimate_chain(chain_data)

        assert isinstance(result, ChainBountyEstimate)
        assert result.chain_id == "chain-test-001"
        assert result.chain_size == 2
        assert len(result.individual_estimates) == 2
        assert result.chain_bonus_applied > 1.0
        assert result.total_expected > 0
        assert "Account takeover" in " ".join(result.notes)

    def test_estimate_chain_empty(self):
        """estimate_chain handles empty vulnerabilities."""
        estimator = BountyEstimator()

        chain_data = {
            "chain_id": "empty-chain",
            "vulnerabilities": [],
        }

        result = estimator.estimate_chain(chain_data)
        assert result.total_expected == 0
        assert result.total_range == (0, 0)

    def test_estimate_findings(self):
        """estimate_findings processes multiple findings."""
        estimator = BountyEstimator()

        findings = [
            {"id": "f1", "type": "sqli", "severity": "high"},
            {"id": "f2", "type": "xss", "severity": "medium"},
            {"id": "f3", "type": "info_disclosure", "severity": "low"},
        ]

        results = estimator.estimate_findings(findings)

        assert len(results) == 3
        assert all(isinstance(r, BountyEstimate) for r in results)

    def test_get_total_estimate_empty(self):
        """get_total_estimate returns zeros when no estimates."""
        estimator = BountyEstimator()
        total = estimator.get_total_estimate()

        assert total["total_min"] == 0
        assert total["total_max"] == 0
        assert total["total_expected"] == 0
        assert total["finding_count"] == 0

    def test_get_total_estimate_with_data(self):
        """get_total_estimate aggregates correctly."""
        estimator = BountyEstimator()

        estimator.estimate(
            vulnerability_id="t1",
            vulnerability_type="sqli",
            severity="high",
        )
        estimator.estimate(
            vulnerability_id="t2",
            vulnerability_type="xss",
            severity="medium",
        )

        total = estimator.get_total_estimate()

        assert total["finding_count"] == 2
        assert total["total_min"] > 0
        assert total["total_max"] > total["total_min"]
        assert total["total_expected"] > 0
        assert "formatted_range" in total
        assert "severity_distribution" in total
        assert "program" in total
        assert "platform" in total
        assert "tier" in total

    def test_clear_estimates(self):
        """clear_estimates removes all stored estimates."""
        estimator = BountyEstimator()

        estimator.estimate(
            vulnerability_id="clear-test",
            vulnerability_type="xss",
            severity="medium",
        )
        assert len(estimator._estimates) == 1

        estimator.clear_estimates()
        assert len(estimator._estimates) == 0

    def test_cvss_to_severity_mapping(self):
        """CVSS scores map to correct severities."""
        estimator = BountyEstimator()

        assert estimator._cvss_to_severity(9.5) == SeverityLevel.CRITICAL
        assert estimator._cvss_to_severity(8.0) == SeverityLevel.HIGH
        assert estimator._cvss_to_severity(5.5) == SeverityLevel.MEDIUM
        assert estimator._cvss_to_severity(2.0) == SeverityLevel.LOW
        assert estimator._cvss_to_severity(0.0) == SeverityLevel.INFORMATIONAL

    def test_severity_rank(self):
        """_severity_rank returns correct ordering."""
        estimator = BountyEstimator()

        assert estimator._severity_rank(SeverityLevel.CRITICAL) > estimator._severity_rank(SeverityLevel.HIGH)
        assert estimator._severity_rank(SeverityLevel.HIGH) > estimator._severity_rank(SeverityLevel.MEDIUM)
        assert estimator._severity_rank(SeverityLevel.MEDIUM) > estimator._severity_rank(SeverityLevel.LOW)
        assert estimator._severity_rank(SeverityLevel.LOW) > estimator._severity_rank(SeverityLevel.INFORMATIONAL)

    def test_vdp_program_zero_bounty(self):
        """VDP program returns zero bounty estimates."""
        vdp_program = ProgramConfig(name="VDP Test", vdp_only=True)
        estimator = BountyEstimator(program=vdp_program)

        estimate = estimator.estimate(
            vulnerability_id="vdp-test",
            vulnerability_type="rce",
            severity="critical",
        )

        assert estimate.estimated_range == (0, 0)
        assert estimate.expected_value == 0
        assert "VDP" in " ".join(estimate.notes)


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_estimate_bounty_basic(self):
        """estimate_bounty returns valid estimate."""
        estimate = estimate_bounty(
            vulnerability_type="sqli",
            severity="high",
        )

        assert isinstance(estimate, BountyEstimate)
        assert estimate.severity == SeverityLevel.HIGH
        assert estimate.expected_value > 0

    def test_estimate_bounty_with_platform(self):
        """estimate_bounty accepts platform parameter."""
        h1_estimate = estimate_bounty(
            vulnerability_type="xss",
            severity="medium",
            platform="hackerone",
            tier="standard",
        )

        bc_estimate = estimate_bounty(
            vulnerability_type="xss",
            severity="medium",
            platform="bugcrowd",
            tier="standard",
        )

        # Both should work
        assert h1_estimate.expected_value > 0
        assert bc_estimate.expected_value > 0

    def test_estimate_bounty_with_cvss(self):
        """estimate_bounty accepts CVSS score as fallback for invalid severity."""
        estimate = estimate_bounty(
            vulnerability_type="unknown",
            severity="invalid_severity",  # Invalid severity triggers CVSS fallback
            cvss_score=9.8,
        )

        # Should use CVSS to determine critical severity
        assert estimate.severity == SeverityLevel.CRITICAL

    def test_create_program_config_basic(self):
        """create_program_config creates valid config."""
        config = create_program_config(
            name="Test Program",
            platform="bugcrowd",
            tier="premium",
        )

        assert config.name == "Test Program"
        assert config.platform == BountyPlatform.BUGCROWD
        assert config.tier == ProgramTier.PREMIUM

    def test_create_program_config_vdp(self):
        """create_program_config handles VDP."""
        config = create_program_config(
            name="VDP Program",
            vdp_only=True,
        )

        assert config.vdp_only is True

    def test_create_program_config_custom_ranges(self):
        """create_program_config handles custom ranges."""
        config = create_program_config(
            name="Custom Program",
            custom_ranges={
                "critical": (50000, 150000),
                "high": (20000, 50000),
            },
        )

        assert config.custom_ranges is not None
        assert SeverityLevel.CRITICAL in config.custom_ranges
        assert config.custom_ranges[SeverityLevel.CRITICAL] == (50000, 150000)


# =============================================================================
# EDGE CASES AND INTEGRATION TESTS
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_unknown_vulnerability_type(self):
        """Unknown vulnerability type uses default modifier."""
        estimator = BountyEstimator()
        estimate = estimator.estimate(
            vulnerability_id="unknown-test",
            vulnerability_type="completely_unknown_vuln_type",
            severity="high",
        )

        # Should still produce valid estimate
        assert estimate.expected_value > 0

    def test_invalid_severity_with_cvss_fallback(self):
        """Invalid severity falls back to CVSS."""
        estimator = BountyEstimator()
        estimate = estimator.estimate(
            vulnerability_id="fallback-test",
            vulnerability_type="xss",
            severity="invalid_severity",
            cvss_score=8.5,
        )

        assert estimate.severity == SeverityLevel.HIGH

    def test_large_chain_capped_bonus(self):
        """Chain bonus is capped for very large chains."""
        estimator = BountyEstimator()

        chain_5 = estimator.estimate(
            vulnerability_id="chain-5",
            vulnerability_type="xss",
            severity="high",
            is_chain=True,
            chain_size=5,
        )

        chain_10 = estimator.estimate(
            vulnerability_id="chain-10",
            vulnerability_type="xss",
            severity="high",
            is_chain=True,
            chain_size=10,
        )

        # Both should have same chain bonus (capped at 5)
        assert chain_5.chain_bonus == chain_10.chain_bonus

    def test_confidence_calculation(self):
        """Confidence varies based on available data."""
        estimator = BountyEstimator()

        # Minimal data
        minimal = estimator.estimate(
            vulnerability_id="minimal",
            vulnerability_type="unknown",
            severity="medium",
        )

        # Full data
        full = estimator.estimate(
            vulnerability_id="full",
            vulnerability_type="sqli",
            severity="high",
            cvss_score=8.5,
            impact=VulnerabilityImpact.DATA_BREACH,
        )

        assert full.confidence > minimal.confidence

    def test_top_tier_ranges_highest(self):
        """TOP_TIER programs have highest bounty ranges."""
        entry_config = ProgramConfig(name="Entry", tier=ProgramTier.ENTRY)
        top_config = ProgramConfig(name="Top", tier=ProgramTier.TOP_TIER)

        entry_range = entry_config.get_range(SeverityLevel.CRITICAL)
        top_range = top_config.get_range(SeverityLevel.CRITICAL)

        assert top_range[0] > entry_range[0]
        assert top_range[1] > entry_range[1]

    def test_rce_highest_modifier(self):
        """RCE has highest vulnerability modifier."""
        rce_modifier = VULNERABILITY_MODIFIERS["rce"]
        for vuln_type, modifier in VULNERABILITY_MODIFIERS.items():
            if vuln_type != "rce":
                assert rce_modifier >= modifier
