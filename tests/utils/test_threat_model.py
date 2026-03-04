"""
Tests for utils/threat_model.py

Comprehensive tests for the Threat Modeling Engine.
Tests cover:
- BusinessImpactLevel enum
- ThreatCategory enum (STRIDE)
- ThreatScenario dataclass
- ThreatModel dataclass
- THREAT_MAPPINGS constants
- ThreatModelEngine class
- Convenience functions
"""

import pytest

from utils.threat_model import (
    # Enums
    BusinessImpactLevel,
    ThreatCategory,
    # Dataclasses
    ThreatScenario,
    ThreatModel,
    # Constants
    THREAT_MAPPINGS,
    # Classes
    ThreatModelEngine,
    # Functions
    generate_threat_report,
)


class TestBusinessImpactLevel:
    """Tests for BusinessImpactLevel enum."""

    def test_all_levels_present(self):
        """Test that all impact levels are defined."""
        levels = {l.name for l in BusinessImpactLevel}
        expected = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFORMATIONAL",
        }
        assert levels == expected

    def test_level_values(self):
        """Test impact level string values."""
        assert BusinessImpactLevel.CRITICAL.value == "critical"
        assert BusinessImpactLevel.HIGH.value == "high"
        assert BusinessImpactLevel.MEDIUM.value == "medium"
        assert BusinessImpactLevel.LOW.value == "low"
        assert BusinessImpactLevel.INFORMATIONAL.value == "info"


class TestThreatCategory:
    """Tests for ThreatCategory enum (STRIDE)."""

    def test_all_stride_categories_present(self):
        """Test that all STRIDE categories are defined."""
        categories = {c.name for c in ThreatCategory}
        expected = {
            "SPOOFING",
            "TAMPERING",
            "REPUDIATION",
            "INFORMATION_DISCLOSURE",
            "DENIAL_OF_SERVICE",
            "ELEVATION_OF_PRIVILEGE",
        }
        assert categories == expected

    def test_category_values(self):
        """Test STRIDE category string values."""
        assert ThreatCategory.SPOOFING.value == "spoofing"
        assert ThreatCategory.TAMPERING.value == "tampering"
        assert ThreatCategory.REPUDIATION.value == "repudiation"
        assert ThreatCategory.INFORMATION_DISCLOSURE.value == "info_disclosure"
        assert ThreatCategory.DENIAL_OF_SERVICE.value == "dos"
        assert ThreatCategory.ELEVATION_OF_PRIVILEGE.value == "elevation"


class TestThreatScenario:
    """Tests for ThreatScenario dataclass."""

    def test_creation(self):
        """Test ThreatScenario creation."""
        scenario = ThreatScenario(
            title="SQL Injection Attack",
            description="Attacker extracts database contents",
            attack_steps=["Find injection point", "Extract data"],
            threat_actor="Cybercriminal",
            likelihood="High",
            business_impact=BusinessImpactLevel.CRITICAL,
            affected_assets=["Database", "User credentials"],
            regulatory_implications=["GDPR", "PCI-DSS"],
            financial_impact="€1M-10M",
            remediation_priority=1,
        )

        assert scenario.title == "SQL Injection Attack"
        assert scenario.likelihood == "High"
        assert scenario.business_impact == BusinessImpactLevel.CRITICAL
        assert scenario.remediation_priority == 1

    def test_attack_steps_list(self):
        """Test attack steps as list."""
        scenario = ThreatScenario(
            title="XSS Attack",
            description="Session hijacking",
            attack_steps=[
                "Find reflected input",
                "Craft payload",
                "Send phishing link",
                "Steal session",
            ],
            threat_actor="Attacker",
            likelihood="Medium",
            business_impact=BusinessImpactLevel.HIGH,
            affected_assets=["User sessions"],
            regulatory_implications=["GDPR"],
            financial_impact="€100K",
            remediation_priority=2,
        )

        assert len(scenario.attack_steps) == 4
        assert "Steal session" in scenario.attack_steps


class TestThreatModel:
    """Tests for ThreatModel dataclass."""

    def test_creation(self):
        """Test ThreatModel creation."""
        scenario = ThreatScenario(
            title="Test Scenario",
            description="Test",
            attack_steps=["Step 1"],
            threat_actor="Attacker",
            likelihood="Medium",
            business_impact=BusinessImpactLevel.MEDIUM,
            affected_assets=["App"],
            regulatory_implications=[],
            financial_impact="Unknown",
            remediation_priority=3,
        )

        model = ThreatModel(
            finding_type="xss",
            finding_severity="HIGH",
            stride_categories=[
                ThreatCategory.INFORMATION_DISCLOSURE,
                ThreatCategory.ELEVATION_OF_PRIVILEGE,
            ],
            attack_scenarios=[scenario],
            business_summary="XSS allows session hijacking",
            executive_summary="Users at risk of account takeover",
            risk_score=7.5,
            recommendations=["Implement output encoding"],
        )

        assert model.finding_type == "xss"
        assert model.risk_score == 7.5
        assert len(model.stride_categories) == 2


class TestThreatMappings:
    """Tests for THREAT_MAPPINGS constant."""

    def test_mappings_exist(self):
        """Test that mappings dict exists and has entries."""
        assert isinstance(THREAT_MAPPINGS, dict)
        assert len(THREAT_MAPPINGS) > 0

    def test_required_vulnerability_types(self):
        """Test that key vulnerability types have mappings."""
        required = ["xss", "sqli", "ssl", "cors", "missing_header"]
        for vuln_type in required:
            assert vuln_type in THREAT_MAPPINGS, f"Missing mapping for {vuln_type}"

    def test_mapping_structure(self):
        """Test that mappings have required structure."""
        for vuln_type, mapping in THREAT_MAPPINGS.items():
            assert "stride" in mapping, f"{vuln_type} missing stride categories"
            assert "scenarios" in mapping, f"{vuln_type} missing scenarios"
            assert "business_summary" in mapping, f"{vuln_type} missing business_summary"
            assert "executive_summary" in mapping, f"{vuln_type} missing executive_summary"

    def test_scenarios_have_required_fields(self):
        """Test that scenarios have required fields."""
        required_fields = [
            "title",
            "threat_actor",
            "description",
            "attack_steps",
            "likelihood",
        ]
        for vuln_type, mapping in THREAT_MAPPINGS.items():
            for scenario in mapping["scenarios"]:
                for field in required_fields:
                    assert field in scenario, f"{vuln_type} scenario missing {field}"

    def test_sqli_mapping_is_critical(self):
        """Test SQLi mapping indicates critical risk."""
        sqli = THREAT_MAPPINGS["sqli"]
        assert ThreatCategory.INFORMATION_DISCLOSURE in sqli["stride"]
        assert ThreatCategory.ELEVATION_OF_PRIVILEGE in sqli["stride"]
        assert "database" in sqli["business_summary"].lower()

    def test_xss_mapping_includes_session_hijacking(self):
        """Test XSS mapping mentions session hijacking."""
        xss = THREAT_MAPPINGS["xss"]
        assert ThreatCategory.INFORMATION_DISCLOSURE in xss["stride"]
        # Check scenario mentions sessions
        scenario_text = str(xss["scenarios"])
        assert "session" in scenario_text.lower()


class TestThreatModelEngine:
    """Tests for ThreatModelEngine class."""

    def test_creation(self):
        """Test ThreatModelEngine creation."""
        engine = ThreatModelEngine()
        assert engine.VERSION == "1.0.0"
        assert engine.mappings == THREAT_MAPPINGS

    def test_analyze_finding_sqli(self):
        """Test analyzing SQLi finding."""
        engine = ThreatModelEngine()
        finding = {
            "type": "sqli",
            "severity": "CRITICAL",
            "name": "SQL Injection",
            "remediation": "Use parameterized queries",
        }

        model = engine.analyze_finding(finding)

        assert model.finding_type == "sqli"
        assert model.finding_severity == "CRITICAL"
        assert model.risk_score >= 9.0
        assert len(model.attack_scenarios) > 0
        assert len(model.recommendations) > 0

    def test_analyze_finding_xss(self):
        """Test analyzing XSS finding."""
        engine = ThreatModelEngine()
        finding = {
            "type": "xss",
            "severity": "HIGH",
            "name": "Cross-Site Scripting",
        }

        model = engine.analyze_finding(finding)

        assert model.finding_type == "xss"
        assert ThreatCategory.INFORMATION_DISCLOSURE in model.stride_categories

    def test_analyze_finding_unknown_type(self):
        """Test analyzing unknown finding type uses fallback."""
        engine = ThreatModelEngine()
        finding = {
            "type": "custom_vulnerability",
            "severity": "MEDIUM",
        }

        model = engine.analyze_finding(finding)

        assert model.finding_type == "custom_vulnerability"
        assert len(model.attack_scenarios) > 0
        assert model.risk_score > 0

    def test_severity_to_impact(self):
        """Test severity to business impact conversion."""
        engine = ThreatModelEngine()

        assert engine._severity_to_impact("CRITICAL") == BusinessImpactLevel.CRITICAL
        assert engine._severity_to_impact("HIGH") == BusinessImpactLevel.HIGH
        assert engine._severity_to_impact("MEDIUM") == BusinessImpactLevel.MEDIUM
        assert engine._severity_to_impact("LOW") == BusinessImpactLevel.LOW
        assert engine._severity_to_impact("INFO") == BusinessImpactLevel.INFORMATIONAL

    def test_severity_to_priority(self):
        """Test severity to remediation priority conversion."""
        engine = ThreatModelEngine()

        assert engine._severity_to_priority("CRITICAL") == 1
        assert engine._severity_to_priority("HIGH") == 2
        assert engine._severity_to_priority("MEDIUM") == 3
        assert engine._severity_to_priority("LOW") == 4
        assert engine._severity_to_priority("INFO") == 5

    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        engine = ThreatModelEngine()

        # Base score
        score = engine._calculate_risk_score("CRITICAL", [])
        assert score == 9.0

        score = engine._calculate_risk_score("HIGH", [])
        assert score == 7.0

        score = engine._calculate_risk_score("MEDIUM", [])
        assert score == 5.0

    def test_calculate_risk_score_with_likelihood(self):
        """Test risk score adjusted by likelihood."""
        engine = ThreatModelEngine()

        high_likelihood_scenario = ThreatScenario(
            title="Test",
            description="Test",
            attack_steps=[],
            threat_actor="Attacker",
            likelihood="High",
            business_impact=BusinessImpactLevel.HIGH,
            affected_assets=[],
            regulatory_implications=[],
            financial_impact="",
            remediation_priority=2,
        )

        score = engine._calculate_risk_score("HIGH", [high_likelihood_scenario])
        assert score == 7.5  # 7.0 + 0.5 for High likelihood

    def test_normalize_finding_type_xss(self):
        """Test XSS type normalization."""
        engine = ThreatModelEngine()

        assert engine._normalize_finding_type("xss") == "xss"
        assert engine._normalize_finding_type("dom_xss") == "xss"
        assert engine._normalize_finding_type("reflected_xss") == "xss"
        assert engine._normalize_finding_type("stored_xss") == "xss"

    def test_normalize_finding_type_sqli(self):
        """Test SQLi type normalization."""
        engine = ThreatModelEngine()

        assert engine._normalize_finding_type("sqli") == "sqli"
        assert engine._normalize_finding_type("sql_injection") == "sqli"
        assert engine._normalize_finding_type("blind_sql") == "sqli"

    def test_normalize_finding_type_ssl(self):
        """Test SSL/TLS type normalization."""
        engine = ThreatModelEngine()

        assert engine._normalize_finding_type("ssl") == "ssl"
        assert engine._normalize_finding_type("tls_weak") == "ssl"
        assert engine._normalize_finding_type("ssl_expired") == "ssl"

    def test_normalize_finding_type_preserves_specific(self):
        """Test that specific types are preserved."""
        engine = ThreatModelEngine()

        assert engine._normalize_finding_type("missing_browser_hardening") == "missing_browser_hardening"
        assert engine._normalize_finding_type("insecure_header") == "insecure_header"
        assert engine._normalize_finding_type("cors_wildcard") == "cors_wildcard"

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        engine = ThreatModelEngine()

        finding = {
            "type": "xss",
            "severity": "HIGH",
            "remediation": "Implement output encoding\nUse CSP headers\nValidate input",
        }

        recs = engine._generate_recommendations(finding)

        assert len(recs) <= 5  # Max 5 recommendations
        assert "Implement output encoding" in recs

    def test_generate_recommendations_fallback(self):
        """Test recommendation fallback when no remediation provided."""
        engine = ThreatModelEngine()

        finding = {"type": "unknown", "severity": "MEDIUM"}

        recs = engine._generate_recommendations(finding)

        assert len(recs) >= 1


class TestExecutiveReport:
    """Tests for executive report generation."""

    def test_generate_executive_report_empty(self):
        """Test executive report with no findings."""
        engine = ThreatModelEngine()
        report = engine.generate_executive_report([])

        assert "executive_summary" in report
        assert report["executive_summary"]["total_findings"] == 0
        assert report["executive_summary"]["overall_risk_level"] == "LOW"

    def test_generate_executive_report_critical(self):
        """Test executive report with critical findings."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "sqli", "severity": "CRITICAL"},
        ]

        report = engine.generate_executive_report(findings)

        assert report["executive_summary"]["overall_risk_level"] == "CRITICAL"
        assert report["executive_summary"]["critical_count"] >= 1

    def test_generate_executive_report_consolidates_types(self):
        """Test that report consolidates same finding types."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "xss", "severity": "HIGH", "name": "XSS on page 1"},
            {"type": "xss", "severity": "HIGH", "name": "XSS on page 2"},
            {"type": "xss", "severity": "MEDIUM", "name": "XSS on page 3"},
        ]

        report = engine.generate_executive_report(findings)

        # Should consolidate 3 XSS findings into 1 threat model
        assert report["executive_summary"]["total_findings"] == 3
        assert report["executive_summary"]["unique_finding_types"] == 1

    def test_generate_executive_report_multiple_types(self):
        """Test report with multiple finding types."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "sqli", "severity": "CRITICAL"},
            {"type": "xss", "severity": "HIGH"},
            {"type": "ssl", "severity": "MEDIUM"},
        ]

        report = engine.generate_executive_report(findings)

        assert report["executive_summary"]["unique_finding_types"] == 3
        assert len(report["top_risks"]) <= 5

    def test_executive_report_business_impact(self):
        """Test business impact section of report."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "sqli", "severity": "CRITICAL"},
        ]

        report = engine.generate_executive_report(findings)

        assert "business_impact" in report
        assert "regulatory_exposure" in report["business_impact"]
        assert "potential_breach_types" in report["business_impact"]
        assert "estimated_financial_exposure" in report["business_impact"]

    def test_executive_report_top_risks(self):
        """Test top risks section of report."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "sqli", "severity": "CRITICAL"},
            {"type": "xss", "severity": "HIGH"},
        ]

        report = engine.generate_executive_report(findings)

        assert "top_risks" in report
        assert len(report["top_risks"]) <= 5
        # Should be sorted by risk score descending
        if len(report["top_risks"]) > 1:
            assert report["top_risks"][0]["risk_score"] >= report["top_risks"][1]["risk_score"]

    def test_executive_report_recommended_actions(self):
        """Test recommended actions in report."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "xss", "severity": "HIGH", "remediation": "Use CSP"},
        ]

        report = engine.generate_executive_report(findings)

        assert "recommended_actions" in report
        assert len(report["recommended_actions"]) <= 10

    def test_executive_report_threat_models(self):
        """Test threat models section of report."""
        engine = ThreatModelEngine()
        findings = [
            {"type": "sqli", "severity": "CRITICAL"},
        ]

        report = engine.generate_executive_report(findings)

        assert "threat_models" in report
        assert len(report["threat_models"]) == 1
        tm = report["threat_models"][0]
        assert "finding_type" in tm
        assert "risk_score" in tm
        assert "scenarios" in tm


class TestBreachTypesAndFinancial:
    """Tests for breach type and financial exposure analysis."""

    def test_get_breach_types(self):
        """Test breach type extraction."""
        engine = ThreatModelEngine()

        model = engine.analyze_finding({"type": "sqli", "severity": "CRITICAL"})
        breach_types = engine._get_breach_types([model])

        assert "Data Breach" in breach_types

    def test_get_breach_types_account_takeover(self):
        """Test account takeover breach type."""
        engine = ThreatModelEngine()

        model = engine.analyze_finding({"type": "xss", "severity": "HIGH"})
        breach_types = engine._get_breach_types([model])

        assert "Account Takeover" in breach_types

    def test_estimate_financial_exposure_critical(self):
        """Test financial exposure for critical findings."""
        engine = ThreatModelEngine()

        model = engine.analyze_finding({"type": "sqli", "severity": "CRITICAL"})
        exposure = engine._estimate_financial_exposure([model])

        assert "€1M" in exposure or "50M" in exposure

    def test_estimate_financial_exposure_medium(self):
        """Test financial exposure for medium findings."""
        engine = ThreatModelEngine()

        model = engine.analyze_finding({"type": "missing_header", "severity": "MEDIUM"})
        exposure = engine._estimate_financial_exposure([model])

        assert "€" in exposure


class TestSerializeThreatModel:
    """Tests for threat model serialization."""

    def test_serialize_threat_model(self):
        """Test threat model serialization to dict."""
        engine = ThreatModelEngine()
        model = engine.analyze_finding({"type": "xss", "severity": "HIGH"})

        serialized = engine._serialize_threat_model(model)

        assert isinstance(serialized, dict)
        assert "finding_type" in serialized
        assert "finding_severity" in serialized
        assert "stride_categories" in serialized
        assert "risk_score" in serialized
        assert "scenarios" in serialized
        assert "recommendations" in serialized

    def test_serialize_stride_categories_as_strings(self):
        """Test STRIDE categories are serialized as strings."""
        engine = ThreatModelEngine()
        model = engine.analyze_finding({"type": "sqli", "severity": "CRITICAL"})

        serialized = engine._serialize_threat_model(model)

        # Should be string values, not enum objects
        for cat in serialized["stride_categories"]:
            assert isinstance(cat, str)

    def test_serialize_scenarios(self):
        """Test scenario serialization."""
        engine = ThreatModelEngine()
        model = engine.analyze_finding({"type": "xss", "severity": "HIGH"})

        serialized = engine._serialize_threat_model(model)

        assert len(serialized["scenarios"]) > 0
        scenario = serialized["scenarios"][0]
        assert "title" in scenario
        assert "description" in scenario
        assert "threat_actor" in scenario
        assert "attack_steps" in scenario
        assert "business_impact" in scenario


class TestConvenienceFunction:
    """Tests for convenience function."""

    def test_generate_threat_report(self):
        """Test generate_threat_report convenience function."""
        findings = [
            {"type": "sqli", "severity": "CRITICAL"},
            {"type": "xss", "severity": "HIGH"},
        ]

        report = generate_threat_report(findings)

        assert "executive_summary" in report
        assert "business_impact" in report
        assert "top_risks" in report

    def test_generate_threat_report_empty(self):
        """Test generate_threat_report with empty findings."""
        report = generate_threat_report([])

        assert report["executive_summary"]["total_findings"] == 0


class TestEdgeCases:
    """Tests for edge cases."""

    def test_severity_case_insensitive(self):
        """Test severity handling is case-insensitive."""
        engine = ThreatModelEngine()

        assert engine._severity_to_impact("critical") == BusinessImpactLevel.CRITICAL
        assert engine._severity_to_impact("CRITICAL") == BusinessImpactLevel.CRITICAL
        assert engine._severity_to_impact("Critical") == BusinessImpactLevel.CRITICAL

    def test_unknown_severity_defaults_to_medium(self):
        """Test unknown severity defaults to medium."""
        engine = ThreatModelEngine()

        impact = engine._severity_to_impact("UNKNOWN")
        assert impact == BusinessImpactLevel.MEDIUM

    def test_partial_finding_type_match(self):
        """Test partial matching of finding types."""
        engine = ThreatModelEngine()

        # "sql" should match "sqli" mapping
        mapping = engine._get_mapping("sql_error_based")
        assert ThreatCategory.INFORMATION_DISCLOSURE in mapping.get("stride", [])

    def test_risk_score_capped_at_10(self):
        """Test risk score doesn't exceed 10."""
        engine = ThreatModelEngine()

        # Create high-likelihood scenarios
        scenarios = [
            ThreatScenario(
                title="Test",
                description="Test",
                attack_steps=[],
                threat_actor="Attacker",
                likelihood="Critical",
                business_impact=BusinessImpactLevel.CRITICAL,
                affected_assets=[],
                regulatory_implications=[],
                financial_impact="",
                remediation_priority=1,
            )
            for _ in range(5)  # Multiple critical scenarios
        ]

        score = engine._calculate_risk_score("CRITICAL", scenarios)
        assert score <= 10.0

    def test_multiline_remediation_parsing(self):
        """Test parsing multiline remediation text."""
        engine = ThreatModelEngine()

        finding = {
            "type": "xss",
            "severity": "HIGH",
            "remediation": """Step 1: Encode output
Step 2: Implement CSP
# This is a comment
Step 3: Validate input""",
        }

        recs = engine._generate_recommendations(finding)

        assert "Step 1: Encode output" in recs
        assert "Step 2: Implement CSP" in recs
        # Comments should be filtered
        assert not any("comment" in r.lower() for r in recs)
