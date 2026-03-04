"""
Tests for phantom/compliance_mapper.py

Comprehensive tests for the compliance mapping engine covering:
- ComplianceFramework, OWASPCategory, PCIDSSRequirement, NISTControlFamily enums
- CWEMapping, ComplianceMapping, ComplianceReport dataclasses
- ComplianceMapper class
- Convenience functions
- Mapping data constants
"""

import pytest
from datetime import datetime

from phantom.compliance_mapper import (
    # Enums
    ComplianceFramework,
    OWASPCategory,
    PCIDSSRequirement,
    NISTControlFamily,
    # Dataclasses
    CWEMapping,
    ComplianceMapping,
    ComplianceReport,
    # Main class
    ComplianceMapper,
    # Constants
    VULNERABILITY_TO_CWE,
    CWE_TO_OWASP,
    OWASP_TO_PCI_DSS,
    OWASP_TO_NIST,
    OWASP_TO_ISO27001,
    SECURITY_GDPR_ARTICLES,
    HIPAA_SAFEGUARDS,
    SOC2_CRITERIA,
    CWE_DATABASE,
    # Convenience functions
    map_to_compliance,
    get_cwe_mapping,
    get_owasp_category,
)


# =============================================================================
# ENUM TESTS
# =============================================================================


class TestComplianceFrameworkEnum:
    """Tests for ComplianceFramework enum."""

    def test_all_frameworks_defined(self):
        """All expected frameworks are defined."""
        frameworks = {f.value for f in ComplianceFramework}
        expected = {
            "cwe", "owasp_top_10", "owasp_asvs", "pci_dss", "nist_800_53",
            "nist_csf", "gdpr", "iso_27001", "hipaa", "soc_2", "sans_top_25",
            "mitre_attack"
        }
        assert frameworks == expected

    def test_framework_from_value(self):
        """Can create framework from value string."""
        assert ComplianceFramework("cwe") == ComplianceFramework.CWE
        assert ComplianceFramework("owasp_top_10") == ComplianceFramework.OWASP_TOP_10
        assert ComplianceFramework("pci_dss") == ComplianceFramework.PCI_DSS


class TestOWASPCategoryEnum:
    """Tests for OWASPCategory enum."""

    def test_all_owasp_categories_defined(self):
        """All 10 OWASP Top 10 2021 categories are defined."""
        categories = list(OWASPCategory)
        assert len(categories) == 10

    def test_owasp_category_values(self):
        """OWASP categories have correct 2021 values."""
        assert OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value == "A01:2021"
        assert OWASPCategory.A03_INJECTION.value == "A03:2021"
        assert OWASPCategory.A10_SSRF.value == "A10:2021"

    def test_all_2021_categories_present(self):
        """All A01-A10 2021 categories are present."""
        values = {cat.value for cat in OWASPCategory}
        for i in range(1, 11):
            expected = f"A{i:02d}:2021"
            assert expected in values, f"Missing {expected}"


class TestPCIDSSRequirementEnum:
    """Tests for PCIDSSRequirement enum."""

    def test_all_12_requirements_defined(self):
        """All 12 PCI DSS requirements are defined."""
        requirements = list(PCIDSSRequirement)
        assert len(requirements) == 12

    def test_requirement_values(self):
        """Requirements have correct values."""
        assert PCIDSSRequirement.REQ_1.value == "1"
        assert PCIDSSRequirement.REQ_6.value == "6"
        assert PCIDSSRequirement.REQ_12.value == "12"


class TestNISTControlFamilyEnum:
    """Tests for NISTControlFamily enum."""

    def test_common_families_defined(self):
        """Common NIST control families are defined."""
        families = {f.value for f in NISTControlFamily}
        common = {"AC", "AU", "SC", "SI", "IA", "CM"}
        assert common.issubset(families)

    def test_family_from_value(self):
        """Can get family from value."""
        assert NISTControlFamily("AC") == NISTControlFamily.AC
        assert NISTControlFamily("SI") == NISTControlFamily.SI


# =============================================================================
# DATACLASS TESTS
# =============================================================================


class TestCWEMapping:
    """Tests for CWEMapping dataclass."""

    def test_creation(self):
        """Can create CWEMapping with all fields."""
        mapping = CWEMapping(
            cwe_id=89,
            name="SQL Injection",
            description="SQL injection vulnerability",
            url="https://cwe.mitre.org/data/definitions/89.html",
            abstraction="Base",
            related_cwes=[564, 20],
        )

        assert mapping.cwe_id == 89
        assert mapping.name == "SQL Injection"
        assert mapping.abstraction == "Base"
        assert 564 in mapping.related_cwes

    def test_default_related_cwes(self):
        """related_cwes defaults to empty list."""
        mapping = CWEMapping(
            cwe_id=79,
            name="XSS",
            description="Cross-site Scripting",
            url="https://cwe.mitre.org/data/definitions/79.html",
            abstraction="Base",
        )
        assert mapping.related_cwes == []

    def test_to_dict(self):
        """to_dict returns complete dictionary."""
        mapping = CWEMapping(
            cwe_id=78,
            name="Command Injection",
            description="OS command injection",
            url="https://cwe.mitre.org/data/definitions/78.html",
            abstraction="Base",
            related_cwes=[77],
        )
        d = mapping.to_dict()

        assert d["cwe_id"] == 78
        assert d["name"] == "Command Injection"
        assert d["url"] == "https://cwe.mitre.org/data/definitions/78.html"
        assert d["abstraction"] == "Base"
        assert 77 in d["related_cwes"]


class TestComplianceMapping:
    """Tests for ComplianceMapping dataclass."""

    def test_creation_minimal(self):
        """Can create with minimal fields."""
        mapping = ComplianceMapping(
            vulnerability_id="vuln-001",
            vulnerability_type="sqli",
        )
        assert mapping.vulnerability_id == "vuln-001"
        assert mapping.vulnerability_type == "sqli"

    def test_default_values(self):
        """All list fields default to empty."""
        mapping = ComplianceMapping(
            vulnerability_id="test",
            vulnerability_type="xss",
        )
        assert mapping.cwe_ids == []
        assert mapping.owasp_categories == []
        assert mapping.pci_dss_requirements == []
        assert mapping.nist_controls == []
        assert mapping.iso27001_controls == []
        assert mapping.gdpr_articles == []
        assert mapping.hipaa_safeguards == []
        assert mapping.soc2_criteria == []
        assert mapping.mitre_techniques == []
        assert mapping.remediation_guidance == ""

    def test_full_mapping(self):
        """Can create with all fields populated."""
        mapping = ComplianceMapping(
            vulnerability_id="vuln-full",
            vulnerability_type="sqli",
            cwe_ids=[89, 564],
            owasp_categories=["A03:2021"],
            pci_dss_requirements=["6.2.4"],
            nist_controls=["SI-10"],
            iso27001_controls=["A.14.2"],
            gdpr_articles=["Art. 32"],
            hipaa_safeguards=["164.312(a)(1)"],
            soc2_criteria=["CC6"],
            remediation_guidance="Use parameterized queries",
        )

        assert 89 in mapping.cwe_ids
        assert "A03:2021" in mapping.owasp_categories
        assert "6.2.4" in mapping.pci_dss_requirements

    def test_to_dict(self):
        """to_dict returns structured dictionary."""
        mapping = ComplianceMapping(
            vulnerability_id="dict-test",
            vulnerability_type="xss",
            cwe_ids=[79],
            owasp_categories=["A03:2021"],
            pci_dss_requirements=["6.2.4"],
            nist_controls=["SI-10"],
            remediation_guidance="Encode output",
        )
        d = mapping.to_dict()

        assert d["vulnerability_id"] == "dict-test"
        assert d["vulnerability_type"] == "xss"
        assert "CWE-79" in d["mappings"]["cwe"]
        assert "A03:2021" in d["mappings"]["owasp_top_10"]
        assert d["remediation_guidance"] == "Encode output"
        assert "timestamp" in d

    def test_get_all_frameworks(self):
        """get_all_frameworks returns populated frameworks only."""
        mapping = ComplianceMapping(
            vulnerability_id="framework-test",
            vulnerability_type="ssrf",
            cwe_ids=[918],
            owasp_categories=["A10:2021"],
            # Leave PCI DSS empty
        )
        frameworks = mapping.get_all_frameworks()

        assert "CWE" in frameworks
        assert "OWASP Top 10" in frameworks
        assert "PCI DSS 4.0" not in frameworks  # Empty, not included

    def test_get_all_frameworks_complete(self):
        """get_all_frameworks includes all when populated."""
        mapping = ComplianceMapping(
            vulnerability_id="complete-test",
            vulnerability_type="auth_bypass",
            cwe_ids=[287],
            owasp_categories=["A07:2021"],
            pci_dss_requirements=["8.2"],
            nist_controls=["IA-2"],
            iso27001_controls=["A.9.2"],
            gdpr_articles=["Art. 32"],
            hipaa_safeguards=["164.312(d)"],
            soc2_criteria=["CC6"],
        )
        frameworks = mapping.get_all_frameworks()

        expected_keys = [
            "CWE", "OWASP Top 10", "PCI DSS 4.0", "NIST 800-53",
            "ISO 27001", "GDPR", "HIPAA", "SOC 2"
        ]
        for key in expected_keys:
            assert key in frameworks


class TestComplianceReport:
    """Tests for ComplianceReport dataclass."""

    def test_creation(self):
        """Can create compliance report."""
        report = ComplianceReport(
            scan_id="scan-001",
            target="https://example.com",
        )
        assert report.scan_id == "scan-001"
        assert report.target == "https://example.com"
        assert report.mappings == []
        assert report.total_findings == 0

    def test_with_mappings(self):
        """Report can contain mappings."""
        mapping = ComplianceMapping(
            vulnerability_id="m1",
            vulnerability_type="sqli",
            cwe_ids=[89],
        )
        report = ComplianceReport(
            scan_id="scan-002",
            target="https://test.com",
            mappings=[mapping],
            total_findings=1,
            owasp_coverage={"A03:2021": 1},
        )

        assert len(report.mappings) == 1
        assert report.total_findings == 1
        assert report.owasp_coverage["A03:2021"] == 1

    def test_to_dict(self):
        """to_dict returns complete report dictionary."""
        mapping = ComplianceMapping(
            vulnerability_id="report-m1",
            vulnerability_type="xss",
            cwe_ids=[79],
        )
        report = ComplianceReport(
            scan_id="report-scan",
            target="https://target.com",
            mappings=[mapping],
            total_findings=1,
            frameworks_covered=["CWE"],
        )
        d = report.to_dict()

        assert d["scan_id"] == "report-scan"
        assert d["target"] == "https://target.com"
        assert d["summary"]["total_findings"] == 1
        assert "CWE" in d["summary"]["frameworks_covered"]
        assert len(d["findings"]) == 1


# =============================================================================
# CONSTANTS TESTS
# =============================================================================


class TestMappingConstants:
    """Tests for mapping data constants."""

    def test_vulnerability_to_cwe_common_vulns(self):
        """Common vulnerabilities have CWE mappings."""
        common = ["sqli", "xss", "cmdi", "ssrf", "idor", "csrf", "rce", "xxe"]
        for vuln in common:
            assert vuln in VULNERABILITY_TO_CWE, f"Missing {vuln}"
            assert len(VULNERABILITY_TO_CWE[vuln]) > 0

    def test_sqli_maps_to_cwe_89(self):
        """SQLi maps to CWE-89."""
        assert 89 in VULNERABILITY_TO_CWE["sqli"]

    def test_xss_maps_to_cwe_79(self):
        """XSS variants map to CWE-79."""
        assert 79 in VULNERABILITY_TO_CWE["xss"]
        assert 79 in VULNERABILITY_TO_CWE["stored_xss"]
        assert 79 in VULNERABILITY_TO_CWE["dom_xss"]

    def test_ssrf_maps_to_cwe_918(self):
        """SSRF maps to CWE-918."""
        assert 918 in VULNERABILITY_TO_CWE["ssrf"]

    def test_cwe_to_owasp_injection_cwes(self):
        """Injection CWEs map to A03."""
        injection_cwes = [77, 78, 79, 89, 90, 91]
        for cwe in injection_cwes:
            if cwe in CWE_TO_OWASP:
                assert CWE_TO_OWASP[cwe] == OWASPCategory.A03_INJECTION

    def test_cwe_to_owasp_auth_cwes(self):
        """Authentication CWEs map to A07."""
        auth_cwes = [287, 306, 307, 384]
        for cwe in auth_cwes:
            if cwe in CWE_TO_OWASP:
                assert CWE_TO_OWASP[cwe] == OWASPCategory.A07_AUTH_FAILURES

    def test_cwe_918_maps_to_ssrf(self):
        """CWE-918 maps to A10 SSRF."""
        assert CWE_TO_OWASP[918] == OWASPCategory.A10_SSRF

    def test_owasp_to_pci_dss_all_categories(self):
        """All OWASP categories have PCI DSS mappings."""
        for category in OWASPCategory:
            assert category in OWASP_TO_PCI_DSS

    def test_owasp_to_nist_all_categories(self):
        """All OWASP categories have NIST mappings."""
        for category in OWASPCategory:
            assert category in OWASP_TO_NIST

    def test_owasp_to_iso27001_all_categories(self):
        """All OWASP categories have ISO 27001 mappings."""
        for category in OWASPCategory:
            assert category in OWASP_TO_ISO27001

    def test_gdpr_articles_present(self):
        """Key GDPR articles are present."""
        assert "Art. 32" in SECURITY_GDPR_ARTICLES
        assert "Art. 33" in SECURITY_GDPR_ARTICLES

    def test_hipaa_safeguards_present(self):
        """Key HIPAA safeguards are present."""
        assert "164.312(a)(1)" in HIPAA_SAFEGUARDS  # Access Control
        assert "164.312(e)(1)" in HIPAA_SAFEGUARDS  # Transmission Security

    def test_soc2_criteria_present(self):
        """SOC 2 trust criteria are present."""
        assert "CC6" in SOC2_CRITERIA  # Logical Access
        assert "CC7" in SOC2_CRITERIA  # System Operations

    def test_cwe_database_common_cwes(self):
        """CWE database has common vulnerabilities."""
        common_cwes = [79, 89, 78, 918, 352, 502, 639]
        for cwe_id in common_cwes:
            assert cwe_id in CWE_DATABASE
            assert "name" in CWE_DATABASE[cwe_id]
            assert "desc" in CWE_DATABASE[cwe_id]


# =============================================================================
# COMPLIANCEMAPPER CLASS TESTS
# =============================================================================


class TestComplianceMapper:
    """Tests for ComplianceMapper class."""

    def test_initialization_default(self):
        """Initializes with all frameworks by default."""
        mapper = ComplianceMapper()
        assert len(mapper.frameworks) == len(ComplianceFramework)
        assert mapper.include_pii_frameworks is True

    def test_initialization_specific_frameworks(self):
        """Can initialize with specific frameworks."""
        mapper = ComplianceMapper(
            frameworks=[ComplianceFramework.CWE, ComplianceFramework.OWASP_TOP_10],
        )
        assert len(mapper.frameworks) == 2

    def test_initialization_no_pii(self):
        """Can disable PII frameworks."""
        mapper = ComplianceMapper(include_pii_frameworks=False)
        assert mapper.include_pii_frameworks is False

    def test_map_vulnerability_basic(self):
        """Basic vulnerability mapping works."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="test-001",
            vulnerability_type="sqli",
        )

        assert isinstance(mapping, ComplianceMapping)
        assert mapping.vulnerability_id == "test-001"
        assert mapping.vulnerability_type == "sqli"
        assert 89 in mapping.cwe_ids

    def test_map_vulnerability_owasp_mapping(self):
        """Vulnerability maps to OWASP category."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="owasp-test",
            vulnerability_type="sqli",
        )

        # SQLi (CWE-89) should map to A03
        assert len(mapping.owasp_categories) > 0
        assert any("A03" in cat for cat in mapping.owasp_categories)

    def test_map_vulnerability_pci_dss(self):
        """Vulnerability maps to PCI DSS requirements."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="pci-test",
            vulnerability_type="sqli",
        )

        assert len(mapping.pci_dss_requirements) > 0

    def test_map_vulnerability_nist(self):
        """Vulnerability maps to NIST controls."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="nist-test",
            vulnerability_type="xss",
        )

        assert len(mapping.nist_controls) > 0

    def test_map_vulnerability_with_pii(self):
        """PII flag adds GDPR articles."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="pii-test",
            vulnerability_type="info_disclosure",
            affects_pii=True,
        )

        assert len(mapping.gdpr_articles) > 0
        assert "Art. 32" in mapping.gdpr_articles

    def test_map_vulnerability_without_pii(self):
        """No PII flag means no GDPR articles."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="no-pii-test",
            vulnerability_type="xss",
            affects_pii=False,
        )

        assert len(mapping.gdpr_articles) == 0

    def test_map_vulnerability_health_data(self):
        """Health data flag adds HIPAA safeguards."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="health-test",
            vulnerability_type="auth_bypass",
            affects_health_data=True,
        )

        assert len(mapping.hipaa_safeguards) > 0

    def test_map_vulnerability_soc2_criteria(self):
        """Vulnerability maps to SOC 2 criteria."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="soc2-test",
            vulnerability_type="auth_bypass",
        )

        assert len(mapping.soc2_criteria) > 0
        assert any("CC6" in c for c in mapping.soc2_criteria)

    def test_map_vulnerability_remediation(self):
        """Mapping includes remediation guidance."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="remediation-test",
            vulnerability_type="sqli",
        )

        assert len(mapping.remediation_guidance) > 0
        assert "parameterized" in mapping.remediation_guidance.lower()

    def test_map_vulnerability_stores_mapping(self):
        """Mappings are stored internally."""
        mapper = ComplianceMapper()

        mapper.map_vulnerability(
            vulnerability_id="store-1",
            vulnerability_type="xss",
        )
        mapper.map_vulnerability(
            vulnerability_id="store-2",
            vulnerability_type="ssrf",
        )

        assert len(mapper._mappings) == 2

    def test_map_findings(self):
        """Can map multiple findings at once."""
        mapper = ComplianceMapper()
        findings = [
            {"id": "f1", "type": "sqli"},
            {"id": "f2", "type": "xss"},
            {"id": "f3", "type": "idor"},
        ]

        mappings = mapper.map_findings(findings)

        assert len(mappings) == 3
        assert all(isinstance(m, ComplianceMapping) for m in mappings)

    def test_map_findings_with_pii_flag(self):
        """map_findings applies PII flag to all."""
        mapper = ComplianceMapper()
        findings = [
            {"id": "pii-f1", "type": "info_disclosure"},
            {"id": "pii-f2", "type": "sensitive_data_exposure"},
        ]

        mappings = mapper.map_findings(findings, affects_pii=True)

        assert all(len(m.gdpr_articles) > 0 for m in mappings)

    def test_generate_report(self):
        """Can generate compliance report."""
        mapper = ComplianceMapper()

        mapper.map_vulnerability("v1", "sqli")
        mapper.map_vulnerability("v2", "xss")
        mapper.map_vulnerability("v3", "ssrf")

        report = mapper.generate_report(
            scan_id="report-scan-001",
            target="https://example.com",
        )

        assert isinstance(report, ComplianceReport)
        assert report.scan_id == "report-scan-001"
        assert report.target == "https://example.com"
        assert report.total_findings == 3
        assert len(report.mappings) == 3
        assert len(report.frameworks_covered) > 0

    def test_generate_report_owasp_coverage(self):
        """Report includes OWASP coverage stats."""
        mapper = ComplianceMapper()

        # Add multiple SQLi (A03)
        mapper.map_vulnerability("sql1", "sqli")
        mapper.map_vulnerability("sql2", "sqli")

        report = mapper.generate_report("test-scan", "https://test.com")

        # Should have A03 count
        a03_count = sum(1 for cat, count in report.owasp_coverage.items() if "A03" in cat)
        assert a03_count > 0 or len(report.owasp_coverage) > 0

    def test_get_cwe_info_known(self):
        """get_cwe_info returns details for known CWE."""
        mapper = ComplianceMapper()
        info = mapper.get_cwe_info(89)

        assert info is not None
        assert info.cwe_id == 89
        assert "SQL" in info.name
        assert info.url == "https://cwe.mitre.org/data/definitions/89.html"

    def test_get_cwe_info_unknown(self):
        """get_cwe_info returns None for unknown CWE."""
        mapper = ComplianceMapper()
        info = mapper.get_cwe_info(999999)

        assert info is None

    def test_get_framework_summary(self):
        """get_framework_summary returns counts per framework."""
        mapper = ComplianceMapper()

        mapper.map_vulnerability("v1", "sqli")
        mapper.map_vulnerability("v2", "xss")

        summary = mapper.get_framework_summary()

        assert isinstance(summary, dict)
        assert sum(summary.values()) > 0

    def test_clear_mappings(self):
        """clear_mappings removes all stored mappings."""
        mapper = ComplianceMapper()

        mapper.map_vulnerability("clear-1", "xss")
        mapper.map_vulnerability("clear-2", "ssrf")
        assert len(mapper._mappings) == 2

        mapper.clear_mappings()
        assert len(mapper._mappings) == 0

    def test_unknown_vulnerability_type(self):
        """Unknown vulnerability type still produces mapping."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="unknown-test",
            vulnerability_type="completely_unknown_type",
        )

        # Should still have basic SOC2 criteria
        assert len(mapping.soc2_criteria) > 0

    def test_ssrf_maps_to_a10(self):
        """SSRF correctly maps to OWASP A10."""
        mapper = ComplianceMapper()
        mapping = mapper.map_vulnerability(
            vulnerability_id="ssrf-owasp",
            vulnerability_type="ssrf",
        )

        assert any("A10" in cat for cat in mapping.owasp_categories)


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_map_to_compliance_basic(self):
        """map_to_compliance creates valid mapping."""
        mapping = map_to_compliance("sqli")

        assert isinstance(mapping, ComplianceMapping)
        assert 89 in mapping.cwe_ids

    def test_map_to_compliance_with_pii(self):
        """map_to_compliance handles PII flag."""
        mapping = map_to_compliance("info_disclosure", affects_pii=True)

        assert len(mapping.gdpr_articles) > 0

    def test_get_cwe_mapping_known_type(self):
        """get_cwe_mapping returns CWEs for known type."""
        cwes = get_cwe_mapping("sqli")

        assert isinstance(cwes, list)
        assert 89 in cwes

    def test_get_cwe_mapping_unknown_type(self):
        """get_cwe_mapping returns empty for unknown type."""
        cwes = get_cwe_mapping("unknown_type")

        assert cwes == []

    def test_get_cwe_mapping_case_insensitive(self):
        """get_cwe_mapping is case insensitive."""
        cwes_lower = get_cwe_mapping("sqli")
        cwes_upper = get_cwe_mapping("SQLI")

        assert cwes_lower == cwes_upper

    def test_get_owasp_category_known_cwe(self):
        """get_owasp_category returns category for known CWE."""
        category = get_owasp_category(89)

        assert category is not None
        assert "A03" in category

    def test_get_owasp_category_unknown_cwe(self):
        """get_owasp_category returns None for unknown CWE."""
        category = get_owasp_category(999999)

        assert category is None

    def test_get_owasp_category_ssrf(self):
        """CWE-918 (SSRF) maps to A10."""
        category = get_owasp_category(918)

        assert category == "A10:2021"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


class TestIntegration:
    """Integration tests for compliance mapping flow."""

    def test_full_mapping_chain(self):
        """Full chain: vuln type -> CWE -> OWASP -> PCI/NIST."""
        mapper = ComplianceMapper()

        # Map SQLi
        mapping = mapper.map_vulnerability("sqli-full", "sqli")

        # CWE-89 should be present
        assert 89 in mapping.cwe_ids

        # OWASP A03 should be present
        assert any("A03" in cat for cat in mapping.owasp_categories)

        # PCI DSS 6.x requirements should be present (secure development)
        assert any("6." in req for req in mapping.pci_dss_requirements)

        # NIST SI controls should be present
        assert any("SI" in ctrl for ctrl in mapping.nist_controls)

    def test_multi_cwe_vulnerability(self):
        """Vulnerability with multiple CWEs gets all mappings."""
        mapper = ComplianceMapper()

        # auth_bypass has CWE-287 and CWE-306
        mapping = mapper.map_vulnerability("auth-multi", "auth_bypass")

        assert len(mapping.cwe_ids) >= 2

    def test_report_generation_workflow(self):
        """Complete workflow: map findings -> generate report."""
        mapper = ComplianceMapper()

        # Simulate scan findings
        findings = [
            {"id": "finding-1", "type": "sqli"},
            {"id": "finding-2", "type": "xss"},
            {"id": "finding-3", "type": "ssrf"},
            {"id": "finding-4", "type": "idor"},
        ]

        # Map all findings
        mapper.map_findings(findings)

        # Generate report
        report = mapper.generate_report(
            scan_id="integration-test-scan",
            target="https://integration-test.example.com",
        )

        # Verify report
        assert report.total_findings == 4
        assert "CWE" in report.frameworks_covered
        assert "OWASP Top 10" in report.frameworks_covered
        assert len(report.owasp_coverage) > 0

    def test_pii_compliance_workflow(self):
        """PII-related compliance mapping workflow."""
        mapper = ComplianceMapper()

        # Map vulnerabilities affecting PII
        mapping = mapper.map_vulnerability(
            vulnerability_id="pii-breach",
            vulnerability_type="sensitive_data_exposure",
            affects_pii=True,
            affects_health_data=True,
        )

        # Should have GDPR
        assert "Art. 32" in mapping.gdpr_articles

        # Should have HIPAA
        assert len(mapping.hipaa_safeguards) > 0

    def test_cwe_info_enrichment(self):
        """Can enrich mapping with detailed CWE info."""
        mapper = ComplianceMapper()

        mapping = mapper.map_vulnerability("enrich-test", "sqli")

        # Get detailed info for each CWE
        for cwe_id in mapping.cwe_ids:
            info = mapper.get_cwe_info(cwe_id)
            if info:
                assert info.cwe_id == cwe_id
                assert len(info.name) > 0
                assert "cwe.mitre.org" in info.url
