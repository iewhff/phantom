"""
Tests for the Unified Finding System.

Tests the core finding infrastructure:
- VulnCategory and VulnType enums
- Finding dataclass
- HttpEvidence
- FindingManager

Author: PHANTOM AI
Version: 2.0.0
"""

import pytest
from datetime import datetime

from scanning.findings import (
    VulnCategory,
    VulnType,
    Severity,
    Finding,
    HttpEvidence,
    FindingCollection,
)


# ═══════════════════════════════════════════════════════════════════════════════
# ENUM TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestVulnCategory:
    """Tests for VulnCategory enum."""

    def test_all_categories_exist(self):
        """Test all expected categories are defined."""
        expected = [
            "INJECTION",
            "AUTHENTICATION",
            "AUTHORIZATION",
            "DISCLOSURE",
            "CONFIGURATION",
            "CRYPTOGRAPHY",
            "SESSION",
            "BUSINESS_LOGIC",
            "CLIENT_SIDE",
            "SERVER_SIDE",
            "API",
            "INFRASTRUCTURE",
        ]
        for cat in expected:
            assert hasattr(VulnCategory, cat), f"Missing category: {cat}"

    def test_category_values(self):
        """Test category string values."""
        assert VulnCategory.INJECTION.value == "injection"
        assert VulnCategory.AUTHENTICATION.value == "authentication"
        assert VulnCategory.API.value == "api"


class TestVulnType:
    """Tests for VulnType enum."""

    def test_injection_types(self):
        """Test injection vulnerability types."""
        injection_types = [
            "SQLI", "XSS_REFLECTED", "XSS_STORED", "XSS_DOM",
            "CMDI", "SSTI", "NOSQL_INJECTION", "LDAP_INJECTION", "XPATH_INJECTION", "XXE", "CRLF",
        ]
        for vtype in injection_types:
            assert hasattr(VulnType, vtype), f"Missing type: {vtype}"

    def test_auth_types(self):
        """Test authentication vulnerability types."""
        auth_types = [
            "AUTH_BYPASS", "SESSION_FIXATION",
            "WEAK_PASSWORD", "MFA_BYPASS",
        ]
        for vtype in auth_types:
            assert hasattr(VulnType, vtype), f"Missing type: {vtype}"

    def test_authz_types(self):
        """Test authorization vulnerability types."""
        authz_types = ["IDOR", "BOLA", "PRIVILEGE_ESCALATION"]
        for vtype in authz_types:
            assert hasattr(VulnType, vtype), f"Missing type: {vtype}"

    def test_type_category_mapping(self):
        """Test that types map to correct categories."""
        # This tests the category property if implemented
        assert VulnType.SQLI.value == "sqli"
        assert VulnType.IDOR.value == "idor"
        assert VulnType.XSS_REFLECTED.value == "xss_reflected"


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_levels(self):
        """Test all severity levels exist."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_ordering(self):
        """Test severity can be compared."""
        # By enum order (if needed for sorting)
        severities = list(Severity)
        assert severities[0] == Severity.CRITICAL
        assert severities[-1] == Severity.INFO


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP EVIDENCE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestHttpEvidence:
    """Tests for HttpEvidence dataclass."""

    def test_create_evidence(self):
        """Test creating HTTP evidence."""
        evidence = HttpEvidence(
            request_method="POST",
            request_url="https://example.com/api/users",
            request_headers={"Content-Type": "application/json"},
            request_body='{"username": "admin"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"id": 1, "role": "admin"}',
        )

        assert evidence.request_method == "POST"
        assert evidence.response_status == 200

    def test_evidence_to_dict(self):
        """Test converting evidence to dict."""
        evidence = HttpEvidence(
            request_method="GET",
            request_url="https://example.com/",
            response_status=200,
        )

        d = evidence.to_dict()
        assert d["request_method"] == "GET"
        assert d["response_status"] == 200

    def test_evidence_defaults(self):
        """Test evidence default values."""
        evidence = HttpEvidence(
            request_method="GET",
            request_url="https://example.com/",
        )

        assert evidence.request_headers == {}
        assert evidence.request_body == ""
        assert evidence.response_status == 0
        assert evidence.response_body == ""


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestFinding:
    """Tests for Finding dataclass."""

    def test_create_finding(self):
        """Test creating a finding."""
        finding = Finding(
            vuln_type=VulnType.SQLI,
            category=VulnCategory.INJECTION,
            severity=Severity.CRITICAL,
            name="SQL Injection",
            description="SQL injection in login form",
            host="example.com",
            endpoint="/api/login",
            parameter="username",
            method="POST",
        )

        assert finding.vuln_type == VulnType.SQLI
        assert finding.severity == Severity.CRITICAL
        assert finding.parameter == "username"
        assert finding.id is not None

    def test_finding_auto_id(self):
        """Test finding generates unique ID."""
        finding1 = Finding(
            vuln_type=VulnType.XSS_REFLECTED,
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            name="XSS",
            description="Reflected XSS",
            host="example.com",
            endpoint="/search",
        )
        finding2 = Finding(
            vuln_type=VulnType.XSS_REFLECTED,
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            name="XSS",
            description="Reflected XSS",
            host="example.com",
            endpoint="/search",
        )

        # IDs should be different
        assert finding1.id != finding2.id

    def test_finding_with_evidence(self):
        """Test finding with HTTP evidence."""
        evidence = HttpEvidence(
            request_method="GET",
            request_url="https://example.com/?q=<script>",
            response_status=200,
            response_body="<script>alert(1)</script>",
        )

        finding = Finding(
            vuln_type=VulnType.XSS_REFLECTED,
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            name="XSS",
            description="Reflected XSS",
            host="example.com",
            endpoint="/",
            http_evidence=evidence,
        )

        assert finding.http_evidence is not None
        assert finding.http_evidence.response_status == 200

    def test_finding_to_dict(self):
        """Test converting finding to dict."""
        finding = Finding(
            vuln_type=VulnType.IDOR,
            category=VulnCategory.AUTHORIZATION,
            severity=Severity.HIGH,
            name="IDOR",
            description="Insecure direct object reference",
            host="example.com",
            endpoint="/api/users/1",
            confidence_score=0.95,
        )

        d = finding.to_dict()
        assert d["vuln_type"] == "idor"
        assert d["category"] == "authorization"
        assert d["severity"] == "HIGH"
        assert d["confidence_score"] == 0.95

    def test_finding_from_dict(self):
        """Test creating finding from dict."""
        data = {
            "vuln_type": "sqli",
            "category": "injection",
            "severity": "CRITICAL",
            "name": "SQL Injection",
            "description": "SQL injection vulnerability",
            "host": "example.com",
            "endpoint": "/api/login",
            "parameter": "username",
            "confidence_score": 0.9,
        }

        finding = Finding.from_dict(data)

        assert finding.vuln_type == VulnType.SQLI
        assert finding.category == VulnCategory.INJECTION
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence_score == 0.9

    def test_finding_defaults(self):
        """Test finding default values."""
        finding = Finding(
            vuln_type=VulnType.INFO_DISCLOSURE,
            category=VulnCategory.DISCLOSURE,
            severity=Severity.LOW,
            name="Info Disclosure",
            description="Information disclosure",
            host="example.com",
            endpoint="/",
        )

        assert finding.parameter == ""
        assert finding.method == "GET"
        assert finding.confidence_score == 50.0  # Default is 50.0
        # CVSS is auto-calculated based on severity (LOW = 2.5)
        assert finding.cvss_score == 2.5
        assert finding.validated == False
        assert finding.false_positive == False
        assert finding.evidence == []

    def test_finding_validation_flag(self):
        """Test marking finding as validated."""
        finding = Finding(
            vuln_type=VulnType.SSRF,
            category=VulnCategory.SERVER_SIDE,  # SSRF is SERVER_SIDE not NETWORK
            severity=Severity.HIGH,
            name="SSRF",
            description="Server-side request forgery",
            host="example.com",
            endpoint="/proxy",
        )

        assert not finding.validated

        # Mark as validated
        finding.validated = True
        finding.confidence_score = 95.0  # Use 0-100 scale

        assert finding.validated
        assert finding.confidence_score == 95.0


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING COLLECTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindingCollection:
    """Tests for FindingCollection."""

    def test_add_finding(self):
        """Test adding findings."""
        collection = FindingCollection()

        finding = Finding(
            vuln_type=VulnType.SQLI,
            category=VulnCategory.INJECTION,
            severity=Severity.CRITICAL,
            name="SQLi",
            description="SQL injection",
            host="example.com",
            endpoint="/login",
        )

        collection.add(finding)
        assert len(collection.findings) == 1

    def test_filter_by_severity(self):
        """Test filtering by severity."""
        collection = FindingCollection()

        collection.add(Finding(
            vuln_type=VulnType.SQLI,
            category=VulnCategory.INJECTION,
            severity=Severity.CRITICAL,
            name="SQLi",
            description="Critical finding",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.XSS_REFLECTED,
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            name="XSS",
            description="High finding",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.CLICKJACKING,
            category=VulnCategory.CONFIGURATION,
            severity=Severity.LOW,
            name="Clickjacking",
            description="Low finding",
            host="example.com",
            endpoint="/",
        ))

        critical = collection.filter_by_severity(Severity.CRITICAL)
        assert len(critical.findings) == 1
        assert critical.findings[0].vuln_type == VulnType.SQLI

        high = collection.filter_by_severity(Severity.HIGH)
        assert len(high.findings) == 1

    def test_filter_by_category(self):
        """Test filtering by category."""
        collection = FindingCollection()

        collection.add(Finding(
            vuln_type=VulnType.SQLI,
            category=VulnCategory.INJECTION,
            severity=Severity.CRITICAL,
            name="SQLi",
            description="Injection",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.IDOR,
            category=VulnCategory.AUTHORIZATION,
            severity=Severity.HIGH,
            name="IDOR",
            description="Authorization",
            host="example.com",
            endpoint="/",
        ))

        injection = collection.filter_by_category(VulnCategory.INJECTION)
        assert len(injection.findings) == 1

        authz = collection.filter_by_category(VulnCategory.AUTHORIZATION)
        assert len(authz.findings) == 1

    def test_deduplicate(self):
        """Test finding deduplication."""
        collection = FindingCollection()

        # Add similar findings
        for i in range(3):
            collection.add(Finding(
                vuln_type=VulnType.SQLI,
                category=VulnCategory.INJECTION,
                severity=Severity.CRITICAL,
                name="SQLi",
                description="SQL injection",
                host="example.com",
                endpoint="/login",
                parameter="username",
            ))

        assert len(collection.findings) == 3

        deduped = collection.deduplicate()
        # Should be reduced to 1 after dedup
        assert len(deduped.findings) == 1

    def test_severity_counts(self):
        """Test severity count properties."""
        collection = FindingCollection()

        collection.add(Finding(
            vuln_type=VulnType.SQLI,
            category=VulnCategory.INJECTION,
            severity=Severity.CRITICAL,
            name="SQLi",
            description="Critical",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.XSS_REFLECTED,
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            name="XSS",
            description="High",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.CORS_MISCONFIGURATION,
            category=VulnCategory.CONFIGURATION,
            severity=Severity.MEDIUM,
            name="CORS",
            description="Medium",
            host="example.com",
            endpoint="/",
        ))

        assert collection.critical_count == 1
        assert collection.high_count == 1
        assert collection.medium_count == 1

    def test_group_by_category(self):
        """Test grouping findings by category."""
        collection = FindingCollection()

        collection.add(Finding(
            vuln_type=VulnType.SQLI,
            category=VulnCategory.INJECTION,
            severity=Severity.CRITICAL,
            name="SQLi",
            description="SQLi",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.XSS_REFLECTED,
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            name="XSS",
            description="XSS",
            host="example.com",
            endpoint="/",
        ))
        collection.add(Finding(
            vuln_type=VulnType.SSRF,
            category=VulnCategory.SERVER_SIDE,
            severity=Severity.HIGH,
            name="SSRF",
            description="SSRF",
            host="example.com",
            endpoint="/proxy",
        ))

        groups = collection.group_by_category()

        assert len(groups[VulnCategory.INJECTION]) == 2
        assert len(groups[VulnCategory.SERVER_SIDE]) == 1
