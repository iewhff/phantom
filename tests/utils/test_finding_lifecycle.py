"""
Tests for utils/finding_lifecycle.py - Finding Lifecycle Manager.

Covers:
- FindingState enum and properties
- Severity enum and CVSS ranges
- EvidenceType enum
- Evidence dataclass
- Finding dataclass with lifecycle methods
- FindingManager class
- create_finding_with_evidence convenience function
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch
import json

from utils.finding_lifecycle import (
    FindingState,
    Severity,
    EvidenceType,
    Evidence,
    Finding,
    FindingManager,
    create_finding_with_evidence,
)


# =============================================================================
# FINDING STATE ENUM TESTS
# =============================================================================

class TestFindingState:
    """Tests for FindingState enum."""

    def test_all_states_defined(self):
        """Test all expected states are defined."""
        assert FindingState.DETECTED.value == "detected"
        assert FindingState.VALIDATED.value == "validated"
        assert FindingState.EXPLOITABLE.value == "exploitable"
        assert FindingState.DISCARDED.value == "discarded"

    def test_is_reportable_detected(self):
        """Test DETECTED is not reportable."""
        assert FindingState.DETECTED.is_reportable is False

    def test_is_reportable_validated(self):
        """Test VALIDATED is reportable."""
        assert FindingState.VALIDATED.is_reportable is True

    def test_is_reportable_exploitable(self):
        """Test EXPLOITABLE is reportable."""
        assert FindingState.EXPLOITABLE.is_reportable is True

    def test_is_reportable_discarded(self):
        """Test DISCARDED is not reportable."""
        assert FindingState.DISCARDED.is_reportable is False

    def test_display_name_detected(self):
        """Test display name for DETECTED."""
        assert "Detected" in FindingState.DETECTED.display_name

    def test_display_name_validated(self):
        """Test display name for VALIDATED."""
        assert "Validated" in FindingState.VALIDATED.display_name

    def test_display_name_exploitable(self):
        """Test display name for EXPLOITABLE."""
        assert "Exploitable" in FindingState.EXPLOITABLE.display_name

    def test_display_name_discarded(self):
        """Test display name for DISCARDED."""
        assert "Discarded" in FindingState.DISCARDED.display_name


# =============================================================================
# SEVERITY ENUM TESTS
# =============================================================================

class TestSeverity:
    """Tests for Severity enum."""

    def test_all_severities_defined(self):
        """Test all severity levels are defined."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_cvss_range_critical(self):
        """Test CVSS range for CRITICAL."""
        low, high = Severity.CRITICAL.cvss_range
        assert low == 9.0
        assert high == 10.0

    def test_cvss_range_high(self):
        """Test CVSS range for HIGH."""
        low, high = Severity.HIGH.cvss_range
        assert low == 7.0
        assert high == 8.9

    def test_cvss_range_medium(self):
        """Test CVSS range for MEDIUM."""
        low, high = Severity.MEDIUM.cvss_range
        assert low == 4.0
        assert high == 6.9

    def test_cvss_range_low(self):
        """Test CVSS range for LOW."""
        low, high = Severity.LOW.cvss_range
        assert low == 0.1
        assert high == 3.9

    def test_cvss_range_info(self):
        """Test CVSS range for INFO."""
        low, high = Severity.INFO.cvss_range
        assert low == 0.0
        assert high == 0.0


# =============================================================================
# EVIDENCE TYPE ENUM TESTS
# =============================================================================

class TestEvidenceType:
    """Tests for EvidenceType enum."""

    def test_all_evidence_types_defined(self):
        """Test all evidence types are defined."""
        expected_types = [
            "http_request", "http_response", "response_diff",
            "timing_data", "error_message", "stack_trace",
            "data_exfiltration", "oob_callback", "screenshot",
            "code_snippet", "explanation"
        ]
        actual_types = [e.value for e in EvidenceType]
        for expected in expected_types:
            assert expected in actual_types

    def test_http_request_type(self):
        """Test HTTP_REQUEST evidence type."""
        assert EvidenceType.HTTP_REQUEST.value == "http_request"

    def test_explanation_type(self):
        """Test EXPLANATION evidence type."""
        assert EvidenceType.EXPLANATION.value == "explanation"


# =============================================================================
# EVIDENCE DATACLASS TESTS
# =============================================================================

class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_evidence_creation(self):
        """Test basic evidence creation."""
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title="Test Request",
            content="GET /test HTTP/1.1"
        )
        assert evidence.evidence_type == EvidenceType.HTTP_REQUEST
        assert evidence.title == "Test Request"
        assert evidence.content == "GET /test HTTP/1.1"

    def test_evidence_default_timestamp(self):
        """Test evidence has default timestamp."""
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title="Test",
            content="Content"
        )
        assert isinstance(evidence.timestamp, datetime)

    def test_evidence_default_metadata(self):
        """Test evidence has default empty metadata."""
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title="Test",
            content="Content"
        )
        assert evidence.metadata == {}

    def test_evidence_custom_metadata(self):
        """Test evidence with custom metadata."""
        evidence = Evidence(
            evidence_type=EvidenceType.TIMING_DATA,
            title="Timing",
            content="500ms",
            metadata={"baseline": 100, "attack": 500}
        )
        assert evidence.metadata["baseline"] == 100
        assert evidence.metadata["attack"] == 500

    def test_evidence_to_dict(self):
        """Test evidence serialization to dict."""
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title="Request",
            content="GET /api"
        )
        result = evidence.to_dict()
        assert result["type"] == "http_request"
        assert result["title"] == "Request"
        assert result["content"] == "GET /api"
        assert "timestamp" in result

    def test_evidence_to_dict_truncates_content(self):
        """Test content is truncated in to_dict."""
        long_content = "x" * 20000
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            title="Response",
            content=long_content
        )
        result = evidence.to_dict()
        assert len(result["content"]) <= 10000

    def test_evidence_to_markdown_http_request(self):
        """Test markdown formatting for HTTP request."""
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title="Request",
            content="GET /api HTTP/1.1"
        )
        md = evidence.to_markdown()
        assert "### Request" in md
        assert "```http" in md
        assert "GET /api HTTP/1.1" in md

    def test_evidence_to_markdown_response_diff(self):
        """Test markdown formatting for response diff."""
        evidence = Evidence(
            evidence_type=EvidenceType.RESPONSE_DIFF,
            title="Diff",
            content="- old\n+ new"
        )
        md = evidence.to_markdown()
        assert "```diff" in md

    def test_evidence_to_markdown_explanation(self):
        """Test markdown formatting for explanation."""
        evidence = Evidence(
            evidence_type=EvidenceType.EXPLANATION,
            title="Why",
            content="This is vulnerable because..."
        )
        md = evidence.to_markdown()
        assert "This is vulnerable because..." in md
        assert "```" not in md  # Explanation should not be in code block


# =============================================================================
# FINDING DATACLASS TESTS
# =============================================================================

class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_default_values(self):
        """Test finding with default values."""
        finding = Finding()
        assert finding.vulnerability_type == ""
        assert finding.state == FindingState.DETECTED
        assert finding.severity == Severity.INFO
        assert finding.confidence_score == 0.0

    def test_finding_has_id(self):
        """Test finding gets unique ID."""
        finding = Finding()
        assert finding.id is not None
        assert len(finding.id) == 8

    def test_finding_unique_ids(self):
        """Test each finding gets unique ID."""
        finding1 = Finding()
        finding2 = Finding()
        assert finding1.id != finding2.id

    def test_finding_state_history_initial(self):
        """Test finding records initial state."""
        finding = Finding()
        assert len(finding.state_history) == 1
        assert finding.state_history[0]["state"] == "detected"

    def test_add_evidence(self):
        """Test adding evidence to finding."""
        finding = Finding()
        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title="Request",
            content="GET /"
        )
        finding.add_evidence(evidence)
        assert len(finding.evidence) == 1
        assert finding.evidence[0].title == "Request"

    def test_add_request_evidence(self):
        """Test convenience method for request evidence."""
        finding = Finding()
        finding.add_request_evidence("GET /api HTTP/1.1")
        assert len(finding.evidence) == 1
        assert finding.evidence[0].evidence_type == EvidenceType.HTTP_REQUEST

    def test_add_response_evidence(self):
        """Test convenience method for response evidence."""
        finding = Finding()
        finding.add_response_evidence("HTTP/1.1 200 OK")
        assert len(finding.evidence) == 1
        assert finding.evidence[0].evidence_type == EvidenceType.HTTP_RESPONSE

    def test_add_diff_evidence(self):
        """Test adding diff evidence."""
        finding = Finding()
        finding.add_diff_evidence("baseline", "attack")
        assert len(finding.evidence) == 1
        assert finding.evidence[0].evidence_type == EvidenceType.RESPONSE_DIFF

    def test_add_explanation(self):
        """Test adding explanation evidence."""
        finding = Finding()
        finding.add_explanation("This is vulnerable because SQL injection")
        assert len(finding.evidence) == 1
        assert finding.evidence[0].evidence_type == EvidenceType.EXPLANATION

    def test_generate_diff(self):
        """Test diff generation."""
        finding = Finding()
        diff = finding._generate_diff("line1\nline2", "line1\nline3")
        assert "- line2" in diff
        assert "+ line3" in diff

    def test_generate_diff_extra_lines(self):
        """Test diff with extra lines in attack."""
        finding = Finding()
        diff = finding._generate_diff("line1", "line1\nline2\nline3")
        assert "+ line2" in diff
        assert "+ line3" in diff


class TestFindingMinimumEvidence:
    """Tests for minimum evidence requirements."""

    @pytest.fixture
    def complete_finding(self):
        """Create finding with all required evidence."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_diff_evidence("baseline", "attack")
        finding.add_explanation("Vulnerable because...")
        return finding

    def test_has_minimum_evidence_complete(self, complete_finding):
        """Test complete finding has minimum evidence."""
        assert complete_finding.has_minimum_evidence() is True

    def test_has_minimum_evidence_missing_request(self):
        """Test missing request evidence."""
        finding = Finding()
        finding.add_response_evidence("200 OK")
        finding.add_diff_evidence("baseline", "attack")
        finding.add_explanation("Vulnerable")
        assert finding.has_minimum_evidence() is False

    def test_has_minimum_evidence_missing_response(self):
        """Test missing response evidence."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_diff_evidence("baseline", "attack")
        finding.add_explanation("Vulnerable")
        assert finding.has_minimum_evidence() is False

    def test_has_minimum_evidence_missing_diff(self):
        """Test missing diff evidence."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_explanation("Vulnerable")
        assert finding.has_minimum_evidence() is False

    def test_has_minimum_evidence_oob_instead_of_diff(self):
        """Test OOB callback counts as diff."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_evidence(Evidence(
            evidence_type=EvidenceType.OOB_CALLBACK,
            title="OOB",
            content="Callback received"
        ))
        finding.add_explanation("Vulnerable")
        assert finding.has_minimum_evidence() is True

    def test_has_minimum_evidence_timing_instead_of_diff(self):
        """Test timing data counts as diff."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_evidence(Evidence(
            evidence_type=EvidenceType.TIMING_DATA,
            title="Timing",
            content="5000ms delay"
        ))
        finding.add_explanation("Vulnerable")
        assert finding.has_minimum_evidence() is True

    def test_get_missing_evidence_empty(self, complete_finding):
        """Test no missing evidence for complete finding."""
        missing = complete_finding.get_missing_evidence()
        assert len(missing) == 0

    def test_get_missing_evidence_all_missing(self):
        """Test all missing for empty finding."""
        finding = Finding()
        missing = finding.get_missing_evidence()
        assert len(missing) == 4
        assert any("Request" in m for m in missing)
        assert any("Response" in m for m in missing)
        assert any("Difference" in m for m in missing)
        assert any("Explanation" in m for m in missing)


class TestFindingValidation:
    """Tests for finding validation."""

    @pytest.fixture
    def complete_finding(self):
        """Create finding with all required evidence."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_diff_evidence("baseline", "attack")
        finding.add_explanation("Vulnerable because...")
        return finding

    def test_validate_success(self, complete_finding):
        """Test successful validation."""
        result = complete_finding.validate("negative_control", 85.0)
        assert result is True
        assert complete_finding.state == FindingState.VALIDATED
        assert complete_finding.validation_method == "negative_control"
        assert complete_finding.confidence_score == 85.0
        assert complete_finding.validated_at is not None

    def test_validate_low_confidence(self, complete_finding):
        """Test validation fails with low confidence."""
        result = complete_finding.validate("test", 30.0)
        assert result is False
        assert complete_finding.state == FindingState.DISCARDED

    def test_validate_missing_evidence(self):
        """Test validation fails without evidence."""
        finding = Finding()
        result = finding.validate("test", 85.0)
        assert result is False
        assert finding.state == FindingState.DETECTED

    def test_mark_exploitable(self, complete_finding):
        """Test marking as exploitable."""
        complete_finding.validate("test", 85.0)
        complete_finding.mark_exploitable("Extracted /etc/passwd")
        assert complete_finding.state == FindingState.EXPLOITABLE

    def test_mark_exploitable_adds_evidence(self, complete_finding):
        """Test exploitable adds exploitation evidence."""
        initial_count = len(complete_finding.evidence)
        complete_finding.mark_exploitable("Extracted data")
        assert len(complete_finding.evidence) == initial_count + 1

    def test_discard(self):
        """Test discarding finding."""
        finding = Finding()
        finding.discard("False positive - test server")
        assert finding.state == FindingState.DISCARDED
        assert "False positive" in finding.state_history[-1]["reason"]


class TestFindingReportable:
    """Tests for is_reportable property."""

    def test_not_reportable_detected(self):
        """Test DETECTED finding not reportable."""
        finding = Finding()
        assert finding.is_reportable is False

    def test_not_reportable_without_evidence(self):
        """Test VALIDATED without evidence not reportable."""
        finding = Finding()
        finding.state = FindingState.VALIDATED
        assert finding.is_reportable is False

    def test_reportable_validated_with_evidence(self):
        """Test VALIDATED with evidence is reportable."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_diff_evidence("baseline", "attack")
        finding.add_explanation("Vulnerable")
        finding.state = FindingState.VALIDATED
        assert finding.is_reportable is True

    def test_reportable_exploitable_with_evidence(self):
        """Test EXPLOITABLE with evidence is reportable."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        finding.add_response_evidence("200 OK")
        finding.add_diff_evidence("baseline", "attack")
        finding.add_explanation("Vulnerable")
        finding.state = FindingState.EXPLOITABLE
        assert finding.is_reportable is True


class TestFindingSerialization:
    """Tests for finding serialization."""

    def test_to_dict(self):
        """Test finding to_dict."""
        finding = Finding(
            vulnerability_type="SQL Injection",
            title="SQLi in login",
            url="https://example.com/login",
            parameter="username",
            severity=Severity.HIGH
        )
        result = finding.to_dict()
        assert result["vulnerability_type"] == "SQL Injection"
        assert result["title"] == "SQLi in login"
        assert result["severity"] == "high"
        assert "id" in result
        assert "state" in result

    def test_to_dict_includes_evidence(self):
        """Test to_dict includes evidence."""
        finding = Finding()
        finding.add_request_evidence("GET /test")
        result = finding.to_dict()
        assert len(result["evidence"]) == 1

    def test_to_markdown_not_reportable(self):
        """Test to_markdown returns empty for non-reportable."""
        finding = Finding()
        md = finding.to_markdown()
        assert md == ""

    def test_to_markdown_reportable(self):
        """Test to_markdown for reportable finding."""
        finding = Finding(
            vulnerability_type="XSS",
            title="Reflected XSS",
            url="https://example.com/search",
            parameter="q",
            severity=Severity.MEDIUM,
            payload_used="<script>alert(1)</script>"
        )
        finding.add_request_evidence("GET /search?q=<script>")
        finding.add_response_evidence("200 OK with script")
        finding.add_diff_evidence("safe", "with script")
        finding.add_explanation("User input reflected")
        finding.state = FindingState.VALIDATED

        md = finding.to_markdown()
        assert "Reflected XSS" in md
        assert "MEDIUM" in md
        assert "XSS" in md


# =============================================================================
# FINDING MANAGER TESTS
# =============================================================================

class TestFindingManager:
    """Tests for FindingManager class."""

    @pytest.fixture
    def manager(self):
        """Create fresh FindingManager."""
        return FindingManager()

    def test_manager_initialization(self, manager):
        """Test manager initializes with empty state."""
        assert len(manager.findings) == 0
        stats = manager.get_statistics()
        assert stats["total_detected"] == 0

    def test_manager_version(self, manager):
        """Test manager has version."""
        assert "ENTERPRISE" in manager.VERSION

    def test_add_finding(self, manager):
        """Test adding a finding."""
        finding = Finding(title="Test")
        finding_id = manager.add_finding(finding)
        assert finding_id == finding.id
        assert finding.id in manager.findings

    def test_create_finding(self, manager):
        """Test create_finding convenience method."""
        finding = manager.create_finding(
            vulnerability_type="XSS",
            title="Reflected XSS",
            url="https://example.com",
            parameter="q",
            severity=Severity.MEDIUM
        )
        assert finding.id in manager.findings
        assert finding.vulnerability_type == "XSS"

    def test_get_finding(self, manager):
        """Test getting finding by ID."""
        finding = Finding(title="Test")
        manager.add_finding(finding)
        retrieved = manager.get_finding(finding.id)
        assert retrieved is finding

    def test_get_finding_not_found(self, manager):
        """Test getting non-existent finding."""
        result = manager.get_finding("nonexistent")
        assert result is None

    def test_update_state(self, manager):
        """Test updating finding state."""
        finding = Finding()
        manager.add_finding(finding)
        manager.update_state(finding.id, FindingState.VALIDATED, "Test validation")
        assert finding.state == FindingState.VALIDATED

    def test_validate_finding(self, manager):
        """Test validate_finding method."""
        finding = manager.create_finding(
            vulnerability_type="SQLi",
            title="SQL Injection",
            url="https://example.com",
            parameter="id",
            severity=Severity.HIGH
        )
        finding.add_request_evidence("GET /api?id=1'")
        finding.add_response_evidence("500 Error")
        finding.add_diff_evidence("normal", "error")
        finding.add_explanation("SQL syntax error")

        result = manager.validate_finding(finding.id, "error_based", 90.0)
        assert result is True
        assert finding.state == FindingState.VALIDATED

    def test_discard_finding(self, manager):
        """Test discarding a finding."""
        finding = Finding()
        manager.add_finding(finding)
        manager.discard_finding(finding.id, "False positive")
        assert finding.state == FindingState.DISCARDED

    def test_get_reportable_findings(self, manager):
        """Test getting reportable findings."""
        # Create non-reportable
        f1 = Finding()
        manager.add_finding(f1)

        # Create reportable
        f2 = manager.create_finding(
            vulnerability_type="XSS",
            title="XSS",
            url="https://example.com",
            parameter="q",
            severity=Severity.HIGH
        )
        f2.add_request_evidence("GET /")
        f2.add_response_evidence("200 OK")
        f2.add_diff_evidence("safe", "xss")
        f2.add_explanation("Reflected")
        # Use manager method to properly update state tracking
        manager.validate_finding(f2.id, "test", 85.0)

        reportable = manager.get_reportable_findings()
        assert len(reportable) == 1
        assert reportable[0].id == f2.id

    def test_reportable_sorted_by_severity(self, manager):
        """Test reportable findings sorted by severity."""
        for sev in [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]:
            f = manager.create_finding(
                vulnerability_type="Test",
                title=f"Test {sev.value}",
                url="https://example.com",
                parameter="p",
                severity=sev
            )
            f.add_request_evidence("GET /")
            f.add_response_evidence("200")
            f.add_diff_evidence("a", "b")
            f.add_explanation("Vuln")
            # Use manager method to properly update state tracking
            manager.validate_finding(f.id, "test", 85.0)

        reportable = manager.get_reportable_findings()
        assert reportable[0].severity == Severity.CRITICAL
        assert reportable[1].severity == Severity.MEDIUM
        assert reportable[2].severity == Severity.LOW

    def test_get_incomplete_findings(self, manager):
        """Test getting incomplete findings."""
        f1 = Finding()  # No evidence
        f2 = Finding()
        f2.add_request_evidence("GET /")  # Partial evidence

        manager.add_finding(f1)
        manager.add_finding(f2)

        incomplete = manager.get_incomplete_findings()
        assert len(incomplete) == 2

    def test_get_discarded_findings(self, manager):
        """Test getting discarded findings."""
        f1 = Finding()
        f2 = Finding()
        manager.add_finding(f1)
        manager.add_finding(f2)

        manager.discard_finding(f1.id, "FP")

        discarded = manager.get_discarded_findings()
        assert len(discarded) == 1
        assert discarded[0].id == f1.id


class TestFindingManagerStatistics:
    """Tests for FindingManager statistics."""

    @pytest.fixture
    def populated_manager(self):
        """Create manager with various findings."""
        manager = FindingManager()

        # Detected (incomplete)
        for _ in range(3):
            manager.add_finding(Finding())

        # Validated
        for sev in [Severity.HIGH, Severity.MEDIUM]:
            f = manager.create_finding(
                vulnerability_type="Test",
                title="Test",
                url="https://example.com",
                parameter="p",
                severity=sev
            )
            f.add_request_evidence("GET /")
            f.add_response_evidence("200")
            f.add_diff_evidence("a", "b")
            f.add_explanation("Vuln")
            # Use manager method to properly update state tracking
            manager.validate_finding(f.id, "test", 85.0)

        # Discarded
        f = Finding()
        manager.add_finding(f)
        manager.discard_finding(f.id, "FP")

        return manager

    def test_get_statistics(self, populated_manager):
        """Test statistics generation."""
        stats = populated_manager.get_statistics()
        assert stats["total_detected"] == 3
        assert stats["total_validated"] == 2
        assert stats["total_discarded"] == 1
        assert stats["total_reportable"] == 2

    def test_statistics_by_severity(self, populated_manager):
        """Test severity breakdown in statistics."""
        stats = populated_manager.get_statistics()
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1

    def test_false_positive_rate(self, populated_manager):
        """Test FP rate calculation."""
        stats = populated_manager.get_statistics()
        # 1 discarded out of 6 total = 16.67%
        assert stats["false_positive_rate"] > 0


class TestFindingManagerReports:
    """Tests for FindingManager report generation."""

    @pytest.fixture
    def manager_with_findings(self):
        """Create manager with reportable findings."""
        manager = FindingManager()

        f = manager.create_finding(
            vulnerability_type="XSS",
            title="Reflected XSS",
            url="https://example.com/search",
            parameter="q",
            severity=Severity.HIGH
        )
        f.add_request_evidence("GET /search?q=<script>")
        f.add_response_evidence("200 OK with script")
        f.add_diff_evidence("safe", "unsafe")
        f.add_explanation("User input reflected unsanitized")
        # Use manager method to properly update state tracking
        manager.validate_finding(f.id, "test", 85.0)

        return manager

    def test_generate_report(self, manager_with_findings):
        """Test report generation."""
        report = manager_with_findings.generate_report()
        assert "Security Assessment Report" in report
        assert "Reflected XSS" in report
        assert "HIGH" in report

    def test_generate_report_with_discarded(self, manager_with_findings):
        """Test report with discarded findings."""
        f = Finding(title="FP Finding")
        manager_with_findings.add_finding(f)
        manager_with_findings.discard_finding(f.id, "Test FP")

        report = manager_with_findings.generate_report(include_discarded=True)
        assert "Discarded Findings" in report
        assert "FP Finding" in report

    def test_to_json(self, manager_with_findings):
        """Test JSON export."""
        json_str = manager_with_findings.to_json()
        data = json.loads(json_str)
        assert "version" in data
        assert "statistics" in data
        assert "reportable_findings" in data
        assert len(data["reportable_findings"]) == 1


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestCreateFindingWithEvidence:
    """Tests for create_finding_with_evidence function."""

    def test_creates_complete_finding(self):
        """Test creates finding with all evidence."""
        manager = FindingManager()
        finding = create_finding_with_evidence(
            manager=manager,
            vulnerability_type="SQLi",
            title="SQL Injection",
            url="https://example.com/api",
            parameter="id",
            severity=Severity.CRITICAL,
            request="GET /api?id=1'",
            response="500 SQL Error",
            baseline_response="200 OK",
            explanation="SQL syntax error in response",
            payload="1'"
        )

        assert finding.has_minimum_evidence() is True
        assert finding.id in manager.findings
        assert finding.payload_used == "1'"

    def test_finding_has_all_evidence_types(self):
        """Test finding has request, response, diff, explanation."""
        manager = FindingManager()
        finding = create_finding_with_evidence(
            manager=manager,
            vulnerability_type="XSS",
            title="XSS",
            url="https://example.com",
            parameter="q",
            severity=Severity.MEDIUM,
            request="GET /",
            response="<script>",
            baseline_response="safe",
            explanation="Script tag reflected",
            payload="<script>"
        )

        types = {e.evidence_type for e in finding.evidence}
        assert EvidenceType.HTTP_REQUEST in types
        assert EvidenceType.HTTP_RESPONSE in types
        assert EvidenceType.RESPONSE_DIFF in types
        assert EvidenceType.EXPLANATION in types


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestFindingLifecycleIntegration:
    """Integration tests for finding lifecycle."""

    def test_complete_lifecycle(self):
        """Test complete finding lifecycle: detect -> validate -> report."""
        manager = FindingManager()

        # 1. Create finding (DETECTED)
        finding = manager.create_finding(
            vulnerability_type="SQL Injection",
            title="Error-based SQLi in search",
            url="https://example.com/search",
            parameter="q",
            severity=Severity.CRITICAL,
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection"
        )
        assert finding.state == FindingState.DETECTED

        # 2. Add evidence
        finding.add_request_evidence("GET /search?q=' OR 1=1--")
        finding.add_response_evidence("500 Internal Server Error\nSQL syntax error")
        finding.add_diff_evidence(
            "200 OK - normal results",
            "500 Error - SQL syntax"
        )
        finding.add_explanation(
            "The application reveals SQL syntax errors when injecting "
            "SQL metacharacters, indicating SQL injection vulnerability."
        )

        # 3. Validate
        result = manager.validate_finding(
            finding.id,
            method="error_based_detection",
            confidence=95.0
        )
        assert result is True
        assert finding.state == FindingState.VALIDATED

        # 4. Generate report
        report = manager.generate_report()
        assert "SQL Injection" in report
        assert "CRITICAL" in report

        # 5. Check statistics
        stats = manager.get_statistics()
        assert stats["total_reportable"] == 1
        assert stats["by_severity"]["critical"] == 1

    def test_false_positive_lifecycle(self):
        """Test finding that turns out to be false positive."""
        manager = FindingManager()

        # Create finding
        finding = manager.create_finding(
            vulnerability_type="SSRF",
            title="Potential SSRF",
            url="https://example.com/fetch",
            parameter="url",
            severity=Severity.HIGH
        )

        # Add partial evidence
        finding.add_request_evidence("GET /fetch?url=http://internal")
        finding.add_response_evidence("200 OK - blocked")

        # Discard as FP
        manager.discard_finding(finding.id, "URL whitelist prevents exploitation")

        assert finding.state == FindingState.DISCARDED
        assert manager.get_statistics()["total_discarded"] == 1
        assert len(manager.get_reportable_findings()) == 0

    def test_exploitable_finding(self):
        """Test finding marked as exploitable."""
        manager = FindingManager()

        finding = manager.create_finding(
            vulnerability_type="LFI",
            title="Local File Inclusion",
            url="https://example.com/include",
            parameter="file",
            severity=Severity.CRITICAL
        )

        finding.add_request_evidence("GET /include?file=../../../etc/passwd")
        finding.add_response_evidence("root:x:0:0:root:/root:/bin/bash")
        finding.add_diff_evidence("normal page", "passwd file contents")
        finding.add_explanation("Path traversal allows reading system files")

        manager.validate_finding(finding.id, "file_content_verification", 99.0)
        finding.mark_exploitable("Successfully extracted /etc/passwd and /etc/shadow")

        assert finding.state == FindingState.EXPLOITABLE
        assert finding.is_reportable is True

