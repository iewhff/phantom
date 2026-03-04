"""
Tests for scanning/modules/firebase_scanner.py

Covers:
- Severity enum (5 members: CRITICAL, HIGH, MEDIUM, LOW, INFO) - local enum, not from scanning.findings
- FirebaseFinding dataclass: defaults, full creation, to_dict(), evidence truncation
- FirebaseScanResult dataclass: defaults, critical_count/high_count properties
- FirebaseScanner class attributes: COMMON_COLLECTIONS (19), COMMON_RTDB_PATHS (12)
- Module-level variables: SAFE_MODE, ALLOW_WRITES
"""

import pytest
from dataclasses import fields

from scanning.modules.firebase_scanner import (
    Severity,
    FirebaseFinding,
    FirebaseScanResult,
    FirebaseScanner,
    SAFE_MODE,
    ALLOW_WRITES,
)


# =============================================================================
# Severity ENUM
# =============================================================================

class TestSeverityEnum:
    def test_member_count(self):
        assert len(Severity) == 5

    def test_critical_exists(self):
        assert hasattr(Severity, "CRITICAL")

    def test_high_exists(self):
        assert hasattr(Severity, "HIGH")

    def test_medium_exists(self):
        assert hasattr(Severity, "MEDIUM")

    def test_low_exists(self):
        assert hasattr(Severity, "LOW")

    def test_info_exists(self):
        assert hasattr(Severity, "INFO")

    def test_all_names(self):
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        actual = {m.name for m in Severity}
        assert actual == expected

    def test_all_values_unique(self):
        values = [m.value for m in Severity]
        assert len(values) == len(set(values))

    def test_ordering_by_value(self):
        """CRITICAL < HIGH < MEDIUM < LOW < INFO by auto() value."""
        assert Severity.CRITICAL.value < Severity.HIGH.value
        assert Severity.HIGH.value < Severity.MEDIUM.value
        assert Severity.MEDIUM.value < Severity.LOW.value
        assert Severity.LOW.value < Severity.INFO.value

    def test_is_not_findings_severity(self):
        """Ensure this is the local Severity, not from scanning.findings."""
        # The local Severity uses auto() which produces ints, not string values
        assert isinstance(Severity.CRITICAL.value, int)


# =============================================================================
# FirebaseFinding DATACLASS
# =============================================================================

class TestFirebaseFinding:
    def test_required_fields(self):
        """FirebaseFinding requires phase, title, severity, description."""
        finding = FirebaseFinding(
            phase="F1",
            title="Test Finding",
            severity=Severity.HIGH,
            description="A test finding.",
        )
        assert finding.phase == "F1"
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.description == "A test finding."

    def test_default_evidence(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW, description="D"
        )
        assert finding.evidence == ""

    def test_default_remediation(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW, description="D"
        )
        assert finding.remediation == ""

    def test_default_resource(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW, description="D"
        )
        assert finding.resource == ""

    def test_default_cwe(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW, description="D"
        )
        assert finding.cwe == ""

    def test_default_confidence(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW, description="D"
        )
        assert finding.confidence == 85.0

    def test_full_creation(self):
        """All fields explicitly set."""
        finding = FirebaseFinding(
            phase="F2",
            title="Public Collection",
            severity=Severity.CRITICAL,
            description="Collection is public.",
            evidence="Found 10 documents",
            remediation="Add security rules",
            resource="users",
            cwe="CWE-284",
            confidence=95.0,
        )
        assert finding.phase == "F2"
        assert finding.title == "Public Collection"
        assert finding.severity == Severity.CRITICAL
        assert finding.description == "Collection is public."
        assert finding.evidence == "Found 10 documents"
        assert finding.remediation == "Add security rules"
        assert finding.resource == "users"
        assert finding.cwe == "CWE-284"
        assert finding.confidence == 95.0

    def test_to_dict_returns_dict(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.HIGH, description="D"
        )
        result = finding.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_keys(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.HIGH, description="D"
        )
        result = finding.to_dict()
        expected_keys = {
            "phase", "title", "severity", "description",
            "evidence", "remediation", "resource", "cwe", "confidence",
        }
        assert set(result.keys()) == expected_keys

    def test_to_dict_severity_is_name_string(self):
        """severity in to_dict() output should be the enum name, not the enum itself."""
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.CRITICAL, description="D"
        )
        result = finding.to_dict()
        assert result["severity"] == "CRITICAL"
        assert isinstance(result["severity"], str)

    def test_to_dict_values(self):
        finding = FirebaseFinding(
            phase="F3",
            title="RTDB Open",
            severity=Severity.MEDIUM,
            description="RTDB is open.",
            evidence="data returned",
            remediation="Lock it down",
            resource="/users",
            cwe="CWE-284",
            confidence=70.0,
        )
        d = finding.to_dict()
        assert d["phase"] == "F3"
        assert d["title"] == "RTDB Open"
        assert d["severity"] == "MEDIUM"
        assert d["description"] == "RTDB is open."
        assert d["evidence"] == "data returned"
        assert d["remediation"] == "Lock it down"
        assert d["resource"] == "/users"
        assert d["cwe"] == "CWE-284"
        assert d["confidence"] == 70.0

    def test_to_dict_evidence_truncated_at_500(self):
        """Evidence longer than 500 chars should be truncated to 500."""
        long_evidence = "A" * 1000
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW,
            description="D", evidence=long_evidence,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500
        assert result["evidence"] == "A" * 500

    def test_to_dict_evidence_exactly_500_not_truncated(self):
        evidence_500 = "B" * 500
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW,
            description="D", evidence=evidence_500,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500
        assert result["evidence"] == evidence_500

    def test_to_dict_evidence_under_500_not_truncated(self):
        evidence_short = "C" * 100
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW,
            description="D", evidence=evidence_short,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 100

    def test_to_dict_empty_evidence(self):
        finding = FirebaseFinding(
            phase="F1", title="T", severity=Severity.LOW, description="D"
        )
        result = finding.to_dict()
        assert result["evidence"] == ""

    def test_field_count(self):
        """FirebaseFinding has exactly 9 fields."""
        assert len(fields(FirebaseFinding)) == 9


# =============================================================================
# FirebaseScanResult DATACLASS
# =============================================================================

class TestFirebaseScanResult:
    def test_default_findings(self):
        result = FirebaseScanResult()
        assert result.findings == []

    def test_default_collections_discovered(self):
        result = FirebaseScanResult()
        assert result.collections_discovered == []

    def test_default_storage_buckets(self):
        result = FirebaseScanResult()
        assert result.storage_buckets == []

    def test_default_exposed_data_paths(self):
        result = FirebaseScanResult()
        assert result.exposed_data_paths == []

    def test_field_count(self):
        """FirebaseScanResult has exactly 4 fields."""
        assert len(fields(FirebaseScanResult)) == 4

    def test_critical_count_empty(self):
        result = FirebaseScanResult()
        assert result.critical_count == 0

    def test_high_count_empty(self):
        result = FirebaseScanResult()
        assert result.high_count == 0

    def test_critical_count_with_findings(self):
        findings = [
            FirebaseFinding(phase="F1", title="A", severity=Severity.CRITICAL, description="D"),
            FirebaseFinding(phase="F2", title="B", severity=Severity.HIGH, description="D"),
            FirebaseFinding(phase="F3", title="C", severity=Severity.CRITICAL, description="D"),
            FirebaseFinding(phase="F4", title="D", severity=Severity.MEDIUM, description="D"),
            FirebaseFinding(phase="F1", title="E", severity=Severity.CRITICAL, description="D"),
        ]
        result = FirebaseScanResult(findings=findings)
        assert result.critical_count == 3

    def test_high_count_with_findings(self):
        findings = [
            FirebaseFinding(phase="F1", title="A", severity=Severity.HIGH, description="D"),
            FirebaseFinding(phase="F2", title="B", severity=Severity.HIGH, description="D"),
            FirebaseFinding(phase="F3", title="C", severity=Severity.CRITICAL, description="D"),
            FirebaseFinding(phase="F4", title="D", severity=Severity.LOW, description="D"),
        ]
        result = FirebaseScanResult(findings=findings)
        assert result.high_count == 2

    def test_mixed_severity_counts(self):
        """Test both critical_count and high_count with a realistic mix."""
        findings = [
            FirebaseFinding(phase="F1", title="Anon Auth", severity=Severity.MEDIUM, description="D"),
            FirebaseFinding(phase="F2", title="Public Write", severity=Severity.CRITICAL, description="D"),
            FirebaseFinding(phase="F3", title="RTDB Open Root", severity=Severity.CRITICAL, description="D"),
            FirebaseFinding(phase="F3", title="RTDB Open Users", severity=Severity.HIGH, description="D"),
            FirebaseFinding(phase="F4", title="Storage Listing", severity=Severity.MEDIUM, description="D"),
            FirebaseFinding(phase="F4", title="Storage Upload", severity=Severity.HIGH, description="D"),
            FirebaseFinding(phase="F1", title="Info", severity=Severity.INFO, description="D"),
        ]
        result = FirebaseScanResult(findings=findings)
        assert result.critical_count == 2
        assert result.high_count == 2

    def test_critical_count_is_property(self):
        """critical_count is a property, not a plain attribute."""
        assert isinstance(
            FirebaseScanResult.__dict__["critical_count"], property
        )

    def test_high_count_is_property(self):
        """high_count is a property, not a plain attribute."""
        assert isinstance(
            FirebaseScanResult.__dict__["high_count"], property
        )

    def test_lists_are_independent_across_instances(self):
        """Default factory ensures each instance has its own lists."""
        r1 = FirebaseScanResult()
        r2 = FirebaseScanResult()
        r1.collections_discovered.append("users")
        assert r2.collections_discovered == []


# =============================================================================
# FirebaseScanner CLASS ATTRIBUTES
# =============================================================================

class TestFirebaseScannerAttributes:
    def test_common_collections_count(self):
        assert len(FirebaseScanner.COMMON_COLLECTIONS) == 19

    def test_common_collections_is_list(self):
        assert isinstance(FirebaseScanner.COMMON_COLLECTIONS, list)

    def test_common_collections_contains_users(self):
        assert "users" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_profiles(self):
        assert "profiles" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_accounts(self):
        assert "accounts" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_posts(self):
        assert "posts" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_comments(self):
        assert "comments" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_orders(self):
        assert "orders" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_products(self):
        assert "products" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_payments(self):
        assert "payments" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_messages(self):
        assert "messages" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_chats(self):
        assert "chats" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_notifications(self):
        assert "notifications" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_settings(self):
        assert "settings" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_configs(self):
        assert "configs" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_documents(self):
        assert "documents" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_admins(self):
        assert "admins" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_roles(self):
        assert "roles" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_permissions(self):
        assert "permissions" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_logs(self):
        assert "logs" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_contains_events(self):
        assert "events" in FirebaseScanner.COMMON_COLLECTIONS

    def test_common_collections_all_strings(self):
        for item in FirebaseScanner.COMMON_COLLECTIONS:
            assert isinstance(item, str)

    def test_common_collections_no_duplicates(self):
        assert len(FirebaseScanner.COMMON_COLLECTIONS) == len(
            set(FirebaseScanner.COMMON_COLLECTIONS)
        )

    def test_common_rtdb_paths_count(self):
        """COMMON_RTDB_PATHS has 12 entries (including the empty string for root)."""
        assert len(FirebaseScanner.COMMON_RTDB_PATHS) == 12

    def test_common_rtdb_paths_is_list(self):
        assert isinstance(FirebaseScanner.COMMON_RTDB_PATHS, list)

    def test_common_rtdb_paths_contains_empty_string(self):
        """Empty string represents the root path."""
        assert "" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_users(self):
        assert "users" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_messages(self):
        assert "messages" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_posts(self):
        assert "posts" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_data(self):
        assert "data" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_admin(self):
        assert "admin" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_config(self):
        assert "config" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_settings(self):
        assert "settings" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_public(self):
        assert "public" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_private(self):
        assert "private" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_logs(self):
        assert "logs" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_contains_analytics(self):
        assert "analytics" in FirebaseScanner.COMMON_RTDB_PATHS

    def test_common_rtdb_paths_all_strings(self):
        for item in FirebaseScanner.COMMON_RTDB_PATHS:
            assert isinstance(item, str)

    def test_not_a_scan_module_subclass(self):
        """FirebaseScanner is standalone, not a ScanModule subclass."""
        mro_names = [cls.__name__ for cls in FirebaseScanner.__mro__]
        assert "ScanModule" not in mro_names

    def test_has_scan_method(self):
        assert hasattr(FirebaseScanner, "scan")
        assert callable(getattr(FirebaseScanner, "scan"))


# =============================================================================
# MODULE-LEVEL VARIABLES
# =============================================================================

class TestModuleLevelVariables:
    def test_safe_mode_is_string(self):
        assert isinstance(SAFE_MODE, str)

    def test_safe_mode_is_lowercase(self):
        assert SAFE_MODE == SAFE_MODE.lower()

    def test_allow_writes_is_bool(self):
        assert isinstance(ALLOW_WRITES, bool)

    def test_allow_writes_consistent_with_safe_mode(self):
        """ALLOW_WRITES should be True only when SAFE_MODE is 'standard' or 'aggressive'."""
        expected = SAFE_MODE in ("standard", "aggressive")
        assert ALLOW_WRITES == expected
