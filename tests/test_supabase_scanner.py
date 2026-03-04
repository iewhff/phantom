"""
Tests for scanning/modules/supabase_scanner.py

Covers:
- Severity enum (5 members)
- SupabaseFinding dataclass (fields, defaults, to_dict)
- SupabaseScanResult dataclass (list fields, critical_count, high_count)
- SupabaseScanner class attributes (name, COMMON_TABLES, COMMON_BUCKETS, RLS_BYPASS_PAYLOADS)
- Module-level variables: SAFE_MODE, ALLOW_WRITES
"""

import pytest
from scanning.modules.supabase_scanner import (
    Severity,
    SupabaseFinding,
    SupabaseScanResult,
    SupabaseScanner,
    SAFE_MODE,
    ALLOW_WRITES,
)


# =============================================================================
# SEVERITY ENUM TESTS
# =============================================================================

class TestSeverity:
    """Test Severity enum."""

    def test_member_count(self):
        assert len(Severity) == 5

    def test_critical_exists(self):
        assert Severity.CRITICAL is not None

    def test_high_exists(self):
        assert Severity.HIGH is not None

    def test_medium_exists(self):
        assert Severity.MEDIUM is not None

    def test_low_exists(self):
        assert Severity.LOW is not None

    def test_info_exists(self):
        assert Severity.INFO is not None

    def test_members_are_distinct(self):
        values = [s.value for s in Severity]
        assert len(values) == len(set(values))

    def test_ordering_critical_first(self):
        members = list(Severity)
        assert members[0] is Severity.CRITICAL
        assert members[1] is Severity.HIGH
        assert members[2] is Severity.MEDIUM
        assert members[3] is Severity.LOW
        assert members[4] is Severity.INFO


# =============================================================================
# SUPABASEFINDING DATACLASS TESTS
# =============================================================================

class TestSupabaseFinding:
    """Test SupabaseFinding dataclass."""

    def test_required_fields(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="Test Finding",
            severity=Severity.HIGH,
            description="A test description",
        )
        assert finding.phase == "FASE_2"
        assert finding.title == "Test Finding"
        assert finding.severity is Severity.HIGH
        assert finding.description == "A test description"

    def test_default_evidence(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
        )
        assert finding.evidence == ""

    def test_default_remediation(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
        )
        assert finding.remediation == ""

    def test_default_table_or_bucket(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
        )
        assert finding.table_or_bucket == ""

    def test_default_cwe(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
        )
        assert finding.cwe == ""

    def test_default_confidence(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
        )
        assert finding.confidence == 85.0

    def test_custom_confidence(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
            confidence=42.5,
        )
        assert finding.confidence == 42.5

    def test_to_dict_returns_dict(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="Test",
            severity=Severity.CRITICAL,
            description="Desc",
        )
        result = finding.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_severity_is_name(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="Test",
            severity=Severity.CRITICAL,
            description="Desc",
        )
        result = finding.to_dict()
        assert result["severity"] == "CRITICAL"

    def test_to_dict_severity_high_name(self):
        finding = SupabaseFinding(
            phase="FASE_3",
            title="Test",
            severity=Severity.HIGH,
            description="Desc",
        )
        result = finding.to_dict()
        assert result["severity"] == "HIGH"

    def test_to_dict_all_keys_present(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="Test",
            severity=Severity.MEDIUM,
            description="Desc",
            evidence="ev",
            remediation="fix",
            table_or_bucket="users",
            cwe="CWE-284",
            confidence=90.0,
        )
        result = finding.to_dict()
        expected_keys = {
            "phase", "title", "severity", "description",
            "evidence", "remediation", "table_or_bucket",
            "cwe", "confidence",
        }
        assert set(result.keys()) == expected_keys

    def test_to_dict_values(self):
        finding = SupabaseFinding(
            phase="FASE_4",
            title="Edge Func",
            severity=Severity.INFO,
            description="Info finding",
            evidence="some evidence",
            remediation="do nothing",
            table_or_bucket="my_func",
            cwe="CWE-200",
            confidence=50.0,
        )
        result = finding.to_dict()
        assert result["phase"] == "FASE_4"
        assert result["title"] == "Edge Func"
        assert result["description"] == "Info finding"
        assert result["evidence"] == "some evidence"
        assert result["remediation"] == "do nothing"
        assert result["table_or_bucket"] == "my_func"
        assert result["cwe"] == "CWE-200"
        assert result["confidence"] == 50.0

    def test_to_dict_evidence_truncated_at_500(self):
        long_evidence = "A" * 1000
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
            evidence=long_evidence,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500

    def test_to_dict_evidence_exactly_500_not_truncated(self):
        evidence_500 = "B" * 500
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
            evidence=evidence_500,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500
        assert result["evidence"] == evidence_500

    def test_to_dict_evidence_under_500_not_truncated(self):
        evidence_short = "C" * 100
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
            evidence=evidence_short,
        )
        result = finding.to_dict()
        assert result["evidence"] == evidence_short

    def test_to_dict_empty_evidence_remains_empty(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
            evidence="",
        )
        result = finding.to_dict()
        assert result["evidence"] == ""

    def test_to_dict_no_evidence_default_empty(self):
        finding = SupabaseFinding(
            phase="FASE_2",
            title="T",
            severity=Severity.LOW,
            description="D",
        )
        result = finding.to_dict()
        assert result["evidence"] == ""


# =============================================================================
# SUPABASESCANRESULT DATACLASS TESTS
# =============================================================================

class TestSupabaseScanResult:
    """Test SupabaseScanResult dataclass."""

    def test_default_findings_empty(self):
        result = SupabaseScanResult()
        assert result.findings == []

    def test_default_tables_discovered_empty(self):
        result = SupabaseScanResult()
        assert result.tables_discovered == []

    def test_default_buckets_discovered_empty(self):
        result = SupabaseScanResult()
        assert result.buckets_discovered == []

    def test_default_edge_functions_empty(self):
        result = SupabaseScanResult()
        assert result.edge_functions == []

    def test_default_realtime_channels_empty(self):
        result = SupabaseScanResult()
        assert result.realtime_channels == []

    def test_all_five_list_fields_independent(self):
        """Each list field must be an independent instance."""
        r1 = SupabaseScanResult()
        r2 = SupabaseScanResult()
        r1.findings.append("something")
        assert r2.findings == []

    def test_critical_count_zero_when_empty(self):
        result = SupabaseScanResult()
        assert result.critical_count == 0

    def test_high_count_zero_when_empty(self):
        result = SupabaseScanResult()
        assert result.high_count == 0

    def test_critical_count_counts_only_critical(self):
        result = SupabaseScanResult()
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="C1", severity=Severity.CRITICAL, description="D",
        ))
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="H1", severity=Severity.HIGH, description="D",
        ))
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="C2", severity=Severity.CRITICAL, description="D",
        ))
        assert result.critical_count == 2

    def test_high_count_counts_only_high(self):
        result = SupabaseScanResult()
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="H1", severity=Severity.HIGH, description="D",
        ))
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="M1", severity=Severity.MEDIUM, description="D",
        ))
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="H2", severity=Severity.HIGH, description="D",
        ))
        result.findings.append(SupabaseFinding(
            phase="FASE_2", title="H3", severity=Severity.HIGH, description="D",
        ))
        assert result.high_count == 3

    def test_critical_count_ignores_other_severities(self):
        result = SupabaseScanResult()
        for sev in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            result.findings.append(SupabaseFinding(
                phase="F", title="T", severity=sev, description="D",
            ))
        assert result.critical_count == 0

    def test_high_count_ignores_other_severities(self):
        result = SupabaseScanResult()
        for sev in [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            result.findings.append(SupabaseFinding(
                phase="F", title="T", severity=sev, description="D",
            ))
        assert result.high_count == 0


# =============================================================================
# SUPABASESCANNER CLASS TESTS
# =============================================================================

class TestSupabaseScanner:
    """Test SupabaseScanner class attributes."""

    def test_not_scanmodule_subclass(self):
        """SupabaseScanner must NOT inherit from ScanModule."""
        from scanning.modules.supabase_scanner import SupabaseScanner as Cls
        mro_names = [c.__name__ for c in Cls.__mro__]
        assert "ScanModule" not in mro_names

    def test_name_is_supabase(self):
        assert SupabaseScanner.name == "supabase"

    def test_common_tables_count(self):
        assert len(SupabaseScanner.COMMON_TABLES) == 25

    def test_common_tables_is_list(self):
        assert isinstance(SupabaseScanner.COMMON_TABLES, list)

    def test_common_tables_all_strings(self):
        for table in SupabaseScanner.COMMON_TABLES:
            assert isinstance(table, str)

    def test_common_tables_contains_users(self):
        assert "users" in SupabaseScanner.COMMON_TABLES

    def test_common_tables_contains_admin(self):
        assert "admin" in SupabaseScanner.COMMON_TABLES

    def test_common_tables_contains_permissions(self):
        assert "permissions" in SupabaseScanner.COMMON_TABLES

    def test_common_buckets_count(self):
        assert len(SupabaseScanner.COMMON_BUCKETS) == 15

    def test_common_buckets_is_list(self):
        assert isinstance(SupabaseScanner.COMMON_BUCKETS, list)

    def test_common_buckets_all_strings(self):
        for bucket in SupabaseScanner.COMMON_BUCKETS:
            assert isinstance(bucket, str)

    def test_common_buckets_contains_avatars(self):
        assert "avatars" in SupabaseScanner.COMMON_BUCKETS

    def test_common_buckets_contains_backups(self):
        assert "backups" in SupabaseScanner.COMMON_BUCKETS

    def test_rls_bypass_payloads_count(self):
        assert len(SupabaseScanner.RLS_BYPASS_PAYLOADS) == 5

    def test_rls_bypass_payloads_is_list(self):
        assert isinstance(SupabaseScanner.RLS_BYPASS_PAYLOADS, list)

    def test_rls_bypass_payloads_all_dicts(self):
        for payload in SupabaseScanner.RLS_BYPASS_PAYLOADS:
            assert isinstance(payload, dict)

    def test_rls_bypass_payloads_id_manipulation(self):
        """First payload should be basic UUID ID manipulation."""
        first = SupabaseScanner.RLS_BYPASS_PAYLOADS[0]
        assert "id" in first

    def test_rls_bypass_payloads_filter_bypass(self):
        """Should include an 'or' filter bypass payload."""
        or_payloads = [p for p in SupabaseScanner.RLS_BYPASS_PAYLOADS if "or" in p]
        assert len(or_payloads) >= 1

    def test_rls_bypass_payloads_array_manipulation(self):
        """Should include an array-based payload."""
        array_payloads = [p for p in SupabaseScanner.RLS_BYPASS_PAYLOADS if "ids" in p]
        assert len(array_payloads) >= 1


# =============================================================================
# MODULE-LEVEL VARIABLE TESTS
# =============================================================================

class TestModuleVariables:
    """Test module-level variables SAFE_MODE and ALLOW_WRITES."""

    def test_safe_mode_is_string(self):
        assert isinstance(SAFE_MODE, str)

    def test_safe_mode_is_lowercase(self):
        assert SAFE_MODE == SAFE_MODE.lower()

    def test_allow_writes_is_bool(self):
        assert isinstance(ALLOW_WRITES, bool)

    def test_allow_writes_consistent_with_safe_mode(self):
        """ALLOW_WRITES should be True only when SAFE_MODE is standard or aggressive."""
        expected = SAFE_MODE in ("standard", "aggressive")
        assert ALLOW_WRITES == expected
