"""
Tests for scanning/modules/advanced_rls_bypass_scanner.py

Covers:
- RLSBypassFinding dataclass (fields, defaults, to_dict, evidence truncation)
- RLSBypassResult dataclass (defaults, critical_count property)
- AdvancedRLSBypassScanner class constants (TIMING_THRESHOLD, TIMING_SAMPLES,
  SUPABASE_BYPASS_PAYLOADS, RPC_BYPASS_FUNCTIONS, FILTER_BYPASS_PAYLOADS)
- Scanner identity (name-less standalone class, NOT ScanModule subclass)
- Module-level convenience function (scan_rls_bypass)
"""

import pytest
from scanning.modules.advanced_rls_bypass_scanner import (
    RLSBypassFinding,
    RLSBypassResult,
    AdvancedRLSBypassScanner,
    scan_rls_bypass,
)


# =============================================================================
# RLSBYPASSFINDING DATACLASS TESTS
# =============================================================================

class TestRLSBypassFinding:
    """Test RLSBypassFinding dataclass."""

    def test_required_fields(self):
        finding = RLSBypassFinding(
            url="http://test.local/api",
            technique="JOIN-bypass",
            severity="CRITICAL",
            title="JOIN-based RLS bypass on users",
            description="Joining users with orders returned more rows.",
        )
        assert finding.url == "http://test.local/api"
        assert finding.technique == "JOIN-bypass"
        assert finding.severity == "CRITICAL"
        assert finding.title == "JOIN-based RLS bypass on users"
        assert finding.description == "Joining users with orders returned more rows."

    def test_default_payload(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        assert finding.payload == ""

    def test_default_evidence(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        assert finding.evidence == ""

    def test_default_remediation(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        assert finding.remediation == ""

    def test_default_cwe(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        assert finding.cwe == "CWE-863"

    def test_default_confidence(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        assert finding.confidence == 90.0

    def test_custom_confidence(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="MEDIUM",
            title="T",
            description="D",
            confidence=55.5,
        )
        assert finding.confidence == 55.5

    def test_custom_cwe(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="LOW",
            title="T",
            description="D",
            cwe="CWE-200",
        )
        assert finding.cwe == "CWE-200"

    # ---- to_dict tests ----

    def test_to_dict_returns_dict(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        result = finding.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_type_field(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="RPC-bypass",
            severity="CRITICAL",
            title="T",
            description="D",
        )
        result = finding.to_dict()
        assert result["type"] == "RLS_BYPASS"

    def test_to_dict_all_keys_present(self):
        finding = RLSBypassFinding(
            url="http://test.local/api",
            technique="JOIN-bypass",
            severity="CRITICAL",
            title="Test Title",
            description="Test Description",
            payload="select=*,orders(*)",
            evidence="Normal: 3 rows, JOIN: 10 rows",
            remediation="Apply RLS policies.",
            cwe="CWE-863",
            confidence=95.0,
        )
        result = finding.to_dict()
        expected_keys = {
            "type", "url", "technique", "severity", "title",
            "description", "payload", "evidence", "remediation",
            "cwe", "confidence",
        }
        assert set(result.keys()) == expected_keys

    def test_to_dict_values(self):
        finding = RLSBypassFinding(
            url="http://test.local/rest/v1/users",
            technique="filter-bypass",
            severity="HIGH",
            title="Filter bypass on users",
            description="Filter returned more rows than baseline.",
            payload='{"or": "(id.gt.0)"}',
            evidence="Baseline: 5, With filter: 20",
            remediation="Ensure RLS policies are applied.",
            cwe="CWE-863",
            confidence=88.0,
        )
        result = finding.to_dict()
        assert result["url"] == "http://test.local/rest/v1/users"
        assert result["technique"] == "filter-bypass"
        assert result["severity"] == "HIGH"
        assert result["title"] == "Filter bypass on users"
        assert result["description"] == "Filter returned more rows than baseline."
        assert result["payload"] == '{"or": "(id.gt.0)"}'
        assert result["evidence"] == "Baseline: 5, With filter: 20"
        assert result["remediation"] == "Ensure RLS policies are applied."
        assert result["cwe"] == "CWE-863"
        assert result["confidence"] == 88.0

    def test_to_dict_evidence_truncated_at_500(self):
        long_evidence = "X" * 1000
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
            evidence=long_evidence,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500

    def test_to_dict_evidence_exactly_500_not_truncated(self):
        evidence_500 = "Y" * 500
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
            evidence=evidence_500,
        )
        result = finding.to_dict()
        assert len(result["evidence"]) == 500
        assert result["evidence"] == evidence_500

    def test_to_dict_evidence_under_500_not_truncated(self):
        evidence_short = "Z" * 100
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
            evidence=evidence_short,
        )
        result = finding.to_dict()
        assert result["evidence"] == evidence_short

    def test_to_dict_empty_evidence_remains_empty(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
            evidence="",
        )
        result = finding.to_dict()
        assert result["evidence"] == ""

    def test_to_dict_no_evidence_default_empty(self):
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        )
        result = finding.to_dict()
        assert result["evidence"] == ""


# =============================================================================
# RLSBYPASSRESULT DATACLASS TESTS
# =============================================================================

class TestRLSBypassResult:
    """Test RLSBypassResult dataclass."""

    def test_default_findings_empty(self):
        result = RLSBypassResult()
        assert result.findings == []

    def test_default_techniques_tested(self):
        result = RLSBypassResult()
        assert result.techniques_tested == 0

    def test_default_timing_samples(self):
        result = RLSBypassResult()
        assert result.timing_samples == 0

    def test_findings_list_independence(self):
        """Each instance must have its own findings list."""
        r1 = RLSBypassResult()
        r2 = RLSBypassResult()
        r1.findings.append("something")
        assert r2.findings == []

    def test_critical_count_zero_when_empty(self):
        result = RLSBypassResult()
        assert result.critical_count == 0

    def test_critical_count_counts_only_critical(self):
        result = RLSBypassResult()
        result.findings.append(RLSBypassFinding(
            url="http://test.local",
            technique="JOIN-bypass",
            severity="CRITICAL",
            title="C1",
            description="D",
        ))
        result.findings.append(RLSBypassFinding(
            url="http://test.local",
            technique="filter-bypass",
            severity="HIGH",
            title="H1",
            description="D",
        ))
        result.findings.append(RLSBypassFinding(
            url="http://test.local",
            technique="RPC-bypass",
            severity="CRITICAL",
            title="C2",
            description="D",
        ))
        assert result.critical_count == 2

    def test_critical_count_ignores_non_critical(self):
        result = RLSBypassResult()
        for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            result.findings.append(RLSBypassFinding(
                url="http://test.local",
                technique="t",
                severity=sev,
                title="T",
                description="D",
            ))
        assert result.critical_count == 0

    def test_critical_count_all_critical(self):
        result = RLSBypassResult()
        for i in range(5):
            result.findings.append(RLSBypassFinding(
                url="http://test.local",
                technique="t",
                severity="CRITICAL",
                title=f"C{i}",
                description="D",
            ))
        assert result.critical_count == 5

    def test_techniques_tested_mutable(self):
        result = RLSBypassResult()
        result.techniques_tested = 7
        assert result.techniques_tested == 7

    def test_timing_samples_mutable(self):
        result = RLSBypassResult()
        result.timing_samples = 25
        assert result.timing_samples == 25


# =============================================================================
# SCANNER CLASS CONSTANTS
# =============================================================================

class TestAdvancedRLSBypassScannerConstants:
    """Test AdvancedRLSBypassScanner class-level constants."""

    def test_timing_threshold(self):
        assert AdvancedRLSBypassScanner.TIMING_THRESHOLD == 0.5

    def test_timing_threshold_is_float(self):
        assert isinstance(AdvancedRLSBypassScanner.TIMING_THRESHOLD, float)

    def test_timing_samples(self):
        assert AdvancedRLSBypassScanner.TIMING_SAMPLES == 5

    def test_timing_samples_is_int(self):
        assert isinstance(AdvancedRLSBypassScanner.TIMING_SAMPLES, int)


# =============================================================================
# SUPABASE_BYPASS_PAYLOADS
# =============================================================================

class TestSupabaseBypassPayloads:
    """Test SUPABASE_BYPASS_PAYLOADS class constant."""

    def test_is_list(self):
        assert isinstance(AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS, list)

    def test_count(self):
        assert len(AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS) == 8

    def test_all_are_dicts(self):
        for payload in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS:
            assert isinstance(payload, dict)

    def test_all_have_select_key(self):
        for payload in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS:
            assert "select" in payload

    def test_has_join_inner_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("!inner" in s for s in selects)

    def test_has_function_call_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("get_all_rows()" in s for s in selects)

    def test_has_rpc_bypass_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("rpc_bypass()" in s for s in selects)

    def test_has_view_reference_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("all_data_view" in s for s in selects)

    def test_has_aggregate_count_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("count(*)" in s for s in selects)

    def test_has_array_agg_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("array_agg(*)" in s for s in selects)

    def test_has_json_agg_payload(self):
        selects = [p["select"] for p in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS]
        assert any("json_agg(*)" in s for s in selects)


# =============================================================================
# RPC_BYPASS_FUNCTIONS
# =============================================================================

class TestRPCBypassFunctions:
    """Test RPC_BYPASS_FUNCTIONS class constant."""

    def test_is_list(self):
        assert isinstance(AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS, list)

    def test_count(self):
        assert len(AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS) == 7

    def test_all_strings(self):
        for func in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS:
            assert isinstance(func, str)

    def test_has_get_all_users(self):
        assert "get_all_users" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_has_get_all_data(self):
        assert "get_all_data" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_has_admin_query(self):
        assert "admin_query" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_has_bypass_rls(self):
        assert "bypass_rls" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_has_fetch_all(self):
        assert "fetch_all" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_has_internal_query(self):
        assert "internal_query" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_has_debug_query(self):
        assert "debug_query" in AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS

    def test_all_unique(self):
        funcs = AdvancedRLSBypassScanner.RPC_BYPASS_FUNCTIONS
        assert len(funcs) == len(set(funcs))


# =============================================================================
# FILTER_BYPASS_PAYLOADS
# =============================================================================

class TestFilterBypassPayloads:
    """Test FILTER_BYPASS_PAYLOADS class constant."""

    def test_is_list(self):
        assert isinstance(AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS, list)

    def test_count(self):
        assert len(AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS) == 7

    def test_all_are_dicts(self):
        for payload in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS:
            assert isinstance(payload, dict)

    def test_has_or_condition(self):
        or_payloads = [p for p in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS if "or" in p]
        assert len(or_payloads) >= 2

    def test_has_not_condition(self):
        not_payloads = [p for p in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS if any("not." in k for k in p)]
        assert len(not_payloads) >= 1

    def test_has_range_exploit_gte(self):
        range_payloads = [p for p in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS if p.get("id") == "gte.0"]
        assert len(range_payloads) == 1

    def test_has_range_exploit_in(self):
        in_payloads = [p for p in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS if "id" in p and "in." in str(p.get("id", ""))]
        assert len(in_payloads) == 1

    def test_has_array_cs_operation(self):
        cs_payloads = [p for p in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS if p.get("ids", "").startswith("cs.")]
        assert len(cs_payloads) == 1

    def test_has_array_ov_operation(self):
        ov_payloads = [p for p in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS if p.get("ids", "").startswith("ov.")]
        assert len(ov_payloads) == 1


# =============================================================================
# SCANNER CLASS IDENTITY
# =============================================================================

class TestAdvancedRLSBypassScannerIdentity:
    """Test AdvancedRLSBypassScanner class identity and structure."""

    def test_not_scanmodule_subclass(self):
        """AdvancedRLSBypassScanner is a standalone class, not ScanModule."""
        mro_names = [c.__name__ for c in AdvancedRLSBypassScanner.__mro__]
        assert "ScanModule" not in mro_names

    def test_instantiation_without_settings(self):
        scanner = AdvancedRLSBypassScanner()
        assert scanner.settings is None

    def test_instantiation_with_settings(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = AdvancedRLSBypassScanner(settings=settings)
        assert scanner.settings == settings

    def test_result_initialized(self):
        scanner = AdvancedRLSBypassScanner()
        assert isinstance(scanner.result, RLSBypassResult)
        assert scanner.result.findings == []

    def test_timeout_initialized(self):
        scanner = AdvancedRLSBypassScanner()
        assert scanner.timeout is not None
        assert scanner.timeout.connect == 20.0

    def test_has_scan_method(self):
        assert hasattr(AdvancedRLSBypassScanner, "scan")
        assert callable(getattr(AdvancedRLSBypassScanner, "scan"))

    def test_has_test_supabase_join_bypass_method(self):
        assert hasattr(AdvancedRLSBypassScanner, "_test_supabase_join_bypass")

    def test_has_test_supabase_rpc_bypass_method(self):
        assert hasattr(AdvancedRLSBypassScanner, "_test_supabase_rpc_bypass")

    def test_has_test_supabase_filter_bypass_method(self):
        assert hasattr(AdvancedRLSBypassScanner, "_test_supabase_filter_bypass")

    def test_has_test_timing_enumeration_method(self):
        assert hasattr(AdvancedRLSBypassScanner, "_test_timing_enumeration")

    def test_has_test_generic_rls_bypass_method(self):
        assert hasattr(AdvancedRLSBypassScanner, "_test_generic_rls_bypass")


# =============================================================================
# MODULE-LEVEL CONVENIENCE FUNCTION
# =============================================================================

class TestScanRLSBypassFunction:
    """Test the module-level scan_rls_bypass convenience function."""

    def test_exists(self):
        assert scan_rls_bypass is not None

    def test_is_callable(self):
        assert callable(scan_rls_bypass)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and cross-cutting concerns."""

    def test_finding_to_dict_preserves_type_field(self):
        """to_dict always includes type=RLS_BYPASS regardless of technique."""
        for technique in ["JOIN-bypass", "RPC-bypass", "filter-bypass", "timing-enumeration", "parameter-bypass"]:
            finding = RLSBypassFinding(
                url="http://test.local",
                technique=technique,
                severity="HIGH",
                title="T",
                description="D",
            )
            assert finding.to_dict()["type"] == "RLS_BYPASS"

    def test_finding_to_dict_technique_preserved(self):
        """to_dict preserves technique value exactly."""
        finding = RLSBypassFinding(
            url="http://test.local",
            technique="JOIN-data-leak",
            severity="HIGH",
            title="T",
            description="D",
        )
        assert finding.to_dict()["technique"] == "JOIN-data-leak"

    def test_multiple_scanners_have_independent_results(self):
        """Two scanner instances must not share result state."""
        s1 = AdvancedRLSBypassScanner()
        s2 = AdvancedRLSBypassScanner()
        s1.result.findings.append(RLSBypassFinding(
            url="http://test.local",
            technique="t",
            severity="HIGH",
            title="T",
            description="D",
        ))
        assert len(s2.result.findings) == 0

    def test_result_critical_count_is_property(self):
        """critical_count should be a property, not a plain attribute."""
        assert isinstance(
            RLSBypassResult.critical_count,
            property,
        )

    def test_all_supabase_payloads_select_values_are_strings(self):
        for payload in AdvancedRLSBypassScanner.SUPABASE_BYPASS_PAYLOADS:
            assert isinstance(payload["select"], str)

    def test_all_filter_payloads_values_are_strings(self):
        for payload in AdvancedRLSBypassScanner.FILTER_BYPASS_PAYLOADS:
            for value in payload.values():
                assert isinstance(value, str)
