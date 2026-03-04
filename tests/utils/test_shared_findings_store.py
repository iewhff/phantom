"""
Tests for utils/shared_findings_store.py - Cross-module finding sharing.

Covers:
- VulnType enum mapping
- ExtractedData and SharedFinding dataclasses
- SharedFindingsStore singleton pattern
- Finding indexing and querying
- Extracted data sharing (THEME-4)
- Amplification hints
"""

import pytest
import asyncio
from datetime import datetime

from utils.shared_findings_store import (
    VulnType,
    ExtractedData,
    SharedFinding,
    SharedFindingsStore,
    get_shared_findings,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def store():
    """Get a fresh store instance for each test."""
    SharedFindingsStore.reset()
    return SharedFindingsStore.get_instance()


@pytest.fixture
async def store_with_findings(store):
    """Store pre-populated with sample findings."""
    await store.add_finding(
        {"type": "sql_injection", "endpoint": "/api/users", "parameter": "id", "severity": "CRITICAL"},
        module="sqli"
    )
    await store.add_finding(
        {"type": "xss", "endpoint": "/search", "parameter": "q", "severity": "MEDIUM"},
        module="xss"
    )
    await store.add_finding(
        {"type": "idor", "endpoint": "/api/users", "parameter": "user_id", "severity": "HIGH"},
        module="authz"
    )
    return store


# =============================================================================
# VULNTYPE ENUM TESTS
# =============================================================================

class TestVulnType:
    """Tests for VulnType enum."""

    def test_injection_types_exist(self):
        """Test that all injection types are defined."""
        assert VulnType.SQL_INJECTION
        assert VulnType.NOSQL_INJECTION
        assert VulnType.COMMAND_INJECTION
        assert VulnType.LDAP_INJECTION
        assert VulnType.XPATH_INJECTION
        assert VulnType.CRLF_INJECTION

    def test_xss_types_exist(self):
        """Test XSS-related types."""
        assert VulnType.XSS
        assert VulnType.DOM_XSS

    def test_file_types_exist(self):
        """Test file-related vulnerability types."""
        assert VulnType.LFI
        assert VulnType.RFI
        assert VulnType.FILE_UPLOAD
        assert VulnType.XXE

    def test_server_side_types_exist(self):
        """Test server-side vulnerability types."""
        assert VulnType.SSRF
        assert VulnType.SSTI
        assert VulnType.DESERIALIZATION

    def test_access_control_types_exist(self):
        """Test access control vulnerability types."""
        assert VulnType.IDOR
        assert VulnType.AUTH_BYPASS
        assert VulnType.BROKEN_ACCESS_CONTROL

    def test_other_type_exists(self):
        """Test fallback type exists."""
        assert VulnType.OTHER


# =============================================================================
# EXTRACTED DATA TESTS
# =============================================================================

class TestExtractedData:
    """Tests for ExtractedData dataclass."""

    def test_creation_minimal(self):
        """Test creating ExtractedData with minimal fields."""
        data = ExtractedData(
            data_type="credentials",
            source_module="sqli",
            source_endpoint="/api/users"
        )

        assert data.data_type == "credentials"
        assert data.source_module == "sqli"
        assert data.source_endpoint == "/api/users"
        assert data.values == []
        assert data.context == {}
        assert data.consumed_by == []

    def test_creation_with_values(self):
        """Test creating ExtractedData with values."""
        creds = [{"username": "admin", "password": "secret"}]
        data = ExtractedData(
            data_type="credentials",
            source_module="sqli",
            source_endpoint="/api/users",
            values=creds,
            context={"database": "mysql"}
        )

        assert data.values == creds
        assert data.context["database"] == "mysql"

    def test_timestamp_auto_generated(self):
        """Test that timestamp is auto-generated."""
        data = ExtractedData(
            data_type="tokens",
            source_module="xss",
            source_endpoint="/dashboard"
        )

        assert isinstance(data.timestamp, datetime)


# =============================================================================
# SHARED FINDING TESTS
# =============================================================================

class TestSharedFinding:
    """Tests for SharedFinding dataclass."""

    def test_creation(self):
        """Test creating a SharedFinding."""
        finding = SharedFinding(
            type="sql_injection",
            endpoint="/api/users",
            parameter="id",
            severity="CRITICAL",
            module="sqli"
        )

        assert finding.type == "sql_injection"
        assert finding.endpoint == "/api/users"
        assert finding.parameter == "id"
        assert finding.severity == "CRITICAL"
        assert finding.module == "sqli"

    def test_timestamp_auto_generated(self):
        """Test that timestamp is auto-generated."""
        finding = SharedFinding(
            type="xss",
            endpoint="/search",
            parameter="q",
            severity="MEDIUM",
            module="xss"
        )

        assert isinstance(finding.timestamp, datetime)

    def test_vuln_type_property_sqli(self):
        """Test vuln_type property for SQL injection variants."""
        assert SharedFinding(type="sql_injection", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION
        assert SharedFinding(type="sqli", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION
        assert SharedFinding(type="blind_sqli", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION
        assert SharedFinding(type="error_based_sqli", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION
        assert SharedFinding(type="union_sqli", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION
        assert SharedFinding(type="time_based_sqli", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION

    def test_vuln_type_property_xss(self):
        """Test vuln_type property for XSS variants."""
        assert SharedFinding(type="xss", endpoint="/", parameter=None, severity="MEDIUM", module="test").vuln_type == VulnType.XSS
        assert SharedFinding(type="reflected_xss", endpoint="/", parameter=None, severity="MEDIUM", module="test").vuln_type == VulnType.XSS
        assert SharedFinding(type="stored_xss", endpoint="/", parameter=None, severity="MEDIUM", module="test").vuln_type == VulnType.XSS

    def test_vuln_type_property_dom_xss(self):
        """Test vuln_type property for DOM XSS (separate type)."""
        assert SharedFinding(type="dom_xss", endpoint="/", parameter=None, severity="MEDIUM", module="test").vuln_type == VulnType.DOM_XSS
        assert SharedFinding(type="dom_based_xss", endpoint="/", parameter=None, severity="MEDIUM", module="test").vuln_type == VulnType.DOM_XSS

    def test_vuln_type_property_cmdi(self):
        """Test vuln_type property for command injection."""
        assert SharedFinding(type="command_injection", endpoint="/", parameter=None, severity="CRITICAL", module="test").vuln_type == VulnType.COMMAND_INJECTION
        assert SharedFinding(type="cmdi", endpoint="/", parameter=None, severity="CRITICAL", module="test").vuln_type == VulnType.COMMAND_INJECTION
        assert SharedFinding(type="rce", endpoint="/", parameter=None, severity="CRITICAL", module="test").vuln_type == VulnType.COMMAND_INJECTION

    def test_vuln_type_property_unknown(self):
        """Test vuln_type property falls back to OTHER for unknown types."""
        assert SharedFinding(type="unknown_vuln", endpoint="/", parameter=None, severity="LOW", module="test").vuln_type == VulnType.OTHER

    def test_vuln_type_case_insensitive(self):
        """Test vuln_type property is case insensitive."""
        assert SharedFinding(type="SQL_INJECTION", endpoint="/", parameter=None, severity="HIGH", module="test").vuln_type == VulnType.SQL_INJECTION
        assert SharedFinding(type="Xss", endpoint="/", parameter=None, severity="MEDIUM", module="test").vuln_type == VulnType.XSS


# =============================================================================
# SHARED FINDINGS STORE - SINGLETON TESTS
# =============================================================================

class TestSharedFindingsStoreSingleton:
    """Tests for SharedFindingsStore singleton behavior."""

    def test_singleton_pattern(self, store):
        """Test that get_instance returns the same instance."""
        store2 = SharedFindingsStore.get_instance()
        assert store is store2

    def test_get_shared_findings_convenience(self, store):
        """Test get_shared_findings convenience function."""
        result = get_shared_findings()
        assert result is store

    def test_reset_clears_findings(self, store):
        """Test that reset clears all data."""
        # Add some findings first (sync test, can't use async)
        store._findings.append(
            SharedFinding(type="xss", endpoint="/", parameter="q", severity="MEDIUM", module="test")
        )
        assert len(store._findings) == 1

        SharedFindingsStore.reset()
        assert len(store._findings) == 0
        assert len(store._by_endpoint) == 0
        assert len(store._by_type) == 0


# =============================================================================
# SHARED FINDINGS STORE - ADDING FINDINGS
# =============================================================================

class TestAddFinding:
    """Tests for adding findings to the store."""

    @pytest.mark.asyncio
    async def test_add_finding_basic(self, store):
        """Test adding a basic finding."""
        finding = await store.add_finding(
            {"type": "sql_injection", "endpoint": "/api/users", "parameter": "id", "severity": "CRITICAL"},
            module="sqli"
        )

        assert finding.type == "sql_injection"
        assert finding.endpoint == "/api/users"
        assert finding.parameter == "id"
        assert finding.severity == "CRITICAL"
        assert finding.module == "sqli"

    @pytest.mark.asyncio
    async def test_add_finding_indexes_by_endpoint(self, store):
        """Test that finding is indexed by endpoint."""
        await store.add_finding(
            {"type": "xss", "endpoint": "/search", "parameter": "q", "severity": "MEDIUM"},
            module="xss"
        )

        assert "/search" in store._by_endpoint
        assert len(store._by_endpoint["/search"]) == 1

    @pytest.mark.asyncio
    async def test_add_finding_indexes_by_parameter(self, store):
        """Test that finding is indexed by endpoint:parameter."""
        await store.add_finding(
            {"type": "sqli", "endpoint": "/api", "parameter": "id", "severity": "HIGH"},
            module="sqli"
        )

        assert "/api:id" in store._by_parameter
        assert len(store._by_parameter["/api:id"]) == 1

    @pytest.mark.asyncio
    async def test_add_finding_indexes_by_type(self, store):
        """Test that finding is indexed by vuln type."""
        await store.add_finding(
            {"type": "sql_injection", "endpoint": "/api", "parameter": "id", "severity": "HIGH"},
            module="sqli"
        )

        assert VulnType.SQL_INJECTION in store._by_type
        assert len(store._by_type[VulnType.SQL_INJECTION]) == 1

    @pytest.mark.asyncio
    async def test_add_finding_with_enum_type(self, store):
        """Test adding finding with VulnType enum as type."""
        await store.add_finding(
            {"type": VulnType.XSS, "endpoint": "/page", "severity": "MEDIUM"},
            module="xss"
        )

        findings = store.get_all_findings()
        assert len(findings) == 1
        # Type should be normalized to lowercase string
        assert findings[0].type == "xss"

    @pytest.mark.asyncio
    async def test_add_finding_uses_matched_at_fallback(self, store):
        """Test that matched_at is used as endpoint fallback."""
        await store.add_finding(
            {"type": "xss", "matched_at": "/fallback/endpoint", "severity": "LOW"},
            module="xss"
        )

        findings = store.get_all_findings()
        assert findings[0].endpoint == "/fallback/endpoint"


# =============================================================================
# SHARED FINDINGS STORE - QUERYING
# =============================================================================

class TestQueryFindings:
    """Tests for querying findings from the store."""

    @pytest.mark.asyncio
    async def test_has_vulnerability_positive(self, store_with_findings):
        """Test has_vulnerability returns True for known vuln."""
        assert store_with_findings.has_vulnerability("/api/users") is True

    @pytest.mark.asyncio
    async def test_has_vulnerability_negative(self, store_with_findings):
        """Test has_vulnerability returns False for unknown endpoint."""
        assert store_with_findings.has_vulnerability("/unknown/endpoint") is False

    @pytest.mark.asyncio
    async def test_has_vulnerability_with_type_match(self, store_with_findings):
        """Test has_vulnerability with matching type."""
        assert store_with_findings.has_vulnerability("/api/users", "sql_injection") is True

    @pytest.mark.asyncio
    async def test_has_vulnerability_with_type_no_match(self, store_with_findings):
        """Test has_vulnerability with non-matching type."""
        assert store_with_findings.has_vulnerability("/api/users", "csrf") is False

    @pytest.mark.asyncio
    async def test_has_parameter_vulnerability(self, store_with_findings):
        """Test has_parameter_vulnerability."""
        assert store_with_findings.has_parameter_vulnerability("/api/users", "id") is True
        assert store_with_findings.has_parameter_vulnerability("/api/users", "other") is False

    @pytest.mark.asyncio
    async def test_has_parameter_vulnerability_with_type(self, store_with_findings):
        """Test has_parameter_vulnerability with specific type."""
        assert store_with_findings.has_parameter_vulnerability("/api/users", "id", "sql_injection") is True
        assert store_with_findings.has_parameter_vulnerability("/api/users", "id", "xss") is False

    @pytest.mark.asyncio
    async def test_get_vulnerable_parameters(self, store_with_findings):
        """Test getting vulnerable parameters for an endpoint."""
        params = store_with_findings.get_vulnerable_parameters("/api/users")

        assert "id" in params
        assert "sql_injection" in params["id"]
        assert "user_id" in params
        assert "idor" in params["user_id"]

    @pytest.mark.asyncio
    async def test_get_findings_by_type(self, store_with_findings):
        """Test getting findings by VulnType."""
        sqli_findings = store_with_findings.get_findings_by_type(VulnType.SQL_INJECTION)

        assert len(sqli_findings) == 1
        assert sqli_findings[0].endpoint == "/api/users"

    @pytest.mark.asyncio
    async def test_get_all_findings(self, store_with_findings):
        """Test getting all findings."""
        findings = store_with_findings.get_all_findings()
        assert len(findings) == 3

    @pytest.mark.asyncio
    async def test_get_critical_findings(self, store_with_findings):
        """Test getting only critical findings."""
        critical = store_with_findings.get_critical_findings()

        assert len(critical) == 1
        assert critical[0].type == "sql_injection"
        assert critical[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_get_findings_by_endpoint(self, store_with_findings):
        """Test getting findings for a specific endpoint."""
        findings = store_with_findings.get_findings_by_endpoint("/api/users")

        assert len(findings) == 2  # sqli and idor
        types = {f.type for f in findings}
        assert "sql_injection" in types
        assert "idor" in types

    @pytest.mark.asyncio
    async def test_get_findings_from_module(self, store_with_findings):
        """Test getting findings from a specific module."""
        sqli_findings = store_with_findings.get_findings_from_module("sqli")

        assert len(sqli_findings) == 1
        assert sqli_findings[0].module == "sqli"

    @pytest.mark.asyncio
    async def test_get_findings_by_types_multiple(self, store_with_findings):
        """Test getting findings matching multiple types."""
        findings = store_with_findings.get_findings_by_types([VulnType.SQL_INJECTION, VulnType.XSS])

        assert len(findings) == 2
        types = {f.type for f in findings}
        assert "sql_injection" in types
        assert "xss" in types


# =============================================================================
# SHARED FINDINGS STORE - TEST TRACKING
# =============================================================================

class TestTestTracking:
    """Tests for endpoint/parameter test tracking."""

    def test_mark_endpoint_tested(self, store):
        """Test marking an endpoint as tested."""
        store.mark_endpoint_tested("/api/users", "sqli")

        assert store.is_endpoint_tested("/api/users", "sqli") is True
        assert store.is_endpoint_tested("/api/users", "xss") is False

    def test_mark_parameter_tested(self, store):
        """Test marking a parameter as tested."""
        store.mark_parameter_tested("/api/users", "id", "sqli")

        assert store.is_parameter_tested("/api/users", "id", "sqli") is True
        assert store.is_parameter_tested("/api/users", "id", "xss") is False
        assert store.is_parameter_tested("/api/users", "name", "sqli") is False

    @pytest.mark.asyncio
    async def test_should_skip_test_already_tested(self, store):
        """Test should_skip_test when already tested."""
        store.mark_parameter_tested("/api", "id", "sqli")

        assert store.should_skip_test("/api", "id", "sqli", reason_log=False) is True

    @pytest.mark.asyncio
    async def test_should_skip_test_vuln_already_found(self, store):
        """Test should_skip_test when vulnerability already found."""
        await store.add_finding(
            {"type": "sqli", "endpoint": "/api", "parameter": "id", "severity": "HIGH"},
            module="sqli"
        )

        assert store.should_skip_test("/api", "id", "sqli", reason_log=False) is True

    @pytest.mark.asyncio
    async def test_should_skip_test_not_tested(self, store):
        """Test should_skip_test returns False when not tested."""
        assert store.should_skip_test("/api", "id", "sqli", reason_log=False) is False


# =============================================================================
# SHARED FINDINGS STORE - STATISTICS
# =============================================================================

class TestStatistics:
    """Tests for store statistics."""

    @pytest.mark.asyncio
    async def test_get_statistics_empty(self, store):
        """Test statistics for empty store."""
        stats = store.get_statistics()

        assert stats["total_findings"] == 0
        assert stats["unique_endpoints"] == 0
        assert stats["by_type"] == {}
        assert stats["by_severity"] == {}

    @pytest.mark.asyncio
    async def test_get_statistics_with_findings(self, store_with_findings):
        """Test statistics with findings."""
        stats = store_with_findings.get_statistics()

        assert stats["total_findings"] == 3
        assert stats["unique_endpoints"] == 2  # /api/users and /search
        assert "CRITICAL" in stats["by_severity"]
        assert stats["by_severity"]["CRITICAL"] == 1

    def test_set_session(self, store):
        """Test setting session ID."""
        store.set_session("scan-12345")
        stats = store.get_statistics()

        assert stats["session_id"] == "scan-12345"


# =============================================================================
# SHARED FINDINGS STORE - HIGH VALUE TARGETS
# =============================================================================

class TestHighValueTargets:
    """Tests for high value target detection."""

    @pytest.mark.asyncio
    async def test_get_high_value_targets(self, store_with_findings):
        """Test getting endpoints with multiple vuln types."""
        # /api/users has both sqli and idor
        targets = store_with_findings.get_high_value_targets()

        assert "/api/users" in targets
        assert "/search" not in targets  # Only has XSS

    @pytest.mark.asyncio
    async def test_get_endpoints_with_severity(self, store_with_findings):
        """Test getting endpoints at or above severity level."""
        high_endpoints = store_with_findings.get_endpoints_with_severity("HIGH")

        assert "/api/users" in high_endpoints  # Has CRITICAL and HIGH
        assert "/search" not in high_endpoints  # Only MEDIUM


# =============================================================================
# SHARED FINDINGS STORE - CHAINABLE FINDINGS
# =============================================================================

class TestChainableFindings:
    """Tests for chainable finding detection."""

    @pytest.mark.asyncio
    async def test_get_chainable_findings_empty(self, store):
        """Test getting chainable findings when none exist."""
        chainable = store.get_chainable_findings()
        assert chainable == []

    @pytest.mark.asyncio
    async def test_get_chainable_findings_with_proof(self, store):
        """Test getting findings marked as chainable in proof metadata."""
        await store.add_finding(
            {
                "type": "xss",
                "endpoint": "/page",
                "severity": "MEDIUM",
                "metadata": {"proof": {"can_chain": True}}
            },
            module="xss"
        )

        chainable = store.get_chainable_findings()
        assert len(chainable) == 1
        assert chainable[0].type == "xss"


# =============================================================================
# SHARED FINDINGS STORE - AMPLIFICATION HINTS
# =============================================================================

class TestAmplificationHints:
    """Tests for cross-module amplification hints."""

    @pytest.mark.asyncio
    async def test_get_amplification_hints_for_lfi(self, store):
        """Test that SQLi finding generates hints for LFI module."""
        await store.add_finding(
            {"type": "sql_injection", "endpoint": "/api", "severity": "CRITICAL"},
            module="sqli"
        )

        hints = store.get_amplification_hints("lfi")

        assert len(hints) >= 1
        assert any("SQLi found" in h["reason"] for h in hints)

    @pytest.mark.asyncio
    async def test_get_amplification_hints_for_session(self, store):
        """Test that XSS finding generates hints for session module."""
        await store.add_finding(
            {"type": "xss", "endpoint": "/page", "severity": "MEDIUM"},
            module="xss"
        )

        hints = store.get_amplification_hints("session_abuse")

        assert len(hints) >= 1
        assert any("XSS found" in h["reason"] for h in hints)

    @pytest.mark.asyncio
    async def test_get_amplification_hints_excludes_own_module(self, store):
        """Test that module doesn't get hints from its own findings."""
        await store.add_finding(
            {"type": "sql_injection", "endpoint": "/api", "severity": "CRITICAL"},
            module="sqli"
        )

        hints = store.get_amplification_hints("sqli")
        assert len(hints) == 0

    @pytest.mark.asyncio
    async def test_amplification_hints_prioritized(self, store):
        """Test that high severity findings get higher priority hints."""
        await store.add_finding(
            {"type": "sql_injection", "endpoint": "/api", "severity": "CRITICAL"},
            module="sqli"
        )
        await store.add_finding(
            {"type": "sqli", "endpoint": "/other", "severity": "LOW"},
            module="sqli"
        )

        hints = store.get_amplification_hints("lfi")

        # Should be sorted by priority (high severity first)
        if len(hints) >= 2:
            assert hints[0]["trigger_severity"] == "CRITICAL"


# =============================================================================
# EXTRACTED DATA SHARING (THEME-4)
# =============================================================================

class TestExtractedDataSharing:
    """Tests for THEME-4 extracted data sharing."""

    @pytest.mark.asyncio
    async def test_add_extracted_credentials(self, store):
        """Test adding extracted credentials."""
        creds = [{"username": "admin", "password_hash": "5f4dcc3b..."}]
        data = await store.add_extracted_data(
            data_type="credentials",
            values=creds,
            source_module="sqli",
            source_endpoint="/api/users?id=1",
            context={"database": "mysql"}
        )

        assert data.data_type == "credentials"
        assert data.values == creds
        assert data.source_module == "sqli"

    @pytest.mark.asyncio
    async def test_get_extracted_credentials(self, store):
        """Test retrieving extracted credentials."""
        await store.add_extracted_data(
            data_type="credentials",
            values=[{"username": "admin", "password": "secret"}],
            source_module="sqli",
            source_endpoint="/api/users"
        )

        creds = store.get_extracted_credentials("session_abuse")

        assert len(creds) == 1
        assert creds[0]["username"] == "admin"
        assert creds[0]["_source_module"] == "sqli"

    @pytest.mark.asyncio
    async def test_get_extracted_user_ids(self, store):
        """Test retrieving extracted user IDs."""
        await store.add_extracted_data(
            data_type="user_ids",
            values=[1, 2, 3, 42],
            source_module="idor",
            source_endpoint="/api/users"
        )

        ids = store.get_extracted_user_ids("business")

        assert "1" in ids
        assert "42" in ids
        # Should be deduplicated and converted to strings
        assert all(isinstance(i, str) for i in ids)

    @pytest.mark.asyncio
    async def test_get_extracted_usernames(self, store):
        """Test retrieving extracted usernames."""
        await store.add_extracted_data(
            data_type="usernames",
            values=["root", "admin", "www-data"],
            source_module="lfi",
            source_endpoint="/read?file=/etc/passwd"
        )

        usernames = store.get_extracted_usernames()

        assert "root" in usernames
        assert "admin" in usernames

    @pytest.mark.asyncio
    async def test_get_extracted_table_names(self, store):
        """Test retrieving extracted table names."""
        await store.add_extracted_data(
            data_type="table_names",
            values=["users", "orders", "sessions"],
            source_module="sqli",
            source_endpoint="/api/search"
        )

        tables = store.get_extracted_table_names()

        assert "users" in tables
        assert "orders" in tables

    @pytest.mark.asyncio
    async def test_get_extracted_tokens(self, store):
        """Test retrieving extracted tokens."""
        await store.add_extracted_data(
            data_type="tokens",
            values=[{"type": "jwt", "token": "eyJ..."}],
            source_module="xss",
            source_endpoint="/dashboard"
        )

        tokens = store.get_extracted_tokens()

        assert len(tokens) == 1
        assert tokens[0]["type"] == "jwt"
        assert tokens[0]["_source_module"] == "xss"

    @pytest.mark.asyncio
    async def test_get_extracted_tokens_string_format(self, store):
        """Test retrieving tokens when stored as plain strings."""
        await store.add_extracted_data(
            data_type="tokens",
            values=["session_abc123"],
            source_module="session",
            source_endpoint="/login"
        )

        tokens = store.get_extracted_tokens()

        assert len(tokens) == 1
        assert tokens[0]["token"] == "session_abc123"

    @pytest.mark.asyncio
    async def test_get_chain_opportunities(self, store):
        """Test retrieving chain opportunities."""
        await store.add_extracted_data(
            data_type="chain_opportunities",
            values=[{"type": "xss_to_session", "description": "Steal JWT via XSS"}],
            source_module="xss",
            source_endpoint="/vulnerable"
        )

        opps = store.get_chain_opportunities()

        assert len(opps) == 1
        assert opps[0]["type"] == "xss_to_session"

    @pytest.mark.asyncio
    async def test_consumption_tracking(self, store):
        """Test that consumption is tracked."""
        await store.add_extracted_data(
            data_type="credentials",
            values=[{"username": "test"}],
            source_module="sqli",
            source_endpoint="/api"
        )

        # First consumer
        store.get_extracted_credentials("session")
        # Second consumer
        store.get_extracted_credentials("auth")

        # Check consumption is tracked
        data = store._by_data_type["credentials"][0]
        assert "session" in data.consumed_by
        assert "auth" in data.consumed_by

    @pytest.mark.asyncio
    async def test_get_extracted_data_summary(self, store):
        """Test getting summary of all extracted data."""
        await store.add_extracted_data(
            data_type="credentials",
            values=[{"username": "admin"}],
            source_module="sqli",
            source_endpoint="/api"
        )
        await store.add_extracted_data(
            data_type="usernames",
            values=["root", "admin"],
            source_module="lfi",
            source_endpoint="/read"
        )

        # Consume some data
        store.get_extracted_credentials("session")

        summary = store.get_extracted_data_summary()

        assert summary["total_extractions"] == 2
        assert "credentials" in summary["by_type"]
        assert summary["by_type"]["credentials"]["count"] == 1
        assert summary["by_type"]["usernames"]["total_values"] == 2


# =============================================================================
# THREAD SAFETY
# =============================================================================

class TestThreadSafety:
    """Tests for thread-safe operations."""

    @pytest.mark.asyncio
    async def test_concurrent_add_findings(self, store):
        """Test adding findings concurrently."""
        async def add_finding(i):
            await store.add_finding(
                {"type": "xss", "endpoint": f"/page{i}", "severity": "MEDIUM"},
                module="xss"
            )

        # Add 50 findings concurrently
        await asyncio.gather(*[add_finding(i) for i in range(50)])

        assert len(store.get_all_findings()) == 50

    def test_concurrent_read_operations(self, store):
        """Test that read operations use RLock (reentrant)."""
        # This tests that synchronous reads don't deadlock
        store._findings.append(
            SharedFinding(type="xss", endpoint="/a", parameter=None, severity="MEDIUM", module="test")
        )
        store._by_endpoint["/a"] = [store._findings[0]]

        # Should not deadlock
        assert store.has_vulnerability("/a") is True
        findings = store.get_all_findings()
        assert len(findings) == 1


# =============================================================================
# RESET BEHAVIOR
# =============================================================================

class TestResetBehavior:
    """Tests for store reset behavior."""

    @pytest.mark.asyncio
    async def test_reset_clears_all_data(self, store):
        """Test that reset clears all data structures."""
        await store.add_finding(
            {"type": "xss", "endpoint": "/page", "severity": "MEDIUM"},
            module="xss"
        )
        await store.add_extracted_data(
            data_type="usernames",
            values=["admin"],
            source_module="lfi",
            source_endpoint="/etc/passwd"
        )
        store.mark_endpoint_tested("/page", "xss")
        store.set_session("test-session")

        SharedFindingsStore.reset()

        assert len(store._findings) == 0
        assert len(store._by_endpoint) == 0
        assert len(store._by_type) == 0
        assert len(store._tested_endpoints) == 0
        assert len(store._extracted_data) == 0
        assert store._session_id is None
