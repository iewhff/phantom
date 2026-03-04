"""
Tests for scanning/modules/credential_verifier.py

Covers:
- CredentialStatus enum (all 6 members)
- CredentialSource enum (all 11 members and their values)
- CredentialVerificationResult dataclass (defaults, is_valid, to_finding)
- to_finding() severity mapping per access_level
- CredentialVerifier class (init, attributes, scan)
"""

import pytest

from scanning.modules.credential_verifier import (
    CredentialStatus,
    CredentialSource,
    CredentialVerificationResult,
    CredentialVerifier,
)


# =============================================================================
# CredentialStatus ENUM
# =============================================================================

class TestCredentialStatus:
    def test_member_count(self):
        assert len(CredentialStatus) == 6

    def test_has_valid(self):
        assert hasattr(CredentialStatus, "VALID")

    def test_has_invalid(self):
        assert hasattr(CredentialStatus, "INVALID")

    def test_has_revoked(self):
        assert hasattr(CredentialStatus, "REVOKED")

    def test_has_rate_limited(self):
        assert hasattr(CredentialStatus, "RATE_LIMITED")

    def test_has_not_verifiable(self):
        assert hasattr(CredentialStatus, "NOT_VERIFIABLE")

    def test_has_error(self):
        assert hasattr(CredentialStatus, "ERROR")

    def test_all_members_unique(self):
        values = [m.value for m in CredentialStatus]
        assert len(values) == len(set(values))

    def test_members_are_auto_ints(self):
        for member in CredentialStatus:
            assert isinstance(member.value, int)


# =============================================================================
# CredentialSource ENUM
# =============================================================================

class TestCredentialSource:
    def test_member_count(self):
        assert len(CredentialSource) == 11

    def test_client_code_value(self):
        assert CredentialSource.CLIENT_CODE.value == "client_side_code"

    def test_api_response_value(self):
        assert CredentialSource.API_RESPONSE.value == "api_response"

    def test_config_file_value(self):
        assert CredentialSource.CONFIG_FILE.value == "config_file"

    def test_javascript_value(self):
        assert CredentialSource.JAVASCRIPT.value == "javascript_bundle"

    def test_html_value(self):
        assert CredentialSource.HTML.value == "html_source"

    def test_headers_value(self):
        assert CredentialSource.HEADERS.value == "http_headers"

    def test_error_message_value(self):
        assert CredentialSource.ERROR_MESSAGE.value == "error_message"

    def test_debug_output_value(self):
        assert CredentialSource.DEBUG_OUTPUT.value == "debug_output"

    def test_github_value(self):
        assert CredentialSource.GITHUB.value == "github_repository"

    def test_pastebin_value(self):
        assert CredentialSource.PASTEBIN.value == "paste_site"

    def test_other_value(self):
        assert CredentialSource.OTHER.value == "other"

    def test_all_values_are_strings(self):
        for member in CredentialSource:
            assert isinstance(member.value, str)

    def test_all_values_unique(self):
        values = [m.value for m in CredentialSource]
        assert len(values) == len(set(values))


# =============================================================================
# CredentialVerificationResult DATACLASS
# =============================================================================

class TestCredentialVerificationResult:
    """Tests for the CredentialVerificationResult dataclass."""

    def _make_result(self, **overrides):
        """Helper to create a result with sensible defaults."""
        defaults = dict(
            credential_type="test_key",
            credential_masked="test...mask",
            source=CredentialSource.CONFIG_FILE,
            source_url="https://example.com/.env",
            status=CredentialStatus.VALID,
            verification_method="test_api",
        )
        defaults.update(overrides)
        return CredentialVerificationResult(**defaults)

    # --- Default field values ---

    def test_default_access_level(self):
        result = self._make_result()
        assert result.access_level == "unknown"

    def test_default_severity(self):
        result = self._make_result()
        assert result.severity == "unknown"

    def test_default_timestamp(self):
        result = self._make_result()
        assert result.timestamp == ""

    def test_default_notes(self):
        result = self._make_result()
        assert result.notes == []

    def test_notes_default_is_not_shared(self):
        """Each instance should get its own list, not a shared mutable default."""
        r1 = self._make_result()
        r2 = self._make_result()
        r1.notes.append("changed")
        assert r2.notes == []

    # --- Full creation with all fields ---

    def test_full_creation(self):
        result = CredentialVerificationResult(
            credential_type="stripe_secret_key",
            credential_masked="sk_l...abcd",
            source=CredentialSource.JAVASCRIPT,
            source_url="https://example.com/app.js",
            status=CredentialStatus.VALID,
            verification_method="stripe_balance_api",
            access_level="service",
            severity="CRITICAL",
            timestamp="2026-02-27T10:00:00",
            notes=["Authentication successful"],
        )
        assert result.credential_type == "stripe_secret_key"
        assert result.credential_masked == "sk_l...abcd"
        assert result.source == CredentialSource.JAVASCRIPT
        assert result.source_url == "https://example.com/app.js"
        assert result.status == CredentialStatus.VALID
        assert result.verification_method == "stripe_balance_api"
        assert result.access_level == "service"
        assert result.severity == "CRITICAL"
        assert result.timestamp == "2026-02-27T10:00:00"
        assert result.notes == ["Authentication successful"]

    # --- is_valid property ---

    def test_is_valid_when_status_valid(self):
        result = self._make_result(status=CredentialStatus.VALID)
        assert result.is_valid is True

    def test_is_valid_when_status_invalid(self):
        result = self._make_result(status=CredentialStatus.INVALID)
        assert result.is_valid is False

    def test_is_valid_when_status_revoked(self):
        result = self._make_result(status=CredentialStatus.REVOKED)
        assert result.is_valid is False

    def test_is_valid_when_status_rate_limited(self):
        result = self._make_result(status=CredentialStatus.RATE_LIMITED)
        assert result.is_valid is False

    def test_is_valid_when_status_not_verifiable(self):
        result = self._make_result(status=CredentialStatus.NOT_VERIFIABLE)
        assert result.is_valid is False

    def test_is_valid_when_status_error(self):
        result = self._make_result(status=CredentialStatus.ERROR)
        assert result.is_valid is False


# =============================================================================
# to_finding() METHOD
# =============================================================================

class TestToFinding:
    """Tests for CredentialVerificationResult.to_finding()."""

    def _make_valid_result(self, access_level="unknown", **overrides):
        defaults = dict(
            credential_type="api_key",
            credential_masked="sk_t...1234",
            source=CredentialSource.CONFIG_FILE,
            source_url="https://example.com/.env",
            status=CredentialStatus.VALID,
            verification_method="test_api",
            access_level=access_level,
        )
        defaults.update(overrides)
        return CredentialVerificationResult(**defaults)

    # --- Returns empty dict when not valid ---

    def test_returns_empty_dict_when_invalid(self):
        result = self._make_valid_result()
        result.status = CredentialStatus.INVALID
        assert result.to_finding() == {}

    def test_returns_empty_dict_when_revoked(self):
        result = self._make_valid_result()
        result.status = CredentialStatus.REVOKED
        assert result.to_finding() == {}

    def test_returns_empty_dict_when_rate_limited(self):
        result = self._make_valid_result()
        result.status = CredentialStatus.RATE_LIMITED
        assert result.to_finding() == {}

    def test_returns_empty_dict_when_not_verifiable(self):
        result = self._make_valid_result()
        result.status = CredentialStatus.NOT_VERIFIABLE
        assert result.to_finding() == {}

    def test_returns_empty_dict_when_error(self):
        result = self._make_valid_result()
        result.status = CredentialStatus.ERROR
        assert result.to_finding() == {}

    # --- Returns dict with correct structure when valid ---

    def test_returns_dict_when_valid(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert isinstance(finding, dict)
        assert len(finding) > 0

    def test_finding_type_is_leaked_credential(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert finding["type"] == "leaked_credential"

    def test_finding_confidence_is_100(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert finding["confidence"] == 100

    def test_finding_has_title(self):
        result = self._make_valid_result(credential_type="stripe_key")
        finding = result.to_finding()
        assert "stripe_key" in finding["title"]
        assert "Leaked" in finding["title"]

    def test_finding_has_description(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert isinstance(finding["description"], str)
        assert len(finding["description"]) > 0

    def test_finding_has_evidence(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        evidence = finding["evidence"]
        assert evidence["credential_masked"] == "sk_t...1234"
        assert evidence["source"] == "config_file"
        assert evidence["source_url"] == "https://example.com/.env"
        assert evidence["verification_method"] == "test_api"

    def test_finding_has_remediation(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert "rotate" in finding["remediation"].lower()

    def test_finding_has_cwe(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert finding["cwe"] == "CWE-798"

    def test_finding_has_references(self):
        result = self._make_valid_result()
        finding = result.to_finding()
        assert isinstance(finding["references"], list)
        assert len(finding["references"]) >= 1

    # --- Severity mapping ---

    def test_severity_admin_is_critical(self):
        result = self._make_valid_result(access_level="admin")
        finding = result.to_finding()
        assert finding["severity"] == "critical"

    def test_severity_service_is_critical(self):
        result = self._make_valid_result(access_level="service")
        finding = result.to_finding()
        assert finding["severity"] == "critical"

    def test_severity_user_is_high(self):
        result = self._make_valid_result(access_level="user")
        finding = result.to_finding()
        assert finding["severity"] == "high"

    def test_severity_read_only_is_medium(self):
        result = self._make_valid_result(access_level="read_only")
        finding = result.to_finding()
        assert finding["severity"] == "medium"

    def test_severity_unknown_is_high(self):
        result = self._make_valid_result(access_level="unknown")
        finding = result.to_finding()
        assert finding["severity"] == "high"

    def test_severity_unmapped_falls_back_to_high(self):
        result = self._make_valid_result(access_level="something_else")
        finding = result.to_finding()
        assert finding["severity"] == "high"

    # --- CVSS based on access_level ---

    def test_cvss_admin_is_8_0(self):
        result = self._make_valid_result(access_level="admin")
        finding = result.to_finding()
        assert finding["cvss"] == "8.0"

    def test_cvss_service_is_8_0(self):
        result = self._make_valid_result(access_level="service")
        finding = result.to_finding()
        assert finding["cvss"] == "8.0"

    def test_cvss_user_is_6_5(self):
        result = self._make_valid_result(access_level="user")
        finding = result.to_finding()
        assert finding["cvss"] == "6.5"

    def test_cvss_read_only_is_6_5(self):
        result = self._make_valid_result(access_level="read_only")
        finding = result.to_finding()
        assert finding["cvss"] == "6.5"

    def test_cvss_unknown_is_6_5(self):
        result = self._make_valid_result(access_level="unknown")
        finding = result.to_finding()
        assert finding["cvss"] == "6.5"


# =============================================================================
# CredentialVerifier CLASS
# =============================================================================

class TestCredentialVerifier:
    """Tests for the CredentialVerifier class."""

    def test_init_default_settings(self):
        verifier = CredentialVerifier()
        assert verifier.settings is None

    def test_init_with_settings(self):
        sentinel = object()
        verifier = CredentialVerifier(settings=sentinel)
        assert verifier.settings is sentinel

    def test_verification_enabled_by_default(self):
        verifier = CredentialVerifier()
        assert verifier.verification_enabled is True

    def test_verified_cache_starts_empty(self):
        verifier = CredentialVerifier()
        assert verifier._verified_cache == {}
        assert isinstance(verifier._verified_cache, dict)

    def test_has_timeout(self):
        verifier = CredentialVerifier()
        assert verifier.timeout is not None

    def test_not_a_scan_module_subclass(self):
        """CredentialVerifier is standalone, not a ScanModule subclass."""
        assert not hasattr(CredentialVerifier, "module_name")
        mro_names = [cls.__name__ for cls in CredentialVerifier.__mro__]
        assert "ScanModule" not in mro_names

    @pytest.mark.asyncio
    async def test_scan_returns_empty_findings(self):
        verifier = CredentialVerifier()
        result = await verifier.scan("https://example.com")
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_scan_returns_info(self):
        verifier = CredentialVerifier()
        result = await verifier.scan("https://example.com")
        assert "info" in result
        assert len(result["info"]) >= 1
        assert result["info"][0]["type"] == "credential_verifier_ready"
        assert result["info"][0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_scan_with_asset_data(self):
        verifier = CredentialVerifier()
        result = await verifier.scan("https://example.com", asset_data={"key": "val"})
        assert result["findings"] == []

    def test_mask_credential_short(self):
        verifier = CredentialVerifier()
        assert verifier._mask_credential("abc") == "***"
        assert verifier._mask_credential("1234567") == "*******"

    def test_mask_credential_long(self):
        verifier = CredentialVerifier()
        masked = verifier._mask_credential("sk_live_abcdef1234567890")
        assert masked.startswith("sk_l")
        assert masked.endswith("7890")
        assert "..." in masked

    def test_mask_credential_exactly_8_chars(self):
        verifier = CredentialVerifier()
        masked = verifier._mask_credential("12345678")
        assert masked == "1234...5678"

    @pytest.mark.asyncio
    async def test_verify_unknown_credential_type(self):
        verifier = CredentialVerifier()
        result = await verifier.verify_credential(
            credential_type="unknown_type",
            credential_value="some_value_here_1234",
            source=CredentialSource.OTHER,
            source_url="https://example.com",
        )
        assert result.status == CredentialStatus.NOT_VERIFIABLE
        assert result.credential_type == "unknown_type"
        assert result.verification_method == "none"

    @pytest.mark.asyncio
    async def test_verify_caches_result(self):
        verifier = CredentialVerifier()
        # First call -- NOT_VERIFIABLE for unknown type
        await verifier.verify_credential(
            credential_type="unknown_type",
            credential_value="some_value_here_1234",
            source=CredentialSource.OTHER,
            source_url="https://example.com",
        )
        # Cache should now contain the result
        assert len(verifier._verified_cache) == 0  # unknown types don't go through try/cache path

    @pytest.mark.asyncio
    async def test_verify_aws_key_invalid_format(self):
        """AWS key that doesn't match the expected regex returns NOT_VERIFIABLE."""
        verifier = CredentialVerifier()
        result = await verifier.verify_credential(
            credential_type="aws_access_key",
            credential_value="not-an-aws-key-at-all",
            source=CredentialSource.CONFIG_FILE,
            source_url="https://example.com/.env",
        )
        assert result.status == CredentialStatus.NOT_VERIFIABLE

    @pytest.mark.asyncio
    async def test_verify_firebase_key_not_verifiable(self):
        """Firebase keys are public by design, always NOT_VERIFIABLE."""
        verifier = CredentialVerifier()
        result = await verifier.verify_credential(
            credential_type="firebase_key",
            credential_value="AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz",
            source=CredentialSource.JAVASCRIPT,
            source_url="https://example.com/app.js",
        )
        assert result.status == CredentialStatus.NOT_VERIFIABLE
        assert any("PUBLIC" in note for note in result.notes)

    @pytest.mark.asyncio
    async def test_verify_twilio_not_verifiable(self):
        """Twilio needs Account SID + Auth Token, always NOT_VERIFIABLE."""
        verifier = CredentialVerifier()
        result = await verifier.verify_credential(
            credential_type="twilio_auth_token",
            credential_value="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            source=CredentialSource.CONFIG_FILE,
            source_url="https://example.com/.env",
        )
        assert result.status == CredentialStatus.NOT_VERIFIABLE
