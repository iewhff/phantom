"""
Tests for scanning/modules/mfa_bypass_scanner.py

Covers:
- MFABypassScanner class identity (name, hierarchy)
- MFA_ENDPOINTS list (17 entries)
- BACKUP_ENDPOINTS list (7 entries)
- DISABLE_ENDPOINTS list (6 entries)
- Endpoint list validation (no empty strings, all start with /, no overlap)
- scan method existence
"""

import pytest
from scanning.modules.mfa_bypass_scanner import MFABypassScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CLASS IDENTITY
# =============================================================================

class TestMFABypassScannerIdentity:
    """Test scanner name and class hierarchy."""

    def test_name(self):
        assert MFABypassScanner.name == "mfa_bypass_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(MFABypassScanner, ScanModule)

    def test_has_scan_method(self):
        assert hasattr(MFABypassScanner, "scan")
        assert callable(getattr(MFABypassScanner, "scan"))


# =============================================================================
# MFA_ENDPOINTS
# =============================================================================

class TestMFAEndpoints:
    """Test MFA_ENDPOINTS list."""

    def test_count(self):
        assert len(MFABypassScanner.MFA_ENDPOINTS) == 18

    def test_has_2fa(self):
        assert "/2fa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_two_factor(self):
        assert "/two-factor" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_mfa(self):
        assert "/mfa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_totp(self):
        assert "/totp" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_verify(self):
        assert "/verify" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_verify_otp(self):
        assert "/verify-otp" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_verify_code(self):
        assert "/verify-code" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_challenge(self):
        assert "/challenge" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_auth_2fa(self):
        assert "/auth/2fa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_auth_mfa(self):
        assert "/auth/mfa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_auth_verify(self):
        assert "/auth/verify" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_login_2fa(self):
        assert "/login/2fa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_login_verify(self):
        assert "/login/verify" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_account_2fa(self):
        assert "/account/2fa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_api_2fa_verify(self):
        assert "/api/2fa/verify" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_api_mfa_verify(self):
        assert "/api/mfa/verify" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_api_auth_2fa(self):
        assert "/api/auth/2fa" in MFABypassScanner.MFA_ENDPOINTS

    def test_has_security_2fa(self):
        assert "/security/2fa" in MFABypassScanner.MFA_ENDPOINTS

    def test_no_empty_strings(self):
        for ep in MFABypassScanner.MFA_ENDPOINTS:
            assert ep != "", f"Empty string found in MFA_ENDPOINTS"

    def test_all_start_with_slash(self):
        for ep in MFABypassScanner.MFA_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint should start with /: {ep}"


# =============================================================================
# BACKUP_ENDPOINTS
# =============================================================================

class TestBackupEndpoints:
    """Test BACKUP_ENDPOINTS list."""

    def test_count(self):
        assert len(MFABypassScanner.BACKUP_ENDPOINTS) == 7

    def test_has_backup_codes(self):
        assert "/backup-codes" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_has_recovery_codes(self):
        assert "/recovery-codes" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_has_emergency_codes(self):
        assert "/emergency-codes" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_has_api_backup_codes(self):
        assert "/api/backup-codes" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_has_2fa_backup(self):
        assert "/2fa/backup" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_has_mfa_recovery(self):
        assert "/mfa/recovery" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_has_account_recovery_codes(self):
        assert "/account/recovery-codes" in MFABypassScanner.BACKUP_ENDPOINTS

    def test_no_empty_strings(self):
        for ep in MFABypassScanner.BACKUP_ENDPOINTS:
            assert ep != "", f"Empty string found in BACKUP_ENDPOINTS"

    def test_all_start_with_slash(self):
        for ep in MFABypassScanner.BACKUP_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint should start with /: {ep}"


# =============================================================================
# DISABLE_ENDPOINTS
# =============================================================================

class TestDisableEndpoints:
    """Test DISABLE_ENDPOINTS list."""

    def test_count(self):
        assert len(MFABypassScanner.DISABLE_ENDPOINTS) == 6

    def test_has_2fa_disable(self):
        assert "/2fa/disable" in MFABypassScanner.DISABLE_ENDPOINTS

    def test_has_mfa_disable(self):
        assert "/mfa/disable" in MFABypassScanner.DISABLE_ENDPOINTS

    def test_has_account_2fa_disable(self):
        assert "/account/2fa/disable" in MFABypassScanner.DISABLE_ENDPOINTS

    def test_has_api_2fa_disable(self):
        assert "/api/2fa/disable" in MFABypassScanner.DISABLE_ENDPOINTS

    def test_has_settings_2fa(self):
        assert "/settings/2fa" in MFABypassScanner.DISABLE_ENDPOINTS

    def test_has_security_2fa_remove(self):
        assert "/security/2fa/remove" in MFABypassScanner.DISABLE_ENDPOINTS

    def test_no_empty_strings(self):
        for ep in MFABypassScanner.DISABLE_ENDPOINTS:
            assert ep != "", f"Empty string found in DISABLE_ENDPOINTS"

    def test_all_start_with_slash(self):
        for ep in MFABypassScanner.DISABLE_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint should start with /: {ep}"


# =============================================================================
# CROSS-LIST VALIDATION
# =============================================================================

class TestEndpointListIntegrity:
    """Test that endpoint lists are well-formed and non-overlapping."""

    def test_no_overlap_mfa_backup(self):
        overlap = set(MFABypassScanner.MFA_ENDPOINTS) & set(MFABypassScanner.BACKUP_ENDPOINTS)
        assert overlap == set(), f"Overlap between MFA and BACKUP: {overlap}"

    def test_no_overlap_mfa_disable(self):
        overlap = set(MFABypassScanner.MFA_ENDPOINTS) & set(MFABypassScanner.DISABLE_ENDPOINTS)
        assert overlap == set(), f"Overlap between MFA and DISABLE: {overlap}"

    def test_no_overlap_backup_disable(self):
        overlap = set(MFABypassScanner.BACKUP_ENDPOINTS) & set(MFABypassScanner.DISABLE_ENDPOINTS)
        assert overlap == set(), f"Overlap between BACKUP and DISABLE: {overlap}"

    def test_no_duplicates_in_mfa(self):
        assert len(MFABypassScanner.MFA_ENDPOINTS) == len(set(MFABypassScanner.MFA_ENDPOINTS))

    def test_no_duplicates_in_backup(self):
        assert len(MFABypassScanner.BACKUP_ENDPOINTS) == len(set(MFABypassScanner.BACKUP_ENDPOINTS))

    def test_no_duplicates_in_disable(self):
        assert len(MFABypassScanner.DISABLE_ENDPOINTS) == len(set(MFABypassScanner.DISABLE_ENDPOINTS))

    def test_all_endpoints_are_strings(self):
        all_eps = (
            MFABypassScanner.MFA_ENDPOINTS
            + MFABypassScanner.BACKUP_ENDPOINTS
            + MFABypassScanner.DISABLE_ENDPOINTS
        )
        for ep in all_eps:
            assert isinstance(ep, str), f"Non-string endpoint: {ep!r}"
