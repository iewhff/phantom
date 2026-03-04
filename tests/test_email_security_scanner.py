"""
Tests for scanning/modules/email_security_scanner.py

Covers:
- EmailSecurityScanner class hierarchy and name
- EMAIL_INJECTION_PAYLOADS constant
- SMTP_INJECTION_PAYLOADS constant
- scan method signature (async)
- DNS/SPF/DMARC helper methods exist
"""

import asyncio
import inspect

import pytest

from scanning.modules.email_security_scanner import EmailSecurityScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CLASS HIERARCHY AND NAME
# =============================================================================

class TestScannerIdentity:
    def test_name_is_email_security_scanner(self):
        assert EmailSecurityScanner.name == "email_security_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(EmailSecurityScanner, ScanModule)

    def test_mro_includes_scan_module(self):
        assert ScanModule in EmailSecurityScanner.__mro__


# =============================================================================
# EMAIL_INJECTION_PAYLOADS
# =============================================================================

class TestEmailInjectionPayloads:
    payloads = EmailSecurityScanner.EMAIL_INJECTION_PAYLOADS

    def test_count_is_8(self):
        assert len(self.payloads) == 8

    def test_all_are_strings(self):
        for payload in self.payloads:
            assert isinstance(payload, str)

    def test_no_empty_strings(self):
        for payload in self.payloads:
            assert len(payload) > 0

    def test_all_contain_email_address(self):
        for payload in self.payloads:
            assert "@" in payload, f"Payload missing email address: {payload!r}"

    def test_all_have_injection_separator(self):
        """Each payload must contain a newline/CRLF injection sequence."""
        separators = ("\n", "\r\n", "%0A", "%0D%0A")
        for payload in self.payloads:
            has_sep = any(sep in payload for sep in separators)
            assert has_sep, f"Payload missing injection separator: {payload!r}"

    def test_contains_cc_injection(self):
        texts = " ".join(self.payloads)
        assert "Cc:" in texts

    def test_contains_bcc_injection(self):
        texts = " ".join(self.payloads)
        assert "Bcc:" in texts

    def test_contains_subject_injection(self):
        texts = " ".join(self.payloads)
        assert "Subject:" in texts

    def test_contains_content_type_injection(self):
        texts = " ".join(self.payloads)
        assert "Content-Type:" in texts


# =============================================================================
# SMTP_INJECTION_PAYLOADS
# =============================================================================

class TestSmtpInjectionPayloads:
    payloads = EmailSecurityScanner.SMTP_INJECTION_PAYLOADS

    def test_count_is_3(self):
        assert len(self.payloads) == 3

    def test_all_are_strings(self):
        for payload in self.payloads:
            assert isinstance(payload, str)

    def test_no_empty_strings(self):
        for payload in self.payloads:
            assert len(payload) > 0

    def test_contains_rcpt_to(self):
        combined = " ".join(self.payloads)
        assert "RCPT TO" in combined

    def test_contains_mail_from(self):
        combined = " ".join(self.payloads)
        assert "MAIL FROM" in combined

    def test_contains_data_command(self):
        combined = " ".join(self.payloads)
        assert "DATA" in combined

    def test_all_contain_smtp_command(self):
        smtp_commands = ("RCPT TO", "MAIL FROM", "DATA")
        for payload in self.payloads:
            has_cmd = any(cmd in payload for cmd in smtp_commands)
            assert has_cmd, f"Payload missing SMTP command: {payload!r}"


# =============================================================================
# SCAN METHOD
# =============================================================================

class TestScanMethod:
    def test_scan_method_exists(self):
        assert hasattr(EmailSecurityScanner, "scan")

    def test_scan_is_coroutine_function(self):
        assert asyncio.iscoroutinefunction(EmailSecurityScanner.scan)

    def test_scan_accepts_host_asset_data_rate_limiter(self):
        sig = inspect.signature(EmailSecurityScanner.scan)
        param_names = list(sig.parameters.keys())
        assert "host" in param_names
        assert "asset_data" in param_names
        assert "rate_limiter" in param_names


# =============================================================================
# HELPER METHODS EXIST
# =============================================================================

class TestHelperMethods:
    def test_has_check_email_dns(self):
        assert hasattr(EmailSecurityScanner, "_check_email_dns")

    def test_check_email_dns_is_coroutine(self):
        assert asyncio.iscoroutinefunction(EmailSecurityScanner._check_email_dns)

    def test_has_check_spf(self):
        assert hasattr(EmailSecurityScanner, "_check_spf")

    def test_check_spf_is_callable(self):
        assert callable(EmailSecurityScanner._check_spf)

    def test_has_check_dmarc(self):
        assert hasattr(EmailSecurityScanner, "_check_dmarc")

    def test_check_dmarc_is_callable(self):
        assert callable(EmailSecurityScanner._check_dmarc)
