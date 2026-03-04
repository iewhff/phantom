"""
Tests for scanning/modules/clickjacking_scanner.py

Covers:
- ClickjackVulnType enum (12 types)
- ProtectionLevel enum (5 levels)
- XFrameOptionsValue enum (5 values)
- SENSITIVE_ACTIONS list
- FrameProtectionStatus dataclass
- ClickjackEndpoint dataclass
- ClickjackFinding dataclass
- ScanConfig dataclass
- FrameProtectionAnalyzer (XFO, CSP, frame-buster analysis)
- ClickjackPoCGenerator (basic PoC, sandbox bypass PoC)
"""

import pytest
from scanning.modules.clickjacking_scanner import (
    VERSION,
    ClickjackVulnType,
    ProtectionLevel,
    XFrameOptionsValue,
    SENSITIVE_ACTIONS,
    FrameProtectionStatus,
    ClickjackEndpoint,
    ClickjackFinding,
    ScanConfig,
    FrameProtectionAnalyzer,
    ClickjackPoCGenerator,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestClickjackVulnType:
    """Test ClickjackVulnType enum."""

    def test_count(self):
        assert len(ClickjackVulnType) == 12

    def test_no_protection(self):
        assert ClickjackVulnType.NO_PROTECTION is not None

    def test_weak_xfo(self):
        assert ClickjackVulnType.WEAK_XFO is not None

    def test_missing_csp_ancestors(self):
        assert ClickjackVulnType.MISSING_CSP_ANCESTORS is not None

    def test_xfo_csp_mismatch(self):
        assert ClickjackVulnType.XFO_CSP_MISMATCH is not None

    def test_frame_buster_bypass(self):
        assert ClickjackVulnType.FRAME_BUSTER_BYPASS is not None

    def test_partial_protection(self):
        assert ClickjackVulnType.PARTIAL_PROTECTION is not None

    def test_sandbox_bypass(self):
        assert ClickjackVulnType.SANDBOX_BYPASS is not None

    def test_drag_drop_vuln(self):
        assert ClickjackVulnType.DRAG_DROP_VULN is not None

    def test_prefilled_form(self):
        assert ClickjackVulnType.PREFILLED_FORM is not None

    def test_double_click(self):
        assert ClickjackVulnType.DOUBLE_CLICK is not None

    def test_cursor_hijack(self):
        assert ClickjackVulnType.CURSOR_HIJACK is not None

    def test_mobile_clickjack(self):
        assert ClickjackVulnType.MOBILE_CLICKJACK is not None


class TestProtectionLevel:
    """Test ProtectionLevel enum."""

    def test_count(self):
        assert len(ProtectionLevel) == 5

    def test_none(self):
        assert ProtectionLevel.NONE is not None

    def test_weak(self):
        assert ProtectionLevel.WEAK is not None

    def test_partial(self):
        assert ProtectionLevel.PARTIAL is not None

    def test_strong(self):
        assert ProtectionLevel.STRONG is not None

    def test_excellent(self):
        assert ProtectionLevel.EXCELLENT is not None


class TestXFrameOptionsValue:
    """Test XFrameOptionsValue enum."""

    def test_count(self):
        assert len(XFrameOptionsValue) == 5

    def test_deny(self):
        assert XFrameOptionsValue.DENY.value == "DENY"

    def test_sameorigin(self):
        assert XFrameOptionsValue.SAMEORIGIN.value == "SAMEORIGIN"

    def test_allow_from(self):
        assert XFrameOptionsValue.ALLOW_FROM.value == "ALLOW-FROM"

    def test_invalid(self):
        assert XFrameOptionsValue.INVALID.value == "INVALID"

    def test_missing(self):
        assert XFrameOptionsValue.MISSING.value == "MISSING"


# =============================================================================
# SENSITIVE ACTIONS
# =============================================================================

class TestSensitiveActions:
    """Test SENSITIVE_ACTIONS list."""

    def test_not_empty(self):
        assert len(SENSITIVE_ACTIONS) > 0

    def test_all_start_with_slash(self):
        for action in SENSITIVE_ACTIONS:
            assert action.startswith("/"), f"Action should start with /: {action}"

    # Account actions
    def test_has_account_delete(self):
        assert "/account/delete" in SENSITIVE_ACTIONS

    def test_has_deactivate(self):
        assert "/deactivate" in SENSITIVE_ACTIONS

    # Financial actions
    def test_has_transfer(self):
        assert "/transfer" in SENSITIVE_ACTIONS

    def test_has_payment(self):
        assert "/payment" in SENSITIVE_ACTIONS

    def test_has_checkout(self):
        assert "/checkout" in SENSITIVE_ACTIONS

    # Permission actions
    def test_has_admin(self):
        assert "/admin" in SENSITIVE_ACTIONS

    def test_has_authorize(self):
        assert "/authorize" in SENSITIVE_ACTIONS

    # Social actions
    def test_has_follow(self):
        assert "/follow" in SENSITIVE_ACTIONS

    def test_has_like(self):
        assert "/like" in SENSITIVE_ACTIONS

    # Settings
    def test_has_change_password(self):
        assert "/change-password" in SENSITIVE_ACTIONS

    def test_has_change_email(self):
        assert "/change-email" in SENSITIVE_ACTIONS

    # OAuth
    def test_has_oauth_authorize(self):
        assert "/oauth/authorize" in SENSITIVE_ACTIONS

    def test_has_oauth_consent(self):
        assert "/oauth/consent" in SENSITIVE_ACTIONS


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestFrameProtectionStatus:
    """Test FrameProtectionStatus dataclass."""

    def test_defaults(self):
        status = FrameProtectionStatus(url="https://target.com")
        assert status.url == "https://target.com"
        assert status.has_xfo is False
        assert status.xfo_value is None
        assert status.xfo_parsed == XFrameOptionsValue.MISSING
        assert status.has_csp is False
        assert status.csp_frame_ancestors is None
        assert status.has_frame_buster is False
        assert status.frame_buster_bypassable is False
        assert status.sandbox_attribute is None
        assert status.protection_level == ProtectionLevel.NONE
        assert status.notes == []

    def test_with_xfo(self):
        status = FrameProtectionStatus(
            url="https://target.com",
            has_xfo=True,
            xfo_value="DENY",
            xfo_parsed=XFrameOptionsValue.DENY,
            protection_level=ProtectionLevel.STRONG,
        )
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.DENY

    def test_with_csp(self):
        status = FrameProtectionStatus(
            url="https://target.com",
            has_csp=True,
            csp_frame_ancestors="'none'",
            protection_level=ProtectionLevel.STRONG,
        )
        assert status.has_csp is True
        assert status.csp_frame_ancestors == "'none'"


class TestClickjackEndpoint:
    """Test ClickjackEndpoint dataclass."""

    def test_defaults(self):
        ep = ClickjackEndpoint(url="https://target.com/transfer")
        assert ep.url == "https://target.com/transfer"
        assert ep.method == "GET"
        assert ep.is_sensitive is False
        assert ep.action_type == "unknown"
        assert ep.requires_auth is False
        assert ep.has_form is False
        assert ep.form_action is None
        assert ep.prefillable_params == []

    def test_sensitive_endpoint(self):
        ep = ClickjackEndpoint(
            url="https://target.com/account/delete",
            method="POST",
            is_sensitive=True,
            action_type="account_deletion",
            requires_auth=True,
            has_form=True,
            form_action="/account/delete",
            prefillable_params=["confirm"],
        )
        assert ep.is_sensitive is True
        assert ep.requires_auth is True


class TestClickjackFinding:
    """Test ClickjackFinding dataclass."""

    def test_creation(self):
        endpoint = ClickjackEndpoint(url="https://target.com/transfer")
        protection = FrameProtectionStatus(url="https://target.com/transfer")
        finding = ClickjackFinding(
            id="CJ-0001",
            vuln_type=ClickjackVulnType.NO_PROTECTION,
            severity="MEDIUM",
            confidence=0.9,
            endpoint=endpoint,
            protection_status=protection,
            description="No clickjacking protection",
            impact="Attacker can overlay invisible iframe",
            remediation="Add X-Frame-Options: DENY",
            poc_html="<html>...</html>",
            cwe_id=1021,
            cvss_score=4.3,
            evidence={"xfo": "missing", "csp": "missing"},
        )
        assert finding.id == "CJ-0001"
        assert finding.cwe_id == 1021
        assert finding.severity == "MEDIUM"


class TestScanConfig:
    """Test ScanConfig dataclass."""

    def test_defaults(self):
        config = ScanConfig(target_url="https://target.com")
        assert config.target_url == "https://target.com"
        assert config.timeout == 30.0
        assert config.test_sensitive_pages is True
        assert config.test_frame_busters is True
        assert config.generate_poc is True
        assert config.follow_redirects is True
        assert config.check_all_pages is False
        assert config.custom_sensitive_paths == []

    def test_custom_config(self):
        config = ScanConfig(
            target_url="https://target.com",
            timeout=60.0,
            generate_poc=False,
            custom_sensitive_paths=["/custom/action"],
        )
        assert config.timeout == 60.0
        assert config.generate_poc is False


# =============================================================================
# FRAME PROTECTION ANALYZER
# =============================================================================

class TestFrameProtectionAnalyzer:
    """Test FrameProtectionAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        return FrameProtectionAnalyzer()

    def test_version(self, analyzer):
        assert FrameProtectionAnalyzer.VERSION == "3.0.0"

    # XFO analysis
    def test_xfo_deny(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_xfo(status, {"X-Frame-Options": "DENY"})
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.DENY

    def test_xfo_sameorigin(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_xfo(status, {"X-Frame-Options": "SAMEORIGIN"})
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.SAMEORIGIN

    def test_xfo_allow_from(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_xfo(status, {"X-Frame-Options": "ALLOW-FROM https://trusted.com"})
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.ALLOW_FROM
        assert any("deprecated" in n.lower() for n in status.notes)

    def test_xfo_invalid(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_xfo(status, {"X-Frame-Options": "GARBAGE"})
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.INVALID

    def test_xfo_missing(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_xfo(status, {})
        assert status.has_xfo is False
        assert status.xfo_parsed == XFrameOptionsValue.MISSING

    def test_xfo_case_insensitive(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_xfo(status, {"x-frame-options": "deny"})
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.DENY

    # CSP analysis
    def test_csp_none(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_csp(status, {"Content-Security-Policy": "frame-ancestors 'none'"})
        assert status.has_csp is True
        assert status.csp_frame_ancestors is not None
        assert "'none'" in status.csp_frame_ancestors

    def test_csp_self(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_csp(status, {"Content-Security-Policy": "frame-ancestors 'self'"})
        assert status.has_csp is True
        assert any("self" in n.lower() for n in status.notes)

    def test_csp_wildcard(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_csp(status, {"Content-Security-Policy": "frame-ancestors *"})
        assert status.has_csp is True
        assert any("WEAK" in n or "any" in n.lower() for n in status.notes)

    def test_csp_missing(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_csp(status, {})
        assert status.has_csp is False

    def test_csp_no_frame_ancestors(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._analyze_csp(status, {"Content-Security-Policy": "default-src 'self'"})
        assert status.has_csp is True
        assert status.csp_frame_ancestors is None

    # Frame buster analysis
    def test_frame_buster_detected(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        body = '<script>if (top !== self) { top.location = self.location; }</script>'
        analyzer._analyze_frame_buster(status, body)
        assert status.has_frame_buster is True
        assert status.frame_buster_bypassable is True

    def test_frame_buster_top_location(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        body = '<script>top.location = window.location;</script>'
        analyzer._analyze_frame_buster(status, body)
        assert status.has_frame_buster is True

    def test_frame_buster_not_detected(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        body = '<html><body><p>Hello world</p></body></html>'
        analyzer._analyze_frame_buster(status, body)
        assert status.has_frame_buster is False

    # Frame buster patterns
    def test_has_frame_buster_patterns(self):
        assert len(FrameProtectionAnalyzer.FRAME_BUSTER_PATTERNS) > 0

    def test_has_frame_buster_bypasses(self):
        assert len(FrameProtectionAnalyzer.FRAME_BUSTER_BYPASSES) > 0

    def test_bypass_has_sandbox(self):
        names = [b[0] for b in FrameProtectionAnalyzer.FRAME_BUSTER_BYPASSES]
        assert "sandbox" in names

    def test_bypass_has_double_frame(self):
        names = [b[0] for b in FrameProtectionAnalyzer.FRAME_BUSTER_BYPASSES]
        assert "double_frame" in names

    # Protection level determination
    def test_excellent_protection(self, analyzer):
        status = FrameProtectionStatus(
            url="https://target.com",
            xfo_parsed=XFrameOptionsValue.DENY,
            has_csp=True,
            csp_frame_ancestors="'none'",
        )
        analyzer._determine_protection_level(status)
        assert status.protection_level == ProtectionLevel.EXCELLENT

    def test_strong_csp_only(self, analyzer):
        status = FrameProtectionStatus(
            url="https://target.com",
            xfo_parsed=XFrameOptionsValue.MISSING,
            has_csp=True,
            csp_frame_ancestors="'self'",
        )
        analyzer._determine_protection_level(status)
        assert status.protection_level == ProtectionLevel.STRONG

    def test_strong_xfo_only(self, analyzer):
        status = FrameProtectionStatus(
            url="https://target.com",
            xfo_parsed=XFrameOptionsValue.DENY,
            has_csp=False,
        )
        analyzer._determine_protection_level(status)
        assert status.protection_level == ProtectionLevel.STRONG

    def test_weak_allow_from(self, analyzer):
        status = FrameProtectionStatus(
            url="https://target.com",
            xfo_parsed=XFrameOptionsValue.ALLOW_FROM,
        )
        analyzer._determine_protection_level(status)
        assert status.protection_level == ProtectionLevel.WEAK

    def test_weak_bypassable_buster(self, analyzer):
        status = FrameProtectionStatus(
            url="https://target.com",
            has_frame_buster=True,
            frame_buster_bypassable=True,
        )
        analyzer._determine_protection_level(status)
        assert status.protection_level == ProtectionLevel.WEAK

    def test_no_protection(self, analyzer):
        status = FrameProtectionStatus(url="https://target.com")
        analyzer._determine_protection_level(status)
        assert status.protection_level == ProtectionLevel.NONE


# =============================================================================
# POC GENERATOR
# =============================================================================

class TestClickjackPoCGenerator:
    """Test ClickjackPoCGenerator class."""

    def test_version(self):
        assert ClickjackPoCGenerator.VERSION == "3.0.0"

    def test_basic_poc(self):
        poc = ClickjackPoCGenerator.generate_basic_poc("https://target.com/transfer")
        assert "iframe" in poc
        assert "https://target.com/transfer" in poc
        assert "opacity" in poc
        assert "Clickjacking" in poc

    def test_basic_poc_custom_button(self):
        poc = ClickjackPoCGenerator.generate_basic_poc("https://target.com", "Win a Prize!")
        assert "Win a Prize!" in poc

    def test_basic_poc_has_toggle(self):
        """PoC should have visibility toggle for testing."""
        poc = ClickjackPoCGenerator.generate_basic_poc("https://target.com")
        assert "toggle" in poc.lower() or "visibility" in poc.lower()

    def test_sandbox_bypass_poc(self):
        poc = ClickjackPoCGenerator.generate_sandbox_bypass_poc("https://target.com/transfer")
        assert "sandbox" in poc.lower()
        assert "https://target.com/transfer" in poc


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    """Test realistic clickjacking attack scenarios."""

    def test_no_protection_on_financial_page(self):
        endpoint = ClickjackEndpoint(
            url="https://bank.com/transfer",
            method="POST",
            is_sensitive=True,
            action_type="financial",
            has_form=True,
        )
        protection = FrameProtectionStatus(
            url="https://bank.com/transfer",
            protection_level=ProtectionLevel.NONE,
        )
        finding = ClickjackFinding(
            id="CJ-0001",
            vuln_type=ClickjackVulnType.NO_PROTECTION,
            severity="HIGH",
            confidence=0.95,
            endpoint=endpoint,
            protection_status=protection,
            description="Financial page has no clickjacking protection",
            impact="Attacker could trick users into initiating money transfers",
            remediation="Add CSP frame-ancestors 'none'",
            poc_html="<html>...</html>",
            cwe_id=1021,
            cvss_score=6.1,
            evidence={"xfo": "missing", "csp": "missing"},
        )
        assert finding.endpoint.is_sensitive is True

    def test_frame_buster_bypass(self):
        """Frame buster script can be bypassed with sandbox attribute."""
        protection = FrameProtectionStatus(
            url="https://target.com/settings",
            has_frame_buster=True,
            frame_buster_bypassable=True,
            protection_level=ProtectionLevel.WEAK,
        )
        assert protection.frame_buster_bypassable is True
        assert protection.protection_level == ProtectionLevel.WEAK

    def test_oauth_consent_clickjacking(self):
        """Clickjacking on OAuth consent page."""
        endpoint = ClickjackEndpoint(
            url="https://auth.target.com/oauth/consent",
            method="POST",
            is_sensitive=True,
            action_type="oauth_consent",
            has_form=True,
        )
        assert endpoint.is_sensitive is True
        assert endpoint.action_type == "oauth_consent"


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_version_constant(self):
        assert VERSION == "3.0.0"

    def test_all_vuln_types_unique(self):
        values = [t.value for t in ClickjackVulnType]
        assert len(values) == len(set(values))

    def test_all_protection_levels_unique(self):
        values = [l.value for l in ProtectionLevel]
        assert len(values) == len(set(values))

    def test_empty_notes_list(self):
        status = FrameProtectionStatus(url="https://target.com")
        assert status.notes == []
        status.notes.append("test")
        assert len(status.notes) == 1

    def test_endpoint_default_method(self):
        ep = ClickjackEndpoint(url="https://target.com")
        assert ep.method == "GET"
