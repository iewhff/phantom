"""
Tests for scanning/modules/clickjacking_scanner.py - Clickjacking Vulnerability Scanner.

Covers:
- ClickjackVulnType and ProtectionLevel enums
- XFrameOptionsValue enum
- SENSITIVE_ACTIONS constant
- FrameProtectionStatus, ClickjackEndpoint, ClickjackFinding dataclasses
- FrameProtectionAnalyzer class
- POC generation
"""

import pytest

from scanning.modules.clickjacking_scanner import (
    ClickjackVulnType,
    ProtectionLevel,
    XFrameOptionsValue,
    SENSITIVE_ACTIONS,
    FrameProtectionStatus,
    ClickjackEndpoint,
    ClickjackFinding,
    ScanConfig,
    FrameProtectionAnalyzer,
)


# =============================================================================
# CLICKJACK VULN TYPE ENUM TESTS
# =============================================================================

class TestClickjackVulnType:
    """Tests for ClickjackVulnType enum."""

    def test_no_protection_exists(self):
        """Test NO_PROTECTION type exists."""
        assert ClickjackVulnType.NO_PROTECTION

    def test_weak_xfo_exists(self):
        """Test WEAK_XFO type exists."""
        assert ClickjackVulnType.WEAK_XFO

    def test_missing_csp_ancestors_exists(self):
        """Test MISSING_CSP_ANCESTORS type exists."""
        assert ClickjackVulnType.MISSING_CSP_ANCESTORS

    def test_xfo_csp_mismatch_exists(self):
        """Test XFO_CSP_MISMATCH type exists."""
        assert ClickjackVulnType.XFO_CSP_MISMATCH

    def test_frame_buster_bypass_exists(self):
        """Test FRAME_BUSTER_BYPASS type exists."""
        assert ClickjackVulnType.FRAME_BUSTER_BYPASS

    def test_partial_protection_exists(self):
        """Test PARTIAL_PROTECTION type exists."""
        assert ClickjackVulnType.PARTIAL_PROTECTION

    def test_sandbox_bypass_exists(self):
        """Test SANDBOX_BYPASS type exists."""
        assert ClickjackVulnType.SANDBOX_BYPASS

    def test_drag_drop_vuln_exists(self):
        """Test DRAG_DROP_VULN type exists."""
        assert ClickjackVulnType.DRAG_DROP_VULN

    def test_prefilled_form_exists(self):
        """Test PREFILLED_FORM type exists."""
        assert ClickjackVulnType.PREFILLED_FORM

    def test_double_click_exists(self):
        """Test DOUBLE_CLICK type exists."""
        assert ClickjackVulnType.DOUBLE_CLICK

    def test_cursor_hijack_exists(self):
        """Test CURSOR_HIJACK type exists."""
        assert ClickjackVulnType.CURSOR_HIJACK

    def test_mobile_clickjack_exists(self):
        """Test MOBILE_CLICKJACK type exists."""
        assert ClickjackVulnType.MOBILE_CLICKJACK


# =============================================================================
# PROTECTION LEVEL ENUM TESTS
# =============================================================================

class TestProtectionLevel:
    """Tests for ProtectionLevel enum."""

    def test_none_exists(self):
        """Test NONE level exists."""
        assert ProtectionLevel.NONE

    def test_weak_exists(self):
        """Test WEAK level exists."""
        assert ProtectionLevel.WEAK

    def test_partial_exists(self):
        """Test PARTIAL level exists."""
        assert ProtectionLevel.PARTIAL

    def test_strong_exists(self):
        """Test STRONG level exists."""
        assert ProtectionLevel.STRONG

    def test_excellent_exists(self):
        """Test EXCELLENT level exists."""
        assert ProtectionLevel.EXCELLENT


# =============================================================================
# X-FRAME-OPTIONS VALUE ENUM TESTS
# =============================================================================

class TestXFrameOptionsValue:
    """Tests for XFrameOptionsValue enum."""

    def test_deny_value(self):
        """Test DENY value is correct."""
        assert XFrameOptionsValue.DENY.value == "DENY"

    def test_sameorigin_value(self):
        """Test SAMEORIGIN value is correct."""
        assert XFrameOptionsValue.SAMEORIGIN.value == "SAMEORIGIN"

    def test_allow_from_value(self):
        """Test ALLOW-FROM value is correct."""
        assert XFrameOptionsValue.ALLOW_FROM.value == "ALLOW-FROM"

    def test_invalid_exists(self):
        """Test INVALID type exists for malformed headers."""
        assert XFrameOptionsValue.INVALID.value == "INVALID"

    def test_missing_exists(self):
        """Test MISSING type exists for absent headers."""
        assert XFrameOptionsValue.MISSING.value == "MISSING"


# =============================================================================
# SENSITIVE_ACTIONS CONSTANT TESTS
# =============================================================================

class TestSensitiveActions:
    """Tests for SENSITIVE_ACTIONS constant."""

    def test_not_empty(self):
        """Test actions list is not empty."""
        assert len(SENSITIVE_ACTIONS) > 0

    def test_account_delete_included(self):
        """Test account delete actions included."""
        account_actions = ["/account/delete", "/profile/delete", "/user/delete"]
        for action in account_actions:
            assert action in SENSITIVE_ACTIONS, f"Missing action: {action}"

    def test_financial_actions_included(self):
        """Test financial actions included."""
        financial = ["/transfer", "/payment", "/checkout", "/purchase"]
        for action in financial:
            assert action in SENSITIVE_ACTIONS, f"Missing action: {action}"

    def test_permission_actions_included(self):
        """Test permission actions included."""
        permissions = ["/admin", "/grant", "/authorize", "/approve"]
        for action in permissions:
            assert action in SENSITIVE_ACTIONS, f"Missing action: {action}"

    def test_social_actions_included(self):
        """Test social actions included."""
        social = ["/follow", "/like", "/share", "/post"]
        for action in social:
            assert action in SENSITIVE_ACTIONS, f"Missing action: {action}"

    def test_oauth_actions_included(self):
        """Test OAuth actions included."""
        oauth = ["/oauth/authorize", "/oauth/consent"]
        for action in oauth:
            assert action in SENSITIVE_ACTIONS, f"Missing action: {action}"

    def test_settings_actions_included(self):
        """Test settings actions included."""
        settings = ["/settings", "/change-password", "/change-email"]
        for action in settings:
            assert action in SENSITIVE_ACTIONS, f"Missing action: {action}"


# =============================================================================
# FRAME PROTECTION STATUS DATACLASS TESTS
# =============================================================================

class TestFrameProtectionStatus:
    """Tests for FrameProtectionStatus dataclass."""

    def test_default_values(self):
        """Test default values are set correctly."""
        status = FrameProtectionStatus(url="https://example.com")
        assert status.url == "https://example.com"
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

    def test_xfo_values_set(self):
        """Test XFO values can be set."""
        status = FrameProtectionStatus(
            url="https://example.com",
            has_xfo=True,
            xfo_value="DENY",
            xfo_parsed=XFrameOptionsValue.DENY
        )
        assert status.has_xfo is True
        assert status.xfo_value == "DENY"
        assert status.xfo_parsed == XFrameOptionsValue.DENY

    def test_csp_values_set(self):
        """Test CSP values can be set."""
        status = FrameProtectionStatus(
            url="https://example.com",
            has_csp=True,
            csp_frame_ancestors="'self'"
        )
        assert status.has_csp is True
        assert status.csp_frame_ancestors == "'self'"

    def test_frame_buster_values(self):
        """Test frame buster values can be set."""
        status = FrameProtectionStatus(
            url="https://example.com",
            has_frame_buster=True,
            frame_buster_bypassable=True
        )
        assert status.has_frame_buster is True
        assert status.frame_buster_bypassable is True

    def test_notes_list(self):
        """Test notes can be added."""
        status = FrameProtectionStatus(url="https://example.com")
        status.notes.append("Missing X-Frame-Options")
        status.notes.append("No CSP frame-ancestors")
        assert len(status.notes) == 2


# =============================================================================
# CLICKJACK ENDPOINT DATACLASS TESTS
# =============================================================================

class TestClickjackEndpoint:
    """Tests for ClickjackEndpoint dataclass."""

    def test_default_values(self):
        """Test default values are set correctly."""
        endpoint = ClickjackEndpoint(url="https://example.com/transfer")
        assert endpoint.url == "https://example.com/transfer"
        assert endpoint.method == "GET"
        assert endpoint.is_sensitive is False
        assert endpoint.action_type == "unknown"
        assert endpoint.requires_auth is False
        assert endpoint.has_form is False
        assert endpoint.form_action is None
        assert endpoint.prefillable_params == []

    def test_sensitive_endpoint(self):
        """Test sensitive endpoint configuration."""
        endpoint = ClickjackEndpoint(
            url="https://example.com/transfer",
            method="POST",
            is_sensitive=True,
            action_type="financial",
            requires_auth=True
        )
        assert endpoint.is_sensitive is True
        assert endpoint.action_type == "financial"
        assert endpoint.requires_auth is True

    def test_form_endpoint(self):
        """Test endpoint with form."""
        endpoint = ClickjackEndpoint(
            url="https://example.com/settings",
            has_form=True,
            form_action="/settings/update",
            prefillable_params=["email", "phone"]
        )
        assert endpoint.has_form is True
        assert endpoint.form_action == "/settings/update"
        assert "email" in endpoint.prefillable_params


# =============================================================================
# SCAN CONFIG DATACLASS TESTS
# =============================================================================

class TestScanConfig:
    """Tests for ScanConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScanConfig(target_url="https://example.com")
        assert config.target_url == "https://example.com"
        assert config.timeout == 30.0
        assert config.test_sensitive_pages is True
        assert config.test_frame_busters is True
        assert config.generate_poc is True
        assert config.follow_redirects is True
        assert config.check_all_pages is False
        assert config.custom_sensitive_paths == []

    def test_custom_config(self):
        """Test custom configuration."""
        config = ScanConfig(
            target_url="https://example.com",
            timeout=60.0,
            check_all_pages=True,
            custom_sensitive_paths=["/admin/delete-all", "/dangerous"]
        )
        assert config.timeout == 60.0
        assert config.check_all_pages is True
        assert len(config.custom_sensitive_paths) == 2


# =============================================================================
# FRAME PROTECTION ANALYZER TESTS
# =============================================================================

class TestFrameProtectionAnalyzer:
    """Tests for FrameProtectionAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = FrameProtectionAnalyzer()
        assert analyzer.http_client is None
        assert analyzer.VERSION == "3.0.0"

    def test_analyzer_with_http_client(self):
        """Test analyzer can be initialized with http_client."""
        mock_client = object()
        analyzer = FrameProtectionAnalyzer(http_client=mock_client)
        assert analyzer.http_client is mock_client

    def test_frame_buster_patterns_exist(self):
        """Test frame buster patterns are defined."""
        assert len(FrameProtectionAnalyzer.FRAME_BUSTER_PATTERNS) > 0

    def test_frame_buster_patterns_common(self):
        """Test common frame buster patterns are included."""
        patterns = FrameProtectionAnalyzer.FRAME_BUSTER_PATTERNS
        # Check for patterns related to frame detection
        patterns_str = " ".join(patterns)
        assert "top" in patterns_str, "Missing top-related pattern"
        assert "location" in patterns_str or "self" in patterns_str, "Missing location/self pattern"

    def test_frame_buster_bypasses_exist(self):
        """Test frame buster bypass techniques are defined."""
        bypasses = FrameProtectionAnalyzer.FRAME_BUSTER_BYPASSES
        assert len(bypasses) > 0
        # Check bypass techniques
        bypass_names = [b[0] for b in bypasses]
        assert "sandbox" in bypass_names
        assert "double_frame" in bypass_names
        assert "onbeforeunload" in bypass_names


class TestFrameProtectionAnalyzerXFO:
    """Tests for X-Frame-Options analysis."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return FrameProtectionAnalyzer()

    @pytest.mark.asyncio
    async def test_missing_xfo(self, analyzer):
        """Test detection of missing X-Frame-Options."""
        headers = {"Content-Type": "text/html"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is False
        assert status.xfo_parsed == XFrameOptionsValue.MISSING
        assert any("missing" in note.lower() for note in status.notes)

    @pytest.mark.asyncio
    async def test_xfo_deny(self, analyzer):
        """Test X-Frame-Options: DENY detection."""
        headers = {"X-Frame-Options": "DENY"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.xfo_value == "DENY"
        assert status.xfo_parsed == XFrameOptionsValue.DENY

    @pytest.mark.asyncio
    async def test_xfo_sameorigin(self, analyzer):
        """Test X-Frame-Options: SAMEORIGIN detection."""
        headers = {"X-Frame-Options": "SAMEORIGIN"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.SAMEORIGIN

    @pytest.mark.asyncio
    async def test_xfo_allow_from(self, analyzer):
        """Test X-Frame-Options: ALLOW-FROM detection."""
        headers = {"X-Frame-Options": "ALLOW-FROM https://trusted.com"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.ALLOW_FROM

    @pytest.mark.asyncio
    async def test_xfo_case_insensitive(self, analyzer):
        """Test X-Frame-Options header is case insensitive."""
        headers = {"x-frame-options": "deny"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.DENY


class TestFrameProtectionAnalyzerCSP:
    """Tests for CSP frame-ancestors analysis."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return FrameProtectionAnalyzer()

    @pytest.mark.asyncio
    async def test_missing_csp(self, analyzer):
        """Test detection of missing CSP."""
        headers = {"Content-Type": "text/html"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_csp is False
        assert status.csp_frame_ancestors is None

    @pytest.mark.asyncio
    async def test_csp_frame_ancestors_none(self, analyzer):
        """Test CSP frame-ancestors: 'none' detection."""
        headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_csp is True
        assert "'none'" in status.csp_frame_ancestors

    @pytest.mark.asyncio
    async def test_csp_frame_ancestors_self(self, analyzer):
        """Test CSP frame-ancestors: 'self' detection."""
        headers = {"Content-Security-Policy": "frame-ancestors 'self'"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_csp is True
        assert "'self'" in status.csp_frame_ancestors

    @pytest.mark.asyncio
    async def test_csp_without_frame_ancestors(self, analyzer):
        """Test CSP without frame-ancestors directive."""
        headers = {"Content-Security-Policy": "default-src 'self'"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        # Has CSP but no frame-ancestors
        assert status.csp_frame_ancestors is None or status.csp_frame_ancestors == ""


class TestFrameProtectionAnalyzerFrameBuster:
    """Tests for frame buster script detection."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return FrameProtectionAnalyzer()

    @pytest.mark.asyncio
    async def test_no_frame_buster(self, analyzer):
        """Test page without frame buster."""
        headers = {}
        body = "<html><script>console.log('hello');</script></html>"
        status = await analyzer.analyze("https://example.com", headers, body)
        assert status.has_frame_buster is False

    @pytest.mark.asyncio
    async def test_frame_buster_top_self(self, analyzer):
        """Test detection of top !== self frame buster."""
        headers = {}
        body = "<html><script>if (top !== self) { top.location = self.location; }</script></html>"
        status = await analyzer.analyze("https://example.com", headers, body)
        assert status.has_frame_buster is True

    @pytest.mark.asyncio
    async def test_frame_buster_top_location(self, analyzer):
        """Test detection of top.location redirect."""
        headers = {}
        body = "<html><script>top.location = window.location;</script></html>"
        status = await analyzer.analyze("https://example.com", headers, body)
        assert status.has_frame_buster is True

    @pytest.mark.asyncio
    async def test_frame_buster_window_top(self, analyzer):
        """Test detection of window.top check."""
        headers = {}
        body = "<html><script>if (window !== top) { document.body.innerHTML = ''; }</script></html>"
        status = await analyzer.analyze("https://example.com", headers, body)
        assert status.has_frame_buster is True


class TestFrameProtectionAnalyzerProtectionLevel:
    """Tests for protection level determination."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return FrameProtectionAnalyzer()

    @pytest.mark.asyncio
    async def test_no_protection(self, analyzer):
        """Test NONE protection level when no headers."""
        headers = {}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.protection_level == ProtectionLevel.NONE

    @pytest.mark.asyncio
    async def test_strong_protection_xfo_deny(self, analyzer):
        """Test STRONG protection with XFO DENY."""
        headers = {"X-Frame-Options": "DENY"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.protection_level == ProtectionLevel.STRONG

    @pytest.mark.asyncio
    async def test_excellent_protection_both(self, analyzer):
        """Test EXCELLENT protection with both XFO and CSP."""
        headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'"
        }
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.has_csp is True
        assert status.protection_level == ProtectionLevel.EXCELLENT

    @pytest.mark.asyncio
    async def test_weak_protection_allow_from(self, analyzer):
        """Test WEAK protection with deprecated ALLOW-FROM."""
        headers = {"X-Frame-Options": "ALLOW-FROM https://example.com"}
        status = await analyzer.analyze("https://example.com", headers, "<html></html>")
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.ALLOW_FROM
        assert status.protection_level == ProtectionLevel.WEAK


# =============================================================================
# CLICKJACK FINDING DATACLASS TESTS
# =============================================================================

class TestClickjackFinding:
    """Tests for ClickjackFinding dataclass."""

    def test_finding_creation(self):
        """Test finding can be created with all fields."""
        endpoint = ClickjackEndpoint(url="https://example.com/transfer")
        status = FrameProtectionStatus(url="https://example.com/transfer")

        finding = ClickjackFinding(
            id="CLICK-001",
            vuln_type=ClickjackVulnType.NO_PROTECTION,
            severity="MEDIUM",
            confidence=0.9,
            endpoint=endpoint,
            protection_status=status,
            description="Page can be framed by any origin",
            impact="User actions can be hijacked",
            remediation="Add X-Frame-Options: DENY",
            poc_html="<iframe src='...'></iframe>",
            cwe_id=1021,
            cvss_score=4.3,
            evidence={"headers": {}}
        )

        assert finding.id == "CLICK-001"
        assert finding.vuln_type == ClickjackVulnType.NO_PROTECTION
        assert finding.severity == "MEDIUM"
        assert finding.confidence == 0.9
        assert finding.cwe_id == 1021
        assert finding.cvss_score == 4.3
        assert "X-Frame-Options" in finding.remediation

    def test_finding_severity_values(self):
        """Test various severity values."""
        endpoint = ClickjackEndpoint(url="https://example.com")
        status = FrameProtectionStatus(url="https://example.com")

        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            finding = ClickjackFinding(
                id=f"CLICK-{severity}",
                vuln_type=ClickjackVulnType.NO_PROTECTION,
                severity=severity,
                confidence=0.8,
                endpoint=endpoint,
                protection_status=status,
                description="Test",
                impact="Test",
                remediation="Test",
                poc_html="",
                cwe_id=1021,
                cvss_score=0.0,
                evidence={}
            )
            assert finding.severity == severity


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestClickjackingIntegration:
    """Integration tests for clickjacking detection scenarios."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return FrameProtectionAnalyzer()

    @pytest.mark.asyncio
    async def test_vulnerable_page_detection(self, analyzer):
        """Test detection of vulnerable page (no protection)."""
        headers = {"Content-Type": "text/html"}
        body = """
        <html>
        <head><title>Transfer Funds</title></head>
        <body>
            <form action="/transfer" method="POST">
                <input name="amount" type="text">
                <input name="to_account" type="text">
                <button type="submit">Transfer</button>
            </form>
        </body>
        </html>
        """
        status = await analyzer.analyze("https://bank.com/transfer", headers, body)
        assert status.protection_level == ProtectionLevel.NONE
        assert status.has_xfo is False
        assert status.has_csp is False

    @pytest.mark.asyncio
    async def test_properly_protected_page(self, analyzer):
        """Test detection of properly protected page."""
        headers = {
            "Content-Type": "text/html",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'"
        }
        body = "<html><body>Protected page</body></html>"
        status = await analyzer.analyze("https://secure.com", headers, body)
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.DENY
        assert status.has_csp is True
        assert status.protection_level == ProtectionLevel.EXCELLENT

    @pytest.mark.asyncio
    async def test_partial_protection_detection(self, analyzer):
        """Test detection of partial protection (only XFO SAMEORIGIN)."""
        headers = {
            "Content-Type": "text/html",
            "X-Frame-Options": "SAMEORIGIN"
        }
        body = "<html><body>Partial protection</body></html>"
        status = await analyzer.analyze("https://example.com", headers, body)
        assert status.has_xfo is True
        assert status.xfo_parsed == XFrameOptionsValue.SAMEORIGIN
        # SAMEORIGIN provides strong protection
        assert status.protection_level == ProtectionLevel.STRONG

    @pytest.mark.asyncio
    async def test_bypassable_frame_buster(self, analyzer):
        """Test detection of bypassable frame buster."""
        headers = {}
        # Simple frame buster that can be bypassed with sandbox attribute
        body = """
        <html>
        <script>
            if (top != self) {
                top.location = self.location;
            }
        </script>
        <body>Page content</body>
        </html>
        """
        status = await analyzer.analyze("https://example.com", headers, body)
        assert status.has_frame_buster is True
        # Without XFO/CSP, frame buster is bypassable via sandbox
        assert status.protection_level in [ProtectionLevel.NONE, ProtectionLevel.WEAK]
