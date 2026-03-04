"""
Tests for XSS scanner base types and constants.

Tests cover:
- Enums (XSSContext, WAFType)
- Dataclasses (XSSEvidence, XSSResult, TrackedInput)
- Constants (payloads, DOM sources/sinks)
"""

import pytest
from unittest.mock import MagicMock

from scanning.modules.xss.xss_base import (
    # Enums
    XSSContext,
    WAFType,
    # Dataclasses
    XSSEvidence,
    XSSResult,
    TrackedInput,
    # Constants
    MIN_CONFIDENCE_THRESHOLD,
    POLYGLOT_PAYLOADS,
)


class TestXSSContext:
    """Tests for XSSContext enum."""

    def test_all_contexts_present(self):
        """Verify all XSS contexts are defined."""
        contexts = {c.name for c in XSSContext}
        expected = {
            "HTML_TEXT",
            "HTML_ATTRIBUTE",
            "HTML_ATTRIBUTE_UNQUOTED",
            "HTML_ATTRIBUTE_SINGLE",
            "JS_STRING",
            "JS_STRING_SINGLE",
            "JS_TEMPLATE",
            "JS_BLOCK",
            "URL_PARAM",
            "CSS_VALUE",
            "SVG_CONTEXT",
            "COMMENT",
            "ALPINE_DIRECTIVE",
            "HTMX_ATTRIBUTE",
            "VUE_DIRECTIVE",
            "SVELTE_BINDING",
            "ANGULAR_BINDING",
            "UNKNOWN",
        }
        assert contexts == expected

    def test_unique_values(self):
        """Verify all contexts have unique values."""
        values = [c.value for c in XSSContext]
        assert len(values) == len(set(values))

    def test_modern_framework_contexts(self):
        """Verify modern framework contexts are present."""
        modern_contexts = [
            XSSContext.ALPINE_DIRECTIVE,
            XSSContext.HTMX_ATTRIBUTE,
            XSSContext.VUE_DIRECTIVE,
            XSSContext.SVELTE_BINDING,
            XSSContext.ANGULAR_BINDING,
        ]
        for ctx in modern_contexts:
            assert ctx in XSSContext


class TestWAFType:
    """Tests for WAFType enum."""

    def test_common_wafs_present(self):
        """Verify common WAFs are defined."""
        waf_names = {w.name for w in WAFType}
        common_wafs = {
            "CLOUDFLARE",
            "AWS_WAF",
            "AKAMAI",
            "MODSECURITY",
            "UNKNOWN",
            "NONE",
        }
        assert common_wafs.issubset(waf_names)

    def test_from_base_conversion(self):
        """Test WAFType.from_base conversion works."""
        from utils.scanner_helpers import WAFType as BaseWAFType

        result = WAFType.from_base(BaseWAFType.CLOUDFLARE)
        assert result == WAFType.CLOUDFLARE

        result = WAFType.from_base(BaseWAFType.NONE)
        assert result == WAFType.NONE


class TestXSSEvidence:
    """Tests for XSSEvidence dataclass."""

    def test_basic_creation(self):
        """Test basic XSSEvidence creation."""
        evidence = XSSEvidence(
            payload="<script>alert(1)</script>",
            context=XSSContext.HTML_TEXT,
            reflected_in="response_body",
            encoding_used="none",
            waf_bypassed=False,
            response_snippet="<div><script>alert(1)</script></div>",
        )

        assert evidence.payload == "<script>alert(1)</script>"
        assert evidence.context == XSSContext.HTML_TEXT
        assert evidence.waf_bypassed is False
        assert evidence.confirmation_count == 0

    def test_with_waf_bypass(self):
        """Test XSSEvidence with WAF bypass."""
        evidence = XSSEvidence(
            payload="<img src=x onerror=alert(1)>",
            context=XSSContext.HTML_ATTRIBUTE,
            reflected_in="response_body",
            encoding_used="html_entity",
            waf_bypassed=True,
            response_snippet='<input value="<img src=x onerror=alert(1)>">',
            confirmation_count=2,
        )

        assert evidence.waf_bypassed is True
        assert evidence.confirmation_count == 2

    def test_to_dict(self):
        """Test XSSEvidence serialization."""
        evidence = XSSEvidence(
            payload="<svg onload=alert(1)>",
            context=XSSContext.SVG_CONTEXT,
            reflected_in="response_body",
            encoding_used="none",
            waf_bypassed=True,
            response_snippet="<svg onload=alert(1)>...",
        )

        data = evidence.to_dict()

        assert data["payload"] == "<svg onload=alert(1)>"
        assert data["context"] == "SVG_CONTEXT"
        assert data["waf_bypassed"] is True
        assert "response_snippet" in data

    def test_to_dict_truncates_long_snippets(self):
        """Test that to_dict truncates long response snippets."""
        long_snippet = "X" * 1000
        evidence = XSSEvidence(
            payload="test",
            context=XSSContext.HTML_TEXT,
            reflected_in="body",
            encoding_used="none",
            waf_bypassed=False,
            response_snippet=long_snippet,
        )

        data = evidence.to_dict()

        assert len(data["response_snippet"]) == 500


class TestXSSResult:
    """Tests for XSSResult dataclass."""

    def test_not_vulnerable(self):
        """Test XSSResult for not vulnerable case."""
        result = XSSResult(
            vulnerable=False,
            context=XSSContext.UNKNOWN,
            confidence=0.0,
            payload="",
        )

        assert result.vulnerable is False
        assert result.confidence == 0.0
        assert result.evidence == []

    def test_vulnerable_with_evidence(self):
        """Test XSSResult with vulnerability found."""
        evidence = XSSEvidence(
            payload="<script>alert(1)</script>",
            context=XSSContext.HTML_TEXT,
            reflected_in="body",
            encoding_used="none",
            waf_bypassed=False,
            response_snippet="...",
        )
        result = XSSResult(
            vulnerable=True,
            context=XSSContext.HTML_TEXT,
            confidence=95.0,
            payload="<script>alert(1)</script>",
            evidence=[evidence],
        )

        assert result.vulnerable is True
        assert result.confidence == 95.0
        assert len(result.evidence) == 1

    def test_with_waf_detection(self):
        """Test XSSResult with WAF detected."""
        result = XSSResult(
            vulnerable=True,
            context=XSSContext.HTML_TEXT,
            confidence=85.0,
            payload="test",
            waf_detected=WAFType.CLOUDFLARE,
        )

        assert result.waf_detected == WAFType.CLOUDFLARE

    def test_with_csp(self):
        """Test XSSResult with CSP present."""
        result = XSSResult(
            vulnerable=True,
            context=XSSContext.JS_STRING,
            confidence=80.0,
            payload="test",
            csp_present=True,
            csp_bypassed=True,
        )

        assert result.csp_present is True
        assert result.csp_bypassed is True


class TestTrackedInput:
    """Tests for TrackedInput dataclass (second-order XSS tracking)."""

    def test_basic_creation(self):
        """Test basic TrackedInput creation."""
        tracked = TrackedInput(
            submit_endpoint="/profile/update",
            submit_method="POST",
            field_name="bio",
            payload="<script>alert(1)</script>",
            payload_marker="XSS_12345",
            timestamp=1645000000.0,
            response_status=200,
            response_contains_marker=False,
        )

        assert tracked.submit_endpoint == "/profile/update"
        assert tracked.submit_method == "POST"
        assert tracked.payload_marker == "XSS_12345"

    def test_to_dict(self):
        """Test TrackedInput serialization."""
        tracked = TrackedInput(
            submit_endpoint="/comment/add",
            submit_method="POST",
            field_name="comment",
            payload="<img src=x onerror=alert(1)>",
            payload_marker="MARKER_ABC",
            timestamp=1645000000.0,
            response_status=201,
            response_contains_marker=True,
        )

        data = tracked.to_dict()

        assert data["submit_endpoint"] == "/comment/add"
        assert data["field_name"] == "comment"
        assert data["response_status"] == 201


class TestPolyglotPayloads:
    """Tests for polyglot payload constants."""

    def test_payloads_exist(self):
        """Test that polyglot payloads are defined."""
        assert len(POLYGLOT_PAYLOADS) > 0

    def test_payloads_are_strings(self):
        """Test that all payloads are strings."""
        for payload in POLYGLOT_PAYLOADS:
            assert isinstance(payload, str)

    def test_payloads_contain_xss_vectors(self):
        """Test that payloads contain common XSS vectors."""
        all_payloads = " ".join(POLYGLOT_PAYLOADS)

        # Common XSS patterns
        assert "script" in all_payloads.lower()
        assert "alert" in all_payloads.lower()

    def test_payloads_multi_context(self):
        """Test that polyglots target multiple contexts."""
        all_payloads = " ".join(POLYGLOT_PAYLOADS)

        # Should contain HTML escapes
        assert "<" in all_payloads
        assert ">" in all_payloads

        # Should contain attribute escapes
        assert '"' in all_payloads or "'" in all_payloads

        # Should contain event handlers
        assert "on" in all_payloads.lower()


class TestConstants:
    """Tests for XSS scanner constants."""

    def test_min_confidence_reasonable(self):
        """Test MIN_CONFIDENCE_THRESHOLD is reasonable."""
        assert 50 <= MIN_CONFIDENCE_THRESHOLD <= 90


class TestXSSContextUsage:
    """Tests for XSSContext usage scenarios."""

    def test_html_text_context(self):
        """Test HTML_TEXT context is for between-tags injection."""
        # HTML_TEXT: <div>INJECTION</div>
        ctx = XSSContext.HTML_TEXT
        assert ctx.name == "HTML_TEXT"

    def test_html_attribute_contexts(self):
        """Test HTML attribute contexts for different quote styles."""
        # Double quoted: <input value="INJECTION">
        assert XSSContext.HTML_ATTRIBUTE is not None

        # Single quoted: <input value='INJECTION'>
        assert XSSContext.HTML_ATTRIBUTE_SINGLE is not None

        # Unquoted: <input value=INJECTION>
        assert XSSContext.HTML_ATTRIBUTE_UNQUOTED is not None

    def test_js_contexts(self):
        """Test JavaScript contexts."""
        # Double quoted string: var x = "INJECTION";
        assert XSSContext.JS_STRING is not None

        # Single quoted: var x = 'INJECTION';
        assert XSSContext.JS_STRING_SINGLE is not None

        # Template literal: var x = `INJECTION`;
        assert XSSContext.JS_TEMPLATE is not None

        # Script block: <script>INJECTION</script>
        assert XSSContext.JS_BLOCK is not None

    def test_modern_framework_contexts_exist(self):
        """Test modern reactive framework contexts exist."""
        # Alpine.js: x-data="INJECTION"
        assert XSSContext.ALPINE_DIRECTIVE is not None

        # HTMX: hx-get="INJECTION"
        assert XSSContext.HTMX_ATTRIBUTE is not None

        # Vue.js: :attr="INJECTION"
        assert XSSContext.VUE_DIRECTIVE is not None

        # Svelte: bind:value="INJECTION"
        assert XSSContext.SVELTE_BINDING is not None

        # Angular: [attr]="INJECTION"
        assert XSSContext.ANGULAR_BINDING is not None
